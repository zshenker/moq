//! Batches sends from every connection on a socket into one `sendmmsg` per scheduler round (see
//! [`Endpoint::batch_sends`](crate::quic::driver::endpoint::Endpoint::batch_sends)).
//!
//! Each connection sends from its own task, so with small objects every datagram costs a syscall
//! of its own. [`BatchSocket`] queues what connections send instead, and one flush task sends the
//! queue once the runtime has polled the other tasks that were ready.

use std::{
	fmt, io,
	net::{IpAddr, SocketAddr},
	sync::{Arc, Mutex, RwLock},
	task::{Context, Poll, Waker},
};

use moq_sock::udp::{EcnCodepoint, RecvMeta, Transmit};
use tokio::sync::Notify;

use super::{AsyncUdpSocket, send_failed};
use crate::{quic::driver::Instant, runtime::Spawner};

/// Queued bytes past which a send waits for the flush, so a socket that can't keep up pushes back
const MAX_QUEUED_BYTES: usize = 1 << 20;

/// Wraps a socket so that sends queue for one batched flush per scheduler round
///
/// A queued send has succeeded as far as its connection knows, so a send that later finds no
/// route is logged and counted as loss. That is what
/// [`handle_unreachable`](moq_quic::connection::Connection::handle_unreachable) makes of it once a
/// connection is established; a handshake, which it fails at once, sends through
/// [`try_send_now`](AsyncUdpSocket::try_send_now) instead.
///
/// Dropping it sends what is still queued, as far as the socket has room, and closes the socket
/// at once, as dropping the socket it wraps would.
pub(crate) struct BatchSocket {
	shared: Arc<Shared>,
}

struct Shared {
	/// The socket, until the [`BatchSocket`] drops and closes it
	inner: RwLock<Option<Box<dyn AsyncUdpSocket>>>,
	/// The socket's queries, which outlive it
	local_addr: io::Result<SocketAddr>,
	max_receive_segments: usize,
	max_transmit_segments: usize,
	may_fragment: bool,
	queue: Mutex<Queue>,
	/// Wakes the flush task once the queue has something in it, or the socket closes
	flush: Notify,
}

#[derive(Default)]
struct Queue {
	buf: Vec<u8>,
	sends: Vec<Queued>,
	/// Whether the flush task has been woken for what is queued
	scheduled: bool,
	/// The sender waiting for the queue to drain
	writable: Option<Waker>,
}

struct Queued {
	destination: SocketAddr,
	ecn: Option<EcnCodepoint>,
	src_ip: Option<IpAddr>,
	segment_size: Option<usize>,
	len: usize,
}

impl BatchSocket {
	/// Wrap `inner`, flushing its queue from a task on `runtime`
	pub(crate) fn new(inner: Box<dyn AsyncUdpSocket>, runtime: &Spawner) -> Self {
		let shared = Arc::new(Shared {
			local_addr: inner.local_addr(),
			max_receive_segments: inner.max_receive_segments(),
			max_transmit_segments: inner.max_transmit_segments(),
			may_fragment: inner.may_fragment(),
			inner: RwLock::new(Some(inner)),
			queue: Mutex::default(),
			flush: Notify::new(),
		});
		runtime.spawn(flush(shared.clone()));
		Self { shared }
	}
}

impl Drop for BatchSocket {
	fn drop(&mut self) {
		let Some(inner) = self.shared.inner.write().unwrap().take() else {
			return;
		};
		let mut out = Queue::default();
		self.shared.queue.lock().unwrap().take_into(&mut out);
		let transmits = out.transmits();
		let mut sent = 0;
		// Connections' closes are queued, so send what the socket has room for now.
		while sent < transmits.len() {
			match inner.try_send_many(&transmits[sent..]) {
				Ok(n) => sent += n,
				Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
				Err(_) => sent += 1,
			}
		}
		self.shared.flush.notify_one();
	}
}

impl fmt::Debug for BatchSocket {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("BatchSocket")
			.field("inner", &self.shared.inner.read().unwrap())
			.finish_non_exhaustive()
	}
}

impl AsyncUdpSocket for BatchSocket {
	fn poll_recv(
		&self,
		cx: &mut Context<'_>,
		bufs: &mut [io::IoSliceMut<'_>],
		meta: &mut [RecvMeta],
	) -> Poll<io::Result<usize>> {
		match self.shared.inner.read().unwrap().as_deref() {
			Some(inner) => inner.poll_recv(cx, bufs, meta),
			None => Poll::Pending,
		}
	}

	fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
		let mut queue = self.shared.queue.lock().unwrap();
		if !queue.buf.is_empty() && queue.buf.len() + transmit.contents.len() > MAX_QUEUED_BYTES {
			return Err(io::ErrorKind::WouldBlock.into());
		}
		queue.buf.extend_from_slice(transmit.contents);
		queue.sends.push(Queued {
			destination: transmit.destination,
			ecn: transmit.ecn,
			src_ip: transmit.src_ip,
			segment_size: transmit.segment_size,
			len: transmit.contents.len(),
		});
		if !std::mem::replace(&mut queue.scheduled, true) {
			drop(queue);
			self.shared.flush.notify_one();
		}
		Ok(())
	}

	/// Sends straight from the caller's task, queueing only when the socket is full
	fn try_send_now(&self, transmit: &Transmit<'_>) -> io::Result<()> {
		let result = match self.shared.inner.read().unwrap().as_deref() {
			Some(inner) => inner.try_send(transmit),
			None => return Ok(()),
		};
		match result {
			Err(err) if err.kind() == io::ErrorKind::WouldBlock => self.try_send(transmit),
			result => result,
		}
	}

	fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let mut queue = self.shared.queue.lock().unwrap();
		if queue.buf.len() < MAX_QUEUED_BYTES / 2 {
			return Poll::Ready(Ok(()));
		}
		queue.writable = Some(cx.waker().clone());
		Poll::Pending
	}

	fn local_addr(&self) -> io::Result<SocketAddr> {
		match &self.shared.local_addr {
			Ok(addr) => Ok(*addr),
			Err(err) => Err(io::Error::new(err.kind(), err.to_string())),
		}
	}

	fn max_receive_segments(&self) -> usize {
		self.shared.max_receive_segments
	}

	fn max_transmit_segments(&self) -> usize {
		self.shared.max_transmit_segments
	}

	fn may_fragment(&self) -> bool {
		self.shared.may_fragment
	}
}

impl Queue {
	/// Move what is queued into `out`, which must be empty, and hand back any waiting sender
	fn take_into(&mut self, out: &mut Self) {
		std::mem::swap(&mut self.buf, &mut out.buf);
		std::mem::swap(&mut self.sends, &mut out.sends);
		self.scheduled = false;
		if let Some(waker) = self.writable.take() {
			waker.wake();
		}
	}

	fn transmits(&self) -> Vec<Transmit<'_>> {
		let mut start = 0;
		self.sends
			.iter()
			.map(|send| {
				let contents = &self.buf[start..start + send.len];
				start += send.len;
				Transmit {
					destination: send.destination,
					ecn: send.ecn,
					contents,
					segment_size: send.segment_size,
					src_ip: send.src_ip,
				}
			})
			.collect()
	}

	fn clear(&mut self) {
		self.buf.clear();
		self.sends.clear();
	}
}

/// Sends whatever the connections queued, once per wake, until the socket closes
async fn flush(shared: Arc<Shared>) {
	let mut out = Queue::default();
	let mut last_send_error = None;
	loop {
		shared.flush.notified().await;
		if shared.inner.read().unwrap().is_none() {
			return;
		}
		// A yield runs after the tasks already ready, so their sends join this batch.
		tokio::task::yield_now().await;

		shared.queue.lock().unwrap().take_into(&mut out);
		send_all(&shared, &out.transmits(), &mut last_send_error).await;
		out.clear();
	}
}

/// Send `transmits` in order, waiting for room as needed, until they are sent or the socket closes
async fn send_all(shared: &Shared, mut transmits: &[Transmit<'_>], last_send_error: &mut Option<Instant>) {
	while !transmits.is_empty() {
		let result = match shared.inner.read().unwrap().as_deref() {
			Some(inner) => inner.try_send_many(transmits),
			None => return,
		};
		match result {
			Ok(sent) => transmits = &transmits[sent..],
			Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
				let writable = std::future::poll_fn(|cx| match shared.inner.read().unwrap().as_deref() {
					Some(inner) => inner.poll_writable(cx),
					None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
				})
				.await;
				if let Err(err) = writable {
					tracing::debug!(%err, dropped = transmits.len(), "batched sends lost waiting for room");
					return;
				}
			}
			Err(err) => {
				if let Err(err) = send_failed(last_send_error, err, &transmits[0]) {
					tracing::debug!(%err, "no route to the peer of a batched send");
				}
				transmits = &transmits[1..];
			}
		}
	}
}
