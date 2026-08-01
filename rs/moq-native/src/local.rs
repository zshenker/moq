//! Local-network discovery and meshing, no relay, internet, or certificate
//! setup needed.
//!
//! [`Discovery`] advertises this process as a `_moq._udp.local.` DNS-SD service
//! and reports every other MoQ process heard on the network. The advertisement
//! carries a QUIC port and the SHA-256 fingerprint of a generated certificate,
//! so a dialer pins the fingerprint instead of needing a CA. [`Mesh`] is the
//! batteries-included layer on top: it runs a dedicated QUIC listener, opens
//! one bidirectional session per discovered peer, and attaches every session
//! (dialed and accepted) to a single shared [`moq_net::origin::Producer`], so
//! all peers see each other's broadcasts. Loop prevention comes from the hop
//! list carried on each broadcast's route, exactly like a relay cluster.
//!
//! Anyone on the network can advertise and join, so use this on networks you
//! trust. Sessions are encrypted, but the advertisement is what's authenticated
//! against, not a certificate authority.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use url::Url;

/// The DNS-SD service MoQ processes advertise under.
const SERVICE_TYPE: &str = "_moq._udp.local.";

/// The TXT key carrying the listener certificate's hex SHA-256 fingerprint.
const TXT_FINGERPRINT: &str = "fp";

/// Reconnect pacing for mesh dials, mirroring the relay's cluster dials: quick
/// on a blip, exponential on repeated failure. A session shorter than
/// `DIAL_STABLE` counts as a failure so a peer that rejects us instantly
/// doesn't turn into a tight loop.
const DIAL_BACKOFF_BASE: Duration = Duration::from_secs(1);
const DIAL_BACKOFF_MAX: Duration = Duration::from_secs(300);
const DIAL_STABLE: Duration = Duration::from_secs(10);

/// Errors from local-network discovery and meshing.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
	/// The mDNS daemon failed (e.g. no multicast-capable interface).
	#[error(transparent)]
	Mdns(#[from] mdns_sd::Error),

	/// Building or driving a QUIC endpoint failed.
	#[error(transparent)]
	Transport(#[from] crate::Error),

	/// The MoQ handshake or an established session failed.
	#[error(transparent)]
	Moq(#[from] moq_net::Error),

	/// The mesh listener produced no certificate fingerprint to advertise.
	#[error("no certificate fingerprint to advertise")]
	NoFingerprint,

	/// A dial ran out of advertised addresses without connecting.
	#[error("no reachable address for peer")]
	NoAddress,

	/// Building the dial URL failed.
	#[error(transparent)]
	Url(#[from] url::ParseError),
}

type Result<T> = std::result::Result<T, Error>;

/// A MoQ process discovered on the local network.
#[derive(Clone, Debug)]
pub struct Peer {
	/// The peer's advertised instance id, opaque and unique per run.
	pub id: String,
	/// The addresses the peer advertised.
	pub addrs: Vec<IpAddr>,
	/// The peer's QUIC port.
	pub port: u16,
	/// The hex SHA-256 fingerprint of the peer's certificate, to pin when dialing.
	pub fingerprint: String,
}

/// A change in the set of discovered peers.
#[derive(Clone, Debug)]
pub enum Event {
	/// A peer appeared on the local network, or refreshed its addresses.
	Found(Peer),
	/// A previously discovered peer (by id) stopped advertising.
	Lost(String),
}

/// Advertises this process on the local network and discovers the others.
///
/// Pure discovery: what to do with peers (dial, list, filter) stays with the
/// caller, and [`Discovery::should_dial`] offers the pair tiebreaker. [`Mesh`]
/// is the canned dial-everyone policy. Dropping this stops advertising.
pub struct Discovery {
	id: String,
	daemon: ServiceDaemon,
	events: mdns_sd::Receiver<ServiceEvent>,
}

impl Discovery {
	/// Advertise a MoQ QUIC listener on `port` with the given certificate
	/// `fingerprint` (hex SHA-256), and start browsing for peers.
	///
	/// The instance id is random per run, so a restarted process shows up as a
	/// new peer.
	pub fn new(port: u16, fingerprint: &str) -> Result<Self> {
		let id = format!("{:016x}", rand::random::<u64>());
		let daemon = ServiceDaemon::new()?;

		let service = ServiceInfo::new(
			SERVICE_TYPE,
			&id,
			&format!("{id}.local."),
			"",
			port,
			&[(TXT_FINGERPRINT, fingerprint)][..],
		)?
		.enable_addr_auto();
		daemon.register(service)?;
		let events = daemon.browse(SERVICE_TYPE)?;

		tracing::info!(%id, port, "advertising on the local network");
		Ok(Self { id, daemon, events })
	}

	/// This process's advertised instance id.
	pub fn id(&self) -> &str {
		&self.id
	}

	/// The next discovery event, or `None` once discovery shuts down.
	///
	/// A peer already dialed may be reported again when its addresses change.
	pub async fn recv(&mut self) -> Option<Event> {
		while let Ok(event) = self.events.recv_async().await {
			match event {
				ServiceEvent::ServiceResolved(info) => {
					let Some(id) = instance_id(&info.fullname) else {
						continue;
					};
					if id == self.id {
						continue;
					}
					// A record without a fingerprint can't be dialed securely; skip it.
					let Some(fingerprint) = info.txt_properties.get_property_val_str(TXT_FINGERPRINT) else {
						continue;
					};
					let mut addrs: Vec<IpAddr> = info.addresses.iter().map(|addr| addr.to_ip_addr()).collect();
					// Deterministic order, v4 first: v6 entries are often link-local
					// and need a scope id we don't have.
					addrs.sort_by_key(|addr| (addr.is_ipv6(), *addr));
					return Some(Event::Found(Peer {
						id: id.to_string(),
						addrs,
						port: info.port,
						fingerprint: fingerprint.to_string(),
					}));
				}
				ServiceEvent::ServiceRemoved(_ty, fullname) => {
					let Some(id) = instance_id(&fullname) else { continue };
					if id == self.id {
						continue;
					}
					return Some(Event::Lost(id.to_string()));
				}
				_ => continue,
			}
		}
		None
	}

	/// Whether this process dials `remote`, or waits for `remote` to dial it.
	///
	/// Both sides of a pair discover each other, and a mesh session is
	/// bidirectional, so one connection suffices: the lower id dials and the
	/// higher accepts. Deterministic on both sides with no coordination, like
	/// the relay cluster's URL tiebreaker.
	pub fn should_dial(&self, remote: &str) -> bool {
		should_dial(&self.id, remote)
	}
}

impl Drop for Discovery {
	fn drop(&mut self) {
		// Best-effort goodbye; peers otherwise learn of the exit via TTL expiry.
		self.daemon.shutdown().ok();
	}
}

/// The [`Discovery::should_dial`] tiebreaker: the lower id dials.
fn should_dial(local: &str, remote: &str) -> bool {
	local < remote
}

/// The instance portion of a DNS-SD fullname like `<instance>._moq._udp.local.`.
fn instance_id(fullname: &str) -> Option<&str> {
	fullname.strip_suffix(SERVICE_TYPE)?.strip_suffix('.')
}

/// Connects every discovered local peer to one shared origin.
///
/// Runs its own QUIC listener (a random port with a generated, fingerprint-
/// pinned certificate), advertises it via [`Discovery`], and opens a single
/// bidirectional MoQ session per peer (the lower id dials, see
/// [`Discovery::should_dial`]). Every session, dialed or accepted, both
/// publishes the origin and ingests the peer's broadcasts into it, so the
/// whole network converges on one set of broadcasts with no relay involved.
pub struct Mesh {
	origin: moq_net::origin::Producer,
	versions: moq_net::Versions,
}

impl Mesh {
	/// A mesh publishing and ingesting `origin` on every session.
	pub fn new(origin: moq_net::origin::Producer) -> Self {
		Self {
			origin,
			versions: moq_net::Versions::all(),
		}
	}

	/// Restrict the MoQ protocol versions offered on mesh sessions.
	pub fn with_versions(mut self, versions: moq_net::Versions) -> Self {
		self.versions = versions;
		self
	}

	/// Discover, dial, and accept peers until interrupted (Ctrl-C).
	///
	/// A lost peer (mDNS expiry) has its dial aborted; a dropped session to a
	/// still-advertised peer reconnects with backoff.
	pub async fn run(self) -> Result<()> {
		let mut server = listener()?;
		let port = server.local_addr()?.port();
		let fingerprint = server
			.certificates()
			.fingerprints()
			.into_iter()
			.next()
			.ok_or(Error::NoFingerprint)?;

		let mut discovery = Discovery::new(port, &fingerprint)?;
		let mut dials: HashMap<String, tokio::task::AbortHandle> = HashMap::new();
		let mut tasks = tokio::task::JoinSet::new();

		loop {
			tokio::select! {
				event = discovery.recv() => match event {
					Some(Event::Found(peer)) => {
						if !discovery.should_dial(&peer.id) || dials.contains_key(&peer.id) {
							continue;
						}
						tracing::info!(peer = %peer.id, "discovered local peer; dialing");
						let origin = self.origin.clone();
						let versions = self.versions.clone();
						let id = peer.id.clone();
						let handle = tasks.spawn(dial_peer(origin, versions, peer));
						dials.insert(id, handle);
					}
					Some(Event::Lost(id)) => {
						if let Some(handle) = dials.remove(&id) {
							tracing::info!(peer = %id, "local peer expired; dropping dial");
							handle.abort();
						}
					}
					None => return Ok(()),
				},
				request = server.accept() => {
					let Some(request) = request else { return Ok(()) };
					let origin = self.origin.clone();
					tasks.spawn(async move {
						if let Err(err) = accept_session(request, origin).await {
							tracing::warn!(%err, "local peer session ended");
						}
					});
				}
				// Reap finished tasks so the set doesn't grow unbounded.
				Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
			}
		}
	}
}

/// The mesh's dedicated QUIC listener: a random port on every interface, with
/// a generated certificate that peers pin by fingerprint.
fn listener() -> Result<crate::Server> {
	let mut config = crate::ServerConfig {
		bind: Some("0.0.0.0:0".to_string()),
		..Default::default()
	};
	config.tls.generate = vec!["moq-local".to_string()];
	Ok(config.init()?)
}

/// Accept one inbound session, attach the shared origin, and wait for it to close.
async fn accept_session(request: crate::Request, origin: moq_net::origin::Producer) -> Result<()> {
	let session = request
		.with_publisher(&origin)
		.with_subscriber(origin.clone())
		.ok()
		.await?;
	tracing::info!("accepted local peer");
	Err(session.closed().await.into())
}

/// Keep one session to `peer` alive, reconnecting with backoff until aborted.
async fn dial_peer(origin: moq_net::origin::Producer, versions: moq_net::Versions, peer: Peer) {
	let mut backoff = DIAL_BACKOFF_BASE;

	loop {
		let started = tokio::time::Instant::now();
		if let Err(err) = dial_session(&origin, &versions, &peer).await {
			tracing::warn!(%err, peer = %peer.id, "local peer session ended; will retry");
		}
		backoff = match started.elapsed() >= DIAL_STABLE {
			true => DIAL_BACKOFF_BASE,
			false => (backoff * 2).min(DIAL_BACKOFF_MAX),
		};
		tokio::time::sleep(backoff).await;
	}
}

/// Dial `peer` on the first reachable advertised address, run the
/// bidirectional session, and wait for it to close.
async fn dial_session(origin: &moq_net::origin::Producer, versions: &moq_net::Versions, peer: &Peer) -> Result<()> {
	let mut last: Option<Error> = None;

	for addr in &peer.addrs {
		let session = match dial_addr(origin, versions, peer, *addr).await {
			Ok(session) => session,
			Err(err) => {
				last = Some(err);
				continue;
			}
		};
		return Err(session.closed().await.into());
	}

	Err(last.unwrap_or(Error::NoAddress))
}

/// One connection attempt: raw QUIC to `addr`, pinning the peer's fingerprint.
async fn dial_addr(
	origin: &moq_net::origin::Producer,
	versions: &moq_net::Versions,
	peer: &Peer,
	addr: IpAddr,
) -> Result<moq_net::Session> {
	let mut config = crate::ClientConfig {
		// Match the bind family to the target so a v4-only host can dial.
		bind: match addr {
			IpAddr::V4(_) => "0.0.0.0:0".parse().expect("valid address"),
			IpAddr::V6(_) => "[::]:0".parse().expect("valid address"),
		},
		..Default::default()
	};
	config.tls.fingerprint = vec![peer.fingerprint.clone()];
	config.version = versions.iter().copied().collect();

	let url: Url = match addr {
		IpAddr::V6(_) => format!("moqt://[{addr}]:{}", peer.port),
		IpAddr::V4(_) => format!("moqt://{addr}:{}", peer.port),
	}
	.parse()?;

	let client = config.init()?.with_publisher(origin).with_subscriber(origin.clone());
	Ok(client.connect(url).await?)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Exactly one side of every pair dials: the lower id. Symmetric ids never
	/// dial themselves.
	#[test]
	fn tiebreak_is_asymmetric() {
		assert!(should_dial("aaaa", "bbbb"));
		assert!(!should_dial("bbbb", "aaaa"));
		assert!(!should_dial("aaaa", "aaaa"));
	}

	#[test]
	fn instance_id_strips_the_service_suffix() {
		assert_eq!(
			instance_id("0123456789abcdef._moq._udp.local."),
			Some("0123456789abcdef")
		);
		assert_eq!(instance_id("weird name._moq._udp.local."), Some("weird name"));
		assert_eq!(instance_id("not-a-moq-service._http._tcp.local."), None);
	}

	/// One mesh session carries both directions: a broadcast published on
	/// either side's origin is announced on the other. Wires the dial and
	/// accept paths directly (no mDNS, so no multicast needed and the test
	/// stays CI-safe), exactly as `Mesh::run` spawns them.
	#[tokio::test]
	async fn session_shares_origin_bidirectionally() {
		const TIMEOUT: Duration = Duration::from_secs(10);

		let origin_a = moq_net::Origin::random().produce();
		let origin_b = moq_net::Origin::random().produce();

		// Publish on the dialing side before the session exists; announcements
		// flow once it connects.
		let _from_a = origin_a
			.create_broadcast("from-a", moq_net::broadcast::Route::new().with_announce(true))
			.expect("failed to create broadcast");

		// The accept side.
		let mut server = listener().expect("failed to bind listener");
		let port = server.local_addr().expect("no local addr").port();
		let fingerprint = server
			.certificates()
			.fingerprints()
			.into_iter()
			.next()
			.expect("no fingerprint");
		let b_origin = origin_b.clone();
		tokio::spawn(async move {
			let request = server.accept().await.expect("accept side closed");
			accept_session(request, b_origin).await.ok();
		});

		// The dial side, seeded with what discovery would have advertised.
		let peer = Peer {
			id: "peer".to_string(),
			addrs: vec!["127.0.0.1".parse().expect("valid address")],
			port,
			fingerprint,
		};
		let a_origin = origin_a.clone();
		tokio::spawn(async move {
			dial_session(&a_origin, &moq_net::Versions::all(), &peer).await.ok();
		});

		let mut announced_on_b = origin_b.consume().announced();
		let update = tokio::time::timeout(TIMEOUT, announced_on_b.next())
			.await
			.expect("timed out waiting for announcement")
			.expect("origin closed");
		assert_eq!(update.path.as_str(), "from-a");

		// And the reverse direction over the same session. This stream replays
		// a's own "from-a" first, so read until the remote broadcast shows up.
		let _from_b = origin_b
			.create_broadcast("from-b", moq_net::broadcast::Route::new().with_announce(true))
			.expect("failed to create broadcast");
		let mut announced_on_a = origin_a.consume().announced();
		loop {
			let update = tokio::time::timeout(TIMEOUT, announced_on_a.next())
				.await
				.expect("timed out waiting for announcement")
				.expect("origin closed");
			if update.path.as_str() == "from-b" {
				break;
			}
		}
	}

	/// The full path: two meshes find each other over real mDNS and converge
	/// on each other's broadcasts. Ignored because it multicasts on the host
	/// network, which CI runners may block; run it by hand when touching
	/// discovery: `cargo test -p moq-native --features local -- --ignored`.
	#[tokio::test]
	#[ignore = "needs multicast on the host network; run manually"]
	async fn mesh_discovers_and_connects() {
		const TIMEOUT: Duration = Duration::from_secs(30);

		let origin_a = moq_net::Origin::random().produce();
		let origin_b = moq_net::Origin::random().produce();

		let _from_a = origin_a
			.create_broadcast("from-a", moq_net::broadcast::Route::new().with_announce(true))
			.expect("failed to create broadcast");

		tokio::spawn(Mesh::new(origin_a.clone()).run());
		tokio::spawn(Mesh::new(origin_b.clone()).run());

		let mut announced_on_b = origin_b.consume().announced();
		let update = tokio::time::timeout(TIMEOUT, announced_on_b.next())
			.await
			.expect("timed out waiting for discovery + announcement")
			.expect("origin closed");
		assert_eq!(update.path.as_str(), "from-a");
	}
}
