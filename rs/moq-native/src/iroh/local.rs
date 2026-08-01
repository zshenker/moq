//! Local-network discovery of MoQ iroh endpoints, no relay or internet needed.
//!
//! [`Discovery`] advertises this endpoint over mDNS and reports every other MoQ
//! endpoint heard on the network. [`Mesh`] is the batteries-included layer on
//! top: it opens one session per discovered peer and attaches every session
//! (dialed and accepted) to a single shared [`moq_net::origin::Producer`], so
//! all peers see each other's broadcasts. Loop prevention comes from the hop
//! list carried on each broadcast's route, exactly like a relay cluster.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use futures::StreamExt;
use iroh_mdns_address_lookup::{DiscoveryEvent, MdnsAddressLookup};
use url::Url;
use web_transport_iroh::iroh::EndpointId;

use super::{Endpoint, Error, Result};

/// The mDNS service MoQ endpoints advertise under (`_moq._udp.local`).
///
/// Distinct from iroh's default service so only MoQ peers discover each other;
/// generic iroh endpoints on the same network stay invisible.
const SERVICE_NAME: &str = "moq";

/// Reconnect pacing for mesh dials, mirroring the relay's cluster dials: quick
/// on a blip, exponential on repeated failure. A session shorter than
/// `DIAL_STABLE` counts as a failure so a peer that rejects us instantly
/// doesn't turn into a tight loop.
const DIAL_BACKOFF_BASE: Duration = Duration::from_secs(1);
const DIAL_BACKOFF_MAX: Duration = Duration::from_secs(300);
const DIAL_STABLE: Duration = Duration::from_secs(10);

/// A MoQ endpoint discovered on the local network.
#[derive(Clone, Debug)]
pub struct Peer {
	/// The peer's iroh endpoint id; dial it as `iroh://<id>`.
	pub id: EndpointId,
	/// The socket addresses the peer advertised, a shortcut past resolution.
	pub addrs: Vec<SocketAddr>,
}

/// A change in the set of discovered peers.
#[derive(Clone, Debug)]
pub enum Event {
	/// An endpoint appeared on the local network, or refreshed its addresses.
	Found(Peer),
	/// A previously discovered endpoint stopped advertising.
	Lost(EndpointId),
}

/// Discovers MoQ iroh endpoints on the local network via mDNS.
///
/// Creating one advertises this endpoint to the network and registers the mDNS
/// resolver on the endpoint, so dialing a discovered peer by id resolves its
/// local addresses automatically. Call [`recv`](Self::recv) in a loop to hear
/// peers come and go; what to do with them (dial, list, filter) stays with the
/// caller. [`Mesh`] is the canned dial-everyone policy.
pub struct Discovery {
	local: EndpointId,
	events: futures::stream::BoxStream<'static, DiscoveryEvent>,
}

impl Discovery {
	/// Start advertising and listening on the local network.
	///
	/// The endpoint keeps advertising for the rest of its lifetime, even after
	/// this handle drops (iroh offers no way to unregister a lookup service),
	/// so create at most one per endpoint.
	pub async fn new(endpoint: &Endpoint) -> Result<Self> {
		let mdns = MdnsAddressLookup::builder()
			.service_name(SERVICE_NAME)
			.build(endpoint.id())
			.map_err(Error::Discovery)?;
		endpoint.address_lookup()?.add(mdns.clone());
		let events = mdns.subscribe().await.boxed();
		tracing::info!("advertising on the local network");
		Ok(Self {
			local: endpoint.id(),
			events,
		})
	}

	/// The next discovery event, or `None` once discovery shuts down.
	pub async fn recv(&mut self) -> Option<Event> {
		while let Some(event) = self.events.next().await {
			match event {
				DiscoveryEvent::Discovered { endpoint_info, .. } => {
					return Some(Event::Found(Peer {
						id: endpoint_info.endpoint_id,
						addrs: endpoint_info.data.ip_addrs().copied().collect(),
					}));
				}
				DiscoveryEvent::Expired { endpoint_id } => return Some(Event::Lost(endpoint_id)),
				// The event enum is non-exhaustive; ignore anything new.
				_ => continue,
			}
		}
		None
	}

	/// Whether this endpoint dials `remote`, or waits for `remote` to dial it.
	///
	/// Both sides of a pair discover each other, and a mesh session is
	/// bidirectional, so one connection suffices: the lower endpoint id dials
	/// and the higher accepts. Deterministic on both sides with no extra
	/// coordination, like the relay cluster's URL tiebreaker.
	pub fn should_dial(&self, remote: &EndpointId) -> bool {
		should_dial(&self.local, remote)
	}
}

/// The [`Discovery::should_dial`] tiebreaker: the lower endpoint id dials.
fn should_dial(local: &EndpointId, remote: &EndpointId) -> bool {
	local.as_bytes() < remote.as_bytes()
}

/// Connects every discovered local peer to one shared origin.
///
/// Runs [`Discovery`] and opens a single bidirectional MoQ session per peer
/// (the lower endpoint id dials, see [`Discovery::should_dial`]). Every
/// session, dialed or accepted, both publishes the origin and ingests the
/// peer's broadcasts into it, so the whole network converges on one set of
/// broadcasts with no relay involved.
///
/// [`run`](Self::run) owns the endpoint's accept side; don't also hand the
/// endpoint to a [`crate::Server`] via `with_iroh`, or the two accept loops
/// would race for incoming connections.
pub struct Mesh {
	endpoint: Endpoint,
	origin: moq_net::origin::Producer,
	versions: moq_net::Versions,
}

impl Mesh {
	/// A mesh over `endpoint`, publishing and ingesting `origin` on every session.
	pub fn new(endpoint: Endpoint, origin: moq_net::origin::Producer) -> Self {
		Self {
			endpoint,
			origin,
			versions: moq_net::Versions::all(),
		}
	}

	/// Restrict the MoQ protocol versions offered on mesh sessions.
	pub fn with_versions(mut self, versions: moq_net::Versions) -> Self {
		self.versions = versions;
		self
	}

	/// Discover, dial, and accept peers until the endpoint closes.
	///
	/// A lost peer (mDNS expiry) has its dial aborted; a dropped session to a
	/// still-advertised peer reconnects with backoff.
	pub async fn run(self) -> Result<()> {
		let mut discovery = Discovery::new(&self.endpoint).await?;
		let mut dials: HashMap<EndpointId, tokio::task::AbortHandle> = HashMap::new();
		let mut tasks = tokio::task::JoinSet::new();

		loop {
			tokio::select! {
				event = discovery.recv() => match event {
					Some(Event::Found(peer)) => {
						if !discovery.should_dial(&peer.id) || dials.contains_key(&peer.id) {
							continue;
						}
						tracing::info!(peer = %peer.id.fmt_short(), "discovered local peer; dialing");
						let endpoint = self.endpoint.clone();
						let origin = self.origin.clone();
						let versions = self.versions.clone();
						let id = peer.id;
						let handle = tasks.spawn(dial_peer(endpoint, origin, versions, peer));
						dials.insert(id, handle);
					}
					Some(Event::Lost(id)) => {
						if let Some(handle) = dials.remove(&id) {
							tracing::info!(peer = %id.fmt_short(), "local peer expired; dropping dial");
							handle.abort();
						}
					}
					None => return Ok(()),
				},
				incoming = self.endpoint.accept() => {
					let Some(incoming) = incoming else { return Ok(()) };
					let origin = self.origin.clone();
					let versions = self.versions.clone();
					tasks.spawn(async move {
						if let Err(err) = accept_peer(incoming, origin, versions).await {
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

/// Keep one session to `peer` alive, reconnecting with backoff until aborted.
async fn dial_peer(endpoint: Endpoint, origin: moq_net::origin::Producer, versions: moq_net::Versions, peer: Peer) {
	let mut backoff = DIAL_BACKOFF_BASE;

	loop {
		let started = tokio::time::Instant::now();
		if let Err(err) = dial_peer_once(&endpoint, &origin, &versions, &peer).await {
			tracing::warn!(%err, peer = %peer.id.fmt_short(), "local peer session ended; will retry");
		}
		backoff = match started.elapsed() >= DIAL_STABLE {
			true => DIAL_BACKOFF_BASE,
			false => (backoff * 2).min(DIAL_BACKOFF_MAX),
		};
		tokio::time::sleep(backoff).await;
	}
}

/// Dial `peer`, run the bidirectional session, and wait for it to close.
async fn dial_peer_once(
	endpoint: &Endpoint,
	origin: &moq_net::origin::Producer,
	versions: &moq_net::Versions,
	peer: &Peer,
) -> Result<()> {
	let url: Url = format!("iroh://{}", peer.id).parse()?;
	// The discovered addresses seed the dial; the registered mDNS resolver
	// keeps them fresh across reconnects.
	let (session, _binding) = super::connect(endpoint, url, peer.addrs.iter().copied()).await?;
	let pair = moq_net::Client::new()
		.with_versions(versions.clone())
		.with_publisher(origin)
		.with_subscriber(origin.clone())
		.connect(session)
		.await?;
	let session = crate::spawn_session(pair);
	Err(session.closed().await.into())
}

/// Accept one inbound session, attach the shared origin, and wait for it to close.
async fn accept_peer(
	incoming: web_transport_iroh::iroh::endpoint::Incoming,
	origin: moq_net::origin::Producer,
	versions: moq_net::Versions,
) -> Result<()> {
	let (session, _url, _identity) = super::accept(incoming).await?;
	let request = moq_net::Server::new()
		.with_versions(versions)
		.with_publisher(&origin)
		.with_subscriber(origin.clone())
		.accept_request(session)
		.await?;
	tracing::info!("accepted local peer");
	let session = crate::spawn_session(request.ok().await?);
	Err(session.closed().await.into())
}

#[cfg(test)]
mod tests {
	use super::*;
	use web_transport_iroh::iroh::SecretKey;

	/// Exactly one side of every pair dials: the lower id. Symmetric ids never
	/// dial themselves.
	#[test]
	fn tiebreak_is_asymmetric() {
		let a = SecretKey::generate().public();
		let b = SecretKey::generate().public();

		assert_ne!(should_dial(&a, &b), should_dial(&b, &a));
		assert!(!should_dial(&a, &a));
		assert_eq!(should_dial(&a, &b), a.as_bytes() < b.as_bytes());
	}

	async fn endpoint() -> Endpoint {
		let config = super::super::EndpointConfig {
			enabled: Some(true),
			..Default::default()
		};
		config
			.bind(&crate::quic::Client::default())
			.await
			.expect("failed to bind endpoint")
			.expect("endpoint not enabled")
	}

	/// One mesh session carries both directions: a broadcast published on either
	/// side's origin is announced on the other. Dials directly by address, so no
	/// mDNS (multicast) is needed and the test stays CI-safe; the discovery path
	/// is covered upstream by iroh-mdns-address-lookup's own tests.
	#[tokio::test]
	async fn session_shares_origin_bidirectionally() {
		const TIMEOUT: Duration = Duration::from_secs(10);

		let a = endpoint().await;
		let b = endpoint().await;

		let origin_a = moq_net::Origin::random().produce();
		let origin_b = moq_net::Origin::random().produce();

		// Publish on the dialing side before the session exists; announcements
		// flow once it connects.
		let _from_a = origin_a
			.create_broadcast("from-a", moq_net::broadcast::Route::new().with_announce(true))
			.expect("failed to create broadcast");

		// The accept side, exactly as `Mesh::run` spawns it.
		let b_endpoint = b.clone();
		let b_origin = origin_b.clone();
		tokio::spawn(async move {
			let incoming = b_endpoint.accept().await.expect("accept side closed");
			accept_peer(incoming, b_origin, moq_net::Versions::all()).await.ok();
		});

		// The dial side, seeded with the address discovery would have heard.
		let peer = Peer {
			id: b.id(),
			addrs: b.addr().ip_addrs().copied().collect(),
		};
		let a_origin = origin_a.clone();
		tokio::spawn(async move {
			dial_peer_once(&a, &a_origin, &moq_net::Versions::all(), &peer)
				.await
				.ok();
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

	/// The full path: two meshes find each other over real mDNS and converge on
	/// each other's broadcasts. Ignored because it multicasts on the host
	/// network, which CI runners may block; run it by hand when touching
	/// discovery: `cargo test -p moq-native --features iroh -- --ignored`.
	#[tokio::test]
	#[ignore = "needs multicast on the host network; run manually"]
	async fn mesh_discovers_and_connects() {
		const TIMEOUT: Duration = Duration::from_secs(30);

		let origin_a = moq_net::Origin::random().produce();
		let origin_b = moq_net::Origin::random().produce();

		let _from_a = origin_a
			.create_broadcast("from-a", moq_net::broadcast::Route::new().with_announce(true))
			.expect("failed to create broadcast");

		tokio::spawn(Mesh::new(endpoint().await, origin_a.clone()).run());
		tokio::spawn(Mesh::new(endpoint().await, origin_b.clone()).run());

		let mut announced_on_b = origin_b.consume().announced();
		let update = tokio::time::timeout(TIMEOUT, announced_on_b.next())
			.await
			.expect("timed out waiting for discovery + announcement")
			.expect("origin closed");
		assert_eq!(update.path.as_str(), "from-a");
	}
}
