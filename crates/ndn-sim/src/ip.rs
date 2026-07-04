//! An in-sim **IP forwarding plane** (Tier-B) — a deterministic model of IP forwarding on ndn-lab's
//! own kernel / world / medium, so the *same* scenario can run NDN-vs-IP and be compared with the
//! same [`FlowStats`](crate::FlowStats), faults, and run/diff harness.
//!
//! It reuses the byte substrate directly: an [`IpNode`] owns [`SimFace`](crate::SimFace) byte
//! channels and forwards over them, inheriting link delay, loss, bandwidth, and the runtime
//! [`Fault`](crate::Fault)s (a downed/degraded [`LinkState`] affects IP exactly as it does NDN).
//! Below the forwarding engine, the sim doesn't care whether the bytes are Interests/Data or IP.
//!
//! **Slice 1**: unicast forward-by-destination (longest-prefix match + TTL) with a built-in echo,
//! and [`ping`](RunningIpNode::ping) measuring round-trip [`FlowStats`]. Routing generation, an
//! NDN-vs-IP diff harness, and richer transports layer on top.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use ndn_runtime::Runtime;
use ndn_transport::{FaceId, Transport};
use tokio::sync::mpsc;

use crate::app::FlowStats;
use crate::sim_face::SimFace;
use crate::sim_link::{FaceProfile, SimLink};

/// A 32-bit IPv4 address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4(pub u32);

impl Ipv4 {
    /// From dotted-quad octets.
    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Ipv4(u32::from_be_bytes([a, b, c, d]))
    }
    /// Whether `self` falls in `net/prefix_len`.
    fn in_prefix(self, net: Ipv4, prefix_len: u8) -> bool {
        if prefix_len == 0 {
            return true;
        }
        let mask = if prefix_len >= 32 { u32::MAX } else { !((1u32 << (32 - prefix_len)) - 1) };
        (self.0 & mask) == (net.0 & mask)
    }
}

impl std::fmt::Display for Ipv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let [a, b, c, d] = self.0.to_be_bytes();
        write!(f, "{a}.{b}.{c}.{d}")
    }
}
impl std::fmt::Debug for Ipv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

/// A minimal IP packet: a fixed 14-byte header (`src`, `dst`, `ttl`, `flags`, `seq`) + payload.
#[derive(Clone, Debug)]
pub struct IpPacket {
    pub src: Ipv4,
    pub dst: Ipv4,
    pub ttl: u8,
    /// `true` = an echo reply; `false` = a request.
    pub reply: bool,
    /// Sequence number, for round-trip correlation.
    pub seq: u32,
    pub payload: Bytes,
}

const IP_HEADER_LEN: usize = 14;

impl IpPacket {
    fn encode(&self) -> Bytes {
        let mut b = BytesMut::with_capacity(IP_HEADER_LEN + self.payload.len());
        b.put_u32(self.src.0);
        b.put_u32(self.dst.0);
        b.put_u8(self.ttl);
        b.put_u8(u8::from(self.reply));
        b.put_u32(self.seq);
        b.extend_from_slice(&self.payload);
        b.freeze()
    }
    fn decode(bytes: &[u8]) -> Option<IpPacket> {
        if bytes.len() < IP_HEADER_LEN {
            return None;
        }
        Some(IpPacket {
            src: Ipv4(u32::from_be_bytes(bytes[0..4].try_into().ok()?)),
            dst: Ipv4(u32::from_be_bytes(bytes[4..8].try_into().ok()?)),
            ttl: bytes[8],
            reply: bytes[9] & 1 != 0,
            seq: u32::from_be_bytes(bytes[10..14].try_into().ok()?),
            payload: Bytes::copy_from_slice(&bytes[IP_HEADER_LEN..]),
        })
    }
}

/// A routing-table entry: `net/prefix_len` reachable via the face at index `via`.
struct Route {
    net: Ipv4,
    prefix_len: u8,
    via: usize,
}

/// Per-node forwarding counters — the IP-plane readout (a peer to NDN's per-face metrics).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpNodeStats {
    pub forwarded: u64,
    pub delivered: u64,
    pub dropped_no_route: u64,
    pub dropped_ttl: u64,
    /// Total bytes this node put on the wire (the IP-side "bytes on the wire" for a cost comparison).
    pub tx_bytes: u64,
}

struct Inner {
    addr: Ipv4,
    faces: Vec<Arc<SimFace>>,
    routes: Mutex<Vec<Route>>,
    clock: Arc<dyn Runtime>,
    forwarded: AtomicU64,
    delivered: AtomicU64,
    dropped_no_route: AtomicU64,
    dropped_ttl: AtomicU64,
    tx_bytes: AtomicU64,
    /// Replies delivered to a local pinger: `(seq, recv_ns, payload_len)`.
    reply_tx: mpsc::UnboundedSender<(u32, u64, usize)>,
}

impl Inner {
    /// Longest-prefix-match: the most specific route matching `dst`.
    fn lpm(&self, dst: Ipv4) -> Option<usize> {
        self.routes
            .lock()
            .unwrap()
            .iter()
            .filter(|r| dst.in_prefix(r.net, r.prefix_len))
            .max_by_key(|r| r.prefix_len)
            .map(|r| r.via)
    }
    async fn send_on(&self, via: usize, pkt: &IpPacket) {
        if let Some(face) = self.faces.get(via) {
            let wire = pkt.encode();
            self.tx_bytes.fetch_add(wire.len() as u64, Ordering::Relaxed);
            let _ = face.send_bytes(wire).await;
        }
    }
    async fn handle(self: &Arc<Self>, pkt: IpPacket) {
        if pkt.dst == self.addr {
            self.delivered.fetch_add(1, Ordering::Relaxed);
            if pkt.reply {
                let _ =
                    self.reply_tx.send((pkt.seq, self.clock.unix_nanos(), pkt.payload.len()));
            } else {
                // Echo: reflect a reply back to the source.
                let reply = IpPacket {
                    src: self.addr,
                    dst: pkt.src,
                    ttl: 64,
                    reply: true,
                    seq: pkt.seq,
                    payload: pkt.payload,
                };
                if let Some(via) = self.lpm(reply.dst) {
                    self.send_on(via, &reply).await;
                }
            }
            return;
        }
        // Not for us — forward (decrement TTL, drop at 0 or with no route).
        if pkt.ttl <= 1 {
            self.dropped_ttl.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut fwd = pkt;
        fwd.ttl -= 1;
        match self.lpm(fwd.dst) {
            Some(via) => {
                self.forwarded.fetch_add(1, Ordering::Relaxed);
                self.send_on(via, &fwd).await;
            }
            None => {
                self.dropped_no_route.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// An IP forwarding node under construction: give it faces and routes, then [`start`](Self::start).
pub struct IpNode {
    addr: Ipv4,
    clock: Arc<dyn Runtime>,
    faces: Vec<Arc<SimFace>>,
    routes: Vec<Route>,
}

impl IpNode {
    pub fn new(addr: Ipv4, clock: Arc<dyn Runtime>) -> Self {
        IpNode { addr, clock, faces: Vec::new(), routes: Vec::new() }
    }
    /// Attach a byte-channel face (one end of an [`ip_link`]); returns its face index for routing.
    pub fn attach(&mut self, face: SimFace) -> usize {
        self.faces.push(Arc::new(face));
        self.faces.len() - 1
    }
    /// Route `net/prefix_len` out the face at index `via`. `Ipv4(0)` + `prefix_len = 0` is a default route.
    pub fn route(&mut self, net: Ipv4, prefix_len: u8, via: usize) {
        self.routes.push(Route { net, prefix_len, via });
    }
    /// Start forwarding: spawn a receive loop per face on the ambient runtime (virtual under DES).
    pub fn start(self) -> RunningIpNode {
        let (reply_tx, reply_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            addr: self.addr,
            faces: self.faces,
            routes: Mutex::new(self.routes),
            clock: self.clock,
            forwarded: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            dropped_no_route: AtomicU64::new(0),
            dropped_ttl: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            reply_tx,
        });
        for i in 0..inner.faces.len() {
            let face = Arc::clone(&inner.faces[i]);
            let node = Arc::clone(&inner);
            ndn_app::rt::spawn(async move {
                while let Ok(bytes) = face.recv_bytes().await {
                    if let Some(pkt) = IpPacket::decode(&bytes) {
                        node.handle(pkt).await;
                    }
                }
            });
        }
        RunningIpNode { inner, reply_rx: tokio::sync::Mutex::new(reply_rx) }
    }
}

/// A live IP node: forwarding runs in the background; [`ping`](Self::ping) a destination and read
/// the round-trip [`FlowStats`], or read forwarding [`stats`](Self::stats).
pub struct RunningIpNode {
    inner: Arc<Inner>,
    reply_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(u32, u64, usize)>>,
}

impl RunningIpNode {
    pub fn addr(&self) -> Ipv4 {
        self.inner.addr
    }

    /// Replace this node's routing table at runtime (dynamic re-route). Each entry is
    /// `(destination network, prefix length, outgoing face index)`.
    pub fn set_routes(&self, routes: Vec<(Ipv4, u8, usize)>) {
        let mut table = self.inner.routes.lock().unwrap();
        *table = routes
            .into_iter()
            .map(|(net, prefix_len, via)| Route { net, prefix_len, via })
            .collect();
    }

    /// Forwarding counters (forwarded / delivered / dropped / tx_bytes).
    pub fn stats(&self) -> IpNodeStats {
        IpNodeStats {
            forwarded: self.inner.forwarded.load(Ordering::Relaxed),
            delivered: self.inner.delivered.load(Ordering::Relaxed),
            dropped_no_route: self.inner.dropped_no_route.load(Ordering::Relaxed),
            dropped_ttl: self.inner.dropped_ttl.load(Ordering::Relaxed),
            tx_bytes: self.inner.tx_bytes.load(Ordering::Relaxed),
        }
    }

    /// Sequentially ping `dst` `count` times (a `payload_len`-byte request each), waiting up to
    /// `lifetime` for each echo and pausing a constant `interval` between them — returning the
    /// round-trip [`FlowStats`] (RTT, loss, goodput), the same shape the NDN apps report.
    pub async fn ping(
        &self,
        dst: Ipv4,
        count: u32,
        payload_len: usize,
        interval: Duration,
        lifetime: Duration,
    ) -> FlowStats {
        self.flow_loop(dst, count, payload_len, lifetime, |_| interval).await
    }

    /// Like [`ping`](Self::ping) but with inter-request delays from a [`TrafficPattern`] (CBR /
    /// Poisson / bursty) — the **same workload shape** that drives the NDN [`TrafficSource`], so a
    /// benchmark applies an identical pattern to both planes and compares the resulting `FlowStats`.
    ///
    /// [`TrafficSource`]: crate::AppSpec::TrafficSource
    pub async fn run_flow(
        &self,
        dst: Ipv4,
        pattern: crate::TrafficPattern,
        count: u32,
        payload_len: usize,
        lifetime: Duration,
    ) -> FlowStats {
        let mut rng = crate::app::SplitMix64::new(0x51_4E44_4E00u64 ^ u64::from(dst.0));
        self.flow_loop(dst, count, payload_len, lifetime, move |i| {
            pattern.next_delay(u64::from(i), &mut rng)
        })
        .await
    }

    /// The shared measured-ping loop: express a request, time the round trip into [`FlowStats`],
    /// then wait `delay(seq)` before the next. Sequential (one outstanding), like `ping -c`.
    async fn flow_loop(
        &self,
        dst: Ipv4,
        count: u32,
        payload_len: usize,
        lifetime: Duration,
        mut delay: impl FnMut(u32) -> Duration,
    ) -> FlowStats {
        let mut rx = self.reply_rx.lock().await;
        let payload = Bytes::from(vec![0u8; payload_len]);
        let (mut sent, mut received, mut lost, mut bytes) = (0u64, 0u64, 0u64, 0u64);
        let (mut rtt_min, mut rtt_max, mut rtt_sum) = (u64::MAX, 0u64, 0u64);
        let (mut first_recv, mut last_recv) = (0u64, 0u64);

        for seq in 0..count {
            let req = IpPacket {
                src: self.inner.addr,
                dst,
                ttl: 64,
                reply: false,
                seq,
                payload: payload.clone(),
            };
            sent += 1;
            let t0 = self.inner.clock.unix_nanos();
            if let Some(via) = self.inner.lpm(dst) {
                self.inner.send_on(via, &req).await;
            }
            tokio::select! {
                r = rx.recv() => {
                    if let Some((rseq, recv_ns, plen)) = r && rseq == seq {
                        let rtt = recv_ns.saturating_sub(t0);
                        received += 1;
                        bytes += plen as u64;
                        rtt_min = rtt_min.min(rtt);
                        rtt_max = rtt_max.max(rtt);
                        rtt_sum += rtt;
                        if first_recv == 0 { first_recv = recv_ns; }
                        last_recv = recv_ns;
                    } else {
                        lost += 1; // a stale / mismatched reply
                    }
                }
                _ = ndn_app::rt::sleep(lifetime) => { lost += 1; }
            }
            let wait = delay(seq);
            if !wait.is_zero() {
                ndn_app::rt::sleep(wait).await;
            }
        }

        FlowStats {
            sent,
            received,
            lost,
            bytes,
            rtt_min_ns: if rtt_min == u64::MAX { 0 } else { rtt_min },
            rtt_max_ns: rtt_max,
            rtt_sum_ns: rtt_sum,
            first_recv_ns: first_recv,
            last_recv_ns: last_recv,
        }
    }
}

/// Config for an IP network running over the Wi-Fi MAC: connectivity range, PHY/MAC [`mode`] +
/// [`op_mode`], transmit power, and a **pluggable** propagation backend mapping distance → SNR.
///
/// [`mode`]: crate::WifiMode
/// [`op_mode`]: crate::WifiOperatingMode
#[derive(Clone)]
pub struct RadioLinkConfig {
    pub range_m: f64,
    pub mode: crate::wifi::WifiMode,
    pub op_mode: crate::wifi::WifiOperatingMode,
    pub tx_power_dbm: f64,
    pub retry_limit: u32,
    pub frame_bytes: usize,
    pub freq_hz: f64,
    pub propagation: Arc<dyn crate::phy::PropagationBackend>,
}

impl RadioLinkConfig {
    /// Defaults: IBSS, the given MAC mode, 20 dBm, free-space propagation at 2.4 GHz, 512-byte frames.
    pub fn new(range_m: f64, mode: crate::wifi::WifiMode) -> Self {
        RadioLinkConfig {
            range_m,
            mode,
            op_mode: crate::wifi::WifiOperatingMode::Ibss,
            tx_power_dbm: 20.0,
            retry_limit: 6,
            frame_bytes: 512,
            freq_hz: 2.4e9,
            propagation: Arc::new(crate::phy::FreeSpace),
        }
    }
    /// Set the operating mode (IBSS / AP / mesh) — the `with_*` spelling matching
    /// [`with_propagation`](Self::with_propagation).
    pub fn with_operating_mode(mut self, op: crate::wifi::WifiOperatingMode) -> Self {
        self.op_mode = op;
        self
    }

    /// Shorthand alias for [`with_operating_mode`](Self::with_operating_mode).
    pub fn operating(self, op: crate::wifi::WifiOperatingMode) -> Self {
        self.with_operating_mode(op)
    }
    /// Swap the propagation backend (free-space, log-distance, …).
    pub fn with_propagation(mut self, p: Arc<dyn crate::phy::PropagationBackend>) -> Self {
        self.propagation = p;
        self
    }
    /// SNR (dB) at a link distance, via the pluggable propagation backend (isotropic gains).
    fn snr_at(&self, dist_m: f64) -> f64 {
        let ctx = crate::phy::PathContext {
            distance_m: dist_m,
            freq_hz: self.freq_hz,
            tx_power_dbm: self.tx_power_dbm,
            tx_gain_dbi: 0.0,
            rx_gain_dbi: 0.0,
        };
        crate::link_model::LinkModel::snr_db(self.propagation.rx_power_dbm(&ctx))
    }
}

/// A ready-to-run IP network built from a topology: `n` nodes addressed `10.0.0.{i+1}`, links wired
/// with a shared `profile`, and shortest-path `/32` routes auto-installed by BFS from each node —
/// the IP analogue of [`topo::add_routes_toward`](crate::topo::add_routes_toward). Started on build.
pub struct IpNetwork {
    nodes: Vec<RunningIpNode>,
    addrs: Vec<Ipv4>,
    /// The undirected link list (index = link id), for rebuilding the topology view on re-route.
    links: Vec<(usize, usize)>,
    /// Per node, its `(neighbour → outgoing face index)` map — to translate a routing table's
    /// next-hop *nodes* into face indices when installing.
    face_to: Vec<HashMap<usize, usize>>,
    /// The live fault knobs for each link's two directed faces (for [`set_link`](Self::set_link)).
    link_states: Vec<(Arc<crate::sim_face::LinkState>, Arc<crate::sim_face::LinkState>)>,
    /// Whether each link is currently up (a down link is excluded from re-routing).
    link_up: Vec<std::sync::atomic::AtomicBool>,
    /// Node positions, for position-based re-routing (GPSR) and range-gated connectivity. Mutable so
    /// mobility ([`reconnect`](Self::reconnect)) can update them.
    positions: Mutex<Option<Vec<crate::world::Position>>>,
    /// The kernel runtime + build epoch, for the World-driven background re-router.
    runtime: Arc<dyn Runtime>,
    epoch_ns: u64,
    /// Per node, whether it is currently associated to its AP (AP mode only). A station roaming out
    /// of and back into range must **re-associate** — the handoff gap monitor mode never pays.
    associated: Vec<std::sync::atomic::AtomicBool>,
    /// Count of (re)associations across all stations — the roaming/handoff overhead of infrastructure
    /// Wi-Fi.
    handoffs: std::sync::atomic::AtomicU64,
    /// Accumulated association-handshake time (ns) — scan+auth+assoc(+4-way) charged per handoff.
    assoc_overhead_ns: std::sync::atomic::AtomicU64,
}

impl IpNetwork {
    /// Build + start from an explicit undirected link list over `n` nodes (`n <= 254`), routed by the
    /// default [`ShortestPath`](crate::routing::ShortestPath) (link-state / OSPF-class).
    pub fn from_links(
        runtime: Arc<dyn Runtime>,
        n: usize,
        links: &[(usize, usize)],
        profile: &FaceProfile,
    ) -> Self {
        Self::from_links_with(runtime, n, links, None, profile, &crate::routing::ShortestPath)
    }

    /// Build + start with an explicit [`RoutingAlgorithm`](crate::routing::RoutingAlgorithm) —
    /// shortest-path, distance-vector, geographic (GPSR), … per the deployment (infrastructure /
    /// MANET / VANET / FANET). `positions` (if given) enable position-based algorithms.
    pub fn from_links_with(
        runtime: Arc<dyn Runtime>,
        n: usize,
        links: &[(usize, usize)],
        positions: Option<Vec<crate::world::Position>>,
        profile: &FaceProfile,
        algo: &dyn crate::routing::RoutingAlgorithm,
    ) -> Self {
        let addrs: Vec<Ipv4> = (0..n).map(|i| Ipv4::new(10, 0, 0, (i + 1) as u8)).collect();
        let mut builders: Vec<IpNode> =
            addrs.iter().map(|&a| IpNode::new(a, Arc::clone(&runtime))).collect();

        // Wire links, tracking each node's (neighbour → face index) map + the links' fault knobs.
        let mut face_to: Vec<HashMap<usize, usize>> = vec![HashMap::new(); n];
        let mut link_states = Vec::with_capacity(links.len());
        for (link_id, &(a, b)) in links.iter().enumerate() {
            let (fa, fb) = ip_link(Arc::clone(&runtime), profile, 256, link_id as u64);
            link_states.push((fa.link_state(), fb.link_state()));
            face_to[a].insert(b, builders[a].attach(fa));
            face_to[b].insert(a, builders[b].attach(fb));
        }

        // Compute routing tables with the chosen algorithm, install as /32 routes toward each dest.
        let mut view = crate::routing::TopologyView::from_links(n, links);
        if let Some(p) = &positions {
            view = view.with_positions(p.clone());
        }
        let tables = algo.compute(&view);
        for (u, table) in tables.iter().enumerate() {
            for entry in table {
                if let Some(&via) = face_to[u].get(&entry.next_hop) {
                    builders[u].route(addrs[entry.dest], 32, via);
                }
            }
        }

        let epoch_ns = runtime.unix_nanos();
        let nodes = builders.into_iter().map(IpNode::start).collect();
        let link_up = links.iter().map(|_| std::sync::atomic::AtomicBool::new(true)).collect();
        IpNetwork {
            nodes,
            addrs,
            links: links.to_vec(),
            face_to,
            link_states,
            link_up,
            positions: Mutex::new(positions),
            runtime,
            epoch_ns,
            associated: (0..n).map(|_| std::sync::atomic::AtomicBool::new(false)).collect(),
            handoffs: std::sync::atomic::AtomicU64::new(0),
            assoc_overhead_ns: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Build + start from a [`Scenario`](crate::Scenario)'s node + link graph (NDN routes / radio are
    /// ignored — IP routes itself), so the *same topology* drives both the NDN and IP planes.
    /// Routed by the default [`ShortestPath`](crate::routing::ShortestPath).
    pub fn from_scenario(
        runtime: Arc<dyn Runtime>,
        scenario: &crate::Scenario,
        profile: &FaceProfile,
    ) -> Self {
        Self::from_scenario_with(runtime, scenario, profile, &crate::routing::ShortestPath)
    }

    /// Like [`from_scenario`](Self::from_scenario) but with an explicit routing algorithm; node
    /// positions from the scenario are passed through, so geographic protocols (GPSR) can route.
    pub fn from_scenario_with(
        runtime: Arc<dyn Runtime>,
        scenario: &crate::Scenario,
        profile: &FaceProfile,
        algo: &dyn crate::routing::RoutingAlgorithm,
    ) -> Self {
        let links: Vec<(usize, usize)> = scenario.links.iter().map(|l| (l.a, l.b)).collect();
        let positions: Vec<crate::world::Position> = scenario
            .nodes
            .iter()
            .map(|n| {
                n.position
                    .map(|[x, y, z]| crate::world::Position::xyz(x, y, z))
                    .unwrap_or(crate::world::Position::ORIGIN)
            })
            .collect();
        Self::from_links_with(runtime, scenario.nodes.len(), &links, Some(positions), profile, algo)
    }

    pub fn node(&self, i: usize) -> &RunningIpNode {
        &self.nodes[i]
    }
    pub fn addr(&self, i: usize) -> Ipv4 {
        self.addrs[i]
    }
    pub fn len(&self) -> usize {
        self.nodes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
    /// Total bytes put on the wire across all nodes — the IP "bytes on the wire" for a cost comparison.
    pub fn total_tx_bytes(&self) -> u64 {
        self.nodes.iter().map(|n| n.stats().tx_bytes).sum()
    }

    /// Cut or restore a link (both directions) — a topology change (mobility / failure). The link is
    /// excluded from / included in subsequent [`reroute_with`](Self::reroute_with). Returns whether
    /// such a link exists. Until you re-route, traffic on a cut link's old route is dropped.
    pub fn set_link(&self, a: usize, b: usize, up: bool) -> bool {
        for (i, &(x, y)) in self.links.iter().enumerate() {
            if (x, y) == (a, b) || (x, y) == (b, a) {
                self.link_up[i].store(up, std::sync::atomic::Ordering::Relaxed);
                let (sa, sb) = &self.link_states[i];
                sa.set_down(!up);
                sb.set_down(!up);
                return true;
            }
        }
        false
    }

    /// Recompute every node's routing table with `algo` over the **currently-up** topology and
    /// install it live — the adaptive-routing step a proactive protocol runs on a topology change
    /// (a link forming/breaking), and a reactive one runs on demand. Positions are carried through
    /// for geographic protocols.
    pub fn reroute_with(&self, algo: &dyn crate::routing::RoutingAlgorithm) {
        let up_links: Vec<(usize, usize)> = self
            .links
            .iter()
            .enumerate()
            .filter(|(i, _)| self.link_up[*i].load(std::sync::atomic::Ordering::Relaxed))
            .map(|(_, &l)| l)
            .collect();
        let mut view = crate::routing::TopologyView::from_links(self.addrs.len(), &up_links);
        if let Some(p) = self.positions.lock().unwrap().clone() {
            view = view.with_positions(p);
        }
        let tables = algo.compute(&view);
        for (u, table) in tables.iter().enumerate() {
            let routes: Vec<(Ipv4, u8, usize)> = table
                .iter()
                .filter_map(|e| {
                    self.face_to[u].get(&e.next_hop).map(|&via| (self.addrs[e.dest], 32, via))
                })
                .collect();
            self.nodes[u].set_routes(routes);
        }
    }

    /// **Mobility-driven re-route.** Update node positions, bring each link up iff its endpoints are
    /// within `range` (the unit-disk-graph connectivity model standard in MANET routing studies),
    /// then [`reroute_with`](Self::reroute_with) over the new topology. Call this as the World moves
    /// nodes — links form and break, and the chosen protocol (proactive / geographic) adapts.
    pub fn reconnect(
        &self,
        positions: &[crate::world::Position],
        range: f64,
        algo: &dyn crate::routing::RoutingAlgorithm,
    ) {
        *self.positions.lock().unwrap() = Some(positions.to_vec());
        for (i, &(a, b)) in self.links.iter().enumerate() {
            let up = positions[a].distance(positions[b]) <= range;
            self.link_up[i].store(up, std::sync::atomic::Ordering::Relaxed);
            let (sa, sb) = &self.link_states[i];
            sa.set_down(!up);
            sb.set_down(!up);
        }
        self.reroute_with(algo);
    }

    /// **Mobility + Wi-Fi MAC re-route.** Like [`reconnect`](Self::reconnect), but a link is up only
    /// if the [operating mode](crate::WifiOperatingMode) permits it (AP mode = star through the AP)
    /// *and* the endpoints are in range, and each up-link's drop probability + added delay come from
    /// the [`Wifi`](crate::Wifi) MAC at the SNR from the config's pluggable propagation backend under
    /// its [`WifiMode`](crate::WifiMode) (Monitor one-shot vs Managed retries). This is IP running
    /// over the modelled broadcast radio.
    pub fn reconnect_wifi(
        &self,
        positions: &[crate::world::Position],
        wifi: &crate::wifi::Wifi,
        cfg: &RadioLinkConfig,
        algo: &dyn crate::routing::RoutingAlgorithm,
    ) {
        *self.positions.lock().unwrap() = Some(positions.to_vec());
        use std::sync::atomic::Ordering::Relaxed;
        // In AP mode a link is the station↔AP association; identify the station endpoint (if any).
        let station_of = |a: usize, b: usize| match cfg.op_mode {
            crate::wifi::WifiOperatingMode::Ap { ap } if a == ap => Some(b),
            crate::wifi::WifiOperatingMode::Ap { ap } if b == ap => Some(a),
            _ => None,
        };
        for (i, &(a, b)) in self.links.iter().enumerate() {
            let dist = positions[a].distance(positions[b]);
            let up = cfg.op_mode.link_allowed(a, b) && dist <= cfg.range_m;
            let (sa, sb) = &self.link_states[i];
            if up {
                let snr = cfg.snr_at(dist);
                let (loss, airtime) = wifi.link_cost(cfg.mode, snr, cfg.frame_bytes, cfg.retry_limit);
                // (Re)association: a station coming into AP range must scan+auth+assoc(+4-way) before
                // it can pass traffic — a one-time per-handoff cost. Account it (handoff count +
                // total handshake time); the link itself carries only the per-frame MAC cost.
                if let Some(station) = station_of(a, b)
                    && !self.associated[station].swap(true, Relaxed)
                {
                    let setup = cfg.op_mode.association_setup();
                    self.handoffs.fetch_add(1, Relaxed);
                    self.assoc_overhead_ns.fetch_add(setup.as_nanos() as u64, Relaxed);
                }
                for s in [sa, sb] {
                    s.set_down(false);
                    s.set_loss(Some(loss));
                    s.set_extra_delay(airtime);
                }
                self.link_up[i].store(true, Relaxed);
            } else {
                // Link down: if it was a station↔AP association, the station is now unassociated and
                // will re-associate (another handoff) when it returns.
                if let Some(station) = station_of(a, b) {
                    self.associated[station].store(false, Relaxed);
                }
                for s in [sa, sb] {
                    s.set_down(true);
                }
                self.link_up[i].store(false, Relaxed);
            }
        }
        self.reroute_with(algo);
    }

    /// Total (re)associations across all stations since build — the roaming/handoff count under AP
    /// (infrastructure) mode. Zero in IBSS/mesh (no AP association) and for monitor-mode radio.
    pub fn handoff_count(&self) -> u64 {
        self.handoffs.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Accumulated association-handshake time across all handoffs — the control overhead
    /// infrastructure Wi-Fi pays for mobility that a connectionless broadcast face never does.
    pub fn association_overhead(&self) -> Duration {
        Duration::from_nanos(self.assoc_overhead_ns.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// A per-node [`IpMetricsSample`](crate::telemetry::IpMetricsSample) snapshot at the current
    /// virtual time — the IP-plane feed for the same telemetry log + OTLP exporter the NDN engine
    /// uses. Sample on a cadence to build a virtual-time series.
    pub fn metrics_snapshot(&self) -> Vec<crate::telemetry::IpMetricsSample> {
        let now = self.runtime.unix_nanos();
        self.nodes
            .iter()
            .enumerate()
            .map(|(i, node)| {
                let s = node.stats();
                crate::telemetry::IpMetricsSample {
                    node: crate::NodeId(i),
                    virtual_time_ns: now,
                    forwarded: s.forwarded,
                    delivered: s.delivered,
                    dropped_no_route: s.dropped_no_route,
                    dropped_ttl: s.dropped_ttl,
                    tx_bytes: s.tx_bytes,
                }
            })
            .collect()
    }

    /// The medium/network-wide [`FabricGauges`](crate::telemetry::FabricGauges) at the current
    /// virtual time: this network's roaming cost, plus `radio_airtime_ns` if the caller supplies the
    /// shared `RadioBus` total (IP-over-radio) — `0` otherwise.
    pub fn fabric_gauges(&self, radio_airtime: Duration) -> crate::telemetry::FabricGauges {
        crate::telemetry::FabricGauges {
            virtual_time_ns: self.runtime.unix_nanos(),
            radio_airtime_ns: radio_airtime.as_nanos() as u64,
            handoffs: self.handoff_count(),
            association_overhead_ns: self.assoc_overhead_ns.load(std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Build a **mobile** IP network: `positions.len()` nodes fully meshed with potential links, but
    /// only links within `range` are initially up (unit-disk-graph connectivity). Drive it with
    /// [`reconnect`](Self::reconnect) as nodes move. `algo` routes over the in-range topology (a
    /// geographic algorithm like GPSR uses the positions directly).
    pub fn from_positions(
        runtime: Arc<dyn Runtime>,
        positions: Vec<crate::world::Position>,
        range: f64,
        profile: &FaceProfile,
        algo: &dyn crate::routing::RoutingAlgorithm,
    ) -> Self {
        let n = positions.len();
        let full: Vec<(usize, usize)> =
            (0..n).flat_map(|i| ((i + 1)..n).map(move |j| (i, j))).collect();
        let net =
            Self::from_links_with(runtime, n, &full, Some(positions.clone()), profile, algo);
        net.reconnect(&positions, range, algo);
        net
    }

    /// Build a mobile IP network **over the Wi-Fi MAC**: like [`from_positions`](Self::from_positions)
    /// but each link's loss + delay come from the [`Wifi`](crate::Wifi) model per `cfg` (mode,
    /// operating mode, propagation — see [`reconnect_wifi`](Self::reconnect_wifi)). The link faces
    /// carry no intrinsic loss/delay — the MAC is the only channel effect.
    pub fn from_positions_wifi(
        runtime: Arc<dyn Runtime>,
        positions: Vec<crate::world::Position>,
        wifi: &crate::wifi::Wifi,
        cfg: &RadioLinkConfig,
        algo: &dyn crate::routing::RoutingAlgorithm,
    ) -> Self {
        let n = positions.len();
        let full: Vec<(usize, usize)> =
            (0..n).flat_map(|i| ((i + 1)..n).map(move |j| (i, j))).collect();
        // A plain in-proc face carries no loss/delay of its own; the MAC supplies both.
        let prof = FaceProfile::internal();
        let net = Self::from_links_with(runtime, n, &full, Some(positions.clone()), &prof, algo);
        net.reconnect_wifi(&positions, wifi, cfg, algo);
        net
    }

    /// Build a mobile IP network **over LoRa**: like [`from_positions_wifi`](Self::from_positions_wifi)
    /// but each in-range link's loss + latency come from the [`LoraLinkConfig`](crate::lora::LoraLinkConfig)
    /// (SF demod curve + Semtech airtime). Long range, high per-frame latency — the sub-GHz counterpoint
    /// to Wi-Fi, so a benchmark can run the *same* NDN/IP workload over LoRa.
    pub fn from_positions_lora(
        runtime: Arc<dyn Runtime>,
        positions: Vec<crate::world::Position>,
        cfg: &crate::lora::LoraLinkConfig,
        algo: &dyn crate::routing::RoutingAlgorithm,
    ) -> Self {
        let n = positions.len();
        let full: Vec<(usize, usize)> =
            (0..n).flat_map(|i| ((i + 1)..n).map(move |j| (i, j))).collect();
        let prof = FaceProfile::internal();
        let net = Self::from_links_with(runtime, n, &full, Some(positions.clone()), &prof, algo);
        net.reconnect_lora(&positions, cfg, algo);
        net
    }

    /// Mobility + LoRa re-route: a link is up when the endpoints are within `cfg.range_m`, and each
    /// up-link's drop probability + added latency come from the LoRa model at the link SNR. LoRa is a
    /// shared ALOHA broadcast medium — no association, no operating modes.
    pub fn reconnect_lora(
        &self,
        positions: &[crate::world::Position],
        cfg: &crate::lora::LoraLinkConfig,
        algo: &dyn crate::routing::RoutingAlgorithm,
    ) {
        use std::sync::atomic::Ordering::Relaxed;
        *self.positions.lock().unwrap() = Some(positions.to_vec());
        for (i, &(a, b)) in self.links.iter().enumerate() {
            let dist = positions[a].distance(positions[b]);
            let (sa, sb) = &self.link_states[i];
            if dist <= cfg.range_m {
                let (loss, airtime) = cfg.link_cost(dist);
                for s in [sa, sb] {
                    s.set_down(false);
                    s.set_loss(Some(loss));
                    s.set_extra_delay(airtime);
                }
                self.link_up[i].store(true, Relaxed);
            } else {
                for s in [sa, sb] {
                    s.set_down(true);
                }
                self.link_up[i].store(false, Relaxed);
            }
        }
        self.reroute_with(algo);
    }

    /// **Hands-free mobility-driven routing.** Spawn a background loop that, every `interval`, reads
    /// node positions from the `world` at the current virtual time (IP node `i` ↔ `NodeId(i)`) and
    /// [`reconnect`](Self::reconnect)s — so a mobility model, a recorded trace, or live co-sim moving
    /// the World automatically re-forms links and re-converges the routing. Runs until `cancel`.
    pub fn spawn_router(
        self: &Arc<Self>,
        world: Arc<crate::world::World>,
        range: f64,
        interval: Duration,
        algo: Arc<dyn crate::routing::RoutingAlgorithm>,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        let me = Arc::clone(self);
        ndn_app::rt::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = ndn_app::rt::sleep(interval) => {}
                }
                let t = me.runtime.unix_nanos().saturating_sub(me.epoch_ns) as f64 / 1e9;
                let view = world.snapshot(t);
                let positions: Vec<crate::world::Position> = (0..me.nodes.len())
                    .map(|i| view.position(crate::NodeId(i)).unwrap_or(crate::world::Position::ORIGIN))
                    .collect();
                me.reconnect(&positions, range, &*algo);
            }
        });
    }
}

/// A byte-channel link between two IP nodes — the same emulated SimLink the NDN plane rides (delay,
/// loss, bandwidth, faults), handed to the IP engine as raw byte faces. `link_id` seeds the two
/// faces' RNGs distinctly.
pub fn ip_link(
    runtime: Arc<dyn Runtime>,
    profile: &FaceProfile,
    buffer: usize,
    link_id: u64,
) -> (SimFace, SimFace) {
    SimLink::pair_profiled_on(
        FaceId(link_id * 2),
        FaceId(link_id * 2 + 1),
        profile,
        buffer,
        runtime,
        0,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_prefix_matching() {
        let a = Ipv4::new(10, 0, 0, 5);
        assert!(a.in_prefix(Ipv4::new(10, 0, 0, 0), 24));
        assert!(!a.in_prefix(Ipv4::new(10, 0, 1, 0), 24));
        assert!(a.in_prefix(Ipv4::new(0, 0, 0, 0), 0)); // default route
        assert_eq!(a.to_string(), "10.0.0.5");
    }

    #[test]
    fn packet_round_trips() {
        let p = IpPacket {
            src: Ipv4::new(10, 0, 0, 1),
            dst: Ipv4::new(10, 0, 0, 3),
            ttl: 64,
            reply: true,
            seq: 7,
            payload: Bytes::from_static(b"hello"),
        };
        let d = IpPacket::decode(&p.encode()).unwrap();
        assert_eq!((d.src, d.dst, d.ttl, d.reply, d.seq), (p.src, p.dst, p.ttl, p.reply, p.seq));
        assert_eq!(&d.payload[..], b"hello");
    }
}
