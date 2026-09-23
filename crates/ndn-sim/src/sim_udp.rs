//! UDP endpoints for config-booted nodes: the socket demux a forwarder's host performs.
//!
//! On the fleet a `[[face]]` UDP peer is not a private pipe to its neighbour. Its datagrams leave
//! from a local `(ip, port)`, and the neighbour's kernel picks the socket that receives them: a
//! `connect()`ed socket whose 4-tuple matches, else the socket bound to the destination port.
//! ndn-fwd's wildcard listener meets a source it has no face for by minting an on-demand face
//! (`ndn_mgmt::run_udp_listener`). A neighbour whose datagrams match none of our faces therefore
//! occupies TWO faces — the configured one we send on, the on-demand one we receive on — and
//! `nexthops_excluding(in_face)` no longer excludes it. That was nfd-divergence-findings.md
//! Round 15: every configured peer bound an ephemeral port, and each `/muas` Interest went back to
//! the node it came from (12 wire copies per Interest against NFD's 9).
//!
//! Here each config-booted node is a [`UdpHost`] with that demux, and each peer face binds as
//! [`ndn_config::boot::udp_peer_binding`] decides (the decision ndn-fwd's face setup realises), so
//! the sim has one face per neighbour exactly when a deployed forwarder does. Links added any other
//! way stay point-to-point [`SimLink`](crate::SimLink) pipes.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Weak};

use anyhow::{Result, bail};
use bytes::Bytes;
use ndn_config::ForwarderConfig;
use ndn_config::boot::UdpPeerBinding;
use ndn_engine::ForwarderEngine;
use ndn_transport::FaceId;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, trace};

use crate::NodeId;
use crate::netstat::{PrefixStats, PrefixTap};
use crate::sim_face::{LinkState, Outbound, SimFace};
use crate::sim_link::FaceProfile;

/// First port a host hands out for a bind to port 0: the bottom of Linux's default
/// `net.ipv4.ip_local_port_range`. Handed out in bind order, so a run is reproducible.
const EPHEMERAL_PORT_BASE: u16 = 32768;

/// One UDP datagram as it reached its destination host, before that host's socket demux: what
/// `tcpdump` on the receiver's interface shows, link loss already applied. See
/// [`RunningSimulation::start_udp_capture`](crate::RunningSimulation::start_udp_capture).
#[derive(Clone, Debug)]
pub struct UdpDatagram {
    /// Arrival time, Unix nanoseconds on the fabric's clock.
    pub unix_ns: u64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    /// The UDP payload: an NDNLPv2 frame on a peer link.
    pub payload: Bytes,
}

/// A config-booted node, as its UDP stack needs it.
pub(crate) struct HostSpec<'a> {
    pub node: NodeId,
    pub ip: IpAddr,
    pub cfg: &'a ForwarderConfig,
    /// The FaceId reserved for each `[[face]]` index.
    pub face_ids: &'a [FaceId],
    pub engine: ForwarderEngine,
    /// The node's shutdown token: its faces die with it.
    pub cancel: CancellationToken,
    pub label: String,
}

/// How every UDP face on the fabric is built.
pub(crate) struct FaceEnv {
    /// A configured peer face: the fabric's peer link, wired with ndn-fwd's persistency.
    pub configured: FaceProfile,
    /// A listener's on-demand face: the same link, wired OnDemand.
    pub on_demand: FaceProfile,
    pub channel_buffer: usize,
    pub world_seed: u64,
    pub prefix: Option<(Arc<PrefixStats>, usize)>,
}

/// The IP network between config-booted nodes: every host's UDP stack, by address.
pub(crate) struct UdpNet {
    hosts: HashMap<IpAddr, UdpHost>,
    env: FaceEnv,
    capture: Mutex<Option<Vec<UdpDatagram>>>,
}

/// Where a UDP face's datagrams go: from its local endpoint to its peer's, across the [`UdpNet`].
#[derive(Clone)]
pub(crate) struct UdpPath {
    net: Weak<UdpNet>,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl UdpPath {
    pub(crate) async fn deliver(&self, pkt: Bytes) {
        if let Some(net) = self.net.upgrade() {
            net.deliver(self.src, self.dst, pkt).await;
        }
    }
}

struct UdpHost {
    node: NodeId,
    ip: IpAddr,
    label: String,
    engine: ForwarderEngine,
    /// Cancelled when the node is removed or shut down; its stack then takes nothing.
    cancel: CancellationToken,
    /// Each node that exchanges datagrams with this one, by address, with the fault knob of this
    /// host's direction toward it — shared by every face this host has toward that node, so a
    /// partition cuts an on-demand face as well as the configured one.
    peers: HashMap<IpAddr, (NodeId, Arc<LinkState>)>,
    sockets: Mutex<Sockets>,
}

struct Sockets {
    /// `connect()`ed sockets by `(local port, peer)`: the kernel's 4-tuple match.
    connected: HashMap<(u16, SocketAddr), mpsc::Sender<Bytes>>,
    /// Unconnected sockets by local port.
    bound: HashMap<u16, Bound>,
    next_ephemeral: u16,
    /// Every face on this host's sockets with the node it reaches, in creation order.
    faces: Vec<(FaceId, NodeId)>,
}

enum Bound {
    /// A peer face on its own unconnected socket: `UdpFace` drops datagrams from any source but
    /// its peer.
    Face {
        peer: SocketAddr,
        rx: mpsc::Sender<Bytes>,
    },
    /// ndn-fwd's wildcard listener: one on-demand face per source endpoint.
    Listener {
        faces: HashMap<SocketAddr, (FaceId, mpsc::Sender<Bytes>)>,
    },
}

impl UdpNet {
    /// Bring up the UDP stacks of `hosts`: their listeners, and one face per `[[face]]` UDP peer
    /// entry whose `remote` is another host. Each peer face is recorded in `links` (the face `a`
    /// has toward `b`), and both directions of every pair that exchanges datagrams in
    /// `link_states`, so faults reach faces a listener mints later.
    pub(crate) fn build(
        hosts: Vec<HostSpec<'_>>,
        env: FaceEnv,
        links: &mut HashMap<(NodeId, NodeId), FaceId>,
        link_states: &mut HashMap<(NodeId, NodeId), Arc<LinkState>>,
    ) -> Result<Arc<Self>> {
        let mut node_at: HashMap<IpAddr, NodeId> = HashMap::new();
        for h in &hosts {
            if let Some(other) = node_at.insert(h.ip, h.node) {
                bail!("{other} and {} both claim address {}", h.node, h.ip);
            }
        }

        // Peer faces in node declaration order, then entry order: ports and ids are reproducible.
        let mut peer_faces = Vec::new();
        let mut pairs = Vec::new();
        for h in &hosts {
            for (i, face) in h.cfg.faces.iter().enumerate() {
                let Some((remote, binding)) = crate::config_boot::udp_peer(face) else {
                    continue;
                };
                let Some(&peer) = node_at.get(&remote.ip()).filter(|&&p| p != h.node) else {
                    info!(node = %h.node, %remote, "ndn-lab: [[face]] remote is not a sim node; no face");
                    continue;
                };
                if links.insert((h.node, peer), h.face_ids[i]).is_some() {
                    bail!("{} and {peer} are linked twice", h.node);
                }
                pairs.extend([(h.node, peer), (peer, h.node)]);
                peer_faces.push((h.ip, h.face_ids[i], remote, binding));
            }
        }
        let ip_of: HashMap<NodeId, IpAddr> = node_at.iter().map(|(ip, n)| (*n, *ip)).collect();
        let mut peers: HashMap<NodeId, HashMap<IpAddr, (NodeId, Arc<LinkState>)>> = HashMap::new();
        for (from, to) in pairs {
            let state = link_states.entry((from, to)).or_insert_with(LinkState::new);
            peers
                .entry(from)
                .or_default()
                .insert(ip_of[&to], (to, Arc::clone(state)));
        }

        let hosts = hosts
            .into_iter()
            .map(|h| {
                let mut bound = HashMap::new();
                for port in crate::config_boot::udp_listener_ports(h.cfg) {
                    bound.entry(port).or_insert_with(|| Bound::Listener {
                        faces: HashMap::new(),
                    });
                }
                let host = UdpHost {
                    node: h.node,
                    ip: h.ip,
                    label: h.label,
                    engine: h.engine,
                    cancel: h.cancel,
                    peers: peers.remove(&h.node).unwrap_or_default(),
                    sockets: Mutex::new(Sockets {
                        connected: HashMap::new(),
                        bound,
                        next_ephemeral: EPHEMERAL_PORT_BASE,
                        faces: Vec::new(),
                    }),
                };
                (h.ip, host)
            })
            .collect();
        let net = Arc::new(Self {
            hosts,
            env,
            capture: Mutex::new(None),
        });
        for (ip, id, remote, binding) in peer_faces {
            net.hosts[&ip].bind_peer_face(&net, id, remote, binding)?;
        }
        Ok(net)
    }

    async fn deliver(self: &Arc<Self>, src: SocketAddr, dst: SocketAddr, pkt: Bytes) {
        let Some(host) = self.hosts.get(&dst.ip()) else {
            return;
        };
        if let Some(capture) = self.capture.lock().as_mut() {
            capture.push(UdpDatagram {
                unix_ns: host.engine.runtime().unix_nanos(),
                src,
                dst,
                payload: pkt.clone(),
            });
        }
        let Some(rx) = host.demux(self, src, dst.port()) else {
            trace!(%src, %dst, "ndn-lab: UDP datagram matched no socket; dropped");
            return;
        };
        // Backpressure as on a point-to-point link; a closed queue (face gone) drops it.
        let _ = rx.send(pkt).await;
    }

    /// Start recording every datagram (restarting any capture in progress).
    pub(crate) fn start_capture(&self) {
        *self.capture.lock() = Some(Vec::new());
    }

    /// Stop recording and return what was captured, in arrival order.
    pub(crate) fn take_capture(&self) -> Vec<UdpDatagram> {
        self.capture.lock().take().unwrap_or_default()
    }

    /// Every UDP face `node` has had (configured and on-demand), with the node at its far end.
    pub(crate) fn link_faces(&self, node: NodeId) -> Vec<(FaceId, NodeId)> {
        self.hosts
            .values()
            .filter(|h| h.node == node)
            .flat_map(|h| h.sockets.lock().faces.clone())
            .collect()
    }
}

impl UdpHost {
    /// Bind a configured peer face as `binding` says and attach it to the engine.
    fn bind_peer_face(
        &self,
        net: &Arc<UdpNet>,
        id: FaceId,
        remote: SocketAddr,
        binding: UdpPeerBinding,
    ) -> Result<()> {
        let mut guard = self.sockets.lock();
        let sockets = &mut *guard;
        let port = match binding.local_port {
            0 => sockets.ephemeral_port(),
            port => port,
        };
        let taken = if binding.connected {
            sockets.connected.contains_key(&(port, remote))
        } else {
            sockets.bound.contains_key(&port)
        };
        if taken {
            // Two sockets the kernel cannot tell apart: which one gets a datagram is unspecified.
            bail!(
                "{}: two UDP sockets on port {port} for {remote} (connected: {})",
                self.node,
                binding.connected
            );
        }
        let (rx, peer) = self.attach_face(net, id, port, remote, &net.env.configured);
        if binding.connected {
            sockets.connected.insert((port, remote), rx);
        } else {
            sockets.bound.insert(port, Bound::Face { peer: remote, rx });
        }
        sockets.faces.push((id, peer));
        Ok(())
    }

    /// The receive queue a datagram from `src` to local `port` lands in, picked as the kernel and
    /// ndn-fwd's listener pick it: a connected socket whose 4-tuple matches, else the socket bound
    /// to `port` — a peer face that takes only its peer, or the listener, which mints an on-demand
    /// face for a source it has none for.
    fn demux(&self, net: &Arc<UdpNet>, src: SocketAddr, port: u16) -> Option<mpsc::Sender<Bytes>> {
        if self.cancel.is_cancelled() {
            return None;
        }
        let mut guard = self.sockets.lock();
        let Sockets {
            connected,
            bound,
            faces: log,
            ..
        } = &mut *guard;
        if let Some(rx) = connected.get(&(port, src)) {
            return Some(rx.clone());
        }
        match bound.get_mut(&port)? {
            Bound::Face { peer, rx } => (*peer == src).then(|| rx.clone()),
            Bound::Listener { faces } => {
                // Like `run_udp_listener`: a face the idle reaper removed is minted afresh, never
                // fed under a dead FaceId.
                if let Some((id, rx)) = faces.get(&src)
                    && self.engine.face_states().contains_key(id)
                {
                    return Some(rx.clone());
                }
                if !self.peers.contains_key(&src.ip()) {
                    return None;
                }
                let id = self.engine.faces().alloc_id();
                let (rx, peer) = self.attach_face(net, id, port, src, &net.env.on_demand);
                faces.insert(src, (id, rx.clone()));
                log.push((id, peer));
                Some(rx)
            }
        }
    }

    /// A face on local `port` exchanging datagrams with `remote`, attached to this node's engine.
    /// Returns what feeds its receive queue, and the node at its far end.
    fn attach_face(
        &self,
        net: &Arc<UdpNet>,
        id: FaceId,
        port: u16,
        remote: SocketAddr,
        profile: &FaceProfile,
    ) -> (mpsc::Sender<Bytes>, NodeId) {
        let (peer, state) = &self.peers[&remote.ip()];
        let env = &net.env;
        let (tx, rx) = mpsc::channel(env.channel_buffer);
        let path = UdpPath {
            net: Arc::downgrade(net),
            src: SocketAddr::new(self.ip, port),
            dst: remote,
        };
        let mut face = SimFace::new(
            id,
            Outbound::Udp(path),
            rx,
            profile,
            self.engine.runtime(),
            env.world_seed,
        )
        .with_link_state(Arc::clone(state));
        if let Some((stats, depth)) = &env.prefix {
            face = face.with_prefix_tap(PrefixTap::new(
                Arc::clone(stats),
                self.label.clone(),
                *depth,
            ));
        }
        profile.attach(&self.engine, face, self.cancel.clone());
        info!(node = self.node.0, face = %id, local = %SocketAddr::new(self.ip, port), %remote, persistency = ?profile.persistency, "ndn-lab: udp face created");
        (tx, *peer)
    }
}

impl Sockets {
    /// The next free port of the ephemeral range, as the kernel picks one for a bind to port 0.
    fn ephemeral_port(&mut self) -> u16 {
        loop {
            let port = self.next_ephemeral;
            self.next_ephemeral = port.checked_add(1).unwrap_or(EPHEMERAL_PORT_BASE);
            if !self.bound.contains_key(&port) && !self.connected.keys().any(|(p, _)| *p == port) {
                return port;
            }
        }
    }
}
