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
            let _ = face.send_bytes(pkt.encode()).await;
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

    /// Forwarding counters (forwarded / delivered / dropped).
    pub fn stats(&self) -> IpNodeStats {
        IpNodeStats {
            forwarded: self.inner.forwarded.load(Ordering::Relaxed),
            delivered: self.inner.delivered.load(Ordering::Relaxed),
            dropped_no_route: self.inner.dropped_no_route.load(Ordering::Relaxed),
            dropped_ttl: self.inner.dropped_ttl.load(Ordering::Relaxed),
        }
    }

    /// Sequentially ping `dst` `count` times (a `payload_len`-byte request each), waiting up to
    /// `lifetime` for each echo and pausing `interval` between them — returning the round-trip
    /// [`FlowStats`] (RTT, loss, goodput), the same shape the NDN apps report.
    pub async fn ping(
        &self,
        dst: Ipv4,
        count: u32,
        payload_len: usize,
        interval: Duration,
        lifetime: Duration,
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
            if !interval.is_zero() {
                ndn_app::rt::sleep(interval).await;
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
