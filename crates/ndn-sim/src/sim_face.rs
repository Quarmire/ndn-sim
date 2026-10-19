//! `SimFace` — one endpoint of a [`SimLink`](crate::SimLink), or a UDP face of a config-booted
//! node whose datagrams the destination host demuxes (`sim_udp`). The send path applies delay,
//! jitter, loss, and bandwidth shaping before delivery, and presents the **per-face-type
//! behavior** of its [`FaceProfile`]: the engine sees the right `FaceKind`,
//! `LinkType`, and `send_mtu`, and either datagram semantics (loss + jitter-reorder) or
//! reliable-stream semantics (no loss, in-order) — so a scenario can express "this is UDP" vs
//! "this is TCP/QUIC" and the forwarder behaves accordingly. An IP-carried profile additionally
//! models IP fragmentation (a datagram above the path MTU dies if any fragment does), and a
//! profile on a [`SharedChannel`] contends for airtime with its siblings.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_runtime::{Instant, Runtime};
use ndn_transport::{FaceError, FaceId, FaceKind, LinkType, Transport};
use parking_lot::Mutex;
use rand::{Rng, SeedableRng, rngs::StdRng};
use tokio::sync::mpsc;
use tracing::trace;

use crate::shared_channel::SharedChannel;
use crate::sim_link::{FaceProfile, IPV4_HEADER, LinkConfig, UDP_HEADER};

/// Which wire frames a [`HoldRule`] arms on, by network-packet type. On an NDNLPv2 link (every
/// UDP/Ethernet-kind face) the packet rides inside an `LpPacket`, so the matcher looks through
/// the LP header at the first fragment's network packet; Acks-only frames, Nacks and non-first
/// fragments match only [`Any`](Self::Any).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameMatcher {
    /// Every frame.
    Any,
    /// Interest packets (outer TLV type `0x05`).
    Interest,
    /// Data packets (outer TLV type `0x06`).
    Data,
}

impl FrameMatcher {
    fn matches(&self, pkt: &[u8]) -> bool {
        let outer = match self {
            Self::Any => return true,
            Self::Interest => 0x05,
            Self::Data => 0x06,
        };
        if !ndn_packet::lp::is_lp_packet(pkt) {
            return pkt.first() == Some(&outer);
        }
        // Only consulted while a hold rule is armed, so the decode copy is off the hot path.
        let Ok(lp) = ndn_packet::lp::LpPacket::decode(Bytes::copy_from_slice(pkt)) else {
            return false;
        };
        lp.nack.is_none()
            && lp.frag_index.unwrap_or(0) == 0
            && lp.fragment.as_ref().and_then(|f| f.first()) == Some(&outer)
    }
}

/// A targeted **hold**: delay matching frames WITHOUT dropping them — the reorder /
/// latency-spike fault a loss knob cannot express (NS-6: a late reply to an already-timed-out
/// request arrives mid-way through the next exchange and shifts every arrival-order-paired
/// stream by one).
///
/// Deterministic by construction: the rule counts *matching* frames crossing the face in
/// arrival order, skips the first [`skip`](Self::skip), and holds the next
/// [`count`](Self::count) by [`delay`](Self::delay) on top of the link's normal latency. Held
/// frames are **exempt from the loss roll** (delayed, never dropped — the contract), but a
/// downed link (partition) still discards everything.
///
/// On a datagram face (`reliable: false`, e.g. the default UDP link) a held frame is overtaken
/// by later traffic — a true reorder. On a reliable (TCP-like) face in-order delivery is
/// preserved, so the hold becomes a head-of-line stall instead; both are faithful.
#[derive(Debug, Clone)]
pub struct HoldRule {
    /// Which frames arm the rule.
    pub matcher: FrameMatcher,
    /// Skip this many matching frames before holding starts.
    pub skip: u64,
    /// Hold this many matching frames, then let the rest flow normally.
    pub count: u64,
    /// Extra delay applied to each held frame (on top of the link's configured latency).
    pub delay: Duration,
}

impl HoldRule {
    /// Hold the `n`-th (0-based) matching frame, once.
    pub fn nth(matcher: FrameMatcher, n: u64, delay: Duration) -> Self {
        Self {
            matcher,
            skip: n,
            count: 1,
            delay,
        }
    }
}

/// Live hold bookkeeping: the rule plus how many matching frames have been seen / held.
#[derive(Debug)]
struct HoldActive {
    rule: HoldRule,
    matched: u64,
    held: u64,
}

/// Live, mutable per-face fault knobs — shared (via `Arc`) with the fabric so a runtime
/// [`Fault`](crate::Fault) can cut a link (partition), or inject loss / extra delay (degrade),
/// *without* rebuilding the link. A face at rest ([`reset`](LinkState::reset)) behaves exactly as
/// its [`FaceProfile`] dictates.
#[derive(Debug)]
pub struct LinkState {
    /// When set, the face silently drops every frame — a down link / partition edge.
    down: AtomicBool,
    /// Loss-rate override, as the bits of an `f64`; a NaN sentinel means "use the profile's rate".
    loss_override_bits: AtomicU64,
    /// Extra delay (ns) added to every frame — congestion / degradation.
    extra_delay_ns: AtomicU64,
    /// Targeted delay-without-drop rule ([`HoldRule`]) — the reorder fault.
    hold: Mutex<Option<HoldActive>>,
}

impl LinkState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            down: AtomicBool::new(false),
            loss_override_bits: AtomicU64::new(f64::NAN.to_bits()),
            extra_delay_ns: AtomicU64::new(0),
            hold: Mutex::new(None),
        })
    }
    /// Cut / restore the link (drop everything when `true`).
    pub fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::Relaxed);
    }
    /// Override the loss rate (`None` restores the profile's).
    pub fn set_loss(&self, rate: Option<f64>) {
        self.loss_override_bits
            .store(rate.unwrap_or(f64::NAN).to_bits(), Ordering::Relaxed);
    }
    /// Add extra per-frame delay (congestion).
    pub fn set_extra_delay(&self, extra: Duration) {
        self.extra_delay_ns
            .store(extra.as_nanos() as u64, Ordering::Relaxed);
    }
    /// Install (or clear) a targeted [`HoldRule`] — delay matching frames without dropping
    /// them. Replaces any prior rule; the match counter restarts.
    pub fn set_hold(&self, rule: Option<HoldRule>) {
        *self.hold.lock() = rule.map(|rule| HoldActive {
            rule,
            matched: 0,
            held: 0,
        });
    }
    /// Restore the link to its profile defaults (up, no override, no extra delay, no hold).
    pub fn reset(&self) {
        self.set_down(false);
        self.set_loss(None);
        self.set_extra_delay(Duration::ZERO);
        self.set_hold(None);
    }
    fn is_down(&self) -> bool {
        self.down.load(Ordering::Relaxed)
    }
    fn loss_override(&self) -> Option<f64> {
        let b = f64::from_bits(self.loss_override_bits.load(Ordering::Relaxed));
        if b.is_nan() { None } else { Some(b) }
    }
    fn extra_delay(&self) -> Duration {
        Duration::from_nanos(self.extra_delay_ns.load(Ordering::Relaxed))
    }
    /// Consult (and advance) the hold rule for one outgoing frame: `Some(delay)` if this frame
    /// is held. Counting is per *matching* frame, in send order — deterministic under the
    /// single-threaded virtual/DES kernels.
    fn hold_delay(&self, pkt: &[u8]) -> Option<Duration> {
        let mut guard = self.hold.lock();
        let active = guard.as_mut()?;
        if !active.rule.matcher.matches(pkt) {
            return None;
        }
        let idx = active.matched;
        active.matched += 1;
        if idx < active.rule.skip || active.held >= active.rule.count {
            return None;
        }
        active.held += 1;
        Some(active.rule.delay)
    }
}

/// SplitMix64 finalizer — spreads adjacent face ids into well-separated RNG seeds so two
/// faces' loss/jitter streams are independent.
fn mix_seed(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Where a face's frames go once they have crossed the link.
#[derive(Clone)]
pub(crate) enum Outbound {
    /// Straight into the far face's receive queue: a point-to-point [`SimLink`](crate::SimLink).
    Pipe(mpsc::Sender<Bytes>),
    /// A UDP datagram, handed to the destination host's socket demux on arrival (see
    /// [`crate::sim_udp`]).
    Udp(crate::sim_udp::UdpPath),
}

impl Outbound {
    async fn deliver(&self, pkt: Bytes) -> Result<(), FaceError> {
        match self {
            Self::Pipe(tx) => tx.send(pkt).await.map_err(|_| FaceError::Closed),
            // A UDP sender never learns whether any socket took the datagram.
            Self::Udp(path) => {
                path.deliver(pkt).await;
                Ok(())
            }
        }
    }
}

/// A simulated face. Created in pairs by [`SimLink`](crate::SimLink), or as a UDP endpoint of a
/// config-booted node; link emulation on send, typed by a [`FaceProfile`].
pub struct SimFace {
    id: FaceId,
    out: Outbound,
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    config: LinkConfig,
    /// Face-type behavior (what the engine sees + delivery semantics).
    kind: FaceKind,
    link_type: LinkType,
    send_mtu: Option<usize>,
    /// Reliable streams (TCP/QUIC/WS/SHM): no loss, in-order delivery.
    reliable: bool,
    /// IP path MTU for an IP-carried (UDP) face; `None` = not IP-carried. See [`on_wire`](Self::on_wire).
    ip_mtu: Option<usize>,
    /// The contended medium this face transmits on, if any (else a dedicated link).
    channel: Option<Arc<SharedChannel>>,
    /// Frame size `loss_rate` is quoted for; `None` = size-blind. See
    /// [`FaceProfile::loss_frame_bytes`](crate::FaceProfile::loss_frame_bytes).
    loss_frame_bytes: Option<usize>,
    /// Bandwidth shaping cursor: earliest time the next byte can transmit.
    next_tx_ready: Mutex<Instant>,
    /// Monotonic delivery cursor for reliable faces — guarantees in-order arrival despite
    /// per-packet scheduling.
    last_delivery: Mutex<Instant>,
    /// The clock + executor seam: delivery delay + task spawn ride this, so the face runs on any
    /// kernel — wall-clock, virtual, or the discrete-event executor (never `tokio::time` directly).
    runtime: Arc<dyn Runtime>,
    /// **Seeded** PRNG for loss/jitter rolls — reproducible (never `thread_rng`).
    rng: Mutex<StdRng>,
    /// Live fault knobs (down / loss-override / extra-delay), shared with the fabric.
    state: Arc<LinkState>,
    /// Optional name-aware per-prefix accounting: when set, this face classifies
    /// each frame and counts it into the shared table (see [`crate::netstat`]).
    prefix_tap: Option<crate::netstat::PrefixTap>,
}

impl SimFace {
    pub(crate) fn new(
        id: FaceId,
        out: Outbound,
        rx: mpsc::Receiver<Bytes>,
        profile: &FaceProfile,
        runtime: Arc<dyn Runtime>,
        world_seed: u64,
    ) -> Self {
        let now = runtime.now();
        // The loss/jitter stream is seeded from BOTH the face id (so two faces are independent) and
        // a per-run `world_seed` (so a seed sweep draws a *different* realization each run). A
        // `world_seed` of 0 reproduces the id-only seeding exactly (`id ^ 0 == id`).
        let face_seed = mix_seed(id.0 ^ world_seed.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        Self {
            id,
            out,
            rx: tokio::sync::Mutex::new(rx),
            config: profile.link.clone(),
            kind: profile.kind,
            link_type: profile.link_type,
            send_mtu: profile.send_mtu,
            reliable: profile.reliable,
            ip_mtu: profile.ip_mtu,
            channel: profile.channel.clone(),
            loss_frame_bytes: profile.loss_frame_bytes,
            next_tx_ready: Mutex::new(now),
            last_delivery: Mutex::new(now),
            runtime,
            rng: Mutex::new(StdRng::seed_from_u64(face_seed)),
            state: LinkState::new(),
            prefix_tap: None,
        }
    }

    /// The live fault knobs for this face — the fabric holds a clone so a runtime `Fault` can cut
    /// or degrade the link.
    pub fn link_state(&self) -> Arc<LinkState> {
        Arc::clone(&self.state)
    }

    /// Share `state` as this face's fault knobs: every UDP face a node has toward one peer (its
    /// configured face and any on-demand face) sends in the same direction of the same link.
    pub(crate) fn with_link_state(mut self, state: Arc<LinkState>) -> Self {
        self.state = state;
        self
    }

    /// Install a name-aware per-prefix tap on this face (the fabric does this at link-build time
    /// when prefix accounting is enabled). Consumes + returns the face so it can be set before the
    /// face moves into an engine.
    pub(crate) fn with_prefix_tap(mut self, tap: crate::netstat::PrefixTap) -> Self {
        self.prefix_tap = Some(tap);
        self
    }

    /// What one datagram of `len` bytes costs on the wire: `(frames, bytes)`. A dedicated
    /// non-IP face sends it as-is. An IP-carried face above the path MTU makes IPv4 fragment it:
    /// every fragment carries its own IP header and at most `mtu - 20` bytes of IP payload
    /// (a multiple of 8), the UDP header riding once in the first.
    fn on_wire(&self, len: usize) -> (usize, usize) {
        let Some(mtu) = self.ip_mtu else {
            return (1, len);
        };
        let per_fragment = (mtu.saturating_sub(IPV4_HEADER) & !7).max(8);
        let ip_payload = len + UDP_HEADER;
        let frames = ip_payload.div_ceil(per_fragment).max(1);
        (frames, ip_payload + frames * IPV4_HEADER)
    }

    /// On-air bytes of each frame [`on_wire`](Self::on_wire) counts for a `len`-byte datagram:
    /// full IP fragments first, the remainder last (the datagram itself on a non-IP face).
    fn frame_bytes(&self, len: usize) -> impl Iterator<Item = usize> {
        let (frames, _) = self.on_wire(len);
        let (payload, per_frame, header) = match self.ip_mtu {
            Some(mtu) => (
                len + UDP_HEADER,
                (mtu.saturating_sub(IPV4_HEADER) & !7).max(8),
                IPV4_HEADER,
            ),
            None => (len, len, 0),
        };
        (0..frames).map(move |i| (payload - i * per_frame).min(per_frame) + header)
    }
}

impl Transport for SimFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        self.kind
    }

    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn send_mtu(&self) -> Option<usize> {
        self.send_mtu
    }

    /// A UDP endpoint names its peer the way `UdpFace` does (`udp4://10.42.0.12:6363`), so
    /// everything that reads the face table — `faces/list`, scope, the strategy's same-node
    /// check — sees what it sees on the fleet.
    fn remote_uri(&self) -> Option<String> {
        match &self.out {
            Outbound::Udp(path) => Some(ndn_transport::ip_face_uri("udp", path.dst)),
            Outbound::Pipe(_) => Some(format!("sim-{}://face#{}", self.kind, self.id.0)),
        }
    }

    fn local_uri(&self) -> Option<String> {
        match &self.out {
            Outbound::Udp(path) => Some(ndn_transport::ip_face_uri("udp", path.src)),
            Outbound::Pipe(_) => None,
        }
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        let pkt = self.rx.lock().await.recv().await.ok_or(FaceError::Closed)?;
        // Per-prefix accounting: count the DELIVERY (post-impairment — what actually arrived).
        if let Some(tap) = &self.prefix_tap {
            tap.observe(&pkt, false);
        }
        Ok(pkt)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        // Per-prefix accounting: count the EMISSION (before the loss roll — the node emitted it, so
        // a lossy link shows out > in for the prefix, which is the informative truth).
        if let Some(tap) = &self.prefix_tap {
            tap.observe(&pkt, true);
        }
        // A partitioned / downed link drops everything (a runtime Fault::Partition or a down link).
        if self.state.is_down() {
            trace!(face = %self.id, "SimFace: packet dropped (link down)");
            return Ok(());
        }
        // Targeted hold (delay WITHOUT drop): a held frame is exempt from the loss roll —
        // "delayed, never dropped" is the rule's contract.
        let hold = self.state.hold_delay(&pkt);
        if hold.is_some() {
            trace!(face = %self.id, "SimFace: frame held (delayed, not dropped)");
        }

        let now = self.runtime.now();
        let (frames, wire_bytes) = self.on_wire(pkt.len());

        // A shared medium is claimed BEFORE the loss roll: a frame lost in the air still held the
        // air for its whole duration, and every sibling link waited behind it.
        let channel_done = match &self.channel {
            Some(channel) => match channel.transmit(now, frames, wire_bytes) {
                Some(done) => Some(done),
                None => {
                    trace!(face = %self.id, channel = channel.name(), "SimFace: tail-dropped (medium backlog full)");
                    return Ok(());
                }
            },
            None => None,
        };

        // Datagram loss (reliable streams never drop) — a runtime Fault::DegradeLink can override the
        // profile's rate. An IP-fragmented datagram survives only if EVERY fragment does: no layer
        // below NDN retransmits a lost IP fragment, so per-frame loss p becomes 1-(1-p)^n per
        // datagram. That is the fleet's video collapse: ~8 KB Data handed to IP whole measured 76%
        // IP-reassembly failure on Wi-Fi while single-datagram telemetry was unaffected. With
        // `loss_frame_bytes`, each frame's loss follows its own size (independent bit errors).
        let loss_rate = self.state.loss_override().unwrap_or(self.config.loss_rate);
        if hold.is_none() && !self.reliable && loss_rate > 0.0 {
            let survive = (1.0 - loss_rate).max(0.0);
            let mut rng = self.rng.lock();
            let lost = match self.loss_frame_bytes {
                None => (0..frames).any(|_| rng.random::<f64>() < loss_rate),
                Some(n) => self
                    .frame_bytes(pkt.len())
                    .any(|bytes| rng.random::<f64>() < 1.0 - survive.powf(bytes as f64 / n as f64)),
            };
            drop(rng);
            if lost {
                trace!(face = %self.id, frames, "SimFace: packet dropped (loss)");
                return Ok(());
            }
        }

        // Transmit timing: the shared channel already serialised this frame (it is on the far end
        // once its airtime ends); otherwise a dedicated link serialises its own transmit starts
        // through a cursor (bandwidth 0 = no shaping).
        #[allow(clippy::manual_checked_ops)]
        let tx_start = match channel_done {
            Some(done) => done,
            None if self.config.bandwidth_bps > 0 => {
                let bits = (wire_bytes as u64) * 8;
                let tx_duration =
                    Duration::from_nanos(bits * 1_000_000_000 / self.config.bandwidth_bps);
                let mut next = self.next_tx_ready.lock();
                if *next < now {
                    *next = now;
                }
                let start = *next;
                *next = start + tx_duration;
                start
            }
            None => now,
        };

        // Reliable streams add no reordering jitter; datagrams may reorder.
        let jitter = if self.reliable {
            Duration::ZERO
        } else {
            self.jitter()
        };
        let mut deliver_at = tx_start
            + self.config.delay
            + jitter
            + self.state.extra_delay()
            + hold.unwrap_or_default();

        // Reliable: never deliver before the previous packet (in-order, HOL-style).
        if self.reliable {
            let mut last = self.last_delivery.lock();
            if deliver_at <= *last {
                deliver_at = *last + Duration::from_nanos(1);
            }
            *last = deliver_at;
        }

        let wait = deliver_at.saturating_duration_since(now);
        if wait.is_zero() {
            self.out.deliver(pkt).await
        } else {
            // Delayed delivery on the runtime seam (virtual under the virtual/DES kernels).
            let out = self.out.clone();
            let face_id = self.id;
            let rt = Arc::clone(&self.runtime);
            self.runtime.spawn(Box::pin(async move {
                rt.sleep(wait).await;
                if out.deliver(pkt).await.is_err() {
                    trace!(face = %face_id, "SimFace: remote end closed during delayed delivery");
                }
            }));
            Ok(())
        }
    }
}

impl SimFace {
    /// A uniform jitter in `[0, config.jitter]`, drawn from the seeded PRNG (reproducible).
    fn jitter(&self) -> Duration {
        let max = self.config.jitter;
        if max.is_zero() {
            return Duration::ZERO;
        }
        let nanos = self.rng.lock().random_range(0..=max.as_nanos() as u64);
        Duration::from_nanos(nanos)
    }
}
