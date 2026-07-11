//! `SimFace` — one endpoint of a [`SimLink`](crate::SimLink). The send path applies delay,
//! jitter, loss, and bandwidth shaping before delivery, and presents the **per-face-type
//! behavior** of its [`FaceProfile`](crate::FaceProfile): the engine sees the right `FaceKind`,
//! `LinkType`, and `send_mtu`, and either datagram semantics (loss + jitter-reorder) or
//! reliable-stream semantics (no loss, in-order) — so a scenario can express "this is UDP" vs
//! "this is TCP/QUIC" and the forwarder behaves accordingly.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_runtime::{Instant, Runtime};
use ndn_transport::{FaceError, FaceId, FaceKind, LinkType, Transport};
use rand::{Rng, SeedableRng, rngs::StdRng};
use tokio::sync::mpsc;
use tracing::trace;

use crate::sim_link::{FaceProfile, LinkConfig};

/// Which wire frames a [`HoldRule`] arms on, by TLV outer type. Frames between two engine
/// faces are bare NDN packets unless the link LP-fragments (an MTU-bearing profile) or a peer
/// initiates NDNLPv2 — match [`Any`](Self::Any) on such links.
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
        match self {
            Self::Any => true,
            Self::Interest => pkt.first() == Some(&0x05),
            Self::Data => pkt.first() == Some(&0x06),
        }
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
/// On a datagram face (`reliable: false`, the `SimLink` default) a held frame is overtaken by
/// later traffic — a true reorder. On a reliable (TCP-like) face in-order delivery is
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
        Self { matcher, skip: n, count: 1, delay }
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
/// its [`FaceProfile`](crate::FaceProfile) dictates.
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
        self.loss_override_bits.store(rate.unwrap_or(f64::NAN).to_bits(), Ordering::Relaxed);
    }
    /// Add extra per-frame delay (congestion).
    pub fn set_extra_delay(&self, extra: Duration) {
        self.extra_delay_ns.store(extra.as_nanos() as u64, Ordering::Relaxed);
    }
    /// Install (or clear) a targeted [`HoldRule`] — delay matching frames without dropping
    /// them. Replaces any prior rule; the match counter restarts.
    pub fn set_hold(&self, rule: Option<HoldRule>) {
        *self.hold.lock().unwrap() =
            rule.map(|rule| HoldActive { rule, matched: 0, held: 0 });
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
        let mut guard = self.hold.lock().unwrap();
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

/// A simulated face. Created in pairs by [`SimLink`](crate::SimLink); backed by Tokio MPSC with
/// link emulation on send, and typed by a [`FaceProfile`](crate::FaceProfile).
pub struct SimFace {
    id: FaceId,
    tx: mpsc::Sender<Bytes>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    config: LinkConfig,
    /// Face-type behavior (what the engine sees + delivery semantics).
    kind: FaceKind,
    link_type: LinkType,
    send_mtu: Option<usize>,
    /// Reliable streams (TCP/QUIC/WS/SHM): no loss, in-order delivery.
    reliable: bool,
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
        tx: mpsc::Sender<Bytes>,
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
            tx,
            rx: tokio::sync::Mutex::new(rx),
            config: profile.link.clone(),
            kind: profile.kind,
            link_type: profile.link_type,
            send_mtu: profile.send_mtu,
            reliable: profile.reliable,
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
    pub(crate) fn link_state(&self) -> Arc<LinkState> {
        Arc::clone(&self.state)
    }

    /// Install a name-aware per-prefix tap on this face (the fabric does this at link-build time
    /// when prefix accounting is enabled). Consumes + returns the face so it can be set before the
    /// face moves into an engine.
    pub(crate) fn with_prefix_tap(mut self, tap: crate::netstat::PrefixTap) -> Self {
        self.prefix_tap = Some(tap);
        self
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

    fn remote_uri(&self) -> Option<String> {
        Some(format!("sim-{}://face#{}", self.kind, self.id.0))
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

        // Datagram loss (reliable streams never drop) — a runtime Fault::DegradeLink can override the
        // profile's rate.
        let loss_rate = self.state.loss_override().unwrap_or(self.config.loss_rate);
        if hold.is_none() && !self.reliable && loss_rate > 0.0 {
            let roll: f64 = self.rng.lock().unwrap().random();
            if roll < loss_rate {
                trace!(face = %self.id, "SimFace: packet dropped (loss)");
                return Ok(());
            }
        }

        let now = self.runtime.now();

        // Bandwidth shaping: serialize transmit start through a cursor (bandwidth 0 = no shaping).
        #[allow(clippy::manual_checked_ops)]
        let tx_start = if self.config.bandwidth_bps > 0 {
            let pkt_bits = (pkt.len() as u64) * 8;
            let tx_duration =
                Duration::from_nanos(pkt_bits * 1_000_000_000 / self.config.bandwidth_bps);
            let mut next = self.next_tx_ready.lock().unwrap();
            if *next < now {
                *next = now;
            }
            let start = *next;
            *next = start + tx_duration;
            start
        } else {
            now
        };

        // Reliable streams add no reordering jitter; datagrams may reorder.
        let jitter = if self.reliable {
            Duration::ZERO
        } else {
            self.jitter()
        };
        let mut deliver_at =
            tx_start + self.config.delay + jitter + self.state.extra_delay() + hold.unwrap_or_default();

        // Reliable: never deliver before the previous packet (in-order, HOL-style).
        if self.reliable {
            let mut last = self.last_delivery.lock().unwrap();
            if deliver_at <= *last {
                deliver_at = *last + Duration::from_nanos(1);
            }
            *last = deliver_at;
        }

        let wait = deliver_at.saturating_duration_since(now);
        if wait.is_zero() {
            self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
        } else {
            // Delayed delivery on the runtime seam (virtual under the virtual/DES kernels).
            let tx = self.tx.clone();
            let face_id = self.id;
            let rt = Arc::clone(&self.runtime);
            self.runtime.spawn(Box::pin(async move {
                rt.sleep(wait).await;
                if tx.send(pkt).await.is_err() {
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
        let nanos = self
            .rng
            .lock()
            .unwrap()
            .random_range(0..=max.as_nanos() as u64);
        Duration::from_nanos(nanos)
    }
}
