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
}

impl LinkState {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            down: AtomicBool::new(false),
            loss_override_bits: AtomicU64::new(f64::NAN.to_bits()),
            extra_delay_ns: AtomicU64::new(0),
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
    /// Restore the link to its profile defaults (up, no override, no extra delay).
    pub fn reset(&self) {
        self.set_down(false);
        self.set_loss(None);
        self.set_extra_delay(Duration::ZERO);
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
        }
    }

    /// The live fault knobs for this face — the fabric holds a clone so a runtime `Fault` can cut
    /// or degrade the link.
    pub(crate) fn link_state(&self) -> Arc<LinkState> {
        Arc::clone(&self.state)
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
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        // A partitioned / downed link drops everything (a runtime Fault::Partition or a down link).
        if self.state.is_down() {
            trace!(face = %self.id, "SimFace: packet dropped (link down)");
            return Ok(());
        }
        // Datagram loss (reliable streams never drop) — a runtime Fault::DegradeLink can override the
        // profile's rate.
        let loss_rate = self.state.loss_override().unwrap_or(self.config.loss_rate);
        if !self.reliable && loss_rate > 0.0 {
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
        let mut deliver_at = tx_start + self.config.delay + jitter + self.state.extra_delay();

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
