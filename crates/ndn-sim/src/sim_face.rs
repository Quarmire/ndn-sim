//! `SimFace` — one endpoint of a [`SimLink`](crate::SimLink). The send path applies delay,
//! jitter, loss, and bandwidth shaping before delivery, and presents the **per-face-type
//! behavior** of its [`FaceProfile`](crate::FaceProfile): the engine sees the right `FaceKind`,
//! `LinkType`, and `send_mtu`, and either datagram semantics (loss + jitter-reorder) or
//! reliable-stream semantics (no loss, in-order) — so a scenario can express "this is UDP" vs
//! "this is TCP/QUIC" and the forwarder behaves accordingly.

use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use ndn_transport::{FaceError, FaceId, FaceKind, LinkType, Transport};
use rand::{Rng, SeedableRng, rngs::StdRng};
use tokio::sync::mpsc;
use tracing::trace;

use crate::sim_link::{FaceProfile, LinkConfig};

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
    next_tx_ready: Mutex<tokio::time::Instant>,
    /// Monotonic delivery cursor for reliable faces — guarantees in-order arrival despite
    /// per-packet scheduling.
    last_delivery: Mutex<tokio::time::Instant>,
    /// **Seeded** PRNG for loss/jitter rolls — reproducible (never `thread_rng`).
    rng: Mutex<StdRng>,
}

impl SimFace {
    pub(crate) fn new(
        id: FaceId,
        tx: mpsc::Sender<Bytes>,
        rx: mpsc::Receiver<Bytes>,
        profile: &FaceProfile,
    ) -> Self {
        let now = tokio::time::Instant::now();
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
            rng: Mutex::new(StdRng::seed_from_u64(mix_seed(id.0))),
        }
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
        // Datagram loss (reliable streams never drop).
        if !self.reliable && self.config.loss_rate > 0.0 {
            let roll: f64 = self.rng.lock().unwrap().random();
            if roll < self.config.loss_rate {
                trace!(face = %self.id, "SimFace: packet dropped (loss)");
                return Ok(());
            }
        }

        let now = tokio::time::Instant::now();

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
        let jitter = if self.reliable { Duration::ZERO } else { self.jitter() };
        let mut deliver_at = tx_start + self.config.delay + jitter;

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
            let tx = self.tx.clone();
            let face_id = self.id;
            tokio::spawn(async move {
                tokio::time::sleep(wait).await;
                if tx.send(pkt).await.is_err() {
                    trace!(face = %face_id, "SimFace: remote end closed during delayed delivery");
                }
            });
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
        let nanos = self.rng.lock().unwrap().random_range(0..=max.as_nanos() as u64);
        Duration::from_nanos(nanos)
    }
}
