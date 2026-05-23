//! `SimFace` — one endpoint of a [`SimLink`](crate::SimLink). The send path
//! applies delay, jitter, loss, and bandwidth shaping before delivery.

use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use ndn_transport::{FaceError, FaceId, FaceKind, Transport};
use rand::Rng;
use tokio::sync::mpsc;
use tracing::trace;

use crate::sim_link::LinkConfig;

/// A simulated face. Created in pairs by [`SimLink::pair`](crate::SimLink::pair);
/// backed by Tokio MPSC with link emulation on send.
pub struct SimFace {
    id: FaceId,
    tx: mpsc::Sender<Bytes>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    config: LinkConfig,
    /// Bandwidth shaping cursor: earliest time the next byte can transmit.
    next_tx_ready: Mutex<tokio::time::Instant>,
}

impl SimFace {
    pub(crate) fn new(
        id: FaceId,
        tx: mpsc::Sender<Bytes>,
        rx: mpsc::Receiver<Bytes>,
        config: LinkConfig,
    ) -> Self {
        Self {
            id,
            tx,
            rx: tokio::sync::Mutex::new(rx),
            config,
            next_tx_ready: Mutex::new(tokio::time::Instant::now()),
        }
    }
}

impl Transport for SimFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Internal
    }

    fn remote_uri(&self) -> Option<String> {
        Some(format!("sim://face#{}", self.id.0))
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.rx.lock().await.recv().await.ok_or(FaceError::Closed)
    }

    async fn send_bytes(&self, pkt: Bytes) -> Result<(), FaceError> {
        if self.config.loss_rate > 0.0 {
            let roll: f64 = rand::rng().random();
            if roll < self.config.loss_rate {
                trace!(face = %self.id, "SimFace: packet dropped (loss)");
                return Ok(());
            }
        }

        // bandwidth_bps == 0 means "no shaping," not a divide-by-zero. The
        // branch also serialises the `next_tx_ready` cursor under a lock, so
        // a `checked_div` rewrite would change behaviour.
        #[allow(clippy::manual_checked_ops)]
        let deliver_delay = if self.config.bandwidth_bps > 0 {
            let pkt_bits = (pkt.len() as u64) * 8;
            let tx_duration =
                Duration::from_nanos(pkt_bits * 1_000_000_000 / self.config.bandwidth_bps);

            let now = tokio::time::Instant::now();
            let tx_start = {
                let mut next = self.next_tx_ready.lock().unwrap();
                if *next < now {
                    *next = now;
                }
                let start = *next;
                *next = start + tx_duration;
                start
            };

            // Arrival = tx_start + propagation_delay + jitter.
            let wait_for_tx = tx_start.saturating_duration_since(now);
            wait_for_tx + self.config.delay + random_jitter(self.config.jitter)
        } else {
            self.config.delay + random_jitter(self.config.jitter)
        };

        if deliver_delay.is_zero() {
            self.tx.send(pkt).await.map_err(|_| FaceError::Closed)
        } else {
            // Background task so send() returns immediately.
            let tx = self.tx.clone();
            let face_id = self.id;
            tokio::spawn(async move {
                tokio::time::sleep(deliver_delay).await;
                if tx.send(pkt).await.is_err() {
                    trace!(face = %face_id, "SimFace: remote end closed during delayed delivery");
                }
            });
            Ok(())
        }
    }
}

fn random_jitter(max_jitter: Duration) -> Duration {
    if max_jitter.is_zero() {
        return Duration::ZERO;
    }
    let nanos = rand::rng().random_range(0..=max_jitter.as_nanos() as u64);
    Duration::from_nanos(nanos)
}
