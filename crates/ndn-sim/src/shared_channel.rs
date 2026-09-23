//! `SharedChannel` — one contended medium that several point-to-point links transmit on.
//!
//! Managed Wi-Fi gives every fleet forwarder one UDP unicast face per peer, but all of those
//! faces ride ONE radio channel: a frame on gcs→iuas-01 occupies the air iuas-02→wuas-01 needs.
//! A dedicated [`SimLink`](crate::SimLink) per pair, each with its own bandwidth cursor, lets a
//! video burst on one peer link cost the others nothing — so the sim could never show the
//! fleet's defining failure shape, where extra wire copies of one flow (Round 15 of
//! `nfd-divergence-findings.md`: 35% more packets on the medium) starve every other flow.
//!
//! Member links keep their own delay/jitter/loss; the channel only **serialises their
//! transmissions by airtime**: a frame starts when the medium is free, holds it for
//! `frames × frame_overhead + on-air bytes × 8 / rate`, and is delivered after it finishes.
//! A frame that is then lost still spent its airtime (the transmitter cannot know).
//!
//! This is a LOGICAL model, not a calibrated 802.11 MAC: no carrier-sense collisions, no rate
//! adaptation, no per-station fairness — one FIFO transmit queue for the whole channel, with a
//! bounded backlog so overload tail-drops instead of queueing forever. Its job is the first-order
//! effect (load on one link delays the others), not absolute throughput numbers.
//!
//! Deterministic under the virtual/DES kernels: reservations happen in `send_bytes` call order on
//! a single-threaded executor, reading the kernel clock.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ndn_runtime::Instant;

/// A shared, airtime-serialised medium. Build one with [`new`](Self::new) (or the
/// [`wifi`](Self::wifi) preset), then put links on it with
/// [`FaceProfile::on_channel`](crate::FaceProfile::on_channel) /
/// [`Simulation::link_on_channel`](crate::Simulation::link_on_channel).
#[derive(Debug)]
pub struct SharedChannel {
    name: String,
    rate_bps: u64,
    frame_overhead: Duration,
    max_backlog: Duration,
    /// When the medium is next free; `None` until the first frame (the channel is built before
    /// the kernel clock it will read exists).
    busy_until: Mutex<Option<Instant>>,
    frames: AtomicU64,
    airtime_ns: AtomicU64,
    tail_drops: AtomicU64,
}

/// Counters a scenario can read to see how loaded the medium was.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChannelStats {
    /// Radio frames carried (an IP-fragmented datagram is several).
    pub frames: u64,
    /// Total airtime consumed, in nanoseconds.
    pub airtime_ns: u64,
    /// Datagrams refused because the transmit backlog exceeded `max_backlog`.
    pub tail_drops: u64,
}

impl SharedChannel {
    /// A channel of `rate_bps` effective PHY rate where every frame also pays `frame_overhead`
    /// (MAC contention + preamble + ACK). Backlog defaults to 200 ms before tail-drop.
    pub fn new(name: impl Into<String>, rate_bps: u64, frame_overhead: Duration) -> Self {
        assert!(rate_bps > 0, "a shared channel needs a positive rate");
        Self {
            name: name.into(),
            rate_bps,
            frame_overhead,
            max_backlog: Duration::from_millis(200),
            busy_until: Mutex::new(None),
            frames: AtomicU64::new(0),
            airtime_ns: AtomicU64::new(0),
            tail_drops: AtomicU64::new(0),
        }
    }

    /// A managed Wi-Fi cell: 24 Mbit/s effective with ~150 µs per-frame overhead (DIFS + mean
    /// backoff + preamble + SIFS + ACK at 802.11g/n basic rates). Representative, not measured.
    pub fn wifi(name: impl Into<String>) -> Self {
        Self::new(name, 24_000_000, Duration::from_micros(150))
    }

    /// Override how much queued airtime the channel holds before it tail-drops new datagrams.
    pub fn with_max_backlog(mut self, max_backlog: Duration) -> Self {
        self.max_backlog = max_backlog;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn stats(&self) -> ChannelStats {
        ChannelStats {
            frames: self.frames.load(Ordering::Relaxed),
            airtime_ns: self.airtime_ns.load(Ordering::Relaxed),
            tail_drops: self.tail_drops.load(Ordering::Relaxed),
        }
    }

    /// Airtime of `frames` radio frames carrying `bytes` on-air bytes in total.
    pub fn airtime(&self, frames: usize, bytes: usize) -> Duration {
        let serialisation = (bytes as u64) * 8 * 1_000_000_000 / self.rate_bps;
        self.frame_overhead * frames as u32 + Duration::from_nanos(serialisation)
    }

    /// Claim the medium for one datagram at `now`: returns when its last frame finishes, or
    /// `None` if the backlog is full (tail-drop — the frame never reaches the air).
    pub(crate) fn transmit(&self, now: Instant, frames: usize, bytes: usize) -> Option<Instant> {
        let airtime = self.airtime(frames, bytes);
        let mut busy = self.busy_until.lock();
        let start = match *busy {
            Some(t) if t > now => t,
            _ => now,
        };
        if start.saturating_duration_since(now) > self.max_backlog {
            self.tail_drops.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let end = start + airtime;
        *busy = Some(end);
        self.frames.fetch_add(frames as u64, Ordering::Relaxed);
        self.airtime_ns
            .fetch_add(airtime.as_nanos() as u64, Ordering::Relaxed);
        Some(end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transmissions_serialise_and_backlog_tail_drops() {
        let ch = SharedChannel::new("t", 8_000_000, Duration::from_micros(100))
            .with_max_backlog(Duration::from_millis(2));
        let t0 = Instant::now();
        // 1000 B at 8 Mbit/s = 1 ms + 100 µs overhead.
        let a = ch.transmit(t0, 1, 1000).unwrap();
        assert_eq!(a - t0, Duration::from_micros(1100));
        // A second frame offered at the same instant waits 1.1 ms (within the 2 ms backlog).
        let b = ch.transmit(t0, 1, 1000).unwrap();
        assert_eq!(b - t0, Duration::from_micros(2200));
        // A third would wait 2.2 ms > 2 ms: refused, and it consumes no airtime.
        assert!(ch.transmit(t0, 1, 1000).is_none());
        assert_eq!(ch.stats().frames, 2);
        assert_eq!(ch.stats().tail_drops, 1);
    }
}
