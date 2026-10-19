//! The **802.11 airtime model** the named-radio face charges — the MAC discipline
//! ([`WifiMode`]) and the textbook 802.11n timing that turns a frame into on-air time:
//!
//! - **Monitor / injection mode** (what *named-data radio* uses): a single broadcast at a
//!   radiotap-specified rate, **no ACK, no retransmission, no per-link rate adaptation**. One
//!   transmission reaches every in-range receiver (multicast-native) — [`broadcast_airtime`].
//! - **Managed unicast** (normal Wi-Fi — IBSS / AP / mesh data frames): EDCA contention + a
//!   link-layer **ACK** (Block-ACK when aggregating) per attempt — [`unicast_airtime`] /
//!   [`managed_unicast_attempt_airtime`]. Reliable per link, but to reach N peers you transmit N
//!   times.
//!
//! [`RadioBus`](crate::RadioBus) uses these to size every frame's collision / half-duplex window
//! ([`frame_airtime`]) and to account monitor-vs-managed airtime. It is *logically* faithful, not
//! calibrated: A-MPDU, Block-ACK and EDCA are reduced to their airtime relationships. The
//! statistical MAC (rate control, retry loop, AP/mesh operating modes) that drives the IP plane lives
//! in the `ndn-sim-studies` crate.
//!
//! ## Timing (802.11n, 20 MHz, textbook constants)
//! Slot 9 µs, SIFS 16 µs, DIFS 34 µs, HT preamble ≈ 36 µs, ACK ≈ 44 µs, CWmin 15.

use std::time::Duration;

use crate::link_model::mcs_phy_rate_bps;

// 802.11n 20 MHz MAC/PHY timing (microseconds).
const SLOT_US: f64 = 9.0;
const SIFS_US: f64 = 16.0;
const DIFS_US: f64 = 34.0;
const HT_PREAMBLE_US: f64 = 36.0;
const ACK_US: f64 = 44.0;
/// A Block-ACK (acknowledges a whole A-MPDU) is a little larger than a normal ACK.
const BLOCK_ACK_US: f64 = 68.0;
const CW_MIN: f64 = 15.0;
/// MAC header + FCS carried with every data frame.
const MAC_OVERHEAD_BYTES: usize = 34;
/// The A-MPDU sub-frame delimiter prepended to each aggregated MPDU.
const MPDU_DELIMITER_BYTES: usize = 4;

/// The **MAC discipline** — raw monitor-mode injection vs a normal Wi-Fi MAC. This is the crux of the
/// named-data-radio vs normal-Wi-Fi comparison: *how a frame is sent* (monitor broadcast vs managed
/// CSMA-CA/ACK), set per medium with [`RadioBus::set_mac_mode`](crate::RadioBus::set_mac_mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiMode {
    /// Raw monitor-mode injection: every frame is a broadcast at a radiotap-chosen rate, with **no
    /// MAC** — no ACK, no retransmission, no rate adaptation, and **no beacons**. Named-data radio.
    Monitor,
    /// Normal Wi-Fi (IBSS / AP / mesh): unicast gets CSMA-CA + ACK + retransmission + rate adaptation
    /// (and A-MPDU aggregation); **multicast/broadcast goes at the basic rate with no ACK**; and the
    /// mode emits periodic **beacons**.
    Managed,
}

/// EDCA access categories — QoS contention parameters (higher priority ⇒ shorter AIFS + smaller
/// contention window ⇒ less airtime waiting). Values are the 802.11 defaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AccessCategory {
    Background,
    #[default]
    BestEffort,
    Video,
    Voice,
}

impl AccessCategory {
    /// AIFS number (slots after SIFS before contention) — lower is higher priority.
    fn aifsn(self) -> f64 {
        match self {
            AccessCategory::Background => 7.0,
            AccessCategory::BestEffort => 3.0,
            AccessCategory::Video => 2.0,
            AccessCategory::Voice => 2.0,
        }
    }
    /// Minimum contention window.
    fn cw_min(self) -> f64 {
        match self {
            AccessCategory::Background | AccessCategory::BestEffort => 15.0,
            AccessCategory::Video => 7.0,
            AccessCategory::Voice => 3.0,
        }
    }
    fn aifs_us(self) -> f64 {
        SIFS_US + self.aifsn() * SLOT_US
    }
    fn backoff_us(self) -> f64 {
        self.cw_min() / 2.0 * SLOT_US
    }
}

fn us(x: f64) -> Duration {
    Duration::from_nanos((x * 1_000.0).max(0.0) as u64)
}

fn avg_backoff_us() -> f64 {
    CW_MIN / 2.0 * SLOT_US
}

/// Airtime to put one `bytes`-payload data frame on the air at `mcs` (HT preamble + framed payload).
pub fn frame_airtime(bytes: usize, mcs: u8) -> Duration {
    let rate = mcs_phy_rate_bps(mcs).max(1) as f64; // bits/sec
    let payload_bits = ((bytes + MAC_OVERHEAD_BYTES) * 8) as f64;
    us(HT_PREAMBLE_US + payload_bits / rate * 1e6)
}

/// Total airtime a broadcast (monitor) frame occupies: contention + the frame (no ACK).
pub fn broadcast_airtime(bytes: usize, mcs: u8) -> Duration {
    us(DIFS_US + avg_backoff_us()) + frame_airtime(bytes, mcs)
}

/// Airtime of one A-MPDU on the air: one HT preamble amortised over `n_agg` sub-frames (each with a
/// delimiter + MAC framing). Aggregation is the big managed-mode throughput lever for bulk.
fn ampdu_airtime(subframe_bytes: usize, n_agg: u32, mcs: u8) -> Duration {
    let rate = mcs_phy_rate_bps(mcs).max(1) as f64;
    let per_sub_bits = ((subframe_bytes + MAC_OVERHEAD_BYTES + MPDU_DELIMITER_BYTES) * 8) as f64;
    us(HT_PREAMBLE_US + n_agg.max(1) as f64 * per_sub_bits / rate * 1e6)
}

/// Airtime one managed unicast (best-effort, no aggregation) occupies — frame + SIFS + ACK +
/// contention. The per-neighbour cost when a broadcast is replaced by unicasts.
pub fn unicast_airtime(bytes: usize, mcs: u8) -> Duration {
    managed_unicast_attempt_airtime(bytes, 1, mcs, AccessCategory::BestEffort)
}

/// Airtime one managed unicast attempt occupies: EDCA contention (per access category) + the
/// (possibly aggregated, `n_agg` sub-frames) frame + SIFS + ACK (or Block-ACK for an A-MPDU). Public
/// so a statistical MAC built on top (the studies crate's retry loop) charges exactly the airtime the
/// radio face does.
pub fn managed_unicast_attempt_airtime(
    bytes: usize,
    n_agg: u32,
    mcs: u8,
    ac: AccessCategory,
) -> Duration {
    let ack = if n_agg > 1 { BLOCK_ACK_US } else { ACK_US };
    us(ac.aifs_us() + ac.backoff_us() + SIFS_US + ack) + ampdu_airtime(bytes, n_agg, mcs)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A-MPDU aggregation amortises the PHY preamble across sub-frames, so airtime-per-frame drops as
    /// the aggregate grows — the managed-mode throughput lever for bulk.
    #[test]
    fn aggregation_amortizes_the_preamble() {
        let per_frame_1 = managed_unicast_attempt_airtime(1500, 1, 7, AccessCategory::BestEffort);
        let agg = managed_unicast_attempt_airtime(1500, 16, 7, AccessCategory::BestEffort);
        let per_frame_16 = agg / 16;
        assert!(
            per_frame_16 < per_frame_1,
            "16-frame A-MPDU is cheaper per frame ({per_frame_16:?} < {per_frame_1:?})"
        );
    }

    /// EDCA prioritises: a Voice frame contends less (shorter AIFS + CW) than a Background frame.
    #[test]
    fn edca_voice_beats_background() {
        let voice = managed_unicast_attempt_airtime(200, 1, 4, AccessCategory::Voice);
        let background = managed_unicast_attempt_airtime(200, 1, 4, AccessCategory::Background);
        assert!(
            voice < background,
            "voice AC waits less than background ({voice:?} < {background:?})"
        );
    }

    /// …but a successful unicast costs more airtime than a monitor broadcast (ACK + contention).
    #[test]
    fn unicast_costs_more_airtime_than_monitor() {
        assert!(
            unicast_airtime(200, 4) > broadcast_airtime(200, 4),
            "unicast attempt (frame+SIFS+ACK) > broadcast (frame only)"
        );
    }

    /// The multicast advantage: one monitor broadcast reaches N receivers in a single airtime, while
    /// unicasting the same frame to N peers costs ~N times as much — the crux of named-data radio.
    #[test]
    fn broadcast_serves_many_in_one_airtime() {
        let bytes = 500;
        let mcs = 4;
        let one_broadcast = broadcast_airtime(bytes, mcs);
        let n = 5;
        let n_unicasts: Duration = (0..n).map(|_| unicast_airtime(bytes, mcs)).sum();
        assert!(
            n_unicasts > one_broadcast * 4,
            "delivering to {n} peers: {n} unicasts ({n_unicasts:?}) ≫ one broadcast ({one_broadcast:?})"
        );
    }
}
