//! A **faithful-enough 802.11 MAC model** on top of the [`LinkModel`](crate::link_model::LinkModel)
//! PHY (RSSI/SNR → MCS → per-frame delivery). The PHY says *whether a frame at a rate is decoded*;
//! this layer models what the MAC does with that — and it's where the comparison the whole radio
//! story is about actually lives:
//!
//! - **Monitor / injection mode** (what *named-data radio* uses): a single broadcast at a
//!   radiotap-specified rate, **no ACK, no retransmission, no per-link rate adaptation**. One
//!   transmission reaches every in-range receiver (multicast-native), but there is no per-link
//!   reliability — a lost frame is just lost.
//! - **Managed unicast** (normal Wi-Fi — IBSS / AP / mesh data frames): CSMA-CA + a link-layer
//!   **ACK** and **retransmission** up to a retry limit, with **rate adaptation** (a Minstrel-HT-style
//!   controller picking the MCS that maximises expected throughput from per-link success history).
//!   Reliable per link, but it costs airtime (retries + ACK + contention) and it is *unicast* — to
//!   reach N peers you transmit N times.
//!
//! That tension — monitor's multicast efficiency vs unicast's per-link reliability + rate control —
//! is exactly the "NDN over monitor mode vs NDN/IP over normal Wi-Fi" question. This module makes it
//! measurable (delivery, retries, airtime, effective rate). It is *logically* faithful, not
//! calibrated: real Minstrel-HT, EDCA, aggregation (A-MPDU), and block-ACK are deliberately abstracted
//! (see the roadmap in the crate docs), but the relationships — retries raise delivery, higher MCS is
//! cheaper airtime but needs more SNR, rate control tracks the channel — are modelled.
//!
//! ## Timing (802.11n, 20 MHz, textbook constants)
//! Slot 9 µs, SIFS 16 µs, DIFS 34 µs, HT preamble ≈ 36 µs, ACK ≈ 44 µs, CWmin 15.

use std::collections::HashMap;
use std::time::Duration;

use rand::Rng;
use rand::rngs::StdRng;

use crate::link_model::{LinkModel, MAX_RELIABLE_MCS, mcs_phy_rate_bps};

// 802.11n 20 MHz MAC/PHY timing (microseconds).
const SLOT_US: f64 = 9.0;
const SIFS_US: f64 = 16.0;
const DIFS_US: f64 = 34.0;
const HT_PREAMBLE_US: f64 = 36.0;
const ACK_US: f64 = 44.0;
const CW_MIN: f64 = 15.0;
/// MAC header + FCS carried with every data frame.
const MAC_OVERHEAD_BYTES: usize = 34;

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

/// Airtime one unicast attempt occupies: contention + frame + SIFS + ACK.
fn unicast_attempt_airtime(bytes: usize, mcs: u8) -> Duration {
    us(DIFS_US + avg_backoff_us() + SIFS_US + ACK_US) + frame_airtime(bytes, mcs)
}

/// The outcome of a modelled transmission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxOutcome {
    /// Whether the frame was delivered (any attempt decoded, and its ACK returned for unicast).
    pub delivered: bool,
    /// Transmission attempts made (1 for monitor; 1..=retry_limit+1 for unicast).
    pub attempts: u32,
    /// Total airtime consumed on the medium.
    pub airtime: Duration,
    /// The MCS used on the final attempt.
    pub mcs: u8,
}

/// A per-link rate controller — picks the MCS for a transmission and learns from the outcome.
pub trait RateControl {
    /// The MCS to send to `peer` at the current `snr_db` (the PHY prior is available via `link`).
    fn select(&mut self, peer: usize, snr_db: f64, link: &LinkModel) -> u8;
    /// Feed back whether the attempt at `mcs` to `peer` succeeded.
    fn feedback(&mut self, peer: usize, mcs: u8, success: bool);
}

/// A fixed rate — no adaptation (a monitor-mode radiotap rate, or a pinned unicast MCS).
#[derive(Clone, Copy, Debug)]
pub struct FixedRate(pub u8);

impl RateControl for FixedRate {
    fn select(&mut self, _peer: usize, _snr_db: f64, _link: &LinkModel) -> u8 {
        self.0.min(MAX_RELIABLE_MCS)
    }
    fn feedback(&mut self, _peer: usize, _mcs: u8, _success: bool) {}
}

const NUM_MCS: usize = (MAX_RELIABLE_MCS + 1) as usize;

/// A **Minstrel-HT-style** rate controller: per-link EWMA of each MCS's success probability, and it
/// picks the MCS maximising expected throughput `rate(mcs) × success(mcs)`. Seeded from the PHY at
/// the observed SNR, then adapted from real feedback (as Minstrel does from its retry statistics).
#[derive(Clone, Debug, Default)]
pub struct MinstrelHt {
    ewma: HashMap<usize, [f64; NUM_MCS]>,
}

impl MinstrelHt {
    pub fn new() -> Self {
        Self::default()
    }

    fn table(&mut self, peer: usize, snr_db: f64, link: &LinkModel) -> &mut [f64; NUM_MCS] {
        self.ewma.entry(peer).or_insert_with(|| {
            let mut t = [0.0; NUM_MCS];
            for (mcs, slot) in t.iter_mut().enumerate() {
                *slot = link.frame_delivery(mcs as u8, snr_db);
            }
            t
        })
    }
}

impl RateControl for MinstrelHt {
    fn select(&mut self, peer: usize, snr_db: f64, link: &LinkModel) -> u8 {
        let t = self.table(peer, snr_db, link);
        (0..NUM_MCS)
            .map(|m| (m as u8, mcs_phy_rate_bps(m as u8) as f64 * t[m]))
            .max_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(m, _)| m)
            .unwrap_or(0)
    }
    fn feedback(&mut self, peer: usize, mcs: u8, success: bool) {
        if let Some(t) = self.ewma.get_mut(&peer) {
            let slot = &mut t[(mcs as usize).min(NUM_MCS - 1)];
            const ALPHA: f64 = 0.25; // EWMA weight on the newest sample
            *slot = ALPHA * f64::from(success) + (1.0 - ALPHA) * *slot;
        }
    }
}

/// The 802.11 MAC transmit model over a [`LinkModel`] PHY.
#[derive(Clone, Copy, Debug, Default)]
pub struct Wifi {
    pub link: LinkModel,
}

impl Wifi {
    pub fn new() -> Self {
        Self { link: LinkModel::new() }
    }

    /// **Monitor / injection** transmit: one broadcast at `mcs`, no ACK, no retry. Delivered iff the
    /// PHY decodes it at the receiver's `snr_db`. This is the named-data-radio transmission.
    pub fn monitor_tx(&self, snr_db: f64, bytes: usize, mcs: u8, rng: &mut StdRng) -> TxOutcome {
        let p = self.link.frame_delivery(mcs, snr_db);
        TxOutcome {
            delivered: rng.random::<f64>() < p,
            attempts: 1,
            airtime: broadcast_airtime(bytes, mcs),
            mcs,
        }
    }

    /// **Managed unicast** transmit to `peer`: CSMA-CA + ACK + retransmit up to `retry_limit` times,
    /// with the MCS chosen (and learned) by `rc`. Airtime accumulates every attempt.
    pub fn unicast_tx(
        &self,
        peer: usize,
        snr_db: f64,
        bytes: usize,
        rc: &mut dyn RateControl,
        retry_limit: u32,
        rng: &mut StdRng,
    ) -> TxOutcome {
        let mut airtime = Duration::ZERO;
        let mut attempts = 0;
        let mut delivered = false;
        let mut last_mcs = 0;
        for _ in 0..=retry_limit {
            let mcs = rc.select(peer, snr_db, &self.link);
            last_mcs = mcs;
            attempts += 1;
            airtime += unicast_attempt_airtime(bytes, mcs);
            let ok = rng.random::<f64>() < self.link.frame_delivery(mcs, snr_db);
            rc.feedback(peer, mcs, ok);
            if ok {
                delivered = true;
                break;
            }
        }
        TxOutcome { delivered, attempts, airtime, mcs: last_mcs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0xF00D)
    }

    /// At a marginal SNR, unicast retransmission delivers far more often than a single monitor shot.
    #[test]
    fn unicast_retries_beat_monitor_at_marginal_snr() {
        let wifi = Wifi::new();
        let snr = 10.0; // ~MCS2 threshold ⇒ ~50% single-frame delivery there
        let (mut r1, mut r2) = (rng(), rng());
        let mut rc = FixedRate(2);
        let (mut mono, mut uni) = (0u32, 0u32);
        for _ in 0..2000 {
            if wifi.monitor_tx(snr, 200, 2, &mut r1).delivered {
                mono += 1;
            }
            if wifi.unicast_tx(0, snr, 200, &mut rc, 4, &mut r2).delivered {
                uni += 1;
            }
        }
        assert!(uni > mono + 300, "ACK+retry raises delivery (uni {uni} vs mono {mono})");
    }

    /// …but a successful unicast costs more airtime than a monitor broadcast (ACK + contention).
    #[test]
    fn unicast_costs_more_airtime_than_monitor() {
        assert!(
            unicast_attempt_airtime(200, 4) > broadcast_airtime(200, 4),
            "unicast attempt (frame+SIFS+ACK) > broadcast (frame only)"
        );
    }

    /// Minstrel picks a conservative MCS on a weak link and an aggressive one on a strong link, and
    /// its throughput-max choice beats pinning the top rate on a weak link.
    #[test]
    fn minstrel_adapts_rate_to_link_quality() {
        let wifi = Wifi::new();
        let mut m = MinstrelHt::new();
        let low = m.select(0, 8.0, &wifi.link); // weak link (fresh peer 0)
        let high = m.select(1, 40.0, &wifi.link); // strong link (fresh peer 1)
        assert!(low < high, "conservative on weak SNR, aggressive on strong ({low} < {high})");
        assert_eq!(high, MAX_RELIABLE_MCS, "very strong link uses the top rate");
    }

    /// The multicast advantage: one monitor broadcast reaches N receivers in a single airtime, while
    /// unicasting the same frame to N peers costs ~N times as much — the crux of named-data radio.
    #[test]
    fn broadcast_serves_many_in_one_airtime() {
        let bytes = 500;
        let mcs = 4;
        let one_broadcast = broadcast_airtime(bytes, mcs);
        let n = 5;
        let n_unicasts: Duration = (0..n).map(|_| unicast_attempt_airtime(bytes, mcs)).sum();
        assert!(
            n_unicasts > one_broadcast * 4,
            "delivering to {n} peers: {n} unicasts ({n_unicasts:?}) ≫ one broadcast ({one_broadcast:?})"
        );
    }
}
