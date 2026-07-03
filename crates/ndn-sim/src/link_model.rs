//! [`LinkModel`] (ndn-lab slice 4): the **logical** 802.11n link — the RSSI/SNR → MCS →
//! per-frame delivery-probability relationship that the named-radio sim face draws against.
//!
//! The design note assumed a `measure::LinkModel` already existed in ndn-rs; it does not, so
//! this authors it here, on top of the *real* primitives that do exist in
//! [`ndn_frame_io`]: the single-stream 20 MHz MCS rate table ([`mcs_phy_rate_bps`]), the
//! RSSI→MCS heuristic ([`mcs_for_rssi`]), and the verified rate ceiling
//! ([`MAX_RELIABLE_MCS`]). The model is **deterministic pure math** — the *randomness* (the
//! per-frame erasure draw) lives in the radio bus, not here.
//!
//! "Logically correct, not physically perfect": the goal is the right *relationships* —
//! delivery rises with SNR, falls as you push to a higher MCS at fixed SNR, and the best
//! sustainable MCS climbs as a peer approaches — not calibrated PER curves. Those
//! monotonicities are what the tests assert.

pub use ndn_frame_io::{MAX_RELIABLE_MCS, mcs_for_rssi, mcs_phy_rate_bps};

/// Receiver noise floor, dBm. `snr = rssi − noise_floor`.
pub const NOISE_FLOOR_DBM: f64 = -95.0;

/// Per-MCS SNR (dB) at which delivery is ~50% — textbook 802.11n single-stream 20 MHz
/// demodulation thresholds (BPSK½ … 64-QAM ⅚), monotonically increasing with MCS.
const REQUIRED_SNR_DB: [f64; 8] = [5.0, 8.0, 10.0, 13.0, 17.0, 21.0, 23.0, 25.0];

/// The logical link: maps `(mcs, snr)` to a delivery probability and picks the best MCS for
/// an SNR. Construct with [`LinkModel::new`].
#[derive(Clone, Copy, Debug)]
pub struct LinkModel {
    /// Width (dB) of the soft transition around each MCS threshold. Smaller ⇒ sharper cliff.
    spread_db: f64,
    /// SNR margin (dB) required above the 50% threshold for [`best_mcs`](Self::best_mcs) to
    /// select an MCS (targets the high-reliability shoulder of the curve).
    select_margin_db: f64,
}

impl Default for LinkModel {
    fn default() -> Self {
        Self::new()
    }
}

impl LinkModel {
    pub fn new() -> Self {
        Self {
            spread_db: 2.0,
            select_margin_db: 4.0,
        }
    }

    /// SNR (dB) for a received signal strength, against [`NOISE_FLOOR_DBM`].
    pub fn snr_db(rssi_dbm: f64) -> f64 {
        rssi_dbm - NOISE_FLOOR_DBM
    }

    /// Probability `0.0..=1.0` that a single frame at `mcs_index` is delivered at `snr_db`.
    /// A logistic around the per-MCS threshold: ≈0.5 at threshold, →1 well above, →0 well
    /// below. Monotonically increasing in SNR, decreasing in MCS (higher MCS needs more SNR).
    pub fn frame_delivery(&self, mcs_index: u8, snr_db: f64) -> f64 {
        let thr = REQUIRED_SNR_DB[(mcs_index as usize).min(REQUIRED_SNR_DB.len() - 1)];
        1.0 / (1.0 + (-(snr_db - thr) / self.spread_db).exp())
    }

    /// The highest MCS (capped at [`MAX_RELIABLE_MCS`]) whose threshold + margin is at or
    /// below `snr_db` — the most aggressive rate that should still deliver reliably. `None`
    /// if even MCS 0 is out of reach (the link is unusable at this SNR).
    pub fn best_mcs(&self, snr_db: f64) -> Option<u8> {
        let mut best = None;
        for mcs in 0..=MAX_RELIABLE_MCS {
            if snr_db >= REQUIRED_SNR_DB[mcs as usize] + self.select_margin_db {
                best = Some(mcs);
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_rises_with_snr_for_a_fixed_mcs() {
        let m = LinkModel::new();
        let weak = m.frame_delivery(3, 5.0);
        let mid = m.frame_delivery(3, 13.0); // at threshold ⇒ ~0.5
        let strong = m.frame_delivery(3, 25.0);
        assert!(weak < mid && mid < strong, "{weak} < {mid} < {strong}");
        assert!(
            (mid - 0.5).abs() < 0.05,
            "≈0.5 at the MCS3 threshold, got {mid}"
        );
        assert!(strong > 0.99 && weak < 0.05, "{strong} / {weak}");
    }

    #[test]
    fn higher_mcs_is_harder_at_fixed_snr() {
        let m = LinkModel::new();
        let snr = 18.0;
        // At a fixed SNR, pushing to a higher MCS lowers delivery.
        let p2 = m.frame_delivery(2, snr);
        let p5 = m.frame_delivery(5, snr);
        let p7 = m.frame_delivery(7, snr);
        assert!(p2 > p5 && p5 > p7, "{p2} > {p5} > {p7}");
    }

    #[test]
    fn best_mcs_climbs_with_snr_and_gives_up_when_unusable() {
        let m = LinkModel::new();
        assert_eq!(m.best_mcs(0.0), None, "below even MCS0+margin ⇒ unusable");
        let low = m.best_mcs(12.0).unwrap();
        let high = m.best_mcs(40.0).unwrap();
        assert!(
            high > low,
            "stronger signal ⇒ more aggressive MCS ({low} → {high})"
        );
        assert_eq!(
            high, MAX_RELIABLE_MCS,
            "very high SNR reaches the reliable ceiling"
        );
        // And the chosen rate is monotone in the choice.
        assert!(mcs_phy_rate_bps(high) > mcs_phy_rate_bps(low));
    }
}
