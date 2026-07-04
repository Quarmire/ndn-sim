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
/// A Block-ACK (acknowledges a whole A-MPDU) is a little larger than a normal ACK.
const BLOCK_ACK_US: f64 = 68.0;
const CW_MIN: f64 = 15.0;
/// MAC header + FCS carried with every data frame.
const MAC_OVERHEAD_BYTES: usize = 34;
/// The A-MPDU sub-frame delimiter prepended to each aggregated MPDU.
const MPDU_DELIMITER_BYTES: usize = 4;
/// Managed multicast/broadcast (and beacons) go out at a **basic (legacy) rate** — MCS 0 here —
/// with no ACK and no rate adaptation, per 802.11's group-addressed-frame rules.
const BASIC_RATE_MCS: u8 = 0;
/// A beacon management frame's size and the standard ~102.4 ms beacon interval.
const BEACON_BYTES: usize = 128;
const BEACON_INTERVAL_US: f64 = 102_400.0;

/// The radio operating mode — the crux of the named-data-radio vs normal-Wi-Fi comparison.
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

impl WifiMode {
    /// Airtime per second spent on beacons (0 for monitor; a basic-rate beacon each interval for
    /// managed modes — IBSS/AP/mesh all beacon).
    pub fn beacon_airtime_per_sec(self) -> Duration {
        match self {
            WifiMode::Monitor => Duration::ZERO,
            WifiMode::Managed => {
                let per_beacon = broadcast_airtime(BEACON_BYTES, BASIC_RATE_MCS).as_nanos() as f64;
                let beacons_per_sec = 1e6 / BEACON_INTERVAL_US;
                Duration::from_nanos((per_beacon * beacons_per_sec) as u64)
            }
        }
    }
}

/// The 802.11 **operating mode** — how nodes organise, distinct from [`WifiMode`] (which is the
/// PHY/MAC discipline). This shapes the connectivity graph and the association cost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiOperatingMode {
    /// Ad-hoc: in-range peers link directly; distributed beacons; no AP association (light join).
    Ibss,
    /// Infrastructure: every station links **only to the AP** (a star) — station↔station traffic
    /// relays through it — and a station must **associate** before sending (setup cost; a handoff
    /// gap when it roams out of and back into range).
    Ap { ap: usize },
    /// 802.11s mesh: in-range peers link and forward for each other (like IBSS for connectivity),
    /// with mesh peering handshakes between neighbours.
    Mesh,
}

impl WifiOperatingMode {
    /// Whether a link between nodes `a` and `b` is *permitted* by the mode (before range gating):
    /// AP mode allows only station↔AP; IBSS/mesh allow any peer pair.
    pub fn link_allowed(self, a: usize, b: usize) -> bool {
        match self {
            WifiOperatingMode::Ibss | WifiOperatingMode::Mesh => true,
            WifiOperatingMode::Ap { ap } => a == ap || b == ap,
        }
    }
    /// The one-time association setup delay a station pays on (re-)joining in this mode — the cost
    /// monitor mode never pays. AP association is the scan+auth+assoc(+handshake) sequence; IBSS/mesh
    /// join/peering is lighter.
    pub fn association_setup(self) -> Duration {
        match self {
            WifiOperatingMode::Ap { .. } => Duration::from_millis(120), // scan+auth+assoc+4-way
            WifiOperatingMode::Mesh => Duration::from_millis(40),       // peering
            WifiOperatingMode::Ibss => Duration::from_millis(5),        // adopt TSF
        }
    }
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

/// A simple free-space SNR (dB) for a `tx_power_dbm` transmitter received `dist_m` away at 2.4 GHz.
/// A placeholder channel model — the pluggable propagation / antenna backend supersedes it.
pub fn snr_from_distance(tx_power_dbm: f64, dist_m: f64) -> f64 {
    let d = dist_m.max(1.0);
    // FSPL(dB) = 20·log10(d) + 20·log10(f) − 147.55.
    let fspl = 20.0 * d.log10() + 20.0 * 2.4e9_f64.log10() - 147.55;
    LinkModel::snr_db(tx_power_dbm - fspl)
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
/// (possibly aggregated) frame + SIFS + ACK (or Block-ACK for an A-MPDU).
fn managed_unicast_attempt_airtime(
    bytes: usize,
    n_agg: u32,
    mcs: u8,
    ac: AccessCategory,
) -> Duration {
    let ack = if n_agg > 1 { BLOCK_ACK_US } else { ACK_US };
    us(ac.aifs_us() + ac.backoff_us() + SIFS_US + ack) + ampdu_airtime(bytes, n_agg, mcs)
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
    /// PHY decodes it at the receiver's `snr_db`. This is the named-data-radio transmission —
    /// multicast-native (one airtime reaches every in-range receiver) at a rate you choose.
    pub fn monitor_tx(&self, snr_db: f64, bytes: usize, mcs: u8, rng: &mut StdRng) -> TxOutcome {
        let p = self.link.frame_delivery(mcs, snr_db);
        TxOutcome {
            delivered: rng.random::<f64>() < p,
            attempts: 1,
            airtime: broadcast_airtime(bytes, mcs),
            mcs,
        }
    }

    /// **Managed unicast** transmit to `peer`: EDCA CSMA-CA + ACK (Block-ACK when aggregating) +
    /// retransmit up to `retry_limit` times, MCS chosen (and learned) by `rc`. `n_agg` sub-frames
    /// aggregate into one A-MPDU (1 = no aggregation). Airtime accumulates every attempt.
    #[allow(clippy::too_many_arguments)]
    pub fn managed_unicast_tx(
        &self,
        peer: usize,
        snr_db: f64,
        bytes: usize,
        rc: &mut dyn RateControl,
        retry_limit: u32,
        n_agg: u32,
        ac: AccessCategory,
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
            airtime += managed_unicast_attempt_airtime(bytes, n_agg, mcs, ac);
            let ok = rng.random::<f64>() < self.link.frame_delivery(mcs, snr_db);
            rc.feedback(peer, mcs, ok);
            if ok {
                delivered = true;
                break;
            }
        }
        TxOutcome { delivered, attempts, airtime, mcs: last_mcs }
    }

    /// The **expected per-frame loss and airtime** for a `bytes` frame to a peer at `snr_db` under
    /// `mode`, with `retry_limit` unicast retries — the *statistical* MAC cost used to drive an
    /// in-sim radio link (loss → the link's drop probability, airtime → its added delay). Monitor is
    /// one-shot (higher loss, lower airtime); managed trades airtime (retries) for reliability.
    pub fn link_cost(
        &self,
        mode: WifiMode,
        snr_db: f64,
        bytes: usize,
        retry_limit: u32,
    ) -> (f64, Duration) {
        let mcs = self.link.best_mcs(snr_db).unwrap_or(0);
        match mode {
            WifiMode::Monitor => {
                let p = self.link.frame_delivery(mcs, snr_db);
                (1.0 - p, broadcast_airtime(bytes, mcs))
            }
            WifiMode::Managed => {
                let p = self.link.frame_delivery(mcs, snr_db).clamp(1e-3, 1.0);
                let attempts = (retry_limit + 1) as i32;
                let delivered = 1.0 - (1.0 - p).powi(attempts);
                let expected_attempts = (delivered / p).max(1.0); // geometric, capped by delivered
                let per = managed_unicast_attempt_airtime(bytes, 1, mcs, AccessCategory::BestEffort);
                let airtime = Duration::from_nanos((per.as_nanos() as f64 * expected_attempts) as u64);
                (1.0 - delivered, airtime)
            }
        }
    }

    /// **Managed multicast / broadcast**: a single group-addressed frame at the **basic (legacy)
    /// rate**, no ACK, no retry, no rate adaptation (802.11's group-frame rule). Contrast monitor
    /// mode, which multicasts at whatever (high) rate you inject — so managed multicast is robust but
    /// slow, and cannot use the aggregation/rate-control that managed *unicast* enjoys.
    pub fn managed_multicast_tx(&self, snr_db: f64, bytes: usize, rng: &mut StdRng) -> TxOutcome {
        let p = self.link.frame_delivery(BASIC_RATE_MCS, snr_db);
        TxOutcome {
            delivered: rng.random::<f64>() < p,
            attempts: 1,
            airtime: broadcast_airtime(bytes, BASIC_RATE_MCS),
            mcs: BASIC_RATE_MCS,
        }
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
            if wifi
                .managed_unicast_tx(0, snr, 200, &mut rc, 4, 1, AccessCategory::BestEffort, &mut r2)
                .delivered
            {
                uni += 1;
            }
        }
        assert!(uni > mono + 300, "ACK+retry raises delivery (uni {uni} vs mono {mono})");
    }

    /// Managed multicast is pinned to the basic (legacy) rate — robust but the slowest airtime — while
    /// monitor mode can multicast at a high MCS, so named-data radio's multicast is much cheaper.
    #[test]
    fn managed_multicast_uses_the_basic_rate() {
        let wifi = Wifi::new();
        let mut r = rng();
        let out = wifi.managed_multicast_tx(30.0, 500, &mut r);
        assert_eq!(out.mcs, 0, "group frames go at the basic rate");
        // The same multicast injected at a high MCS in monitor mode occupies far less airtime.
        let monitor_fast = broadcast_airtime(500, MAX_RELIABLE_MCS);
        assert!(out.airtime > monitor_fast * 2, "basic-rate multicast ≫ high-rate monitor airtime");
    }

    /// Managed modes spend airtime on beacons; monitor mode does not.
    #[test]
    fn only_managed_mode_beacons() {
        assert_eq!(WifiMode::Monitor.beacon_airtime_per_sec(), Duration::ZERO);
        assert!(WifiMode::Managed.beacon_airtime_per_sec() > Duration::ZERO, "managed beacons cost airtime");
    }

    /// A-MPDU aggregation amortises the PHY preamble across sub-frames, so airtime-per-frame drops as
    /// the aggregate grows — the managed-mode throughput lever for bulk.
    #[test]
    fn aggregation_amortizes_the_preamble() {
        let per_frame_1 = managed_unicast_attempt_airtime(1500, 1, 7, AccessCategory::BestEffort);
        let agg = managed_unicast_attempt_airtime(1500, 16, 7, AccessCategory::BestEffort);
        let per_frame_16 = agg / 16;
        assert!(per_frame_16 < per_frame_1, "16-frame A-MPDU is cheaper per frame ({per_frame_16:?} < {per_frame_1:?})");
    }

    /// EDCA prioritises: a Voice frame contends less (shorter AIFS + CW) than a Background frame.
    #[test]
    fn edca_voice_beats_background() {
        let voice = managed_unicast_attempt_airtime(200, 1, 4, AccessCategory::Voice);
        let background = managed_unicast_attempt_airtime(200, 1, 4, AccessCategory::Background);
        assert!(voice < background, "voice AC waits less than background ({voice:?} < {background:?})");
    }

    /// …but a successful unicast costs more airtime than a monitor broadcast (ACK + contention).
    #[test]
    fn unicast_costs_more_airtime_than_monitor() {
        assert!(
            managed_unicast_attempt_airtime(200, 1, 4, AccessCategory::BestEffort)
                > broadcast_airtime(200, 4),
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
        let n_unicasts: Duration = (0..n)
            .map(|_| managed_unicast_attempt_airtime(bytes, 1, mcs, AccessCategory::BestEffort))
            .sum();
        assert!(
            n_unicasts > one_broadcast * 4,
            "delivering to {n} peers: {n} unicasts ({n_unicasts:?}) ≫ one broadcast ({one_broadcast:?})"
        );
    }
}
