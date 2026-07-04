//! A **LoRa** PHY + LoRaWAN-style MAC model — the long-range, low-rate, sub-GHz counterpoint to
//! Wi-Fi, plugged onto the same [`phy`](crate::phy) channel/propagation seams so it composes with
//! everything else and can be iterated independently.
//!
//! LoRa's character is the opposite of Wi-Fi's: a chirp-spread-spectrum PHY that trades bitrate for
//! **processing gain**, so with a high spreading factor it decodes *below the noise floor* (km-range
//! links) at a few hundred bits/s. The MAC is **ALOHA** — no CSMA, just transmit — with a strict
//! **duty-cycle** limit (e.g. 1 % in EU868) and (for LoRaWAN Class A) two downlink RX windows.
//!
//! "Logically faithful, not calibrated": the airtime formula is Semtech's; the per-SF demodulation
//! SNR limits and rates are the datasheet figures; spreading factors are treated as quasi-orthogonal
//! (concurrent transmissions on different SFs don't collide). Richer capture-effect / imperfect-
//! orthogonality models plug in behind the same API.

use std::time::Duration;

/// A LoRa **spreading factor** (SF7…SF12): higher SF ⇒ more processing gain (longer range, decodes
/// at lower SNR) but exponentially longer airtime (lower rate).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SpreadingFactor {
    Sf7,
    Sf8,
    Sf9,
    Sf10,
    Sf11,
    Sf12,
}

impl SpreadingFactor {
    /// The integer SF (7…12).
    pub fn factor(self) -> u32 {
        match self {
            SpreadingFactor::Sf7 => 7,
            SpreadingFactor::Sf8 => 8,
            SpreadingFactor::Sf9 => 9,
            SpreadingFactor::Sf10 => 10,
            SpreadingFactor::Sf11 => 11,
            SpreadingFactor::Sf12 => 12,
        }
    }
    /// The demodulation SNR floor (dB) — LoRa decodes down to these (all negative; SF12 ≈ −20 dB, so
    /// it works *below* the thermal noise floor). Semtech SX127x figures.
    pub fn required_snr_db(self) -> f64 {
        match self {
            SpreadingFactor::Sf7 => -7.5,
            SpreadingFactor::Sf8 => -10.0,
            SpreadingFactor::Sf9 => -12.5,
            SpreadingFactor::Sf10 => -15.0,
            SpreadingFactor::Sf11 => -17.5,
            SpreadingFactor::Sf12 => -20.0,
        }
    }
    /// Whether this SF uses the low-data-rate optimisation (SF11/SF12 at 125 kHz).
    fn low_data_rate_opt(self, bandwidth_hz: f64) -> bool {
        self.factor() >= 11 && bandwidth_hz <= 125_000.0
    }
    /// All spreading factors, fastest → most robust.
    pub fn all() -> [SpreadingFactor; 6] {
        use SpreadingFactor::*;
        [Sf7, Sf8, Sf9, Sf10, Sf11, Sf12]
    }
}

/// Coding rate 4/(4+cr), `cr` ∈ 1..=4 (4/5 … 4/8). Higher = more forward error correction, more airtime.
#[derive(Clone, Copy, Debug)]
pub struct CodingRate(pub u32);
impl Default for CodingRate {
    fn default() -> Self {
        CodingRate(1) // 4/5
    }
}

/// A LoRa link/PHY configuration: spreading factor, bandwidth, coding rate.
#[derive(Clone, Copy, Debug)]
pub struct LoraConfig {
    pub sf: SpreadingFactor,
    pub bandwidth_hz: f64,
    pub coding_rate: CodingRate,
    /// Preamble symbols (default 8).
    pub preamble_symbols: u32,
}

impl LoraConfig {
    /// Defaults: 125 kHz, 4/5 coding, 8-symbol preamble.
    pub fn new(sf: SpreadingFactor) -> Self {
        LoraConfig { sf, bandwidth_hz: 125_000.0, coding_rate: CodingRate::default(), preamble_symbols: 8 }
    }
    /// The on-air time of a `payload` byte frame — the **Semtech LoRa airtime formula**.
    pub fn airtime(&self, payload: usize) -> Duration {
        let sf = self.sf.factor() as f64;
        let t_sym = 2f64.powf(sf) / self.bandwidth_hz; // symbol duration (s)
        let t_preamble = (self.preamble_symbols as f64 + 4.25) * t_sym;
        let de = if self.sf.low_data_rate_opt(self.bandwidth_hz) { 1.0 } else { 0.0 };
        let cr = self.coding_rate.0 as f64;
        // Number of payload symbols (header enabled, CRC on).
        let num = 8.0 * payload as f64 - 4.0 * sf + 28.0 + 16.0;
        let den = 4.0 * (sf - 2.0 * de);
        let payload_symbols = 8.0 + (num / den).ceil().max(0.0) * (cr + 4.0);
        let t_payload = payload_symbols * t_sym;
        Duration::from_secs_f64(t_preamble + t_payload)
    }
    /// The effective payload bitrate (bits/s) for a representative frame.
    pub fn bitrate_bps(&self, payload: usize) -> f64 {
        (payload as f64 * 8.0) / self.airtime(payload).as_secs_f64()
    }
    /// Probability a frame is delivered at `snr_db` — a logistic around this SF's demod floor.
    pub fn frame_delivery(&self, snr_db: f64) -> f64 {
        1.0 / (1.0 + (-(snr_db - self.sf.required_snr_db()) / 1.5).exp())
    }
}

/// **Adaptive Data Rate**: the fastest spreading factor whose demod floor + `margin_db` is met at
/// `snr_db` (LoRaWAN ADR's goal — minimise airtime while staying reliable). `None` if even SF12
/// can't close the link.
pub fn adr_select(snr_db: f64, margin_db: f64) -> Option<SpreadingFactor> {
    SpreadingFactor::all()
        .into_iter()
        .find(|sf| snr_db >= sf.required_snr_db() + margin_db)
}

/// A **duty-cycle** regulator (e.g. EU868 sub-band at 1 %): after transmitting for `airtime`, the
/// radio must stay off for `airtime/limit − airtime` before it may transmit again.
#[derive(Clone, Copy, Debug)]
pub struct DutyCycle {
    /// Allowed fraction of time on-air (0..1), e.g. 0.01 for 1 %.
    pub limit: f64,
}

impl DutyCycle {
    pub const EU868_1PCT: DutyCycle = DutyCycle { limit: 0.01 };

    /// The mandatory off-time after a transmission of `airtime`.
    pub fn off_time(&self, airtime: Duration) -> Duration {
        let t = airtime.as_secs_f64();
        Duration::from_secs_f64((t / self.limit.max(1e-9) - t).max(0.0))
    }
}

/// LoRaWAN device **class** — the downlink (network→device) behaviour, trading energy for latency.
/// Every device supports Class A; B and C add more downlink opportunity at higher receive energy.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum DeviceClass {
    /// **Class A**: the device opens two short RX windows only right after each *uplink* (lowest
    /// energy, highest downlink latency). The baseline every LoRaWAN device must implement.
    A,
    /// **Class B**: adds scheduled, beacon-synchronised **ping slots** every `ping_period`, so the
    /// network gets periodic downlink chances without waiting for an uplink (middle ground).
    B { ping_period: Duration },
    /// **Class C**: the device listens **continuously** except while transmitting — near-immediate
    /// downlink at the cost of the highest receive energy (mains-powered).
    C,
}

impl DeviceClass {
    /// Default RX1 delay after an uplink (LoRaWAN default 1 s).
    const RX1_DELAY: Duration = Duration::from_secs(1);
    /// A modelled RX-window dwell (preamble detect + a short listen).
    const RX_WINDOW: Duration = Duration::from_millis(15);

    /// Expected latency before the network can deliver a downlink, given the device uplinks every
    /// `uplink_interval`. Class A waits for the next uplink's RX window; Class B for the next ping
    /// slot; Class C listens continuously (≈ immediate).
    pub fn downlink_latency(self, uplink_interval: Duration) -> Duration {
        match self {
            DeviceClass::A => uplink_interval / 2 + Self::RX1_DELAY,
            DeviceClass::B { ping_period } => ping_period / 2,
            DeviceClass::C => Duration::from_millis(1),
        }
    }

    /// Fraction of time the receiver is on (an energy proxy): Class A only in the two post-uplink
    /// windows, Class B additionally one ping-slot dwell per period, Class C ≈ always on.
    pub fn receive_duty(self, uplink_interval: Duration) -> f64 {
        let ui = uplink_interval.as_secs_f64().max(1e-9);
        let a_duty = 2.0 * Self::RX_WINDOW.as_secs_f64() / ui;
        match self {
            DeviceClass::A => a_duty,
            DeviceClass::B { ping_period } => {
                a_duty + Self::RX_WINDOW.as_secs_f64() / ping_period.as_secs_f64().max(1e-9)
            }
            DeviceClass::C => 1.0,
        }
    }
}

/// A LoRa link for the IP/NDN fabric: a range gate + PHY config + tx power + a pluggable propagation
/// backend + duty-cycle regulator. The LoRa analogue of [`RadioLinkConfig`](crate::RadioLinkConfig)
/// — consumed by [`IpNetwork::from_positions_lora`](crate::IpNetwork::from_positions_lora) so a
/// scenario can run IP/NDN over LoRa's long-range, low-rate links.
#[derive(Clone)]
pub struct LoraLinkConfig {
    pub range_m: f64,
    pub cfg: LoraConfig,
    pub tx_power_dbm: f64,
    pub payload_bytes: usize,
    pub freq_hz: f64,
    pub propagation: std::sync::Arc<dyn crate::phy::PropagationBackend>,
    pub duty: DutyCycle,
}

impl LoraLinkConfig {
    /// Defaults: the given SF at 125 kHz, 14 dBm (EU868 max EIRP), 32-byte payload, free-space at
    /// 868 MHz, 1 % duty cycle.
    pub fn new(range_m: f64, sf: SpreadingFactor) -> Self {
        LoraLinkConfig {
            range_m,
            cfg: LoraConfig::new(sf),
            tx_power_dbm: 14.0,
            payload_bytes: 32,
            freq_hz: 868.1e6,
            propagation: std::sync::Arc::new(crate::phy::FreeSpace),
            duty: DutyCycle::EU868_1PCT,
        }
    }
    /// Swap the propagation backend (free-space, log-distance, …).
    pub fn with_propagation(mut self, p: std::sync::Arc<dyn crate::phy::PropagationBackend>) -> Self {
        self.propagation = p;
        self
    }
    /// LoRa thermal noise floor (dBm) for the configured bandwidth: −174 + 10·log₁₀(BW) + 6 dB NF.
    fn noise_floor_dbm(&self) -> f64 {
        -174.0 + 10.0 * self.cfg.bandwidth_hz.log10() + 6.0
    }
    /// SNR (dB) at a link distance — received power (pluggable propagation) minus the LoRa noise
    /// floor. High SFs still close the link at *negative* SNR (below the noise floor).
    pub fn snr_at(&self, dist_m: f64) -> f64 {
        let ctx = crate::phy::PathContext {
            distance_m: dist_m,
            freq_hz: self.freq_hz,
            tx_power_dbm: self.tx_power_dbm,
            tx_gain_dbi: 0.0,
            rx_gain_dbi: 0.0,
        };
        self.propagation.rx_power_dbm(&ctx) - self.noise_floor_dbm()
    }
    /// Per-link `(loss, airtime)` for the fabric: loss from this SF's demod curve at the link SNR,
    /// airtime from the Semtech formula for `payload_bytes` (so LoRa's long on-air time shows up as
    /// link latency, an order of magnitude beyond Wi-Fi).
    pub fn link_cost(&self, dist_m: f64) -> (f64, Duration) {
        let loss = (1.0 - self.cfg.frame_delivery(self.snr_at(dist_m))).clamp(0.0, 1.0);
        (loss, self.cfg.airtime(self.payload_bytes))
    }
}

/// A LoRa channel (sub-GHz). The general [`Channel`](crate::phy::Channel) covers the spectral
/// relationships; this is a convenience for the common bands.
pub fn eu868_channel() -> crate::phy::Channel {
    crate::phy::Channel { center_hz: 868.1e6, bandwidth_hz: 125_000.0 }
}
pub fn us915_channel(ch: u8) -> crate::phy::Channel {
    crate::phy::Channel { center_hz: 902.3e6 + ch as f64 * 200_000.0, bandwidth_hz: 125_000.0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn airtime_climbs_steeply_with_spreading_factor() {
        let fast = LoraConfig::new(SpreadingFactor::Sf7).airtime(20);
        let slow = LoraConfig::new(SpreadingFactor::Sf12).airtime(20);
        // SF12 is dramatically longer on air than SF7 (roughly an order of magnitude+).
        assert!(slow > fast * 8, "SF12 airtime ≫ SF7 ({slow:?} vs {fast:?})");
        // And SF7 out-rates SF12 by a wide margin.
        assert!(
            LoraConfig::new(SpreadingFactor::Sf7).bitrate_bps(20)
                > LoraConfig::new(SpreadingFactor::Sf12).bitrate_bps(20) * 8.0
        );
    }

    #[test]
    fn high_sf_decodes_below_the_noise_floor() {
        // At −18 dB SNR (below thermal noise), SF12 still decodes but SF7 is hopeless.
        let sf12 = LoraConfig::new(SpreadingFactor::Sf12).frame_delivery(-18.0);
        let sf7 = LoraConfig::new(SpreadingFactor::Sf7).frame_delivery(-18.0);
        assert!(sf12 > 0.7, "SF12 decodes below the noise floor ({sf12})");
        assert!(sf7 < 0.05, "SF7 cannot ({sf7})");
    }

    #[test]
    fn adr_picks_the_fastest_working_sf() {
        // Strong link ⇒ SF7 (fastest); marginal ⇒ a high SF; hopeless ⇒ None.
        assert_eq!(adr_select(10.0, 3.0), Some(SpreadingFactor::Sf7));
        assert_eq!(adr_select(-16.0, 3.0), Some(SpreadingFactor::Sf12));
        assert_eq!(adr_select(-30.0, 3.0), None, "even SF12 can't close a −30 dB link");
    }

    #[test]
    fn device_class_trades_downlink_latency_for_receive_energy() {
        let ui = Duration::from_secs(60); // uplink once a minute
        let (a, b, c) = (
            DeviceClass::A,
            DeviceClass::B { ping_period: Duration::from_secs(2) },
            DeviceClass::C,
        );
        // Latency: Class A (wait for uplink) ≫ Class B (ping slot) ≫ Class C (always listening).
        assert!(a.downlink_latency(ui) > b.downlink_latency(ui));
        assert!(b.downlink_latency(ui) > c.downlink_latency(ui));
        // Receive energy is the inverse tradeoff: A < B < C (C listens continuously).
        assert!(a.receive_duty(ui) < b.receive_duty(ui));
        assert!(b.receive_duty(ui) < c.receive_duty(ui));
        assert_eq!(c.receive_duty(ui), 1.0, "Class C's receiver is always on");
    }

    #[test]
    fn lora_link_cost_closes_long_range_only_at_high_sf() {
        use crate::phy::LogDistance;
        use std::sync::Arc;
        // A lossy (exponent-3.5) 1 km link: SF7 (needs high SNR) can't close it; SF12, decoding below
        // the noise floor, can. And LoRa's airtime is far beyond Wi-Fi's — the link latency reflects it.
        let far = 1000.0;
        let prop = || Arc::new(LogDistance { exponent: 3.5, ref_loss_db: 40.0, ref_dist_m: 1.0 });
        let sf7 = LoraLinkConfig::new(10_000.0, SpreadingFactor::Sf7).with_propagation(prop());
        let sf12 = LoraLinkConfig::new(10_000.0, SpreadingFactor::Sf12).with_propagation(prop());
        let (loss7, air7) = sf7.link_cost(far);
        let (loss12, air12) = sf12.link_cost(far);
        assert!(loss7 > 0.5, "SF7 can't close the lossy 1 km link ({loss7})");
        assert!(loss12 < 0.2, "SF12 closes it below the noise floor ({loss12})");
        assert!(air12 > air7, "SF12 pays for the range in airtime ({air12:?} vs {air7:?})");
        assert!(air12 > Duration::from_millis(500), "LoRa SF12 airtime is very long: {air12:?}");
    }

    #[test]
    fn duty_cycle_enforces_off_time() {
        let air = LoraConfig::new(SpreadingFactor::Sf12).airtime(20);
        let off = DutyCycle::EU868_1PCT.off_time(air);
        // At 1 %, off-time ≈ 99× the airtime.
        assert!(off > air * 90 && off < air * 110, "1% duty ⇒ ~99× off-time ({off:?} for {air:?})");
    }
}
