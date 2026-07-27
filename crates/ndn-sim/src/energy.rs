//! Energy accounting — a pluggable model, like [`PropagationModel`](crate::medium::PropagationModel)
//! and [`InterferenceModel`](crate::medium::InterferenceModel), so "how much power does this radio
//! burn?" is a swappable policy, not a hard-coded constant.
//!
//! The [`RadioBus`](crate::radio::RadioBus) charges energy per frame: the transmitter pays
//! [`EnergyModel::tx_energy_j`] once, and **every in-range radio** pays [`EnergyModel::rx_energy_j`]
//! — the "listen to everything" cost the named-radio doctrine (§3.1) says monitor mode incurs. Idle
//! draw ([`EnergyModel::idle_power_w`]) is time-based, so callers integrate it over the run duration.
//!
//! The result is a per-node [`EnergyAccount`], from which the two numbers that matter fall out:
//! **joules per node** (the §4 cooperation-vs-power dial — a relay that forwards more, or a
//! wide-filter node that processes more frames, burns more) and **energy per delivered bit** (the
//! efficiency metric a real deployment budgets against).

use std::collections::HashMap;
use std::time::Duration;

/// How a radio converts airtime + PHY settings into joules. Implement this to model a specific
/// front-end (a USB Wi-Fi NIC, a LoRa SoC, a HaLow module); [`RadioEnergyModel`] is a reasonable
/// Wi-Fi-class default.
pub trait EnergyModel: Send + Sync {
    /// Energy (J) to transmit one frame of `airtime` at `tx_power_dbm` on `mcs`. The radiated power
    /// plus the PA/circuit draw over the on-air window.
    fn tx_energy_j(&self, airtime: Duration, tx_power_dbm: f64, mcs: u8) -> f64;
    /// Energy (J) for one radio to receive/decode a frame of `airtime` on `mcs` it hears — the
    /// per-frame cost of *processing* a frame that reached the front-end.
    fn rx_energy_j(&self, airtime: Duration, mcs: u8) -> f64;
    /// Baseline listen/idle draw (W) while the radio is on but not TX/RX — integrated over wall time
    /// by the caller (`idle_power_w() * run_seconds`).
    fn idle_power_w(&self) -> f64;
    /// **Host** CPU energy (J) to process one frame that reaches the host — parse + name-hash +
    /// FIB/PIT longest-prefix-match (and, past the PIT gate, verify). This is the cost the
    /// mac-addressing-doctrine §3.1 "listen to everything" tax is really made of, and the cost a
    /// hardware name-group filter **offloads** by dropping non-matching frames before waking the CPU.
    /// It typically dwarfs the radio's per-frame RX energy — which is exactly why the offload matters.
    fn host_process_energy_j(&self, frame_len: usize) -> f64;
}

/// A Wi-Fi-class energy model with order-of-magnitude-realistic front-end constants. Every field is
/// public so a scenario can dial in a different radio (a low-power LoRa SoC: tiny `rx_active_w`,
/// tiny `idle_w`; a hungry MIMO NIC: large baselines).
#[derive(Clone, Copy, Debug)]
pub struct RadioEnergyModel {
    /// Circuit draw (W) during TX, on top of the PA output — LO, DAC, mixer, baseband.
    pub tx_baseline_w: f64,
    /// Power-amplifier efficiency (radiated / DC drawn), typically 0.2–0.35 for a small Wi-Fi PA.
    pub pa_efficiency: f64,
    /// Draw (W) while actively receiving/decoding a frame.
    pub rx_active_w: f64,
    /// Baseline listen/idle draw (W) — the "radio on, hearing the channel" cost.
    pub idle_w: f64,
    /// Host CPU draw (W) while processing a frame (the delta over idle for the core doing the work).
    pub host_cpu_w: f64,
    /// Host CPU time (s) to process one frame (parse + name-hash + LPM). Measured ~60–120 µs per
    /// delivered frame on the real 8812au host path (mac-addressing-doctrine §3.1 / task #43).
    pub host_process_s: f64,
}

impl Default for RadioEnergyModel {
    fn default() -> Self {
        // A commodity 2.4/5 GHz USB Wi-Fi front end, roughly: ~1.1 W of circuit draw during TX with
        // a ~25%-efficient PA on top, ~0.9 W receiving, ~0.7 W just listening. Host processing: ~2 W
        // over ~90 µs of CPU per frame (parse + name-hash + LPM), i.e. ~180 µJ/frame — an order of
        // magnitude above the ~7 µJ radio RX, so the host is where the "process everything" tax
        // lands. Not a datasheet — an honest order of magnitude (swap it for measured numbers).
        Self {
            tx_baseline_w: 1.1,
            pa_efficiency: 0.25,
            rx_active_w: 0.9,
            idle_w: 0.7,
            host_cpu_w: 2.0,
            host_process_s: 90e-6,
        }
    }
}

impl EnergyModel for RadioEnergyModel {
    fn tx_energy_j(&self, airtime: Duration, tx_power_dbm: f64, _mcs: u8) -> f64 {
        let radiated_w = 10f64.powf(tx_power_dbm / 10.0) / 1000.0; // dBm → W
        let draw_w = self.tx_baseline_w + radiated_w / self.pa_efficiency.max(1e-3);
        draw_w * airtime.as_secs_f64()
    }
    fn rx_energy_j(&self, airtime: Duration, _mcs: u8) -> f64 {
        self.rx_active_w * airtime.as_secs_f64()
    }
    fn idle_power_w(&self) -> f64 {
        self.idle_w
    }
    fn host_process_energy_j(&self, _frame_len: usize) -> f64 {
        self.host_cpu_w * self.host_process_s
    }
}

/// Per-node running energy tally (active TX + RX; idle is added by the caller from wall time).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct EnergyAccount {
    pub tx_j: f64,
    pub rx_j: f64,
    /// **Host** CPU energy processing frames that reached the host (the offloadable §3.1 cost).
    pub host_j: f64,
    pub frames_tx: u64,
    pub frames_rx: u64,
    /// Frames that reached the host CPU — all in-range frames when promiscuous; only name-group
    /// matches when a hardware filter is installed (the MAC offload).
    pub frames_to_host: u64,
    /// Payload bits this node put on air (for energy-per-offered-bit).
    pub bits_tx: u64,
}

impl EnergyAccount {
    /// Active energy (TX + RX radio + host CPU), excluding the time-based idle baseline.
    pub fn active_j(&self) -> f64 {
        self.tx_j + self.rx_j + self.host_j
    }
    /// Total energy including `run_seconds` of idle draw at `idle_power_w`.
    pub fn total_j(&self, idle_power_w: f64, run_seconds: f64) -> f64 {
        self.active_j() + idle_power_w * run_seconds
    }
}

/// A collection of per-node accounts (what the bus hands back).
pub type EnergyAccounts = HashMap<crate::topology::NodeId, EnergyAccount>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_energy_scales_with_power_and_airtime() {
        let m = RadioEnergyModel::default();
        let air = Duration::from_millis(1);
        // 20 dBm = 100 mW radiated; at 25% PA that is 0.4 W of PA draw + 1.1 W baseline = 1.5 W.
        assert!((m.tx_energy_j(air, 20.0, 5) - 1.5e-3).abs() < 1e-5, "{}", m.tx_energy_j(air, 20.0, 5));
        // Doubling airtime doubles energy; raising power raises it.
        assert!(m.tx_energy_j(Duration::from_millis(2), 20.0, 5) > m.tx_energy_j(air, 20.0, 5));
        assert!(m.tx_energy_j(air, 23.0, 5) > m.tx_energy_j(air, 20.0, 5));
    }

    #[test]
    fn rx_and_idle_are_simple_power_times_time() {
        let m = RadioEnergyModel::default();
        assert!((m.rx_energy_j(Duration::from_millis(1), 0) - 0.9e-3).abs() < 1e-6);
        assert_eq!(m.idle_power_w(), 0.7);
    }

    #[test]
    fn account_total_adds_idle_over_time() {
        let a = EnergyAccount { tx_j: 1.0, rx_j: 2.0, host_j: 4.0, ..Default::default() };
        assert_eq!(a.active_j(), 7.0); // tx + rx + host
        assert_eq!(a.total_j(0.7, 10.0), 7.0 + 7.0); // + idle 0.7 W · 10 s
    }

    #[test]
    fn host_energy_dwarfs_radio_rx_per_frame() {
        // The doctrine's point: processing a frame on the host costs far more than the radio's RX —
        // which is why offloading the drop to a hardware name-filter matters.
        let m = RadioEnergyModel::default();
        let air = Duration::from_micros(9); // a short frame's airtime
        assert!(m.host_process_energy_j(200) > 10.0 * m.rx_energy_j(air, 5));
    }
}
