//! Bridge between the simulated radio medium and the real `ndn-radio-cognition` control plane.
//!
//! ndn-sim models the *medium* (SINR, contention, LoRa airtime) but historically not the
//! sense→decide→act loop. `SimCognition` closes that: a sim node owns one of these, feeds it the RSSI
//! it hears off the [`RadioBus`](crate::radio::RadioBus) (`observe`) and the airtime it spends
//! (`record_tx`), and asks it — per named object — which rate to transmit at (`decide_mcs`). It reuses
//! the same `MediumState` + `RadioPolicy` the real LoRa/Wi-Fi nodes run, so a simulated node makes the
//! *identical* decisions as hardware — which is the whole point of running the N=3 LBT / co-band /
//! rate-adaptation experiments in the sim when the radios are unavailable.

use ndn_radio_cognition::{
    MediumState, NameContext, Priority, RadioCapability, RadioId, RadioPolicy,
};

/// One node's cognition instance: measured medium + policy, mapping named demand → a sim MCS index.
pub struct SimCognition {
    radio: RadioId,
    policy: RadioPolicy,
    medium: MediumState,
    /// Robustness ceiling for this radio (sim `mcs_index` never exceeds it).
    max_mcs: u8,
}

impl SimCognition {
    /// Build for one radio with its capability descriptor. `max_mcs` clamps the returned index to the
    /// sim's reliable range (see `crate::link_model::MAX_RELIABLE_MCS`).
    pub fn new(radio: RadioId, cap: RadioCapability, max_mcs: u8) -> Self {
        let mut medium = MediumState::new();
        medium.register_radio(radio, cap);
        Self { radio, policy: RadioPolicy::default(), medium, max_mcs }
    }

    /// Feed a heard frame's RSSI (dBm) from `neighbor` (an ephemeral source key) into the sense plane.
    pub fn observe(&mut self, neighbor: u64, rssi_dbm: f64, now_ms: u64) {
        self.medium
            .observe_rx(self.radio, neighbor, Some(rssi_dbm.round() as i8), now_ms);
    }

    /// Charge airtime spent transmitting (drives the duty-cycle budget the LoRa policy respects).
    pub fn record_tx(&mut self, airtime_ms: f32, now_ms: u64) {
        self.medium.record_airtime(self.radio, airtime_ms, now_ms);
    }

    /// Note the measured re-Interest rate for a name (the ARQ signal the redundancy budget reads).
    pub fn observe_reinterest(&mut self, prefix_hash: u64, rate: f32, now_ms: u64) {
        self.medium.observe_reinterest(prefix_hash, rate, now_ms);
    }

    /// Decide the transmit MCS index for one named object, running the real `RadioPolicy`.
    ///
    /// Maps the plan's chosen rate into the sim's `mcs_index` space: a Wi-Fi plan's MCS maps directly;
    /// a LoRa plan's spreading factor maps inverse-to-robustness (higher SF = more robust = lower
    /// index). Clamped to `max_mcs`. Returns `None` if the plan suppresses this transmission.
    pub fn decide_mcs(&mut self, prefix_hash: u64, priority: Priority, now_ms: u64) -> Option<u8> {
        let ctx = NameContext { priority, ..NameContext::new(prefix_hash) };
        let plan = self.policy.decide(&ctx, &self.medium, now_ms);
        if plan.suppress {
            return None;
        }
        let alloc = plan.allocation_for(self.radio)?;
        let idx = if let Some(mcs) = alloc.params.mcs() {
            mcs
        } else if let Some(sf) = alloc.params.spreading_factor() {
            // SF7..12 → robustness-ordered index: SF7 (fast) = max_mcs, SF12 (robust) = 0.
            self.max_mcs.saturating_sub(sf.saturating_sub(7))
        } else {
            0
        };
        Some(idx.min(self.max_mcs))
    }

    /// The sense plane, e.g. to read back neighbor RSSI / occupancy for telemetry.
    pub fn medium(&self) -> &MediumState {
        &self.medium
    }
}
