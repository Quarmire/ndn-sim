//! The wireless **physics seams** the named-radio face ([`RadioBus`](crate::RadioBus)) is built on:
//! a [`PropagationModel`] decides per `(tx, rx)` pair whether a frame arrives, with what RSSI, after
//! what delay; an [`InterferenceModel`] decides whether concurrent in-air frames collide; a
//! [`ChannelModel`] says how much one channel leaks into another.
//!
//! Propagation is **deterministic by construction** — given node positions it always answers the
//! same way. Randomness that belongs to the radio (per-MPDU erasure from
//! [`LinkModel`](crate::LinkModel), collisions) is layered on by the `RadioBus`.

use std::time::Duration;

use crate::NodeId;
use crate::world::{Environment, Position};

/// Speed of light, m/s — propagation delay is `distance / C`.
const C: f64 = 299_792_458.0;

/// `20·log10(4π/c)` ≈ −147.55 dB — the constant term of the Friis free-space path loss.
const FSPL_K: f64 = -147.55;

/// Friis free-space path loss (dB) at `distance_m` and `freq_hz`:
/// `20·log10(d) + 20·log10(f) − 147.55`, with `d` clamped to ≥ 1 m (no log singularity / negative
/// loss at sub-metre range). The one FSPL formula in the tree — [`FreeSpacePathLoss`] and the
/// studies crate's `PropagationBackend` both evaluate it, so the NDN radio and the IP plane cannot
/// silently disagree on reach.
pub fn free_space_path_loss_db(distance_m: f64, freq_hz: f64) -> f64 {
    20.0 * distance_m.max(1.0).log10() + 20.0 * freq_hz.log10() + FSPL_K
}

/// Inputs to a propagation calculation for one `(tx, rx)` pair.
pub struct TxContext<'a> {
    pub tx_pos: Position,
    pub rx_pos: Position,
    pub tx_power_dbm: f64,
    pub environment: &'a dyn Environment,
    pub frame_len: usize,
}

impl TxContext<'_> {
    pub fn distance(&self) -> f64 {
        self.tx_pos.distance(self.rx_pos)
    }
    /// Free-space propagation delay for this pair.
    pub fn propagation_delay(&self) -> Duration {
        Duration::from_secs_f64(self.distance() / C)
    }
}

/// Why a frame did (or didn't) arrive — the causal evidence axis 4 records so a failure can be
/// *explained* instead of vanishing into a `trace!` log.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryReason {
    /// The frame arrived.
    #[default]
    Delivered,
    /// Beyond the model's hard range (range-threshold).
    OutOfRange,
    /// Received power below the receiver's sensitivity (free-space path loss).
    Weak,
    /// Line of sight blocked by an obstacle (geometry backend).
    Obstructed,
    /// Lost to a concurrent transmission (interference) — set by the [`RadioBus`](crate::RadioBus).
    Collision,
    /// Detectable but lost to per-frame erasure at that SNR — set by the [`RadioBus`](crate::RadioBus).
    Erased,
    /// The receiver was itself transmitting when the frame arrived — a half-duplex radio cannot
    /// receive while it transmits. Set by the [`RadioBus`](crate::RadioBus).
    HalfDuplex,
}

impl DeliveryReason {
    /// A human phrase for a causal explanation.
    pub fn describe(self) -> &'static str {
        match self {
            DeliveryReason::Delivered => "delivered",
            DeliveryReason::OutOfRange => "out of radio range",
            DeliveryReason::Weak => "signal below receiver sensitivity",
            DeliveryReason::Obstructed => "line of sight blocked by an obstacle",
            DeliveryReason::Collision => "collided with a concurrent transmission",
            DeliveryReason::Erased => "lost to per-frame erasure at low SNR",
            DeliveryReason::HalfDuplex => "receiver was transmitting (half-duplex)",
        }
    }

    /// Whether the receiver was a **decodable candidate** — the frame was detectable (in range, above
    /// sensitivity, line-of-sight) and either landed or was lost to erasure/collision/half-duplex.
    /// `OutOfRange`/`Weak`/`Obstructed` were never candidates, so they must not dilute a delivery-fraction
    /// denominator (H3).
    pub fn is_decodable_candidate(self) -> bool {
        !matches!(
            self,
            DeliveryReason::OutOfRange | DeliveryReason::Weak | DeliveryReason::Obstructed
        )
    }
}

/// The outcome of propagation for one `(tx, rx)` pair.
#[derive(Clone, Copy, Debug)]
pub struct Delivery {
    pub delivered: bool,
    pub rssi_dbm: f64,
    pub delay: Duration,
    /// Why (the causal reason) — `Delivered` when `delivered`, else the propagation cause.
    pub reason: DeliveryReason,
}

/// Decides, per `(tx, rx)` pair, whether a frame arrives and with what RSSI/delay.
pub trait PropagationModel: Send + Sync {
    fn deliver(&self, ctx: &TxContext) -> Delivery;

    /// An upper bound on the distance at which `deliver` can ever return `delivered = true`
    /// (ignoring environment, which only *reduces* range). Bounds the spatial-index query so
    /// `transmit` never scans the whole world.
    fn max_range_m(&self) -> f64;
}

/// Simplest useful model: a hard range disc. Inside `range_m` the frame always arrives;
/// outside it never does. RSSI falls off linearly across the disc (for plumbing telemetry).
pub struct RangeThreshold {
    pub range_m: f64,
    pub tx_power_dbm: f64,
}

impl Default for RangeThreshold {
    fn default() -> Self {
        Self {
            range_m: 100.0,
            tx_power_dbm: 20.0,
        }
    }
}

/// A perfect broadcast medium: every receiver hears every send at full strength, no attenuation, no
/// distance dependence (up to a generous `max_range_m` that only bounds the spatial query). Paired
/// with the default no-interference bus, this is a **collision-free all-hear-all segment** — the
/// natural home for sync/discovery protocols, with no geometry to reason about. See
/// [`Simulation::broadcast_segment`](crate::Simulation::broadcast_segment) for the one-call sugar.
#[derive(Clone, Copy, Debug)]
pub struct PerfectPropagation {
    /// The constant RSSI reported to receivers (telemetry only; delivery is unconditional).
    pub rssi_dbm: f64,
    /// Bounds the spatial-index query (keep members within this of each other). Delivery itself is
    /// distance-independent; this only stops `transmit` scanning an unbounded grid.
    pub max_range_m: f64,
}

impl Default for PerfectPropagation {
    fn default() -> Self {
        Self {
            rssi_dbm: -30.0,
            max_range_m: 1000.0,
        }
    }
}

impl PropagationModel for PerfectPropagation {
    fn deliver(&self, ctx: &TxContext) -> Delivery {
        Delivery {
            delivered: true,
            rssi_dbm: self.rssi_dbm,
            delay: ctx.propagation_delay(),
            reason: DeliveryReason::Delivered,
        }
    }
    fn max_range_m(&self) -> f64 {
        self.max_range_m
    }
}

impl PropagationModel for RangeThreshold {
    fn deliver(&self, ctx: &TxContext) -> Delivery {
        let d = ctx.distance();
        let delivered = d <= self.range_m;
        // Linear fade from tx_power at 0 m to tx_power − 60 dB at the edge (telemetry only).
        let frac = (d / self.range_m).clamp(0.0, 1.0);
        Delivery {
            delivered,
            rssi_dbm: self.tx_power_dbm - 60.0 * frac,
            delay: ctx.propagation_delay(),
            reason: if delivered {
                DeliveryReason::Delivered
            } else {
                DeliveryReason::OutOfRange
            },
        }
    }
    fn max_range_m(&self) -> f64 {
        self.range_m
    }
}

/// Textbook Friis free-space path loss. Received power
/// `Prx = Ptx − FSPL(d, f) − env_attenuation`, delivered when `Prx ≥ sensitivity`, with FSPL from
/// [`free_space_path_loss_db`].
pub struct FreeSpacePathLoss {
    pub tx_power_dbm: f64,
    pub freq_hz: f64,
    pub rx_sensitivity_dbm: f64,
}

impl Default for FreeSpacePathLoss {
    fn default() -> Self {
        // 20 dBm (100 mW), 2.4 GHz, −85 dBm sensitivity ⇒ ~hundreds of m free-space.
        Self {
            tx_power_dbm: 20.0,
            freq_hz: 2.4e9,
            rx_sensitivity_dbm: -85.0,
        }
    }
}

impl PropagationModel for FreeSpacePathLoss {
    fn deliver(&self, ctx: &TxContext) -> Delivery {
        let d = ctx.distance();
        // H5: received power uses the SENDER's per-node TX power (`ctx.tx_power_dbm`, set from
        // set_tx_power), not the model's fixed default — so the power dial actually moves RSSI / reach /
        // delivery (was `self.tx_power_dbm`, which made a reach-vs-power study conclude "lowering power is
        // free"). `self.tx_power_dbm` stays the widest-case anchor for `max_range_m`.
        let prx = ctx.tx_power_dbm
            - free_space_path_loss_db(d, self.freq_hz)
            - ctx.environment.attenuation(ctx.tx_pos, ctx.rx_pos);
        let delivered = prx >= self.rx_sensitivity_dbm;
        Delivery {
            delivered,
            rssi_dbm: prx,
            delay: ctx.propagation_delay(),
            reason: if delivered {
                DeliveryReason::Delivered
            } else {
                DeliveryReason::Weak
            },
        }
    }

    fn max_range_m(&self) -> f64 {
        // Solve Ptx − sens = 20·log10(d) + 20·log10(f) + K (env-free, the widest case).
        let lhs =
            self.tx_power_dbm - self.rx_sensitivity_dbm - 20.0 * self.freq_hz.log10() - FSPL_K;
        10f64.powf(lhs / 20.0)
    }
}

/// Decides whether concurrent in-air frames collide at a receiver. The [`RadioBus`](crate::RadioBus)
/// consults it with its in-air tracking; the default there is [`CarrierSenseInterference`].
pub trait InterferenceModel: Send + Sync {
    fn collides(&self, _rx: NodeId, _concurrent_senders: &[NodeId]) -> bool {
        false
    }
}

/// No collisions ever (the collision-free idealization).
pub struct NoInterference;
impl InterferenceModel for NoInterference {}

/// Carrier-sense collision: a frame is lost at a receiver if *any* other in-range transmitter
/// is mid-frame when it arrives (the hidden-terminal / concurrent-transmission failure). Used by
/// [`RadioBus`](crate::RadioBus) with its in-air tracking.
pub struct CarrierSenseInterference;
impl InterferenceModel for CarrierSenseInterference {
    fn collides(&self, _rx: NodeId, concurrent_senders: &[NodeId]) -> bool {
        !concurrent_senders.is_empty()
    }
}

/// How much a transmitter on one channel interferes with a signal on another — a **pluggable**
/// channel model (like [`PropagationModel`]/[`InterferenceModel`]) so the fidelity can grow over
/// time (measured ACLR masks, guard bands, overlapping-but-not-adjacent DSSS/OFDM spectra, …).
/// Returns a coupling in `[0, 1]`: `1.0` = co-channel (full collision), `0.0` = fully orthogonal,
/// in between = **side-band leakage** — because real channels are not perfectly orthogonal.
pub trait ChannelModel: Send + Sync {
    fn coupling(&self, interferer_ch: u8, signal_ch: u8) -> f64;
}

/// The naive default: perfectly orthogonal channels (co-channel = 1, everything else = 0). Real
/// radios do not behave like this — use it only as a baseline.
pub struct OrthogonalChannels;
impl ChannelModel for OrthogonalChannels {
    fn coupling(&self, a: u8, b: u8) -> f64 {
        if a == b { 1.0 } else { 0.0 }
    }
}

/// Adjacent-channel leakage: co-channel interferes fully; a neighbour ±1 leaks at `adjacent`; ±2 at
/// `adjacent²`; beyond that, negligible. A crude but honest side-band model — raise `adjacent` for
/// poorly-filtered front ends / narrow guard bands, lower it for well-separated channels. The point
/// is that "put the flows on different channels" is not a free 1/K: adjacent channels still couple.
pub struct AdjacentLeakChannel {
    /// Coupling to an immediately-adjacent channel (≈ the inverse adjacent-channel rejection ratio).
    pub adjacent: f64,
}
impl Default for AdjacentLeakChannel {
    fn default() -> Self {
        Self { adjacent: 0.2 } // ~ −7 dB ACLR — deliberately pessimistic; tune per radio
    }
}
impl ChannelModel for AdjacentLeakChannel {
    fn coupling(&self, a: u8, b: u8) -> f64 {
        match a.abs_diff(b) {
            0 => 1.0,
            1 => self.adjacent,
            2 => self.adjacent * self.adjacent,
            _ => 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::world::FreeSpace;

    fn deliver(prop: &dyn PropagationModel, rx: Position) -> Delivery {
        prop.deliver(&TxContext {
            tx_pos: Position::xy(0.0, 0.0),
            rx_pos: rx,
            tx_power_dbm: 20.0,
            environment: &FreeSpace,
            frame_len: 100,
        })
    }

    #[test]
    fn range_threshold_delivers_only_inside_its_disc() {
        let prop = RangeThreshold {
            range_m: 100.0,
            tx_power_dbm: 20.0,
        };
        let near = deliver(&prop, Position::xy(50.0, 0.0));
        assert!(near.delivered);
        assert_eq!(near.reason, DeliveryReason::Delivered);
        let far = deliver(&prop, Position::xy(500.0, 0.0));
        assert!(!far.delivered);
        assert_eq!(far.reason, DeliveryReason::OutOfRange);
    }

    #[test]
    fn fspl_rssi_decreases_with_distance_and_cuts_off_at_max_range() {
        let prop = FreeSpacePathLoss::default();
        let max = prop.max_range_m();
        let d10 = deliver(&prop, Position::xy(10.0, 0.0));
        let d100 = deliver(&prop, Position::xy(100.0, 0.0));
        assert!(d10.delivered && d100.delivered);
        assert!(
            d10.rssi_dbm > d100.rssi_dbm,
            "closer node has stronger RSSI"
        );
        // max_range_m is the exact sensitivity crossing: just inside delivers, just past does not.
        assert!(deliver(&prop, Position::xy(max * 0.99, 0.0)).delivered);
        let past = deliver(&prop, Position::xy(max * 1.01, 0.0));
        assert!(!past.delivered, "node past max range is unreachable");
        assert_eq!(past.reason, DeliveryReason::Weak);
    }

    /// The Friis anchor: at 100 m / 2.4 GHz free space loses ≈ 80.05 dB (the textbook figure).
    #[test]
    fn free_space_path_loss_matches_friis() {
        let loss = free_space_path_loss_db(100.0, 2.4e9);
        assert!(
            (loss - 80.05).abs() < 0.05,
            "FSPL(100 m, 2.4 GHz) = {loss} dB"
        );
        assert_eq!(
            free_space_path_loss_db(0.2, 2.4e9),
            free_space_path_loss_db(1.0, 2.4e9),
            "sub-metre distances clamp to the 1 m loss"
        );
    }
}
