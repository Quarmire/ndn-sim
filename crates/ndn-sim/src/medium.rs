//! The wireless **medium** (ndn-lab slice 3): one `transmit` fans a frame out to every
//! in-range receiver, and a [`PropagationModel`] decides per `(tx, rx)` pair whether it
//! arrives, with what RSSI, after what delay.
//!
//! This is the *physics* layer and it is **deterministic by construction** — given node
//! positions it always delivers the same way. Randomness that belongs to the radio (per-MPDU
//! erasure from `measure::LinkModel`, collisions) is layered on in slice 4 when the
//! named-radio face plugs onto this medium; the medium keeps the seam open via
//! [`InterferenceModel`] but defaults to none.
//!
//! Relationship to the wired path: [`SimLink`](crate::SimLink) is the degenerate *static
//! channel* (a fixed P2P pipe); the [`WirelessMedium`] is the shared, position-driven one.
//! Both deliver frames after a delay over Tokio channels, so both are virtual under a
//! [`VirtualKernel`](crate::VirtualKernel).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::NodeId;
use crate::world::{Environment, Position, World, WorldView};

/// Speed of light, m/s — propagation delay is `distance / C`.
const C: f64 = 299_792_458.0;

/// A frame that survived propagation, handed to a receiver. In slice 4 the named-radio face
/// enriches this into a `CapturedFrame { rssi, mcs, addr, group }`; here it carries the
/// minimum the medium can know: who sent it and at what signal strength.
#[derive(Clone, Debug)]
pub struct ReceivedFrame {
    pub from: NodeId,
    pub rssi_dbm: f64,
    pub bytes: Bytes,
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
/// `Prx = Ptx − FSPL(d, f) − env_attenuation`, delivered when `Prx ≥ sensitivity`.
/// `FSPL_dB = 20·log10(d) + 20·log10(f) − 147.55`.
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

impl FreeSpacePathLoss {
    /// `20·log10(4π/c)` ≈ −147.55 dB.
    const FSPL_K: f64 = -147.55;

    fn fspl_db(&self, d: f64) -> f64 {
        if d <= 1.0 {
            // Avoid the log singularity / negative loss at sub-metre range.
            return 20.0 * self.freq_hz.log10() + Self::FSPL_K;
        }
        20.0 * d.log10() + 20.0 * self.freq_hz.log10() + Self::FSPL_K
    }
}

impl PropagationModel for FreeSpacePathLoss {
    fn deliver(&self, ctx: &TxContext) -> Delivery {
        let d = ctx.distance();
        let prx = self.tx_power_dbm
            - self.fspl_db(d)
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
        let lhs = self.tx_power_dbm
            - self.rx_sensitivity_dbm
            - 20.0 * self.freq_hz.log10()
            - Self::FSPL_K;
        10f64.powf(lhs / 20.0)
    }
}

/// Decides whether concurrent in-air frames collide at a receiver. Defaulted to none for
/// slice 3; the named-radio face supplies a real one (CSMA/EDCCA) in a later slice.
pub trait InterferenceModel: Send + Sync {
    fn collides(&self, _rx: NodeId, _concurrent_senders: &[NodeId]) -> bool {
        false
    }
}

/// No collisions ever (the default).
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

/// A shared, position-driven broadcast medium. Radios [`attach`](Self::attach) to get a
/// receiver; a [`transmit`](Self::transmit) fans the frame to every node the
/// [`PropagationModel`] can reach (found via the world's spatial index), each after its own
/// propagation delay.
pub struct WirelessMedium {
    world: Arc<World>,
    propagation: Arc<dyn PropagationModel>,
    #[allow(dead_code)] // seam for slice-4 collision modelling
    interference: Arc<dyn InterferenceModel>,
    /// World epoch in nanoseconds — `transmit`'s `now_ns` is converted to seconds-since-epoch
    /// to query mobility. Matches the engine's `unix_nanos` clock.
    epoch_ns: u64,
    /// Clock + executor seam for delayed delivery (runs on any kernel, never `tokio::time`).
    runtime: Arc<dyn ndn_runtime::Runtime>,
    receivers: Mutex<HashMap<NodeId, mpsc::UnboundedSender<ReceivedFrame>>>,
    /// Per-instant snapshot cache `(now_ns, world_generation, view)` — so a burst of transmits
    /// at the same virtual instant rebuilds the `SpatialGrid` once, not per packet (the
    /// "snapshot per tick" the design calls for; recovers O(local) range queries).
    view_cache: Mutex<Option<(u64, u64, Arc<WorldView>)>>,
}

impl WirelessMedium {
    /// A medium over `world` using `propagation`, with the world epoch set to `epoch_ns`
    /// (the kernel's `unix_nanos` at t=0). Defaults to no interference + the Tokio runtime; use
    /// [`new_on`](Self::new_on) to run delivery on a specific kernel.
    pub fn new(world: Arc<World>, propagation: Arc<dyn PropagationModel>, epoch_ns: u64) -> Self {
        Self::new_on(world, propagation, epoch_ns, ndn_runtime::default_runtime())
    }

    /// [`new`](Self::new) on a specific [`Runtime`](ndn_runtime::Runtime).
    pub fn new_on(
        world: Arc<World>,
        propagation: Arc<dyn PropagationModel>,
        epoch_ns: u64,
        runtime: Arc<dyn ndn_runtime::Runtime>,
    ) -> Self {
        Self {
            world,
            propagation,
            interference: Arc::new(NoInterference),
            epoch_ns,
            runtime,
            receivers: Mutex::new(HashMap::new()),
            view_cache: Mutex::new(None),
        }
    }

    pub fn with_interference(mut self, model: Arc<dyn InterferenceModel>) -> Self {
        self.interference = model;
        self
    }

    /// Attach `node` as a radio on this medium; returns the channel its received frames land
    /// on. Re-attaching replaces the previous receiver. The channel is **unbounded**: buffering
    /// never drops or stalls, so loss is purely the propagation model — not consumer scheduling.
    pub fn attach(&self, node: NodeId) -> mpsc::UnboundedReceiver<ReceivedFrame> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.receivers.lock().unwrap().insert(node, tx);
        rx
    }

    /// Detach `node` (its sender is dropped; in-flight deliveries to it are discarded).
    pub fn detach(&self, node: NodeId) {
        self.receivers.lock().unwrap().remove(&node);
    }

    fn t_secs(&self, now_ns: u64) -> f64 {
        now_ns.saturating_sub(self.epoch_ns) as f64 / 1e9
    }

    /// The world snapshot for `now_ns`, reusing the cached one when neither the instant nor the
    /// world has changed (keyed on `(now_ns, world.generation())`).
    fn view_at(&self, now_ns: u64) -> Arc<WorldView> {
        let generation = self.world.generation();
        let mut cache = self.view_cache.lock().unwrap();
        if let Some((cn, cg, view)) = cache.as_ref()
            && *cn == now_ns
            && *cg == generation
        {
            return Arc::clone(view);
        }
        let view = Arc::new(self.world.snapshot(self.t_secs(now_ns)));
        *cache = Some((now_ns, generation, Arc::clone(&view)));
        view
    }

    /// Broadcast `frame` from `node` at virtual time `now_ns`. Returns the list of receivers
    /// the frame was (or will be) delivered to, with their computed RSSI — useful for tests
    /// and telemetry. Each delivery is scheduled after its own propagation delay (virtual
    /// under a [`VirtualKernel`](crate::VirtualKernel)).
    pub fn transmit(&self, node: NodeId, frame: Bytes, now_ns: u64) -> Vec<(NodeId, f64)> {
        let view = self.view_at(now_ns);
        let Some(tx_pos) = view.position(node) else {
            return Vec::new(); // unplaced sender ⇒ heard by no one
        };
        let env = self.world.environment();

        let mut delivered = Vec::new();
        let receivers = self.receivers.lock().unwrap();
        // Spatial index bounds this to nearby nodes (never the whole world).
        for rx_node in view.within_range(tx_pos, self.propagation.max_range_m()) {
            if rx_node == node {
                continue; // a radio does not hear itself
            }
            let Some(rx_pos) = view.position(rx_node) else {
                continue;
            };
            let Some(sender) = receivers.get(&rx_node).cloned() else {
                continue;
            };

            let ctx = TxContext {
                tx_pos,
                rx_pos,
                tx_power_dbm: 20.0,
                environment: env.as_ref(),
                frame_len: frame.len(),
            };
            let d = self.propagation.deliver(&ctx);
            if !d.delivered {
                continue;
            }
            delivered.push((rx_node, d.rssi_dbm));

            let rf = ReceivedFrame {
                from: node,
                rssi_dbm: d.rssi_dbm,
                bytes: frame.clone(),
            };
            if d.delay.is_zero() {
                let _ = sender.send(rf);
            } else {
                let delay = d.delay;
                let rt = Arc::clone(&self.runtime);
                self.runtime.spawn(Box::pin(async move {
                    rt.sleep(delay).await;
                    let _ = sender.send(rf);
                }));
            }
        }
        delivered.sort_by_key(|(n, _)| n.0);
        delivered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::world::{LinearMobility, World};

    fn medium_with(
        positions: &[(NodeId, Position)],
        prop: Arc<dyn PropagationModel>,
    ) -> WirelessMedium {
        let world = World::new();
        for (id, p) in positions {
            world.place(*id, *p);
        }
        WirelessMedium::new(Arc::new(world), prop, 0)
    }

    #[tokio::test]
    async fn range_threshold_fans_out_only_to_in_range() {
        let medium = medium_with(
            &[
                (NodeId(0), Position::xy(0.0, 0.0)),
                (NodeId(1), Position::xy(50.0, 0.0)), // in range
                (NodeId(2), Position::xy(500.0, 0.0)), // out of range
            ],
            Arc::new(RangeThreshold {
                range_m: 100.0,
                tx_power_dbm: 20.0,
            }),
        );
        let mut r1 = medium.attach(NodeId(1));
        let mut r2 = medium.attach(NodeId(2));

        let hit = medium.transmit(NodeId(0), Bytes::from_static(b"hi"), 0);
        assert_eq!(
            hit.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![NodeId(1)]
        );

        // Node 1 hears it; node 2 (out of range) gets nothing.
        let got = tokio::time::timeout(Duration::from_millis(50), r1.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.bytes, &b"hi"[..]);
        assert_eq!(got.from, NodeId(0));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), r2.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn fspl_rssi_decreases_with_distance_and_cuts_off() {
        let prop = Arc::new(FreeSpacePathLoss::default());
        let max = prop.max_range_m();
        let medium = medium_with(
            &[
                (NodeId(0), Position::xy(0.0, 0.0)),
                (NodeId(1), Position::xy(10.0, 0.0)),
                (NodeId(2), Position::xy(100.0, 0.0)),
                (NodeId(3), Position::xy(max * 2.0, 0.0)), // far beyond sensitivity
            ],
            prop,
        );
        medium.attach(NodeId(1));
        medium.attach(NodeId(2));
        medium.attach(NodeId(3));

        let hit = medium.transmit(NodeId(0), Bytes::from_static(b"x"), 0);
        let rssi: HashMap<NodeId, f64> = hit.iter().copied().collect();
        assert!(rssi.contains_key(&NodeId(1)) && rssi.contains_key(&NodeId(2)));
        assert!(
            !rssi.contains_key(&NodeId(3)),
            "node past max range is unreachable"
        );
        assert!(
            rssi[&NodeId(1)] > rssi[&NodeId(2)],
            "closer node has stronger RSSI"
        );
    }

    /// The medium is deterministic by construction: identical positions ⇒ identical fan-out
    /// and RSSI, every run.
    #[tokio::test]
    async fn transmit_is_reproducible() {
        let positions = [
            (NodeId(0), Position::xy(0.0, 0.0)),
            (NodeId(1), Position::xy(30.0, 10.0)),
            (NodeId(2), Position::xy(70.0, 40.0)),
        ];
        let run = || {
            let m = medium_with(&positions, Arc::new(FreeSpacePathLoss::default()));
            m.attach(NodeId(1));
            m.attach(NodeId(2));
            m.transmit(NodeId(0), Bytes::from_static(b"x"), 0)
        };
        assert_eq!(run(), run());
    }

    /// A moving node crosses into range over (virtual) time — the snapshot at `now_ns`
    /// reflects the world at that instant.
    #[tokio::test(start_paused = true)]
    async fn mobility_brings_node_into_range() {
        let world = World::new();
        world.place(NodeId(0), Position::xy(0.0, 0.0));
        // Node 1 starts 500 m away, approaches at 100 m/s along −x.
        world.set_mobility(
            NodeId(1),
            Arc::new(LinearMobility {
                start: Position::xy(500.0, 0.0),
                velocity: (-100.0, 0.0, 0.0),
            }),
        );
        let medium = WirelessMedium::new(
            Arc::new(world),
            Arc::new(RangeThreshold {
                range_m: 100.0,
                tx_power_dbm: 20.0,
            }),
            0,
        );
        medium.attach(NodeId(1));

        // t = 0 s: 500 m away ⇒ out of range.
        assert!(
            medium
                .transmit(NodeId(0), Bytes::from_static(b"a"), 0)
                .is_empty()
        );
        // t = 4.5 s: 500 − 450 = 50 m ⇒ in range.
        let now = 4_500_000_000u64;
        let hit = medium.transmit(NodeId(0), Bytes::from_static(b"b"), now);
        assert_eq!(
            hit.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
            vec![NodeId(1)]
        );
    }
}
