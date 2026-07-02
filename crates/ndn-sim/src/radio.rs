//! The named-radio **simulated face** (ndn-lab slice 4): a real `ForwarderEngine` face whose
//! "wire" is a position-driven broadcast medium with an 802.11n link model — no driver, no
//! kernel, no calibration.
//!
//! Two pieces:
//! - [`RadioBus`] — the radio analogue of `ndn-frame-io`'s `LoopbackMonitorBus`, but RSSI is
//!   *pairwise* (from [`World`] positions via a [`PropagationModel`]) instead of a fixed
//!   per-endpoint constant, and each delivery survives an independent **per-frame erasure**
//!   drawn from a [`LinkModel`] (`p = frame_delivery(mcs, snr)`). The erasure is the *only*
//!   randomness; it uses a seeded RNG so a run is reproducible under a
//!   [`VirtualKernel`](crate::VirtualKernel).
//! - [`SimRadioFace`] — implements [`Transport`] (`FaceKind::Wfb`, `LinkType::AdHoc`, an MTU
//!   that drives LP fragmentation), broadcasts on send, and on receive publishes
//!   [`LinkSignals`] (rssi / snr / phy-rate / mcs) into a [`SignalsTable`] exactly as the real
//!   monitor-wifi face would — so the cognitive/measured strategies above it behave the same.
//!
//! What's faithfully reused vs. the real stack: the MCS rate table, RSSI→MCS heuristic, and
//! reliable-rate ceiling come straight from [`ndn_frame_io`]; the signal surface is the real
//! [`ndn_signals_core::LinkSignals`]. What's *net-new* over the loopback bus: pairwise RSSI
//! (range), per-frame loss, and adaptive MCS from heard signal.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use ndn_frame_io::{MAX_RELIABLE_MCS, MONITOR_MTU, mcs_phy_rate_bps};
use ndn_runtime::Runtime;
use ndn_signals_core::{LinkSignals, SignalStore};
use ndn_strategy::signals::SignalsTable;
use ndn_transport::{FaceAddr, FaceError, FaceId, FaceKind, LinkType, Transport};
use rand::{Rng, SeedableRng, rngs::StdRng};
use tokio::sync::mpsc;
use tracing::trace;

use crate::NodeId;
use crate::link_model::LinkModel;
use crate::medium::{InterferenceModel, PropagationModel, TxContext};
use crate::world::{Position, World};

/// A frame that propagated *and* survived erasure, handed to a receiving radio.
#[derive(Clone, Debug)]
pub struct RadioRx {
    pub from: NodeId,
    pub rssi_dbm: f64,
    pub mcs_index: u8,
    pub bytes: Bytes,
}

/// How a radio picks its transmit MCS.
#[derive(Clone, Copy, Debug)]
pub enum RadioMcs {
    /// A fixed MCS index (clamped to [`MAX_RELIABLE_MCS`]).
    Fixed(u8),
    /// Adapt to the *weakest* heard peer (conservative for a broadcast), via
    /// [`LinkModel::best_mcs`]. Starts at the most robust rate before anything is heard.
    Adaptive,
}

/// The shared radio medium. Radios [`attach`](Self::attach) to get a receiver; a
/// [`transmit`](Self::transmit) broadcasts to every in-range node, each delivery gated by the
/// [`LinkModel`] erasure for that pair's SNR.
pub struct RadioBus {
    world: Arc<World>,
    propagation: Arc<dyn PropagationModel>,
    link_model: LinkModel,
    interference: Arc<dyn InterferenceModel>,
    /// World epoch (ns) — `transmit`'s `now_ns` minus this gives seconds for mobility.
    epoch_ns: u64,
    tx_power_dbm: f64,
    /// Clock + executor seam for delayed delivery — so a radio fabric runs on any kernel
    /// (wall-clock, virtual, discrete-event), never `tokio::time` directly.
    runtime: Arc<dyn Runtime>,
    rng: Mutex<StdRng>,
    receivers: Mutex<HashMap<NodeId, mpsc::UnboundedSender<RadioRx>>>,
    /// Frames currently on the air `(sender, start_ns, end_ns)` — for collision detection.
    in_air: Mutex<Vec<(NodeId, u64, u64)>>,
    /// Per-instant world-snapshot cache `(now_ns, world_generation, view)` — rebuild the
    /// spatial index once per instant, not per transmit.
    view_cache: Mutex<Option<(u64, u64, Arc<crate::world::WorldView>)>>,
    /// Optional causal capture (axis 4): every delivery decision, with its reason, for `explain`.
    radio_log: Mutex<Option<Arc<crate::analysis::RadioLog>>>,
}

impl RadioBus {
    /// A bus over `world` using `propagation` for RSSI, with the world epoch at `epoch_ns` and
    /// the erasure RNG seeded by `seed` (fix it for reproducible runs).
    pub fn new(
        world: Arc<World>,
        propagation: Arc<dyn PropagationModel>,
        epoch_ns: u64,
        seed: u64,
    ) -> Arc<Self> {
        Self::build(
            world,
            propagation,
            epoch_ns,
            seed,
            Arc::new(crate::medium::NoInterference),
            ndn_runtime::default_runtime(),
        )
    }

    /// Build a bus that models collisions with `interference` (e.g.
    /// [`CarrierSenseInterference`](crate::medium::CarrierSenseInterference)). The bus tracks
    /// frame airtime (from MCS PHY rate) so concurrent in-range transmissions collide.
    pub fn with_interference(
        world: Arc<World>,
        propagation: Arc<dyn PropagationModel>,
        epoch_ns: u64,
        seed: u64,
        interference: Arc<dyn InterferenceModel>,
    ) -> Arc<Self> {
        Self::build(world, propagation, epoch_ns, seed, interference, ndn_runtime::default_runtime())
    }

    /// [`new`](Self::new) but on a specific [`Runtime`] — delivery timing rides it, so the radio
    /// medium runs on whatever kernel drives the fabric (this is what the fabric uses).
    pub fn new_on(
        world: Arc<World>,
        propagation: Arc<dyn PropagationModel>,
        epoch_ns: u64,
        seed: u64,
        runtime: Arc<dyn Runtime>,
    ) -> Arc<Self> {
        Self::build(world, propagation, epoch_ns, seed, Arc::new(crate::medium::NoInterference), runtime)
    }

    fn build(
        world: Arc<World>,
        propagation: Arc<dyn PropagationModel>,
        epoch_ns: u64,
        seed: u64,
        interference: Arc<dyn InterferenceModel>,
        runtime: Arc<dyn Runtime>,
    ) -> Arc<Self> {
        Arc::new(Self {
            world,
            propagation,
            link_model: LinkModel::new(),
            interference,
            epoch_ns,
            tx_power_dbm: 20.0,
            runtime,
            rng: Mutex::new(StdRng::seed_from_u64(seed)),
            receivers: Mutex::new(HashMap::new()),
            in_air: Mutex::new(Vec::new()),
            view_cache: Mutex::new(None),
            radio_log: Mutex::new(None),
        })
    }

    /// Attach a [`RadioLog`](crate::analysis::RadioLog): from now on, every delivery decision is
    /// recorded with its cause — the evidence [`explain_link`](crate::analysis::explain_link) reads.
    pub fn set_radio_log(&self, log: Arc<crate::analysis::RadioLog>) {
        *self.radio_log.lock().unwrap() = Some(log);
    }

    pub fn link_model(&self) -> &LinkModel {
        &self.link_model
    }

    /// The RSSI (dBm) a receiver at `rx` would hear from a transmitter at `tx`, or `None` if the
    /// pair is below sensitivity (out of range). For the scene's radio reachability edges.
    pub fn link_rssi(&self, tx: Position, rx: Position) -> Option<f64> {
        let env = self.world.environment();
        let d = self.propagation.deliver(&TxContext {
            tx_pos: tx,
            rx_pos: rx,
            tx_power_dbm: self.tx_power_dbm,
            environment: env.as_ref(),
            frame_len: 0,
        });
        d.delivered.then_some(d.rssi_dbm)
    }

    /// Attach `node` as a radio; returns the channel its surviving frames land on. **Unbounded**:
    /// loss is purely the link model's seeded erasure, never buffer pressure or consumer timing.
    pub fn attach(&self, node: NodeId) -> mpsc::UnboundedReceiver<RadioRx> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.receivers.lock().unwrap().insert(node, tx);
        rx
    }

    /// World snapshot for `now_ns`, reusing the cached one when neither the instant nor the world
    /// changed (keyed on `(now_ns, world.generation())`).
    fn view_at(&self, now_ns: u64) -> Arc<crate::world::WorldView> {
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

    pub fn detach(&self, node: NodeId) {
        self.receivers.lock().unwrap().remove(&node);
    }

    fn t_secs(&self, now_ns: u64) -> f64 {
        now_ns.saturating_sub(self.epoch_ns) as f64 / 1e9
    }

    /// Broadcast `frame` from `node` at MCS `mcs_index` and virtual time `now_ns`. Returns
    /// `(receiver, rssi_dbm, delivered)` for every in-range node (whether or not it survived
    /// erasure) — for tests and telemetry. Survivors are delivered after their propagation
    /// delay (virtual under a [`VirtualKernel`](crate::VirtualKernel)).
    pub fn transmit(
        &self,
        node: NodeId,
        mcs_index: u8,
        frame: Bytes,
        now_ns: u64,
    ) -> Vec<(NodeId, f64, bool)> {
        let view = self.view_at(now_ns);
        let Some(tx_pos) = view.position(node) else {
            return Vec::new();
        };
        let env = self.world.environment();

        // This frame's airtime (bits / PHY rate) → its on-air window. Snapshot the *other*
        // frames overlapping the start instant (concurrent transmitters) before recording ours.
        // Collision model: the newcomer loses at any receiver that also hears a concurrent
        // in-range transmitter (hidden-terminal). Deterministic — no RNG.
        let rate = mcs_phy_rate_bps(mcs_index).max(1) as u64;
        let airtime_ns = (frame.len() as u64).saturating_mul(8).saturating_mul(1_000_000_000) / rate;
        let end_ns = now_ns.saturating_add(airtime_ns);
        let concurrent: Vec<(NodeId, Position)> = {
            let mut in_air = self.in_air.lock().unwrap();
            in_air.retain(|(_, _, e)| *e > now_ns); // prune finished transmissions
            let snapshot: Vec<(NodeId, Position)> = in_air
                .iter()
                .filter(|(s, _, _)| *s != node)
                .filter_map(|(s, _, _)| view.position(*s).map(|p| (*s, p)))
                .collect();
            in_air.push((node, now_ns, end_ns));
            snapshot
        };
        let max_range = self.propagation.max_range_m();

        let mut out = Vec::new();
        let receivers = self.receivers.lock().unwrap();
        // NodeId-sorted (spatial index) ⇒ the erasure draws happen in a deterministic order.
        for rx_node in view.within_range(tx_pos, self.propagation.max_range_m()) {
            if rx_node == node {
                continue; // half-duplex: a radio never hears itself
            }
            let Some(rx_pos) = view.position(rx_node) else { continue };
            let Some(sender) = receivers.get(&rx_node).cloned() else { continue };

            let ctx = TxContext {
                tx_pos,
                rx_pos,
                tx_power_dbm: self.tx_power_dbm,
                environment: env.as_ref(),
                frame_len: frame.len(),
            };
            let dist = tx_pos.distance(rx_pos);
            let log_delivery = |delivered: bool, reason: crate::medium::DeliveryReason, rssi: f64| {
                if let Some(log) = self.radio_log.lock().unwrap().as_ref() {
                    log.record(crate::analysis::RadioDelivery {
                        t_ns: now_ns,
                        from: node,
                        to: rx_node,
                        delivered,
                        reason,
                        rssi_dbm: rssi,
                        distance_m: dist,
                    });
                }
            };
            let d = self.propagation.deliver(&ctx);
            if !d.delivered {
                log_delivery(false, d.reason, d.rssi_dbm);
                continue; // below receiver sensitivity / obstructed — not even detectable
            }
            // Collision: did this receiver also hear a concurrent (in-range) transmitter?
            let clashers: Vec<NodeId> = concurrent
                .iter()
                .filter(|(_, p)| p.distance(rx_pos) <= max_range)
                .map(|(s, _)| *s)
                .collect();
            if self.interference.collides(rx_node, &clashers) {
                out.push((rx_node, d.rssi_dbm, false));
                log_delivery(false, crate::medium::DeliveryReason::Collision, d.rssi_dbm);
                trace!(from = node.0, to = rx_node.0, "radio: frame lost to collision");
                continue;
            }
            let snr = LinkModel::snr_db(d.rssi_dbm);
            let p = self.link_model.frame_delivery(mcs_index, snr);
            let roll: f64 = self.rng.lock().unwrap().random();
            let survived = roll < p;
            out.push((rx_node, d.rssi_dbm, survived));
            log_delivery(
                survived,
                if survived { crate::medium::DeliveryReason::Delivered } else { crate::medium::DeliveryReason::Erased },
                d.rssi_dbm,
            );

            if survived {
                let rf = RadioRx { from: node, rssi_dbm: d.rssi_dbm, mcs_index, bytes: frame.clone() };
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
            } else {
                trace!(from = node.0, to = rx_node.0, mcs = mcs_index, snr, "radio: frame erased");
            }
        }
        out
    }
}

/// Map a node id to a stable, locally-administered 48-bit address (for `FaceAddr::Ether`).
fn node_addr(node: NodeId) -> [u8; 6] {
    let n = node.0 as u32;
    [0x02, 0x4e, (n >> 24) as u8, (n >> 16) as u8, (n >> 8) as u8, n as u8]
}

/// A simulated named-radio face on a [`RadioBus`]. Implements [`Transport`] so it plugs into
/// a `ForwarderEngine` with `engine.add_face(face, cancel)`.
pub struct SimRadioFace {
    id: FaceId,
    node: NodeId,
    bus: Arc<RadioBus>,
    rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<RadioRx>>,
    signals: Option<Arc<SignalsTable>>,
    mcs: RadioMcs,
    /// Last RSSI heard from each peer — drives [`RadioMcs::Adaptive`].
    heard: Mutex<HashMap<NodeId, f64>>,
    clock: Arc<dyn Runtime>,
}

impl SimRadioFace {
    /// Attach a radio for `node` to `bus`, with face id `id` and the kernel `clock` (used to
    /// stamp transmit time and signal staleness). Defaults to [`RadioMcs::Adaptive`] and no
    /// signal sink; refine with [`with_mcs`](Self::with_mcs) / [`with_signals`](Self::with_signals).
    pub fn new(id: FaceId, node: NodeId, bus: Arc<RadioBus>, clock: Arc<dyn Runtime>) -> Self {
        let rx = bus.attach(node);
        Self {
            id,
            node,
            bus,
            rx: tokio::sync::Mutex::new(rx),
            signals: None,
            mcs: RadioMcs::Adaptive,
            heard: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Publish per-link [`LinkSignals`] (rssi/snr/phy-rate/mcs) into `signals` on receive —
    /// the cross-layer surface measured strategies read.
    pub fn with_signals(mut self, signals: Arc<SignalsTable>) -> Self {
        self.signals = Some(signals);
        self
    }

    pub fn with_mcs(mut self, mcs: RadioMcs) -> Self {
        self.mcs = mcs;
        self
    }

    fn choose_mcs(&self) -> u8 {
        match self.mcs {
            RadioMcs::Fixed(m) => m.min(MAX_RELIABLE_MCS),
            RadioMcs::Adaptive => {
                let heard = self.heard.lock().unwrap();
                let min_rssi = heard.values().copied().fold(f64::INFINITY, f64::min);
                if min_rssi.is_finite() {
                    self.bus
                        .link_model()
                        .best_mcs(LinkModel::snr_db(min_rssi))
                        .unwrap_or(0)
                } else {
                    0 // nobody heard yet ⇒ the most robust rate
                }
            }
        }
    }

    fn observe(&self, from: NodeId, rssi_dbm: f64, mcs_index: u8) {
        self.heard.lock().unwrap().insert(from, rssi_dbm);
        if let Some(sig) = &self.signals {
            let mut s = LinkSignals {
                rssi_dbm: Some(rssi_dbm.round() as i8),
                snr_db: Some(LinkModel::snr_db(rssi_dbm).round() as i8),
                observed_tput_bps: Some(mcs_phy_rate_bps(mcs_index)),
                updated_ms: (self.clock.unix_nanos() / 1_000_000) as u32,
                ..Default::default()
            };
            s.ext_set("mcs", mcs_index as f32);
            sig.set_link(self.id, s);
        }
    }
}

impl Transport for SimRadioFace {
    fn id(&self) -> FaceId {
        self.id
    }

    fn kind(&self) -> FaceKind {
        FaceKind::Wfb
    }

    fn remote_uri(&self) -> Option<String> {
        Some(format!("sim-radio://node#{}", self.node.0))
    }

    fn link_type(&self) -> LinkType {
        LinkType::AdHoc
    }

    fn send_mtu(&self) -> Option<usize> {
        Some(MONITOR_MTU)
    }

    async fn send_bytes(&self, wire: Bytes) -> Result<(), FaceError> {
        let now = self.clock.unix_nanos();
        let mcs = self.choose_mcs();
        self.bus.transmit(self.node, mcs, wire, now);
        Ok(())
    }

    async fn recv_bytes(&self) -> Result<Bytes, FaceError> {
        self.recv_bytes_with_addr().await.map(|(b, _)| b)
    }

    async fn recv_bytes_with_addr(&self) -> Result<(Bytes, Option<FaceAddr>), FaceError> {
        let rf = self.rx.lock().await.recv().await.ok_or(FaceError::Closed)?;
        self.observe(rf.from, rf.rssi_dbm, rf.mcs_index);
        Ok((rf.bytes, Some(FaceAddr::Ether(node_addr(rf.from)))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::medium::FreeSpacePathLoss;
    use crate::world::{Position, World};

    fn bus_with(positions: &[(NodeId, Position)], seed: u64) -> Arc<RadioBus> {
        let world = World::new();
        for (id, p) in positions {
            world.place(*id, *p);
        }
        RadioBus::new(Arc::new(world), Arc::new(FreeSpacePathLoss::default()), 0, seed)
    }

    #[tokio::test]
    async fn close_link_delivers_far_link_erases() {
        // Node 1 is metres away (huge SNR); node 2 sits at the sensitivity edge.
        let max = FreeSpacePathLoss::default().max_range_m();
        let bus = bus_with(
            &[
                (NodeId(0), Position::xy(0.0, 0.0)),
                (NodeId(1), Position::xy(5.0, 0.0)),
                (NodeId(2), Position::xy(max * 0.98, 0.0)),
            ],
            1,
        );
        bus.attach(NodeId(1));
        bus.attach(NodeId(2));

        // Push aggressively (MCS7). Over many frames the close node gets ~all, the edge node
        // few-to-none (low SNR ⇒ low frame_delivery at MCS7).
        let (mut near, mut far) = (0usize, 0usize);
        for _ in 0..200 {
            for (rx, _rssi, ok) in bus.transmit(NodeId(0), 7, Bytes::from_static(b"x"), 0) {
                if ok && rx == NodeId(1) {
                    near += 1;
                }
                if ok && rx == NodeId(2) {
                    far += 1;
                }
            }
        }
        assert!(near > 190, "close, high-SNR link delivers nearly all: {near}/200");
        assert!(far < near, "edge link at MCS7 delivers far fewer: {far} vs {near}");
    }

    /// The erasure RNG is seeded ⇒ identical positions + seed replay the identical
    /// delivered/erased pattern.
    #[tokio::test]
    async fn erasure_is_reproducible_for_a_seed() {
        let positions = [
            (NodeId(0), Position::xy(0.0, 0.0)),
            // ~450 m ⇒ SNR sits right at the MCS5 threshold ⇒ a genuine mix of hits/misses.
            (NodeId(1), Position::xy(450.0, 0.0)),
        ];
        let run = || {
            let bus = bus_with(&positions, 42);
            bus.attach(NodeId(1));
            let mut pattern = Vec::new();
            for _ in 0..50 {
                let r = bus.transmit(NodeId(0), 5, Bytes::from_static(b"x"), 0);
                pattern.push(r.iter().map(|(_, _, ok)| *ok).collect::<Vec<_>>());
            }
            pattern
        };
        let a = run();
        let b = run();
        assert_eq!(a, b, "same seed + positions ⇒ identical erasure pattern");
        let hits: usize = a.iter().flatten().filter(|ok| **ok).count();
        assert!(hits > 0 && hits < 50, "a genuine mix, not all/none: {hits}/50");
    }

    #[tokio::test]
    async fn concurrent_transmissions_collide_under_carrier_sense() {
        use crate::medium::CarrierSenseInterference;
        let world = World::new();
        world.place(NodeId(0), Position::xy(0.0, 0.0)); // receiver
        world.place(NodeId(1), Position::xy(5.0, 0.0)); // sender 1
        world.place(NodeId(2), Position::xy(5.0, 1.0)); // sender 2 (also in range of rx)
        let bus = RadioBus::with_interference(
            Arc::new(world),
            Arc::new(FreeSpacePathLoss::default()),
            0,
            1,
            Arc::new(CarrierSenseInterference),
        );
        bus.attach(NodeId(0));

        // Both fire at t=0; sender 1 is still on the air when sender 2 starts.
        let r1 = bus.transmit(NodeId(1), 7, Bytes::from_static(b"aaaaaaaa"), 0);
        let r2 = bus.transmit(NodeId(2), 7, Bytes::from_static(b"aaaaaaaa"), 0);
        assert!(
            r1.iter().any(|(n, _, ok)| *n == NodeId(0) && *ok),
            "first frame reaches the receiver"
        );
        assert!(
            r2.iter().any(|(n, _, ok)| *n == NodeId(0) && !*ok),
            "the concurrent second frame collides at the receiver"
        );
    }

    #[tokio::test]
    async fn no_interference_lets_concurrent_frames_through() {
        let bus = bus_with(
            &[
                (NodeId(0), Position::xy(0.0, 0.0)),
                (NodeId(1), Position::xy(5.0, 0.0)),
                (NodeId(2), Position::xy(5.0, 1.0)),
            ],
            1,
        );
        bus.attach(NodeId(0));
        let r1 = bus.transmit(NodeId(1), 7, Bytes::from_static(b"aaaaaaaa"), 0);
        let r2 = bus.transmit(NodeId(2), 7, Bytes::from_static(b"aaaaaaaa"), 0);
        assert!(r1.iter().any(|(n, _, ok)| *n == NodeId(0) && *ok));
        assert!(r2.iter().any(|(n, _, ok)| *n == NodeId(0) && *ok), "no collision without a model");
    }
}
