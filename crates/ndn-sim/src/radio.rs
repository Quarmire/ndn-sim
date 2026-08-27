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
    /// The world seed — mixed into the per-link erasure hash so each link's realization is fixed by its
    /// own (tx, rx, instant, frame#) identity, independent of global draw order (see `erasure_roll`).
    seed: u64,
    /// Per-transmitter frame counter, mixed into the erasure hash so two distinct frames from the same
    /// node at the SAME virtual instant draw independently (not an identical roll). It is local to the
    /// sending node and advances in that node's own app-driven send order, so it stays independent of
    /// any other link's activity — preserving the order-independence the hashed roll buys.
    tx_seq: Mutex<HashMap<NodeId, u64>>,
    receivers: Mutex<HashMap<NodeId, mpsc::UnboundedSender<RadioRx>>>,
    /// Frames currently on the air `(sender, start_ns, end_ns, collided_rx)` — for collision detection.
    /// `collided_rx` is the shared set of receivers a *later* overlapping frame has retro-collided this
    /// one at, so both frames lose at a shared receiver (F2 both-lose, not first-caller-wins).
    in_air: Mutex<Vec<(NodeId, u64, u64, Arc<Mutex<std::collections::HashSet<NodeId>>>)>>,
    /// Per-instant world-snapshot cache `(now_ns, world_generation, view)` — rebuild the
    /// spatial index once per instant, not per transmit.
    view_cache: Mutex<Option<(u64, u64, Arc<crate::world::WorldView>)>>,
    /// Optional causal capture (axis 4): every delivery decision, with its reason, for `explain`.
    radio_log: Mutex<Option<Arc<crate::analysis::RadioLog>>>,
    /// The MAC discipline the airtime accounting assumes: `Monitor` (named-data radio) charges one
    /// broadcast per frame; `Managed` charges a unicast per in-range receiver (normal Wi-Fi loses
    /// NDN's multicast efficiency). Default `Monitor`.
    mac_mode: Mutex<crate::wifi::WifiMode>,
    /// Total airtime consumed on the medium (ns) — the cost NDN-over-monitor vs NDN-over-managed differ on.
    airtime_ns: std::sync::atomic::AtomicU64,
    /// Managed-mode ACK/retransmit budget: in `Managed` a frame's per-receiver delivery is
    /// retry-improved (`1−(1−p)^(retry+1)`) — the reliability normal Wi-Fi buys that monitor lacks.
    retry_limit: std::sync::atomic::AtomicU32,
    /// When set, concurrent in-range transmitters degrade a frame's **SINR** (their power adds to the
    /// noise) rather than only causing a binary collision — the capture effect. Opt-in (off preserves
    /// the simple collision model existing scenarios rely on).
    sinr_interference: std::sync::atomic::AtomicBool,
    /// Optional pluggable energy model; when set, `transmit` tallies per-node TX/RX joules.
    energy_model: Mutex<Option<Arc<dyn crate::energy::EnergyModel>>>,
    /// Per-node energy accounts (active TX+RX joules); idle is time-based, added by the caller.
    energy_acct: Mutex<crate::energy::EnergyAccounts>,
    /// Optional hardware name-filter (`node → registered name-group key`) for the MAC-offload
    /// accounting: a listed node pays host-processing energy only for `transmit_named` frames whose
    /// group matches its key; unlisted nodes (or unnamed frames) are promiscuous — the host sees all.
    host_filter: Mutex<Option<HashMap<NodeId, u64>>>,
    /// Per-node TX power override (dBm). A cognitive policy that trims power (spatial reuse / energy)
    /// sets it here; `transmit` then uses it for BOTH propagation (RSSI → delivery) and energy, so
    /// the power dial is a real trade-off. Unset nodes fall back to the bus-wide `tx_power_dbm`.
    tx_power: Mutex<HashMap<NodeId, f64>>,
    /// Per-node channel (unset = 0). With a `channel_model`, a concurrent transmitter only interferes
    /// per the channels' coupling — orthogonal channels don't collide, adjacent ones leak.
    channels: Mutex<HashMap<NodeId, u8>>,
    /// Pluggable channel-coupling model (side-band leakage). `None` = perfectly-orthogonal channels.
    channel_model: Mutex<Option<Arc<dyn crate::medium::ChannelModel>>>,
    /// Half-duplex: a radio mid-transmit cannot receive. Default ON (real broadcast radios are HD) —
    /// this is what makes a single-radio multi-hop chain degrade *worse* than 1/hop.
    half_duplex: std::sync::atomic::AtomicBool,
    /// Interference range as a multiple of the delivery (`max_range`). Real interference range exceeds
    /// the decode range (~1.5–2×), which limits spatial reuse and is *why* chains fall below 1/hop.
    /// Default 1.0 (interference = decode range) to preserve existing scenarios; studies raise it.
    interference_range_factor: Mutex<f64>,
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
            Arc::new(crate::medium::CarrierSenseInterference), // F3: physics ON by default; opt OUT via with_interference(NoInterference)
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
        Self::build(
            world,
            propagation,
            epoch_ns,
            seed,
            interference,
            ndn_runtime::default_runtime(),
        )
    }

    /// [`with_interference`](Self::with_interference) but on a specific [`Runtime`] — delivery
    /// timing rides it. Pass [`ImmediateRuntime`](crate::ImmediateRuntime) for a synchronous batch
    /// Monte-Carlo (no kernel, no real timers); pass a kernel's runtime for an event-driven run.
    pub fn with_interference_on(
        world: Arc<World>,
        propagation: Arc<dyn PropagationModel>,
        epoch_ns: u64,
        seed: u64,
        interference: Arc<dyn InterferenceModel>,
        runtime: Arc<dyn Runtime>,
    ) -> Arc<Self> {
        Self::build(world, propagation, epoch_ns, seed, interference, runtime)
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
        Self::build(
            world,
            propagation,
            epoch_ns,
            seed,
            Arc::new(crate::medium::CarrierSenseInterference), // F3: physics ON by default; opt OUT via with_interference(NoInterference)
            runtime,
        )
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
            seed,
            tx_seq: Mutex::new(HashMap::new()),
            receivers: Mutex::new(HashMap::new()),
            in_air: Mutex::new(Vec::new()),
            view_cache: Mutex::new(None),
            radio_log: Mutex::new(None),
            mac_mode: Mutex::new(crate::wifi::WifiMode::Monitor),
            airtime_ns: std::sync::atomic::AtomicU64::new(0),
            retry_limit: std::sync::atomic::AtomicU32::new(6),
            sinr_interference: std::sync::atomic::AtomicBool::new(false),
            energy_model: Mutex::new(None),
            energy_acct: Mutex::new(HashMap::new()),
            host_filter: Mutex::new(None),
            tx_power: Mutex::new(HashMap::new()),
            channels: Mutex::new(HashMap::new()),
            channel_model: Mutex::new(None),
            half_duplex: std::sync::atomic::AtomicBool::new(true),
            // F3: interference range ≈ 1.8× decode range so a transmitter outside decode range still
            // corrupts (hidden terminal) — the real CSMA failure mode. 1.0 hid all hidden-terminal loss.
            interference_range_factor: Mutex::new(1.8),
        })
    }

    /// Assign a node's channel (default 0). Combined with [`set_channel_model`](Self::set_channel_model),
    /// this makes multi-radio/multi-channel scenarios real: transmitters on orthogonal channels stop
    /// colliding, adjacent channels still leak.
    pub fn set_channel(&self, node: NodeId, channel: u8) {
        self.channels.lock().unwrap().insert(node, channel);
    }

    /// Install a pluggable [`ChannelModel`](crate::medium::ChannelModel) (side-band leakage). Without
    /// one, channels are treated as perfectly orthogonal (co-channel collides, else not).
    pub fn set_channel_model(&self, model: Arc<dyn crate::medium::ChannelModel>) {
        *self.channel_model.lock().unwrap() = Some(model);
    }

    /// Toggle the half-duplex constraint (a radio cannot receive while transmitting). Default ON.
    pub fn set_half_duplex(&self, on: bool) {
        self.half_duplex.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Set the interference range as a multiple of the decode range (default 1.0). Values >1 model the
    /// real "interference range exceeds decode range" effect that drops multi-hop throughput below 1/hop.
    pub fn set_interference_range_factor(&self, factor: f64) {
        *self.interference_range_factor.lock().unwrap() = factor.max(1.0);
    }

    fn channel_of(&self, node: NodeId) -> u8 {
        self.channels.lock().unwrap().get(&node).copied().unwrap_or(0)
    }

    /// Coupling between an interferer node and a signal on `signal_ch`, via the channel model
    /// (or perfectly-orthogonal if none installed).
    fn channel_coupling(&self, interferer: NodeId, signal_ch: u8) -> f64 {
        let ich = self.channel_of(interferer);
        match self.channel_model.lock().unwrap().as_ref() {
            Some(m) => m.coupling(ich, signal_ch),
            None => {
                if ich == signal_ch {
                    1.0
                } else {
                    0.0
                }
            }
        }
    }

    /// Override one node's TX power (dBm). Used for BOTH propagation (RSSI → delivery) and energy, so
    /// a policy that trims power really trades reach for joules. Clears back to the bus default with
    /// the bus-wide value. This is the actuator the cognitive power arm drives in the sim.
    pub fn set_tx_power(&self, node: NodeId, dbm: f64) {
        self.tx_power.lock().unwrap().insert(node, dbm);
    }

    /// Install a pluggable [`EnergyModel`](crate::energy::EnergyModel). Once set, `transmit` tallies
    /// per-node TX energy (the sender) and RX energy (every in-range radio — the "listen to
    /// everything" cost) into [`energy_accounts`](Self::energy_accounts). Off by default (no cost).
    pub fn set_energy_model(&self, model: Arc<dyn crate::energy::EnergyModel>) {
        *self.energy_model.lock().unwrap() = Some(model);
    }

    /// The per-node energy tally so far (empty if no [`EnergyModel`](crate::energy::EnergyModel) is
    /// installed). Idle draw is time-based — add `idle_power_w * run_seconds` per node from the model.
    pub fn energy_accounts(&self) -> crate::energy::EnergyAccounts {
        self.energy_acct.lock().unwrap().clone()
    }

    /// Install a hardware name-group filter (`node → registered group key`) for the MAC-offload
    /// accounting. A listed node then pays **host** processing energy only for [`transmit_named`]
    /// (Self::transmit_named) frames whose group matches its key — the radio drops the rest before
    /// the CPU wakes. Without it (default) every in-range host processes every frame (monitor mode).
    pub fn set_host_filter(&self, filter: HashMap<NodeId, u64>) {
        *self.host_filter.lock().unwrap() = Some(filter);
    }

    /// Set the MAC discipline for airtime accounting + reliability (`Monitor` = named-data radio, one
    /// broadcast per frame, no retries; `Managed` = normal Wi-Fi, a unicast per in-range receiver
    /// with ACK/retransmit-improved delivery).
    pub fn set_mac_mode(&self, mode: crate::wifi::WifiMode) {
        *self.mac_mode.lock().unwrap() = mode;
    }

    /// Whether the medium is in managed (CSMA) mode — the discipline that listens before talking.
    pub fn is_managed(&self) -> bool {
        matches!(*self.mac_mode.lock().unwrap(), crate::wifi::WifiMode::Managed)
    }

    /// F4 carrier-sense: the instant the medium clears for `node` — the latest `end_ns` among frames
    /// currently on the air within carrier-sense (interference) range on `node`'s channel. `None` if the
    /// medium is idle. A managed sender uses this to DEFER (listen-before-talk) rather than fire and
    /// collide, which is what actually serialises CSMA transmissions and yields its throughput advantage.
    pub fn sense_busy_until(&self, node: NodeId, now_ns: u64) -> Option<u64> {
        let view = self.view_at(now_ns);
        let node_pos = view.position(node)?;
        let node_ch = self.channel_of(node);
        let cs_range = self.propagation.max_range_m() * *self.interference_range_factor.lock().unwrap();
        let in_air = self.in_air.lock().unwrap();
        in_air
            .iter()
            .filter(|(s, _, e, _)| *s != node && *e > now_ns && self.channel_coupling(*s, node_ch) > 0.1)
            .filter_map(|(s, _, e, _)| view.position(*s).map(|p| (p, *e)))
            .filter(|(p, _)| p.distance(node_pos) <= cs_range)
            .map(|(_, e)| e)
            .max()
    }

    /// F4 CSMA backoff: a random number of 9 µs slots in `[0, CW]`, CW doubling from 15 (CWmin) per retry
    /// (capped at 1023, CWmax) — the exponential backoff that spreads simultaneous deferrers so one wins.
    pub fn csma_backoff_ns(&self, attempt: u32) -> u64 {
        let cw = (15u64 << attempt.min(6)).min(1023);
        let slots = (self.rng.lock().unwrap().random::<f64>() * (cw + 1) as f64) as u64;
        slots.min(cw) * 9_000
    }

    /// Order-independent per-link erasure draw in `[0, 1)`. Hashes `(seed, tx, rx, instant, frame#)`
    /// rather than pulling from one shared RNG in global order — so a link's realization is fixed by its
    /// OWN identity, and adding an unrelated (non-interfering) link no longer perturbs which frames this
    /// link erases. `frame_seq` (the sender's per-node counter) disambiguates distinct frames sent at the
    /// same virtual instant, which would otherwise collapse to one identical roll. The old shared `StdRng`
    /// coupled every link through draw order, which two executors need not match.
    fn erasure_roll(&self, tx: NodeId, rx: NodeId, now_ns: u64, frame_seq: u64) -> f64 {
        let mut h = 0xcbf2_9ce4_8422_2325u64; // FNV-1a over the key words…
        for w in [self.seed, tx.0 as u64, rx.0 as u64, now_ns, frame_seq] {
            h ^= w;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        // …then a splitmix64 finalizer for good avalanche, mapped to a uniform [0,1) via the top 53 bits.
        h ^= h >> 30;
        h = h.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        h ^= h >> 27;
        h = h.wrapping_mul(0x94d0_49bb_1331_11eb);
        h ^= h >> 31;
        (h >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Set the managed-mode retransmit budget (default 6).
    pub fn set_retry_limit(&self, retry_limit: u32) {
        self.retry_limit.store(retry_limit, std::sync::atomic::Ordering::Relaxed);
    }

    /// Enable SINR-based interference: concurrent in-range transmitters raise the effective noise at
    /// a receiver (capture effect), instead of only a binary collision. Off by default.
    pub fn set_sinr_interference(&self, on: bool) {
        self.sinr_interference.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Total airtime consumed on the medium so far.
    pub fn total_airtime(&self) -> std::time::Duration {
        std::time::Duration::from_nanos(self.airtime_ns.load(std::sync::atomic::Ordering::Relaxed))
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
    ///
    /// The frame carries no name-group, so under energy accounting it reaches **every** in-range
    /// host (promiscuous / monitor mode). Use [`transmit_named`](Self::transmit_named) to carry a
    /// name-group so a hardware name-filter can offload non-matching frames off the host CPU.
    pub fn transmit(&self, node: NodeId, mcs_index: u8, frame: Bytes, now_ns: u64) -> Vec<(NodeId, f64, bool)> {
        self.transmit_inner(node, mcs_index, frame, now_ns, None)
    }

    /// Like [`transmit`](Self::transmit) but the frame carries a `group_key` (its name-group hash).
    /// When a hardware name-filter is installed ([`set_host_filter`](Self::set_host_filter)), only
    /// receivers registered for this group pay host-processing energy — the MAC offload; the rest
    /// have the frame dropped by the radio before the CPU wakes. Radio RX energy is charged to all
    /// in-range radios regardless (the front end still hears it).
    pub fn transmit_named(&self, node: NodeId, mcs_index: u8, group_key: u64, frame: Bytes, now_ns: u64) -> Vec<(NodeId, f64, bool)> {
        self.transmit_inner(node, mcs_index, frame, now_ns, Some(group_key))
    }

    fn transmit_inner(
        &self,
        node: NodeId,
        mcs_index: u8,
        frame: Bytes,
        now_ns: u64,
        group: Option<u64>,
    ) -> Vec<(NodeId, f64, bool)> {
        let view = self.view_at(now_ns);
        let Some(tx_pos) = view.position(node) else {
            return Vec::new();
        };
        // This frame's per-sender sequence number — advanced once per transmit, in `node`'s own send
        // order — so same-instant frames from this node draw independent erasures (see `erasure_roll`).
        let frame_seq = {
            let mut seq = self.tx_seq.lock().unwrap();
            let e = seq.entry(node).or_insert(0);
            let s = *e;
            *e += 1;
            s
        };
        let env = self.world.environment();
        let mode = *self.mac_mode.lock().unwrap();
        let sinr_on = self.sinr_interference.load(std::sync::atomic::Ordering::Relaxed);
        // The sender's TX power: a per-node override (a policy trimming power) or the bus default.
        // Used for BOTH this frame's RSSI (delivery) and its energy — so the power dial trades reach
        // against joules honestly.
        let tx_dbm = self.tx_power.lock().unwrap().get(&node).copied().unwrap_or(self.tx_power_dbm);
        let signal_ch = self.channel_of(node);
        let half_duplex = self.half_duplex.load(std::sync::atomic::Ordering::Relaxed);
        let irange_factor = *self.interference_range_factor.lock().unwrap();

        // This frame's airtime (bits / PHY rate) → its on-air window. Snapshot the *other*
        // frames overlapping the start instant (concurrent transmitters) before recording ours.
        // Collision model: the newcomer loses at any receiver that also hears a concurrent
        // in-range transmitter (hidden-terminal). Deterministic — no RNG.
        // On-air signal time = HT preamble + framed payload (`wifi::frame_airtime`). This one value
        // drives the collision-overlap window, the half-duplex busy window, AND the receive delay, so
        // all three agree with the airtime *accounting* below (`broadcast_airtime` = DIFS + backoff +
        // `frame_airtime`). The old `bytes·8/rate` omitted the ~36 µs HT preamble + MAC header — up to
        // ~12× too short for a small frame — so overlapping preambles read as non-colliding and the
        // delivery/half-duplex timing disagreed with the accounted airtime.
        let airtime_ns = crate::wifi::frame_airtime(frame.len(), mcs_index).as_nanos() as u64;
        let end_ns = now_ns.saturating_add(airtime_ns);
        let my_collided: Arc<Mutex<std::collections::HashSet<NodeId>>> =
            Arc::new(Mutex::new(std::collections::HashSet::new()));
        let concurrent: Vec<(NodeId, Position, Arc<Mutex<std::collections::HashSet<NodeId>>>)> = {
            let mut in_air = self.in_air.lock().unwrap();
            in_air.retain(|(_, _, e, _)| *e > now_ns); // prune finished transmissions
            // Batch/instantaneous mode stamps every frame with the same `now_ns`, so `e > now_ns` never
            // fires and the retain can't shrink — bound the live set (and the O(n) snapshot scan below)
            // by evicting the oldest transmissions. Under a real DES clock `now_ns` advances and the
            // retain reclaims first, so this cap only bites in the degenerate same-instant case.
            const IN_AIR_CAP: usize = 4096;
            if in_air.len() > IN_AIR_CAP {
                let drop = in_air.len() - IN_AIR_CAP;
                in_air.drain(0..drop);
            }
            let snapshot = in_air
                .iter()
                .filter(|(s, _, _, _)| *s != node)
                .filter_map(|(s, _, _, c)| view.position(*s).map(|p| (*s, p, Arc::clone(c))))
                .collect();
            in_air.push((node, now_ns, end_ns, Arc::clone(&my_collided)));
            snapshot
        };
        let max_range = self.propagation.max_range_m();

        // Energy accounting (opt-in): the sender pays TX once; every in-range radio pays RX — the
        // "listen to everything" cost the named-radio doctrine (§3.1) attributes to monitor mode.
        // Independent of whether a receiver is attached: a real radio in range still burns RX energy.
        if let Some(model) = self.energy_model.lock().unwrap().as_ref() {
            let airtime = std::time::Duration::from_nanos(airtime_ns);
            let mut acct = self.energy_acct.lock().unwrap();
            let tx = acct.entry(node).or_default();
            tx.tx_j += model.tx_energy_j(airtime, tx_dbm, mcs_index);
            tx.frames_tx += 1;
            tx.bits_tx += (frame.len() as u64) * 8;
            let rx_e = model.rx_energy_j(airtime, mcs_index);
            let host_e = model.host_process_energy_j(frame.len());
            let filter = self.host_filter.lock().unwrap();
            for rx_node in view.within_range(tx_pos, max_range) {
                if rx_node == node {
                    continue; // half-duplex: the transmitter is not receiving its own frame
                }
                // Radio RX energy is always charged (the front end hears every in-range frame). Host
                // CPU energy is charged only when the frame reaches the host: promiscuous unless this
                // node runs a hardware name-filter that this frame's group does not match (the offload).
                let reaches_host = match (filter.as_ref().and_then(|f| f.get(&rx_node)), group) {
                    (Some(reg), Some(g)) => *reg == g,
                    _ => true,
                };
                let rx = acct.entry(rx_node).or_default();
                rx.rx_j += rx_e;
                rx.frames_rx += 1;
                if reaches_host {
                    rx.host_j += host_e;
                    rx.frames_to_host += 1;
                }
            }
        }

        let mut out = Vec::new();
        let mut managed_attempts = 0f64; // F5: Σ expected transmissions across the managed unicasts
        let receivers = self.receivers.lock().unwrap();
        // NodeId-sorted (spatial index) ⇒ the erasure draws happen in a deterministic order.
        for rx_node in view.within_range(tx_pos, self.propagation.max_range_m()) {
            if rx_node == node {
                continue; // half-duplex: a radio never hears itself
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
                tx_power_dbm: tx_dbm,
                environment: env.as_ref(),
                frame_len: frame.len(),
            };
            let dist = tx_pos.distance(rx_pos);
            let log_delivery =
                |delivered: bool, reason: crate::medium::DeliveryReason, rssi: f64| {
                    if let Some(log) = self.radio_log.lock().unwrap().as_ref() {
                        log.record(crate::analysis::RadioDelivery {
                            t_ns: now_ns,
                            from: node,
                            to: rx_node,
                            delivered,
                            reason,
                            rssi_dbm: rssi,
                            distance_m: dist,
                            frame_len: frame.len(),
                        });
                    }
                };
            let d = self.propagation.deliver(&ctx);
            if !d.delivered {
                log_delivery(false, d.reason, d.rssi_dbm);
                continue; // below receiver sensitivity / obstructed — not even detectable
            }
            // Half-duplex: if this receiver is itself transmitting right now, it cannot hear the frame
            // at all. This is the single most important reason a one-radio multi-hop chain falls below
            // 1/hop — a relay busy forwarding drops the next frame headed for it.
            if half_duplex && concurrent.iter().any(|(s, _, _)| *s == rx_node) {
                out.push((rx_node, d.rssi_dbm, false));
                log_delivery(false, crate::medium::DeliveryReason::HalfDuplex, d.rssi_dbm);
                continue;
            }
            // Concurrent transmitters this receiver hears as INTERFERENCE: within the interference
            // range (which exceeds the decode range) AND coupling on the channel (co-channel fully,
            // adjacent channels leak, orthogonal not at all). Excludes the receiver itself (half-duplex
            // handled above).
            let irange = max_range * irange_factor;
            let clashers: Vec<(NodeId, Position, Arc<Mutex<std::collections::HashSet<NodeId>>>)> =
                concurrent
                    .iter()
                    .filter(|(s, p, _)| {
                        *s != rx_node
                            && p.distance(rx_pos) <= irange
                            && self.channel_coupling(*s, signal_ch) > 0.1
                    })
                    .map(|(s, p, c)| (*s, *p, Arc::clone(c)))
                    .collect();
            // Without SINR modelling, any in-range concurrent transmitter is a hard collision.
            if !sinr_on {
                let clasher_ids: Vec<NodeId> = clashers.iter().map(|(s, _, _)| *s).collect();
                if self.interference.collides(rx_node, &clasher_ids) {
                    // F2 both-lose: retro-collide the concurrent frames at this receiver too, so the
                    // earlier transmitter's already-scheduled delivery to rx_node also drops. Without
                    // this the first-by-call-order frame would win a simultaneous collision.
                    for (_, _, c) in &clashers {
                        c.lock().unwrap().insert(rx_node);
                    }
                    out.push((rx_node, d.rssi_dbm, false));
                    log_delivery(false, crate::medium::DeliveryReason::Collision, d.rssi_dbm);
                    trace!(
                        from = node.0,
                        to = rx_node.0,
                        "radio: frame lost to collision"
                    );
                    continue;
                }
            }
            // Effective SNR: the plain link SNR, or — with SINR modelling on — degraded by the
            // aggregate power of the concurrent transmitters (capture effect: a strong wanted signal
            // survives a weak interferer; two comparable signals both drown).
            let snr = if sinr_on && !clashers.is_empty() {
                let noise_floor = d.rssi_dbm - LinkModel::snr_db(d.rssi_dbm);
                let mut interf_mw = 10f64.powf(noise_floor / 10.0);
                for (s, p, _) in &clashers {
                    let ictx = TxContext {
                        tx_pos: *p,
                        rx_pos,
                        // F8: the interferer's per-node TX power (its override, not the bus default) —
                        // mirrors the sender path, so trimming an interferer's power earns SINR/capture
                        // credit (spatial reuse). Was `self.tx_power_dbm`, ignoring set_tx_power.
                        tx_power_dbm: self.tx_power.lock().unwrap().get(s).copied().unwrap_or(self.tx_power_dbm),
                        environment: env.as_ref(),
                        frame_len: frame.len(),
                    };
                    interf_mw += 10f64.powf(self.propagation.deliver(&ictx).rssi_dbm / 10.0);
                }
                d.rssi_dbm - 10.0 * interf_mw.log10()
            } else {
                LinkModel::snr_db(d.rssi_dbm)
            };
            // Per-frame delivery. Managed Wi-Fi ACKs + retransmits, so a receiver's effective
            // delivery is retry-improved (1−(1−p)^(retry+1)); monitor injection has no ACK.
            let base_p = self.link_model.frame_delivery(mcs_index, snr);
            let mut p = base_p;
            if matches!(mode, crate::wifi::WifiMode::Managed) {
                let retries = self.retry_limit.load(std::sync::atomic::Ordering::Relaxed) as i32;
                p = 1.0 - (1.0 - base_p).powi(retries + 1);
                // F5: managed reliability (the retry lift above) is NOT free airtime. Accumulate this
                // link's EXPECTED transmissions until success or exhausting retries — Σ_{k=0}^{R}(1-base_p)^k
                // (base_p→0 ⇒ the full R+1 attempts) — and charge it below instead of a single unicast.
                managed_attempts += if base_p > 1e-9 {
                    (1.0 - (1.0 - base_p).powi(retries + 1)) / base_p
                } else {
                    (retries + 1) as f64
                };
            }
            let roll = self.erasure_roll(node, rx_node, now_ns, frame_seq);
            let survived = roll < p;
            out.push((rx_node, d.rssi_dbm, survived));

            if survived {
                let rf = RadioRx {
                    from: node,
                    rssi_dbm: d.rssi_dbm,
                    mcs_index,
                    bytes: frame.clone(),
                };
                // A frame is decodable only once FULLY received: the sender's airtime (last bit on air)
                // plus propagation. Delivering after propagation ALONE lets a receiver act on the frame
                // before the sender has finished transmitting it — so a causally-later reply is emitted
                // *within* the request's still-open airtime window and the half-duplex check drops it.
                // That artifact is invisible under a real/paused clock (processing burns wall/virtual
                // time) but fatal under the discrete-event kernel, whose engine+app processing is
                // instantaneous in virtual time. Airtime + propagation makes delivery causal on every
                // kernel: any reply is necessarily emitted after the request's airtime ends.
                let recv_delay = std::time::Duration::from_nanos(airtime_ns) + d.delay;
                // H4b: log at RECEIPT time (now + airtime + propagation) and only as Delivered once the
                // frame actually lands — a later frame may have F2-retro-collided us. Stamping at receipt
                // (not the shared transmit instant) gives a real time span for throughput, and a
                // retro-collided frame is logged as a Collision, never a phantom delivery.
                let receipt_ns = now_ns.saturating_add(recv_delay.as_nanos() as u64);
                let rt = Arc::clone(&self.runtime);
                let collided = Arc::clone(&my_collided);
                let rx_id = rx_node;
                let log = self.radio_log.lock().unwrap().clone();
                let (from_id, dist_m, flen, rssi) = (node, dist, frame.len(), d.rssi_dbm);
                self.runtime.spawn(Box::pin(async move {
                    rt.sleep(recv_delay).await;
                    let collided = collided.lock().unwrap().contains(&rx_id);
                    if let Some(log) = &log {
                        log.record(crate::analysis::RadioDelivery {
                            t_ns: receipt_ns,
                            from: from_id,
                            to: rx_id,
                            delivered: !collided,
                            reason: if collided {
                                crate::medium::DeliveryReason::Collision
                            } else {
                                crate::medium::DeliveryReason::Delivered
                            },
                            rssi_dbm: rssi,
                            distance_m: dist_m,
                            frame_len: flen,
                        });
                    }
                    if !collided {
                        let _ = sender.send(rf);
                    }
                }));
            } else {
                log_delivery(false, crate::medium::DeliveryReason::Erased, d.rssi_dbm);
                trace!(
                    from = node.0,
                    to = rx_node.0,
                    mcs = mcs_index,
                    snr,
                    "radio: frame erased"
                );
            }
        }

        // Airtime cost under the MAC discipline: monitor charges one broadcast (reaches all in-range
        // in a single transmission — NDN's multicast advantage); managed charges a unicast per
        // in-range receiver (normal Wi-Fi replaces the broadcast with N unicasts).
        let cost = match mode {
            crate::wifi::WifiMode::Monitor => crate::wifi::broadcast_airtime(frame.len(), mcs_index),
            crate::wifi::WifiMode::Managed => {
                // F5: sum of EXPECTED attempts across the managed unicasts (retransmissions included),
                // not one attempt per receiver — retries cost airtime. `wifi::link_cost` uses the same
                // expected-attempts model; this is the per-transmission analog.
                let ns = crate::wifi::unicast_airtime(frame.len(), mcs_index).as_nanos() as f64
                    * managed_attempts.max(1.0);
                std::time::Duration::from_nanos(ns as u64)
            }
        };
        self.airtime_ns.fetch_add(
            cost.as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        out
    }
}

/// Map a node id to a stable, locally-administered 48-bit address (for `FaceAddr::Ether`).
fn node_addr(node: NodeId) -> [u8; 6] {
    let n = node.0 as u32;
    [
        0x02,
        0x4e,
        (n >> 24) as u8,
        (n >> 16) as u8,
        (n >> 8) as u8,
        n as u8,
    ]
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
        // F4 CSMA carrier-sense: a managed node listens before talking. If the medium is busy with an
        // in-range same-channel transmitter, defer past the busy period + a random backoff, so concurrent
        // managed attempts SERIALISE instead of both firing and colliding — the deferral CSMA is built on,
        // not just the collision outcome. Monitor injection (the named-data radio default) does not sense.
        if self.bus.is_managed() {
            let mut attempt = 0u32;
            while attempt < 8 {
                let now = self.clock.unix_nanos();
                match self.bus.sense_busy_until(self.node, now) {
                    Some(busy_until) if busy_until > now => {
                        let backoff = self.bus.csma_backoff_ns(attempt);
                        self.clock
                            .sleep(std::time::Duration::from_nanos((busy_until - now) + backoff))
                            .await;
                        attempt += 1;
                    }
                    _ => break, // medium idle (or gave up after 8 backoffs — transmit anyway, as real CSMA)
                }
            }
        }
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
        RadioBus::new(
            Arc::new(world),
            Arc::new(FreeSpacePathLoss::default()),
            0,
            seed,
        )
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
        assert!(
            near > 190,
            "close, high-SNR link delivers nearly all: {near}/200"
        );
        assert!(
            far < near,
            "edge link at MCS7 delivers far fewer: {far} vs {near}"
        );
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
        assert!(
            hits > 0 && hits < 50,
            "a genuine mix, not all/none: {hits}/50"
        );
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
    async fn default_collides_and_no_interference_opts_out() {
        // F3: physics is ON by default now. Two concurrent in-range same-channel frames collide at a
        // shared receiver under the default (CarrierSenseInterference); the old collision-free
        // idealization is still reachable by explicitly opting into NoInterference.
        let positions = [
            (NodeId(0), Position::xy(0.0, 0.0)),
            (NodeId(1), Position::xy(5.0, 0.0)),
            (NodeId(2), Position::xy(5.0, 1.0)),
        ];
        // Default bus: at least one of two concurrent frames must collide at the shared receiver.
        let def = bus_with(&positions, 1);
        def.attach(NodeId(0));
        let d1 = def.transmit(NodeId(1), 7, Bytes::from_static(b"aaaaaaaa"), 0);
        let d2 = def.transmit(NodeId(2), 7, Bytes::from_static(b"aaaaaaaa"), 0);
        let d1_ok = d1.iter().any(|(n, _, ok)| *n == NodeId(0) && *ok);
        let d2_ok = d2.iter().any(|(n, _, ok)| *n == NodeId(0) && *ok);
        assert!(!(d1_ok && d2_ok), "default (physics ON) must collide concurrent frames");

        // Explicit NoInterference opt-out: the idealization still lets both through.
        let world = World::new();
        for (id, p) in positions {
            world.place(id, p);
        }
        let ideal = RadioBus::with_interference(
            Arc::new(world),
            Arc::new(FreeSpacePathLoss::default()),
            0,
            1,
            Arc::new(crate::medium::NoInterference),
        );
        ideal.attach(NodeId(0));
        let r1 = ideal.transmit(NodeId(1), 7, Bytes::from_static(b"aaaaaaaa"), 0);
        let r2 = ideal.transmit(NodeId(2), 7, Bytes::from_static(b"aaaaaaaa"), 0);
        assert!(r1.iter().any(|(n, _, ok)| *n == NodeId(0) && *ok));
        assert!(
            r2.iter().any(|(n, _, ok)| *n == NodeId(0) && *ok),
            "explicit NoInterference opt-out lets concurrent frames through"
        );
    }

    /// Managed Wi-Fi ACKs + retransmits, so on a marginal link its per-frame delivery is
    /// retry-improved over monitor-mode injection (which has no ACK). Same seed, same link.
    #[tokio::test]
    async fn managed_retries_improve_delivery_over_monitor_at_the_edge() {
        let positions = [
            (NodeId(0), Position::xy(0.0, 0.0)),
            // ~450 m at MCS5 ⇒ SNR at the threshold ⇒ a genuine mix of hits/misses on monitor.
            (NodeId(1), Position::xy(450.0, 0.0)),
        ];
        let delivered = |mode| {
            let bus = bus_with(&positions, 7);
            bus.set_mac_mode(mode);
            bus.attach(NodeId(1));
            let mut hits = 0usize;
            for _ in 0..200 {
                for (rx, _rssi, ok) in bus.transmit(NodeId(0), 5, Bytes::from_static(b"x"), 0) {
                    if ok && rx == NodeId(1) {
                        hits += 1;
                    }
                }
            }
            hits
        };
        let monitor = delivered(crate::wifi::WifiMode::Monitor);
        let managed = delivered(crate::wifi::WifiMode::Managed);
        assert!(
            monitor > 0 && monitor < 200,
            "marginal link ⇒ a genuine mix on monitor: {monitor}/200"
        );
        assert!(
            managed > monitor,
            "managed ACK/retransmit lifts delivery: managed {managed} vs monitor {monitor}"
        );
    }

    /// With SINR modelling on, a strong wanted signal survives a weak concurrent interferer (capture
    /// effect), but drowns under a comparably-strong one — richer than a binary collision.
    #[tokio::test]
    async fn sinr_capture_survives_a_weak_interferer_but_drowns_a_strong_one() {
        let max = FreeSpacePathLoss::default().max_range_m();

        // Weak interferer (far, near sensitivity) vs a very strong wanted signal (metres away).
        let capture = bus_with(
            &[
                (NodeId(0), Position::xy(0.0, 0.0)),      // receiver
                (NodeId(1), Position::xy(3.0, 0.0)),      // wanted: strong
                (NodeId(2), Position::xy(max * 0.9, 0.0)), // interferer: weak
            ],
            3,
        );
        capture.set_sinr_interference(true);
        capture.attach(NodeId(0));
        capture.transmit(NodeId(2), 7, Bytes::from_static(b"interfere"), 0); // interferer on the air
        let r = capture.transmit(NodeId(1), 7, Bytes::from_static(b"wanted!!!"), 0);
        assert!(
            r.iter().any(|(n, _, ok)| *n == NodeId(0) && *ok),
            "strong signal captures the receiver over a weak interferer"
        );

        // A comparably-strong interferer: neither captures, so the wanted frame drowns.
        let drown = bus_with(
            &[
                (NodeId(0), Position::xy(0.0, 0.0)),
                (NodeId(1), Position::xy(3.0, 0.0)),
                (NodeId(2), Position::xy(3.0, 0.5)), // interferer: comparable power
            ],
            3,
        );
        drown.set_sinr_interference(true);
        drown.attach(NodeId(0));
        drown.transmit(NodeId(2), 7, Bytes::from_static(b"interfere"), 0);
        let r = drown.transmit(NodeId(1), 7, Bytes::from_static(b"wanted!!!"), 0);
        assert!(
            r.iter().any(|(n, _, ok)| *n == NodeId(0) && !*ok),
            "two comparable signals collide ⇒ the wanted frame drowns"
        );
    }
}
