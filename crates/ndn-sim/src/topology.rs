//! `Simulation` (builder) + `RunningSimulation` (the live fabric) — multi-node in-process
//! NDN networks of real `ForwarderEngine`s on a pluggable [`SimKernel`](crate::SimKernel).
//!
//! The builder declares an initial topology; [`start`](Simulation::start) instantiates it on
//! the kernel and returns a [`RunningSimulation`] — the headless **fabric** handle that
//! implements [`FabricControl`](crate::FabricControl): live spawn/remove/connect/route +
//! topology introspection, with a [`SimTracer`] capturing engine face events.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, bail};
use ndn_engine::ForwarderEngine;
use ndn_engine::builder::{EngineBuilder, EngineConfig};
use ndn_engine::engine::ShutdownHandle;
use ndn_packet::Name;
use ndn_transport::FaceId;
use tracing::info;

use crate::app::{AppHandle, AppId, AppSpec};
use crate::control::{LinkInfo, NodeInfo, TopologySnapshot, TracerFaceSink};
use crate::kernel::{SimKernel, WallClockKernel};
use crate::profile::NodeProfile;
use crate::radio::{RadioBus, SimRadioFace};
use crate::sim_link::{FaceProfile, LinkConfig, SimLink};
use crate::tracer::{EventKind, SimTracer};
use crate::world::World;

/// Opaque, stable handle to a node in the fabric (survives other nodes being removed).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct NodeId(pub usize);

impl std::fmt::Display for NodeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node#{}", self.0)
    }
}

struct PendingLink {
    a: NodeId,
    b: NodeId,
    profile: FaceProfile,
}

struct PendingRoute {
    node: NodeId,
    prefix: Name,
    nexthop_node: NodeId,
}

struct PendingStrategy {
    node: NodeId,
    prefix: Name,
    /// NFD-style short strategy name (`"best-route"`, `"multicast"`, …), resolved via
    /// [`ndn_strategy::registry::create_by_name`] at [`start`](Simulation::start).
    strategy: String,
}

/// Builder for an initial fabric topology. Register nodes / links / routes, then
/// [`start`](Self::start) instantiates everything on the [`SimKernel`] and returns a live
/// [`RunningSimulation`].
pub struct Simulation {
    profiles: Vec<NodeProfile>,
    links: Vec<PendingLink>,
    routes: Vec<PendingRoute>,
    channel_buffer: usize,
    kernel: std::sync::Arc<dyn SimKernel>,
    world: Option<std::sync::Arc<World>>,
    /// Shared radio medium spec `(propagation, seed)` — built into a `RadioBus` at `start`.
    radio: Option<(std::sync::Arc<dyn crate::medium::PropagationModel>, u64)>,
    /// Nodes that get a `SimRadioFace` on the shared bus, with their world positions.
    radio_nodes: Vec<(NodeId, crate::world::Position)>,
    /// Apps to spawn on each node once its engine is up (declarative producers/consumers).
    pending_apps: Vec<(NodeId, AppSpec)>,
    /// Per-node/prefix strategy choices applied once every engine is up.
    strategies: Vec<PendingStrategy>,
    /// Broadcast routes over a node's radio face: `(node, prefix)`, applied once radio faces exist.
    radio_routes: Vec<(NodeId, Name)>,
    /// Perturbs every face's loss/jitter RNG (and the radio erasure RNG). 0 = the default single
    /// realization; a validation seed sweep varies it to draw independent random realizations.
    seed: u64,
}

impl Default for Simulation {
    fn default() -> Self {
        Self::new()
    }
}

impl Simulation {
    pub fn new() -> Self {
        Self {
            profiles: Vec::new(),
            links: Vec::new(),
            routes: Vec::new(),
            channel_buffer: 256,
            kernel: std::sync::Arc::new(WallClockKernel::new()),
            world: None,
            radio: None,
            radio_nodes: Vec::new(),
            pending_apps: Vec::new(),
            strategies: Vec::new(),
            radio_routes: Vec::new(),
            seed: 0,
        }
    }

    /// Declare a broadcast route for `prefix` over `node`'s radio face (the declarative form of
    /// [`RunningSimulation::route_over_radio`]). Applied at [`start`](Self::start).
    pub fn add_radio_route(&mut self, node: NodeId, prefix: &str) {
        self.radio_routes
            .push((node, Name::from_str(prefix).expect("valid NDN name")));
    }

    /// Set the world seed — perturbs every simulated face's loss/jitter RNG (and the radio erasure
    /// RNG) so a different `seed` draws an independent random realization. Determinism is preserved:
    /// the same seed always replays identically. Default 0.
    pub fn seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Declare an app to spawn on `node` at [`start`](Self::start) (a producer/consumer). The
    /// "test my apps" surface: scenarios + the builder say what runs where.
    pub fn add_app(&mut self, node: NodeId, app: AppSpec) {
        self.pending_apps.push((node, app));
    }

    /// Enable a shared **radio medium** ([`RadioBus`]) over the world, using `propagation` for
    /// RSSI and `seed` for the per-frame erasure RNG. Nodes added with
    /// [`add_radio_node`](Self::add_radio_node) get a [`SimRadioFace`] on it at `start`, each
    /// publishing `LinkSignals` into its own engine's signal table.
    pub fn with_radio_medium(
        mut self,
        propagation: std::sync::Arc<dyn crate::medium::PropagationModel>,
        seed: u64,
    ) -> Self {
        self.radio = Some((propagation, seed));
        self
    }

    /// Add a node placed at `position` that will get a radio face on the shared medium (see
    /// [`with_radio_medium`](Self::with_radio_medium)). Ensures a world exists and places it.
    pub fn add_radio_node(
        &mut self,
        config: EngineConfig,
        position: crate::world::Position,
    ) -> NodeId {
        let id = self.add_node(config);
        let world = self
            .world
            .get_or_insert_with(|| std::sync::Arc::new(World::new()));
        world.place(id, position);
        self.radio_nodes.push((id, position));
        id
    }

    /// Put existing nodes on a **collision-free broadcast segment**: a shared multi-access bus
    /// where every member hears every other member's sends, with *no geometry to reason about* — the
    /// natural home for sync/discovery (an SVS `/time` group, a neighbour-discovery beacon). Each
    /// member gets a radio face on a [`PerfectPropagation`](crate::medium::PerfectPropagation) medium
    /// (everyone in range, no attenuation) over the default no-interference bus (no collisions), and
    /// — unless `prefix` is empty — a broadcast route for `prefix` so Interests fan to the whole
    /// segment. The members are clustered geometry-free; don't mix this with a geometric radio in the
    /// same sim (the fabric has one shared medium).
    ///
    /// ```no_run
    /// # use ndn_sim::Simulation; use ndn_engine::builder::EngineConfig;
    /// # let mut sim = Simulation::new();
    /// let a = sim.add_node(EngineConfig::default());
    /// let b = sim.add_node(EngineConfig::default());
    /// let c = sim.add_node(EngineConfig::default());
    /// sim.broadcast_segment(&[a, b, c], "/time");   // all three hear each other on /time
    /// ```
    pub fn broadcast_segment(&mut self, members: &[NodeId], prefix: &str) {
        if self.radio.is_none() {
            self.radio = Some((
                std::sync::Arc::new(crate::medium::PerfectPropagation::default()),
                self.seed,
            ));
        }
        let world = std::sync::Arc::clone(
            self.world
                .get_or_insert_with(|| std::sync::Arc::new(World::new())),
        );
        for (i, &member) in members.iter().enumerate() {
            // Cluster them tightly (1 m apart) — well within PerfectPropagation's range, and cheap
            // for the spatial index. Geometry is irrelevant on a perfect bus.
            let pos = crate::world::Position::xy(i as f64, 0.0);
            world.place(member, pos);
            self.radio_nodes.push((member, pos));
            if !prefix.is_empty() {
                self.add_radio_route(member, prefix);
            }
        }
    }

    /// Run on a specific [`SimKernel`] (default: [`WallClockKernel`]). This is the one knob
    /// that switches the whole time model (wall-clock now; virtual/parallel later).
    pub fn kernel(mut self, kernel: std::sync::Arc<dyn SimKernel>) -> Self {
        self.kernel = kernel;
        self
    }

    /// Attach a spatial [`World`] (node positions + mobility + environment). It's carried onto
    /// the running fabric ([`RunningSimulation::world`]) where position-driven faces — a
    /// [`WirelessMedium`](crate::WirelessMedium) and the slice-4 named-radio face — read it.
    /// Wired links don't need a world; this is only for position-dependent delivery.
    pub fn world(mut self, world: World) -> Self {
        self.world = Some(std::sync::Arc::new(world));
        self
    }

    /// Set the channel buffer size for SimLinks (default: 256).
    pub fn channel_buffer(mut self, size: usize) -> Self {
        self.channel_buffer = size;
        self
    }

    /// Ensure the builder has a world, returning a handle to it.
    fn ensure_world(&mut self) -> std::sync::Arc<World> {
        std::sync::Arc::clone(
            self.world
                .get_or_insert_with(|| std::sync::Arc::new(World::new())),
        )
    }

    /// Place a (already-added) node at a fixed world position — for positioning wired nodes so
    /// the scene/medium can see them. Ensures a world exists.
    pub fn place_node(&mut self, node: NodeId, position: crate::world::Position) {
        self.ensure_world().place(node, position);
    }

    /// Give a node a mobility model declaratively (ensures a world exists).
    pub fn set_node_mobility(
        &mut self,
        node: NodeId,
        model: std::sync::Arc<dyn crate::world::MobilityModel>,
    ) {
        self.ensure_world().set_mobility(node, model);
    }

    /// Set the world's environment model (ensures a world exists).
    pub fn environment(&mut self, env: std::sync::Arc<dyn crate::world::Environment>) {
        self.ensure_world().set_environment(env);
    }

    /// Add a forwarding node from an engine config (label auto-assigned), return its handle.
    pub fn add_node(&mut self, config: EngineConfig) -> NodeId {
        let id = NodeId(self.profiles.len());
        self.profiles
            .push(NodeProfile::new(format!("node#{}", id.0)).with_config(config));
        id
    }

    /// Add a forwarding node from a [`NodeProfile`] (named template).
    pub fn add_node_profile(&mut self, profile: NodeProfile) -> NodeId {
        let id = NodeId(self.profiles.len());
        self.profiles.push(profile);
        id
    }

    /// Connect two nodes with a symmetric in-proc wired link.
    pub fn link(&mut self, a: NodeId, b: NodeId, config: LinkConfig) {
        self.links.push(PendingLink {
            a,
            b,
            profile: FaceProfile::internal().with_link(config),
        });
    }

    /// Connect two nodes with a typed link from the per-face catalogue (UDP/TCP/QUIC/BLE/…) — the
    /// engine sees that face type's `FaceKind`/MTU/delivery semantics.
    pub fn link_profiled(&mut self, a: NodeId, b: NodeId, profile: FaceProfile) {
        self.links.push(PendingLink { a, b, profile });
    }

    /// Connect two nodes — the `add_*` spelling matching [`add_node`](Self::add_node) /
    /// [`add_route`](Self::add_route) / [`add_app`](Self::add_app). Same as [`link`](Self::link).
    pub fn add_link(&mut self, a: NodeId, b: NodeId, config: LinkConfig) {
        self.link(a, b, config);
    }

    /// Typed-link form of [`add_link`](Self::add_link) (same as [`link_profiled`](Self::link_profiled)).
    pub fn add_link_profiled(&mut self, a: NodeId, b: NodeId, profile: FaceProfile) {
        self.link_profiled(a, b, profile);
    }

    /// Pre-install a FIB route: packets for `prefix` at `node` forward toward `nexthop_node`
    /// via the SimLink face connecting them.
    pub fn add_route(&mut self, node: NodeId, prefix: &str, nexthop_node: NodeId) {
        self.routes.push(PendingRoute {
            node,
            prefix: Name::from_str(prefix).expect("valid NDN name"),
            nexthop_node,
        });
    }

    /// Choose the forwarding `strategy` for `prefix` on `node`, applied at [`start`](Self::start).
    /// Accepts a typed [`Strategy`] (`Strategy::Multicast`) or an NFD short name (`"multicast"` /
    /// `"best-route"`). Multicast fans an Interest to every eligible next-hop — inherently tolerant
    /// of a single dead upstream, and the fix for the multi-local-app-face trap (see
    /// [`RunningSimulation::explain_route`]).
    pub fn add_strategy(&mut self, node: NodeId, prefix: &str, strategy: impl AsRef<str>) {
        self.strategies.push(PendingStrategy {
            node,
            prefix: Name::from_str(prefix).expect("valid NDN name"),
            strategy: strategy.as_ref().to_string(),
        });
    }

    pub async fn start(self) -> Result<RunningSimulation> {
        let n = self.profiles.len();
        info!(
            nodes = n,
            links = self.links.len(),
            kernel = self.kernel.name(),
            "ndn-lab: starting fabric"
        );

        // Tracer timestamps come from the kernel clock — virtual (reproducible) under a
        // VirtualKernel, real under wall-clock.
        let tracer = std::sync::Arc::new(SimTracer::with_clock(self.kernel.runtime()));
        let mut nodes: HashMap<NodeId, NodeEntry> = HashMap::new();

        // Build every node on the kernel's runtime, with a tracer face-sink installed
        // *before* faces are added so their FaceUp events are captured.
        for (i, profile) in self.profiles.into_iter().enumerate() {
            let id = NodeId(i);
            let (engine, handle) = EngineBuilder::new(profile.config)
                .runtime(self.kernel.runtime())
                .build()
                .await?;
            engine.set_face_lifecycle_sink(std::sync::Arc::new(TracerFaceSink {
                tracer: std::sync::Arc::clone(&tracer),
                node: id.0,
            }));
            nodes.insert(
                id,
                NodeEntry {
                    engine,
                    handle,
                    label: profile.label,
                },
            );
        }

        let mut links: HashMap<(NodeId, NodeId), FaceId> = HashMap::new();
        let mut link_states: HashMap<(NodeId, NodeId), std::sync::Arc<crate::sim_face::LinkState>> =
            HashMap::new();
        for link in &self.links {
            if !nodes.contains_key(&link.a) || !nodes.contains_key(&link.b) {
                bail!("link references non-existent node");
            }
            wire_link(
                &nodes,
                &mut links,
                &mut link_states,
                link.a,
                link.b,
                &link.profile,
                self.channel_buffer,
                self.seed,
            );
        }

        for route in &self.routes {
            let face_id = links
                .get(&(route.node, route.nexthop_node))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "no link between {} and {} for route {}",
                        route.node,
                        route.nexthop_node,
                        route.prefix
                    )
                })?;
            nodes[&route.node]
                .engine
                .fib()
                .add_nexthop(&route.prefix, *face_id, 10);
        }

        for sc in &self.strategies {
            let entry = nodes.get(&sc.node).ok_or_else(|| {
                anyhow::anyhow!("strategy choice references non-existent node {}", sc.node)
            })?;
            let strategy = ndn_strategy::registry::create_by_name(sc.strategy.as_bytes())
                .ok_or_else(|| anyhow::anyhow!("unknown forwarding strategy {:?}", sc.strategy))?;
            entry.engine.strategy_table().insert(&sc.prefix, strategy);
        }

        let epoch_ns = self.kernel.runtime().unix_nanos();
        // A fabric always has a world (empty by default) so live-world commands and scene
        // snapshots work whether or not the scenario declared one.
        let world = self
            .world
            .unwrap_or_else(|| std::sync::Arc::new(World::new()));

        // Build the shared radio medium (if enabled) and attach a SimRadioFace to each radio
        // node — publishing LinkSignals into that node's own engine signal table.
        let mut radio_faces: HashMap<NodeId, FaceId> = HashMap::new();
        let kernel_runtime = self.kernel.runtime();
        let world_seed = self.seed;
        let radio_bus = self.radio.map(|(propagation, seed)| {
            // Fold the world seed into the radio erasure seed so a sweep varies radio realizations
            // too (world_seed 0 leaves the declared radio seed untouched).
            let seed = seed ^ world_seed;
            // Build the bus on the fabric's kernel runtime so radio delivery timing rides the same
            // clock/executor as the engines (including the discrete-event kernel).
            let bus = RadioBus::new_on(
                std::sync::Arc::clone(&world),
                propagation,
                epoch_ns,
                seed,
                std::sync::Arc::clone(&kernel_runtime),
            );
            for (id, _pos) in &self.radio_nodes {
                let Some(entry) = nodes.get(id) else { continue };
                let face_id = entry.engine.faces().alloc_id();
                let face = SimRadioFace::new(
                    face_id,
                    *id,
                    std::sync::Arc::clone(&bus),
                    entry.engine.runtime(),
                )
                .with_signals(entry.engine.signals());
                entry.engine.add_face(face, entry.handle.cancel_token());
                radio_faces.insert(*id, face_id);
                info!(node = id.0, face = %face_id, "ndn-lab: radio face attached");
            }
            bus
        });

        // Radio FIB routes: broadcast `prefix` over the node's radio face (like route_over_radio,
        // but declarative). Applied now that radio faces exist.
        for (node, prefix) in &self.radio_routes {
            let face = radio_faces.get(node).copied().ok_or_else(|| {
                anyhow::anyhow!("radio route on node {node} which has no radio face")
            })?;
            nodes
                .get(node)
                .ok_or_else(|| anyhow::anyhow!("radio route references non-existent node {node}"))?
                .engine
                .fib()
                .add_nexthop(prefix, face, 10);
        }

        // Spawn declared apps now that every engine is up.
        let mut apps: HashMap<AppId, AppHandle> = HashMap::new();
        for (i, (node, spec)) in self.pending_apps.iter().enumerate() {
            let Some(entry) = nodes.get(node) else {
                bail!("app references non-existent node {node}");
            };
            let id = AppId(i);
            let handle = crate::app::spawn_app(&entry.engine, id, *node, spec)?;
            apps.insert(id, handle);
            info!(
                node = node.0,
                app = id.0,
                kind = spec.kind(),
                "ndn-lab: app spawned"
            );
        }
        let next_app = self.pending_apps.len();

        // Diagnose the silent multi-local-app-face trap now that apps have registered their prefixes.
        warn_multi_app_faces(&nodes, &links, &radio_faces);

        Ok(RunningSimulation {
            kernel: self.kernel,
            tracer,
            world,
            epoch_ns,
            radio_bus,
            radio_faces,
            apps: Mutex::new(apps),
            next_app: AtomicUsize::new(next_app),
            inner: Mutex::new(FabricInner { nodes, links, link_states }),
            channel_buffer: self.channel_buffer,
            next_node: AtomicUsize::new(n),
            seed: self.seed,
        })
    }
}

struct NodeEntry {
    engine: ForwarderEngine,
    handle: ShutdownHandle,
    label: String,
}

struct FabricInner {
    nodes: HashMap<NodeId, NodeEntry>,
    /// Directed: the face at `.0` pointing toward `.1`.
    links: HashMap<(NodeId, NodeId), FaceId>,
    /// The live fault knob for each directed link face — cut / degrade a link at runtime.
    link_states: HashMap<(NodeId, NodeId), std::sync::Arc<crate::sim_face::LinkState>>,
}

/// Wire a symmetric SimLink between two existing nodes, recording both directed faces and their
/// live fault knobs.
#[allow(clippy::too_many_arguments)]
fn wire_link(
    nodes: &HashMap<NodeId, NodeEntry>,
    links: &mut HashMap<(NodeId, NodeId), FaceId>,
    link_states: &mut HashMap<(NodeId, NodeId), std::sync::Arc<crate::sim_face::LinkState>>,
    a: NodeId,
    b: NodeId,
    profile: &FaceProfile,
    channel_buffer: usize,
    world_seed: u64,
) {
    let ea = &nodes[&a];
    let eb = &nodes[&b];
    let id_a = ea.engine.faces().alloc_id();
    let id_b = eb.engine.faces().alloc_id();
    // Build the link faces on the fabric's kernel runtime so their delivery timing rides the
    // same clock/executor as the engines — including the discrete-event kernel.
    let (face_a, face_b) = SimLink::pair_profiled_on(
        id_a,
        id_b,
        profile,
        channel_buffer,
        ea.engine.runtime(),
        world_seed,
    );
    // Grab the live fault knobs before the faces move into the engines.
    link_states.insert((a, b), face_a.link_state());
    link_states.insert((b, a), face_b.link_state());
    ea.engine.add_face(face_a, ea.handle.cancel_token());
    eb.engine.add_face(face_b, eb.handle.cancel_token());
    links.insert((a, b), id_a);
    links.insert((b, a), id_b);
    info!(node_a = a.0, face_a = %id_a, node_b = b.0, face_b = %id_b, "ndn-lab: link created");
}

/// The NFD short strategy name (`multicast`, `best-route`) from a full strategy Name
/// (`/localhost/nfd/strategy/<name>/<version>`).
fn short_strategy_name(name: &Name) -> String {
    let s = name.to_string();
    if let Some(idx) = s.find("/strategy/") {
        let rest = &s[idx + "/strategy/".len()..];
        let short = rest.split('/').next().unwrap_or(rest);
        if !short.is_empty() {
            return short.to_string();
        }
    }
    s
}

/// Warn (once, at start) about the silent multi-local-app-face trap: a prefix served by ≥2 local
/// app faces under a non-multicast strategy — the forwarder delivers each Interest to only one.
fn warn_multi_app_faces(
    nodes: &HashMap<NodeId, NodeEntry>,
    links: &HashMap<(NodeId, NodeId), FaceId>,
    radio_faces: &HashMap<NodeId, FaceId>,
) {
    for (node, entry) in nodes {
        let link_faces: std::collections::HashSet<FaceId> = links
            .iter()
            .filter(|((from, _), _)| from == node)
            .map(|(_, face)| *face)
            .collect();
        let radio = radio_faces.get(node).copied();
        for (prefix, fib_entry) in entry.engine.fib().dump() {
            let app_faces = fib_entry
                .nexthops
                .iter()
                .filter(|nh| Some(nh.face_id) != radio && !link_faces.contains(&nh.face_id))
                .count();
            if app_faces < 2 {
                continue;
            }
            let strategy = entry
                .engine
                .strategy_table()
                .lpm(&prefix)
                .map(|s| short_strategy_name(s.name()))
                .unwrap_or_else(|| "best-route".to_string());
            if !strategy.contains("multicast") {
                tracing::warn!(
                    node = node.0,
                    %prefix,
                    app_faces,
                    strategy = %strategy,
                    "ndn-lab: {app_faces} local app faces serve {prefix} under '{strategy}' — the \
                     forwarder delivers each Interest to only ONE. Use the multicast strategy to \
                     fan to all (fabric.explain_route(node, name) to inspect)."
                );
            }
        }
    }
}

/// A cheap, cloneable handle to the fabric's virtual clock — capture it in a spawned task instead
/// of cloning `Arc<dyn SimKernel>` and calling `k.runtime().unix_nanos()` everywhere.
/// [`RunningSimulation::clock`] hands one out.
#[derive(Clone)]
pub struct Clock {
    rt: std::sync::Arc<dyn ndn_runtime::Runtime>,
}

impl Clock {
    /// Virtual time now, in nanoseconds since the epoch (advances with the kernel's clock).
    pub fn now_ns(&self) -> u64 {
        self.rt.unix_nanos()
    }

    /// Virtual time now as a monotonic `Instant` (advances with the kernel's clock).
    pub fn now(&self) -> ndn_runtime::Instant {
        self.rt.now()
    }
}

impl std::fmt::Debug for Clock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Clock")
            .field("now_ns", &self.now_ns())
            .finish()
    }
}

/// A typed forwarding strategy — the discoverable, typo-proof alternative to the stringly-typed
/// NFD short name. Both `Strategy::Multicast` and `"multicast"` are accepted anywhere a strategy is
/// taken (the argument is `impl AsRef<str>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Strategy {
    /// Single best next-hop; fails over to another only on a consumer retransmission (NFD default).
    BestRoute,
    /// Fan every Interest to *all* eligible next-hops — the failover / all-local-faces knob. Use
    /// this when a prefix is served by more than one local app face (a Publisher **and** a
    /// Subscriber on `/time`), or when a disjoint backup path must survive a dead upstream.
    Multicast,
}

impl Strategy {
    /// The NFD short name the engine's strategy registry resolves.
    pub fn as_str(&self) -> &'static str {
        match self {
            Strategy::BestRoute => "best-route",
            Strategy::Multicast => "multicast",
        }
    }
}

impl AsRef<str> for Strategy {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for Strategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a FIB next-hop leaves the node — the classification [`RunningSimulation::explain_route`] and
/// [`RunningSimulation::face_stats`] attach so `recvs=0` becomes legible.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FaceKind {
    /// A wired link toward another fabric node.
    Link { toward: usize },
    /// This node's radio face on the shared medium.
    Radio,
    /// A local application face (a producer/consumer/Publisher/Subscriber on this node).
    App,
}

/// One next-hop in a [`RouteExplanation`].
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RouteNexthop {
    pub face: String,
    pub cost: u32,
    #[serde(flatten)]
    pub kind: FaceKind,
}

/// The answer to "where does an Interest for this name go, and why might it not arrive?" — the
/// longest-matching FIB prefix, the strategy that will pick among the next-hops, each next-hop
/// classified (link / radio / local app), and a `warning` for the classic silent trap: two local
/// app faces on one prefix under `best-route`, where only one ever receives.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RouteExplanation {
    pub node: usize,
    pub name: String,
    /// The longest FIB prefix matching `name`, or `None` if there is no route (→ Interests drop).
    pub matched_prefix: Option<String>,
    /// The strategy governing this name (`"best-route"` when none is set explicitly).
    pub strategy: String,
    pub nexthops: Vec<RouteNexthop>,
    /// A human-readable caution when the route is a silent trap (e.g. multi-app-face under best-route).
    pub warning: Option<String>,
}

/// Per-face packet counters (readable in a test) — turn `recvs=0` into "12 Interests in, 0 Data out
/// on the link toward node 3". Counts come straight from the engine's face counters; `satisfied` /
/// `nacked` breakdowns aren't tracked at the face level, so only the raw in/out/drops are reported.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FaceStats {
    pub face: String,
    #[serde(flatten)]
    pub kind: FaceKind,
    pub in_interests: u64,
    pub out_interests: u64,
    pub in_data: u64,
    pub out_data: u64,
    pub in_bytes: u64,
    pub out_bytes: u64,
    pub out_drops: u64,
}

/// A running fabric: live `ForwarderEngine`s on the kernel, with a control API and event
/// tracer. Implements [`FabricControl`](crate::FabricControl).
pub struct RunningSimulation {
    kernel: std::sync::Arc<dyn SimKernel>,
    tracer: std::sync::Arc<SimTracer>,
    world: std::sync::Arc<World>,
    /// Kernel clock at fabric start — the world's `t=0`, so scene snapshots query mobility at
    /// the elapsed virtual time.
    epoch_ns: u64,
    /// The shared radio medium, if the scenario enabled one via `with_radio_medium`.
    radio_bus: Option<std::sync::Arc<RadioBus>>,
    /// Per-radio-node face id, for routing over the radio.
    radio_faces: HashMap<NodeId, FaceId>,
    /// Live apps (producers/consumers) by id.
    apps: Mutex<HashMap<AppId, AppHandle>>,
    next_app: AtomicUsize,
    inner: Mutex<FabricInner>,
    channel_buffer: usize,
    next_node: AtomicUsize,
    /// The world seed, so links added at runtime (`connect`) seed their RNG consistently.
    seed: u64,
}

impl RunningSimulation {
    /// The kernel this fabric runs on.
    pub fn kernel(&self) -> &std::sync::Arc<dyn SimKernel> {
        &self.kernel
    }

    /// The shared event tracer (engine face events + control-plane events).
    pub fn tracer(&self) -> std::sync::Arc<SimTracer> {
        std::sync::Arc::clone(&self.tracer)
    }

    /// A cheap, cloneable handle to the fabric's virtual clock — capture it in a spawned task
    /// (`let clock = fabric.clock();`) and read `clock.now_ns()` instead of threading
    /// `Arc<dyn SimKernel>` through and calling `k.runtime().unix_nanos()`.
    pub fn clock(&self) -> Clock {
        Clock {
            rt: self.kernel.runtime(),
        }
    }

    /// The fabric's spatial [`World`] (empty unless declared via [`Simulation::world`]).
    /// Position-driven faces (a [`WirelessMedium`](crate::WirelessMedium)) read node
    /// positions/mobility from here; it is live-mutable through `&self`.
    pub fn world(&self) -> std::sync::Arc<World> {
        std::sync::Arc::clone(&self.world)
    }

    /// Drive node motion live from a [`MobilitySource`](crate::MobilitySource) (co-simulation): each
    /// pushed [`NodeState`](crate::NodeState) updates the World (and thus the radio) as it arrives,
    /// and the whole stream is captured into the returned [`MobilityTrace`](crate::MobilityTrace).
    /// `tick` is the poll granularity. Returns when the source is exhausted or `cancel` fires.
    ///
    /// On the [`RealTimeKernel`](crate::RealTimeKernel) governor this rides real time for a live feed
    /// (SITL/Gazebo); on a virtual/DES kernel with a scripted source it is deterministic.
    pub async fn drive_mobility(
        &self,
        source: Box<dyn crate::cosim::MobilitySource>,
        tick: std::time::Duration,
        cancel: tokio_util::sync::CancellationToken,
    ) -> crate::cosim::MobilityTrace {
        crate::cosim::drive_cosim(
            self.world(),
            self.epoch_ns,
            self.kernel.runtime(),
            source,
            tick,
            cancel,
        )
        .await
    }

    /// Install a recorded [`MobilityTrace`](crate::MobilityTrace) as deterministic per-node motion
    /// (one [`SampledMobility`](crate::SampledMobility) each) — the replay leg: a live co-sim capture
    /// becomes an ordinary, reproducible scenario the axis-2 validator can gate.
    pub fn install_trace(&self, trace: &crate::cosim::MobilityTrace) {
        for (node, model) in trace.into_models() {
            self.world.set_mobility(node, model);
        }
    }

    /// Spawn an app (producer/consumer) on `node` live; returns its [`AppId`].
    pub fn spawn_app(&self, node: NodeId, spec: AppSpec) -> Result<AppId> {
        let engine = self
            .engine_of(node)
            .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?;
        let id = AppId(self.next_app.fetch_add(1, Ordering::Relaxed));
        let handle = crate::app::spawn_app(&engine, id, node, &spec)?;
        self.apps.lock().unwrap().insert(id, handle);
        Ok(id)
    }

    /// Stop an app (cancels its tasks). Returns an error if no such app.
    pub fn stop_app(&self, app: AppId) -> Result<()> {
        let handle = self
            .apps
            .lock()
            .unwrap()
            .remove(&app)
            .ok_or_else(|| anyhow::anyhow!("no such app {}", app.0))?;
        handle.stop();
        Ok(())
    }

    /// Data served (producer) / fetched (consumer) by an app so far, if it exists.
    pub fn app_successes(&self, app: AppId) -> Option<u64> {
        self.apps.lock().unwrap().get(&app).map(|h| h.successes())
    }

    /// The full protocol-neutral [`FlowStats`](crate::FlowStats) for an app — RTT, loss, and goodput,
    /// not just the success count. The benchmark readout (and the shape the IP flow apps share).
    pub fn flow_stats(&self, app: AppId) -> Option<crate::app::FlowStats> {
        self.apps.lock().unwrap().get(&app).map(|h| h.stats())
    }

    /// `(id, node, kind)` for every live app.
    pub fn apps(&self) -> Vec<(AppId, NodeId, &'static str)> {
        let mut v: Vec<_> = self
            .apps
            .lock()
            .unwrap()
            .values()
            .map(|h| (h.id(), h.node(), h.kind()))
            .collect();
        v.sort_by_key(|(id, _, _)| id.0);
        v
    }

    /// The shared radio medium ([`RadioBus`]), if the scenario enabled one via
    /// [`Simulation::with_radio_medium`]. Use it to inspect deliveries or attach more radios.
    pub fn radio_bus(&self) -> Option<std::sync::Arc<RadioBus>> {
        self.radio_bus.clone()
    }

    /// Start recording radio delivery decisions (axis 4 causal capture) and return the
    /// [`RadioLog`](crate::analysis::RadioLog) — then [`explain_link`](crate::analysis::explain_link)
    /// answers "why couldn't node A reach node B?". `None` if the fabric has no radio medium.
    pub fn capture_radio(&self) -> Option<std::sync::Arc<crate::analysis::RadioLog>> {
        let bus = self.radio_bus.as_ref()?;
        let log = crate::analysis::RadioLog::new();
        bus.set_radio_log(std::sync::Arc::clone(&log));
        Some(log)
    }

    /// Spawn a **world-state history** sampler: every `interval`, record every node's position into a
    /// shared [`MobilityTrace`](crate::cosim::MobilityTrace) — the run's trajectory archive, for
    /// correlating a failure against where a node was over time (or for replay). Rides the fabric's
    /// kernel clock (virtual on DES). Stop it with `cancel`.
    pub fn spawn_position_sampler(
        &self,
        interval: std::time::Duration,
        cancel: tokio_util::sync::CancellationToken,
    ) -> std::sync::Arc<Mutex<crate::cosim::MobilityTrace>> {
        let history = std::sync::Arc::new(Mutex::new(crate::cosim::MobilityTrace::default()));
        let out = std::sync::Arc::clone(&history);
        let world = self.world();
        let epoch = self.epoch_ns;
        let runtime = self.kernel.runtime();
        let rt = std::sync::Arc::clone(&runtime);
        let nodes: Vec<NodeId> = self.inner.lock().unwrap().nodes.keys().copied().collect();
        runtime.spawn(Box::pin(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }
                let t_secs = rt.unix_nanos().saturating_sub(epoch) as f64 / 1e9;
                let view = world.snapshot(t_secs);
                {
                    let mut h = out.lock().unwrap();
                    for node in &nodes {
                        if let Some(pos) = view.position(*node) {
                            h.record(crate::cosim::NodeState {
                                node: *node,
                                t_secs,
                                position: pos,
                                velocity: None,
                            });
                        }
                    }
                }
                rt.sleep(interval).await;
            }
        }));
        history
    }

    /// Snapshot this run's observable outputs into a [`RunCapture`](crate::analysis::RunCapture) —
    /// terminal metrics, app fetch-successes, and (if a `radio` log is supplied) the radio delivery
    /// evidence. Two captures feed [`diff_runs`](crate::analysis::diff_runs) for a cross-run diff.
    pub fn capture_run(
        &self,
        radio: Option<&crate::analysis::RadioLog>,
    ) -> crate::analysis::RunCapture {
        let mut app_successes = std::collections::BTreeMap::new();
        for (id, _node, _kind) in self.apps() {
            if let Some(n) = self.app_successes(id) {
                app_successes.insert(id.0, n);
            }
        }
        crate::analysis::RunCapture {
            metrics: self.snapshot_metrics(),
            app_successes,
            radio: radio.map(|l| l.records()).unwrap_or_default(),
        }
    }

    /// The [`FaceId`] of `node`'s radio face (if it has one) — route over the radio with
    /// `engine.fib().add_nexthop(prefix, radio_face(node)?, cost)`.
    pub fn radio_face(&self, node: NodeId) -> Option<FaceId> {
        self.radio_faces.get(&node).copied()
    }

    /// Install a FIB route at `node`: `prefix` → its radio face (broadcast to all in-range
    /// radios). Convenience over [`radio_face`](Self::radio_face).
    pub fn route_over_radio(&self, node: NodeId, prefix: &Name) -> Result<()> {
        let face = self
            .radio_face(node)
            .ok_or_else(|| anyhow::anyhow!("node {node} has no radio face"))?;
        let engine = self
            .inner
            .lock()
            .unwrap()
            .nodes
            .get(&node)
            .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?
            .engine
            .clone();
        engine.fib().add_nexthop(prefix, face, 10);
        Ok(())
    }

    /// Move a node to a fixed position (live). The scene + any position-driven medium pick it
    /// up on their next snapshot — the seam for GUI drag-to-move.
    pub fn move_node(&self, node: NodeId, position: crate::world::Position) {
        self.world.place(node, position);
    }

    /// Give a node a mobility model live (e.g. a [`LinearMobility`](crate::world::LinearMobility)).
    pub fn set_mobility(
        &self,
        node: NodeId,
        model: std::sync::Arc<dyn crate::world::MobilityModel>,
    ) {
        self.world.set_mobility(node, model);
    }

    /// Snapshot every live node's engine metrics at the current (virtual) time — CS hit-rate,
    /// PIT depth, per-face throughput/drops — each stamped with the kernel clock. The on-demand
    /// counterpart of [`spawn_gauge_emitter`](Self::spawn_gauge_emitter); deterministic under a
    /// [`VirtualKernel`](crate::VirtualKernel).
    pub fn snapshot_metrics(&self) -> Vec<crate::telemetry::MetricsSample> {
        let guard = self.inner.lock().unwrap();
        let mut samples: Vec<_> = guard
            .nodes
            .iter()
            .map(|(id, e)| crate::telemetry::sample_engine(*id, &e.engine))
            .collect();
        samples.sort_by_key(|s| s.node.0);
        samples
    }

    /// A renderable [`SceneSnapshot`](crate::scene::SceneSnapshot) of the fabric — node
    /// positions (from the [`World`] at the current elapsed virtual time, else a deterministic
    /// circle layout), links, per-node metric badges, and world bounds. The `world_snapshot()`
    /// a GUI client draws (see [`scene`](crate::scene)).
    pub fn scene_snapshot(&self) -> crate::scene::SceneSnapshot {
        let topo = self.topology();
        let metrics = self.snapshot_metrics();
        let now = self.kernel.runtime().unix_nanos();
        let ids: Vec<usize> = topo.nodes.iter().map(|n| n.id.0).collect();

        // Default to an auto-layout, then override with real positions where the world places them.
        let mut positions = crate::scene::circle_layout(&ids, 100.0);
        let t_secs = now.saturating_sub(self.epoch_ns) as f64 / 1e9;
        let view = self.world.snapshot(t_secs);
        for id in &ids {
            if let Some(p) = view.position(NodeId(*id)) {
                positions.insert(*id, crate::scene::ScenePoint { x: p.x, y: p.y });
            }
        }
        let mut scene = crate::scene::project_scene(&topo, &metrics, &positions, now);

        // Radio reachability edges (RSSI) between radio nodes, for "links light up by RSSI".
        if let Some(bus) = &self.radio_bus {
            let mut radios: Vec<NodeId> = self.radio_faces.keys().copied().collect();
            radios.sort_by_key(|n| n.0);
            for (i, a) in radios.iter().enumerate() {
                for b in &radios[i + 1..] {
                    if let (Some(pa), Some(pb)) = (view.position(*a), view.position(*b))
                        && let Some(rssi) = bus.link_rssi(pa, pb)
                    {
                        scene.radio_links.push(crate::scene::RadioLink {
                            from: a.0,
                            to: b.0,
                            rssi_dbm: rssi,
                        });
                    }
                }
            }
        }
        scene
    }

    /// Spawn a periodic gauge emitter that snapshots every node into `log` once per `interval`
    /// (on the kernel clock — **virtual** time under a [`VirtualKernel`](crate::VirtualKernel),
    /// so samples land at deterministic virtual instants). Runs until `cancel` fires or the
    /// runtime is dropped. The sampled node set is fixed at spawn (engine handles are cloned).
    pub fn spawn_gauge_emitter(
        &self,
        interval: std::time::Duration,
        log: std::sync::Arc<crate::telemetry::MetricsLog>,
        cancel: tokio_util::sync::CancellationToken,
    ) {
        let mut engines: Vec<(NodeId, ForwarderEngine)> = self
            .inner
            .lock()
            .unwrap()
            .nodes
            .iter()
            .map(|(id, e)| (*id, e.engine.clone()))
            .collect();
        // Stable order ⇒ the emitted sample series replays identically.
        engines.sort_by_key(|(id, _)| id.0);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {
                        for (id, engine) in &engines {
                            log.record(crate::telemetry::sample_engine(*id, engine));
                        }
                    }
                }
            }
        });
    }

    /// The node's engine handle (a cheap `Arc` clone), or `None` if no such node.
    pub fn engine_of(&self, node: NodeId) -> Option<ForwarderEngine> {
        self.inner
            .lock()
            .unwrap()
            .nodes
            .get(&node)
            .map(|e| e.engine.clone())
    }

    /// Number of live nodes.
    pub fn nodes(&self) -> usize {
        self.inner.lock().unwrap().nodes.len()
    }

    /// A cancellation token tied to `node`'s lifetime — bridge faces use it so they shut down
    /// with the node. `None` if no such node.
    pub(crate) fn node_cancel(&self, node: NodeId) -> Option<tokio_util::sync::CancellationToken> {
        self.inner
            .lock()
            .unwrap()
            .nodes
            .get(&node)
            .map(|e| e.handle.cancel_token())
    }

    /// The FaceId of `from`'s face toward `to`, if linked.
    pub fn face_between(&self, from: NodeId, to: NodeId) -> Option<FaceId> {
        self.inner.lock().unwrap().links.get(&(from, to)).copied()
    }

    /// Install a FIB route at `node`: `prefix` → the link face toward `nexthop`.
    pub fn route(&self, node: NodeId, prefix: &Name, nexthop: NodeId) -> Result<()> {
        let guard = self.inner.lock().unwrap();
        let face_id = *guard
            .links
            .get(&(node, nexthop))
            .ok_or_else(|| anyhow::anyhow!("no link between {node} and {nexthop}"))?;
        let engine = guard
            .nodes
            .get(&node)
            .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?
            .engine
            .clone();
        drop(guard);
        engine.fib().add_nexthop(prefix, face_id, 10);
        Ok(())
    }

    /// Set the forwarding `strategy` for `prefix` on a live `node`. Accepts a typed
    /// [`Strategy`] or an NFD short name (`"best-route"` / `"multicast"`).
    pub fn set_strategy(
        &self,
        node: NodeId,
        prefix: &Name,
        strategy: impl AsRef<str>,
    ) -> Result<()> {
        let strategy = strategy.as_ref();
        let engine = {
            let guard = self.inner.lock().unwrap();
            guard
                .nodes
                .get(&node)
                .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?
                .engine
                .clone()
        };
        let strat = ndn_strategy::registry::create_by_name(strategy.as_bytes())
            .ok_or_else(|| anyhow::anyhow!("unknown forwarding strategy {strategy:?}"))?;
        engine.strategy_table().insert(prefix, strat);
        Ok(())
    }

    /// Explain where an Interest for `name` goes from `node` — the matched FIB prefix, the strategy,
    /// each next-hop classified (link toward a node / this node's radio / a local app face), and a
    /// `warning` for the silent trap that costs the most debugging time: two local app faces on one
    /// prefix under `best-route`, where the forwarder delivers each Interest to only **one** of them.
    pub fn explain_route(&self, node: NodeId, name: &Name) -> Result<RouteExplanation> {
        let (engine, link_faces) = {
            let guard = self.inner.lock().unwrap();
            let engine = guard
                .nodes
                .get(&node)
                .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?
                .engine
                .clone();
            // Faces of this node that are wired links, mapped to the node they point at.
            let link_faces: HashMap<FaceId, NodeId> = guard
                .links
                .iter()
                .filter(|((from, _), _)| *from == node)
                .map(|((_, to), face)| (*face, *to))
                .collect();
            (engine, link_faces)
        };
        let radio_face = self.radio_faces.get(&node).copied();
        let classify = |face: FaceId| -> FaceKind {
            if Some(face) == radio_face {
                FaceKind::Radio
            } else if let Some(to) = link_faces.get(&face) {
                FaceKind::Link { toward: to.0 }
            } else {
                FaceKind::App
            }
        };

        // Longest FIB prefix matching `name` (and its classified next-hops).
        let mut matched_prefix: Option<Name> = None;
        let mut nexthops: Vec<RouteNexthop> = Vec::new();
        for (prefix, entry) in engine.fib().dump() {
            if name.has_prefix(&prefix)
                && matched_prefix
                    .as_ref()
                    .is_none_or(|p| prefix.len() > p.len())
            {
                nexthops = entry
                    .nexthops
                    .iter()
                    .map(|nh| RouteNexthop {
                        face: nh.face_id.to_string(),
                        cost: nh.cost,
                        kind: classify(nh.face_id),
                    })
                    .collect();
                matched_prefix = Some(prefix);
            }
        }
        let strategy = engine
            .strategy_table()
            .lpm(name)
            .map(|s| short_strategy_name(s.name()))
            .unwrap_or_else(|| "best-route".to_string());

        let app_faces = nexthops.iter().filter(|n| n.kind == FaceKind::App).count();
        let warning = if matched_prefix.is_none() {
            Some(format!(
                "no FIB route for {name} at {node} — Interests will drop (no-route)"
            ))
        } else if app_faces >= 2 && !strategy.contains("multicast") {
            Some(format!(
                "{app_faces} local app faces serve this prefix under '{strategy}' — the forwarder \
                 delivers each Interest to only ONE of them. Use the multicast strategy to fan to all."
            ))
        } else {
            None
        };

        Ok(RouteExplanation {
            node: node.0,
            name: name.to_string(),
            matched_prefix: matched_prefix.map(|p| p.to_string()),
            strategy,
            nexthops,
            warning,
        })
    }

    /// Per-face packet counters for a `node` (in/out interests + data + bytes + drops), each face
    /// classified. Reach for this when "why didn't it arrive?" — `recvs=0` becomes "12 Interests in,
    /// 0 Data out on the link toward node 3". Readable directly in a test.
    pub fn face_stats(&self, node: NodeId) -> Result<Vec<FaceStats>> {
        let (engine, link_faces) = {
            let guard = self.inner.lock().unwrap();
            let engine = guard
                .nodes
                .get(&node)
                .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?
                .engine
                .clone();
            let link_faces: HashMap<FaceId, NodeId> = guard
                .links
                .iter()
                .filter(|((from, _), _)| *from == node)
                .map(|((_, to), face)| (*face, *to))
                .collect();
            (engine, link_faces)
        };
        let radio_face = self.radio_faces.get(&node).copied();

        let mut out = Vec::new();
        for e in engine.face_states().iter() {
            let face = *e.key();
            let c = &e.value().counters;
            let kind = if Some(face) == radio_face {
                FaceKind::Radio
            } else if let Some(to) = link_faces.get(&face) {
                FaceKind::Link { toward: to.0 }
            } else {
                FaceKind::App
            };
            out.push(FaceStats {
                face: face.to_string(),
                kind,
                in_interests: c.in_interests.load(Ordering::Relaxed),
                out_interests: c.out_interests.load(Ordering::Relaxed),
                in_data: c.in_data.load(Ordering::Relaxed),
                out_data: c.out_data.load(Ordering::Relaxed),
                in_bytes: c.in_bytes.load(Ordering::Relaxed),
                out_bytes: c.out_bytes.load(Ordering::Relaxed),
                out_drops: c.out_drops.load(Ordering::Relaxed),
            });
        }
        out.sort_by(|a, b| a.face.cmp(&b.face));
        Ok(out)
    }

    /// Connect two live nodes with a symmetric in-proc wired link.
    pub fn connect(&self, a: NodeId, b: NodeId, config: LinkConfig) -> Result<()> {
        self.connect_profiled(a, b, FaceProfile::internal().with_link(config))
    }

    /// Connect two live nodes with a typed link from the per-face catalogue.
    pub fn connect_profiled(&self, a: NodeId, b: NodeId, profile: FaceProfile) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        if !guard.nodes.contains_key(&a) || !guard.nodes.contains_key(&b) {
            bail!("connect references non-existent node");
        }
        let FabricInner { nodes, links, link_states } = &mut *guard;
        wire_link(nodes, links, link_states, a, b, &profile, self.channel_buffer, self.seed);
        drop(guard);
        self.tracer.record_now(
            a.0,
            None,
            EventKind::Custom("link".into()),
            b.to_string(),
            None,
        );
        Ok(())
    }

    /// Cut or restore the (undirected) link between `a` and `b` — a link failure / recovery, both
    /// directions. A cut link silently drops every frame until restored (or [`heal`](Self::heal)).
    pub fn set_link_up(&self, a: NodeId, b: NodeId, up: bool) -> Result<()> {
        let (sa, sb) = self.link_state_pair(a, b)?;
        sa.set_down(!up);
        sb.set_down(!up);
        Ok(())
    }

    /// Degrade the link between `a` and `b` (both directions): override its loss rate and/or add
    /// extra per-frame delay (congestion). `None` leaves that knob at the profile default.
    pub fn degrade_link(
        &self,
        a: NodeId,
        b: NodeId,
        loss_rate: Option<f64>,
        extra_delay: Option<std::time::Duration>,
    ) -> Result<()> {
        let (sa, sb) = self.link_state_pair(a, b)?;
        for s in [sa, sb] {
            if let Some(l) = loss_rate {
                s.set_loss(Some(l));
            }
            if let Some(d) = extra_delay {
                s.set_extra_delay(d);
            }
        }
        Ok(())
    }

    /// Partition the fabric: cut every link that crosses the boundary of `group` (exactly one
    /// endpoint in `group`). Links wholly inside or outside are untouched. Undo with [`heal`](Self::heal).
    pub fn partition(&self, group: &[NodeId]) {
        let set: std::collections::HashSet<NodeId> = group.iter().copied().collect();
        let guard = self.inner.lock().unwrap();
        for ((from, to), state) in guard.link_states.iter() {
            if set.contains(from) != set.contains(to) {
                state.set_down(true);
            }
        }
    }

    /// Heal all link faults: restore every link to its profile defaults (up, no loss override, no
    /// extra delay).
    pub fn heal(&self) {
        let guard = self.inner.lock().unwrap();
        for state in guard.link_states.values() {
            state.reset();
        }
    }

    /// The live fault knobs for both directions of the link between `a` and `b`.
    fn link_state_pair(
        &self,
        a: NodeId,
        b: NodeId,
    ) -> Result<(
        std::sync::Arc<crate::sim_face::LinkState>,
        std::sync::Arc<crate::sim_face::LinkState>,
    )> {
        let guard = self.inner.lock().unwrap();
        let sa = guard.link_states.get(&(a, b)).cloned();
        let sb = guard.link_states.get(&(b, a)).cloned();
        match (sa, sb) {
            (Some(sa), Some(sb)) => Ok((sa, sb)),
            _ => bail!("no link between {a} and {b}"),
        }
    }

    /// Spawn a new node from `profile` on the running fabric; returns its handle.
    pub async fn spawn_node(&self, profile: NodeProfile) -> Result<NodeId> {
        let id = NodeId(self.next_node.fetch_add(1, Ordering::Relaxed));
        // Build off-lock (async), then insert under the lock.
        let (engine, handle) = EngineBuilder::new(profile.config)
            .runtime(self.kernel.runtime())
            .build()
            .await?;
        engine.set_face_lifecycle_sink(std::sync::Arc::new(TracerFaceSink {
            tracer: std::sync::Arc::clone(&self.tracer),
            node: id.0,
        }));
        self.inner.lock().unwrap().nodes.insert(
            id,
            NodeEntry {
                engine,
                handle,
                label: profile.label,
            },
        );
        self.tracer
            .record_now(id.0, None, EventKind::Custom("node-spawn".into()), "", None);
        info!(node = id.0, "ndn-lab: node spawned");
        Ok(id)
    }

    /// Remove a node (shutting its engine down) and drop all its links.
    pub async fn remove_node(&self, node: NodeId) -> Result<()> {
        let entry = {
            let mut guard = self.inner.lock().unwrap();
            guard
                .links
                .retain(|(from, to), _| *from != node && *to != node);
            guard.nodes.remove(&node)
        };
        let Some(entry) = entry else {
            bail!("no such node {node}");
        };
        self.tracer.record_now(
            node.0,
            None,
            EventKind::Custom("node-remove".into()),
            "",
            None,
        );
        entry.handle.shutdown().await;
        info!(node = node.0, "ndn-lab: node removed");
        Ok(())
    }

    /// A snapshot of the current topology.
    pub fn topology(&self) -> TopologySnapshot {
        let guard = self.inner.lock().unwrap();
        let mut nodes: Vec<NodeInfo> = guard
            .nodes
            .iter()
            .map(|(id, e)| NodeInfo {
                id: *id,
                label: e.label.clone(),
            })
            .collect();
        nodes.sort_by_key(|n| n.id.0);
        let mut links: Vec<LinkInfo> = guard
            .links
            .iter()
            .map(|((from, to), face)| LinkInfo {
                from: *from,
                to: *to,
                face: face.0,
            })
            .collect();
        links.sort_by_key(|l| (l.from.0, l.to.0));
        TopologySnapshot { nodes, links }
    }

    /// Shut down every node's engine. Takes `&self` so the fabric can be held in an
    /// `Arc` (e.g. behind a [`ControlPlane`](crate::ControlPlane)); after this the fabric is
    /// empty.
    pub async fn shutdown(&self) {
        for (_, handle) in std::mem::take(&mut *self.apps.lock().unwrap()) {
            handle.stop();
        }
        let nodes = std::mem::take(&mut self.inner.lock().unwrap().nodes);
        for (_, entry) in nodes {
            entry.handle.shutdown().await;
        }
    }
}

#[async_trait::async_trait]
impl crate::control::FabricControl for RunningSimulation {
    async fn spawn_node(&self, profile: NodeProfile) -> Result<NodeId> {
        RunningSimulation::spawn_node(self, profile).await
    }
    async fn remove_node(&self, node: NodeId) -> Result<()> {
        RunningSimulation::remove_node(self, node).await
    }
    fn connect(&self, a: NodeId, b: NodeId, config: LinkConfig) -> Result<()> {
        RunningSimulation::connect(self, a, b, config)
    }
    fn route(&self, node: NodeId, prefix: &Name, nexthop: NodeId) -> Result<()> {
        RunningSimulation::route(self, node, prefix, nexthop)
    }
    fn engine_of(&self, node: NodeId) -> Option<ForwarderEngine> {
        RunningSimulation::engine_of(self, node)
    }
    fn topology(&self) -> TopologySnapshot {
        RunningSimulation::topology(self)
    }
    fn nodes(&self) -> usize {
        RunningSimulation::nodes(self)
    }
}
