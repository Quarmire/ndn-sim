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

use crate::control::{LinkInfo, NodeInfo, TopologySnapshot, TracerFaceSink};
use crate::kernel::{SimKernel, WallClockKernel};
use crate::profile::NodeProfile;
use crate::sim_link::{LinkConfig, SimLink};
use crate::tracer::{EventKind, SimTracer};
use crate::world::World;

/// Opaque, stable handle to a node in the fabric (survives other nodes being removed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
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
    config: LinkConfig,
}

struct PendingRoute {
    node: NodeId,
    prefix: Name,
    nexthop_node: NodeId,
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

    /// Connect two nodes with a symmetric link.
    pub fn link(&mut self, a: NodeId, b: NodeId, config: LinkConfig) {
        self.links.push(PendingLink { a, b, config });
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
        for link in &self.links {
            if !nodes.contains_key(&link.a) || !nodes.contains_key(&link.b) {
                bail!("link references non-existent node");
            }
            wire_link(&nodes, &mut links, link.a, link.b, &link.config, self.channel_buffer);
        }

        for route in &self.routes {
            let face_id = links.get(&(route.node, route.nexthop_node)).ok_or_else(|| {
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

        let epoch_ns = self.kernel.runtime().unix_nanos();
        Ok(RunningSimulation {
            kernel: self.kernel,
            tracer,
            world: self.world,
            epoch_ns,
            inner: Mutex::new(FabricInner { nodes, links }),
            channel_buffer: self.channel_buffer,
            next_node: AtomicUsize::new(n),
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
}

/// Wire a symmetric SimLink between two existing nodes, recording both directed faces.
fn wire_link(
    nodes: &HashMap<NodeId, NodeEntry>,
    links: &mut HashMap<(NodeId, NodeId), FaceId>,
    a: NodeId,
    b: NodeId,
    config: &LinkConfig,
    channel_buffer: usize,
) {
    let ea = &nodes[&a];
    let eb = &nodes[&b];
    let id_a = ea.engine.faces().alloc_id();
    let id_b = eb.engine.faces().alloc_id();
    let (face_a, face_b) = SimLink::pair(id_a, id_b, config.clone(), channel_buffer);
    ea.engine.add_face(face_a, ea.handle.cancel_token());
    eb.engine.add_face(face_b, eb.handle.cancel_token());
    links.insert((a, b), id_a);
    links.insert((b, a), id_b);
    info!(node_a = a.0, face_a = %id_a, node_b = b.0, face_b = %id_b, "ndn-lab: link created");
}

/// A running fabric: live `ForwarderEngine`s on the kernel, with a control API and event
/// tracer. Implements [`FabricControl`](crate::FabricControl).
pub struct RunningSimulation {
    kernel: std::sync::Arc<dyn SimKernel>,
    tracer: std::sync::Arc<SimTracer>,
    world: Option<std::sync::Arc<World>>,
    /// Kernel clock at fabric start — the world's `t=0`, so scene snapshots query mobility at
    /// the elapsed virtual time.
    epoch_ns: u64,
    inner: Mutex<FabricInner>,
    channel_buffer: usize,
    next_node: AtomicUsize,
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

    /// The spatial [`World`] attached via [`Simulation::world`], if any. Position-driven faces
    /// (a [`WirelessMedium`](crate::WirelessMedium)) read node positions/mobility from here.
    pub fn world(&self) -> Option<std::sync::Arc<World>> {
        self.world.clone()
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

        // Default to an auto-layout, then override with real positions where a world places them.
        let mut positions = crate::scene::circle_layout(&ids, 100.0);
        if let Some(world) = &self.world {
            let t_secs = now.saturating_sub(self.epoch_ns) as f64 / 1e9;
            let view = world.snapshot(t_secs);
            for id in &ids {
                if let Some(p) = view.position(NodeId(*id)) {
                    positions.insert(*id, crate::scene::ScenePoint { x: p.x, y: p.y });
                }
            }
        }
        crate::scene::project_scene(&topo, &metrics, &positions, now)
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
        self.inner.lock().unwrap().nodes.get(&node).map(|e| e.engine.clone())
    }

    /// Number of live nodes.
    pub fn nodes(&self) -> usize {
        self.inner.lock().unwrap().nodes.len()
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

    /// Connect two live nodes with a symmetric link.
    pub fn connect(&self, a: NodeId, b: NodeId, config: LinkConfig) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        if !guard.nodes.contains_key(&a) || !guard.nodes.contains_key(&b) {
            bail!("connect references non-existent node");
        }
        let FabricInner { nodes, links } = &mut *guard;
        wire_link(nodes, links, a, b, &config, self.channel_buffer);
        drop(guard);
        self.tracer.record_now(a.0, None, EventKind::Custom("link".into()), b.to_string(), None);
        Ok(())
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
        self.tracer.record_now(id.0, None, EventKind::Custom("node-spawn".into()), "", None);
        info!(node = id.0, "ndn-lab: node spawned");
        Ok(id)
    }

    /// Remove a node (shutting its engine down) and drop all its links.
    pub async fn remove_node(&self, node: NodeId) -> Result<()> {
        let entry = {
            let mut guard = self.inner.lock().unwrap();
            guard.links.retain(|(from, to), _| *from != node && *to != node);
            guard.nodes.remove(&node)
        };
        let Some(entry) = entry else {
            bail!("no such node {node}");
        };
        self.tracer.record_now(node.0, None, EventKind::Custom("node-remove".into()), "", None);
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
