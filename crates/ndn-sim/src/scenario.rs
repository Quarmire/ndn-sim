//! Declarative scenario files (ndn-lab follow-on, requested next-focus).
//!
//! A [`Scenario`] is the whole simulation as **one diff-able, AI-authorable artifact** —
//! kernel, environment, radio medium, nodes (positions / mobility / radio), links, and routes —
//! serialized to TOML or JSON. It's the missing keystone the design's front-ends presuppose:
//! `ndn-lab run scenario.toml`, MCP `create_scenario`, reproducible sharing, and `compare_runs`
//! (a "same scenario" to compare) all build on it. The control-plane DTOs were already
//! serde-ready; this serializes the *builder*.
//!
//! [`Scenario::build`] turns the document into a ready-to-`start` [`Simulation`] on a kernel the
//! caller supplies (so a `virtual` scenario is driven inside `VirtualKernel::run`, a `wall_clock`
//! one directly). Round-trips: `from_toml`/`to_toml`, `from_json`/`to_json`; load a file with
//! [`from_toml_file`](Scenario::from_toml_file) so relative paths resolve against it.
//!
//! A node is either a default-config forwarder or **booted from an ndn-fwd config**
//! (`config = "gcs.toml"`, `addr = "10.0.0.11"`): its `[[face]]` UDP peers between sim nodes
//! become [`peer_links`](Scenario::peer_links), and its routes/strategies are applied by ndn-fwd's
//! own boot code. Not yet captured: app lifecycle (spawn_app — its own follow-on) and waypoint
//! mobility (linear only).

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use ndn_engine::builder::EngineConfig;
use serde::{Deserialize, Serialize};

use crate::medium::{FreeSpacePathLoss, PropagationModel, RangeThreshold};
use crate::world::{LinearMobility, Position, UniformAttenuation};
use crate::{NodeId, SimKernel, Simulation};

/// A complete simulation, declaratively.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Scenario {
    #[serde(default)]
    pub kernel: KernelSpec,
    /// World seed — perturbs every face's loss/jitter RNG and the radio erasure RNG. 0 = the
    /// default realization; a validation seed sweep overrides it to draw independent realizations.
    #[serde(default)]
    pub seed: u64,
    /// Path to a recorded co-sim [`MobilityTrace`](crate::cosim::MobilityTrace) JSON — relative to the scenario file when
    /// loaded with [`from_toml_file`](Scenario::from_toml_file) (else to the working directory).
    /// When set, each node named in the trace is driven by a deterministic `SampledMobility`
    /// replaying it — the replay leg of co-simulation: a live capture (e.g. an ArduPilot flight)
    /// becomes a reproducible, gate-able scenario.
    #[serde(default)]
    pub mobility_trace: Option<String>,
    #[serde(default)]
    pub environment: EnvSpec,
    #[serde(default)]
    pub radio: Option<RadioMediumSpec>,
    #[serde(default)]
    pub nodes: Vec<NodeSpec>,
    #[serde(default)]
    pub links: Vec<ScenarioLink>,
    #[serde(default)]
    pub routes: Vec<RouteSpec>,
    /// Broadcast routes over a radio face (`node` must be a `radio` node) — the declarative form of
    /// routing over the shared medium. Wired routes use [`routes`](Scenario::routes) instead.
    #[serde(default)]
    pub radio_routes: Vec<RadioRouteSpec>,
    #[serde(default)]
    pub strategies: Vec<StrategyChoiceSpec>,
    /// External peers attached at the edge over real UDP (the bridge doctrine: a real face *on a
    /// node*, never a fake node). Applied post-start by [`apply_bridges`](Scenario::apply_bridges);
    /// requires a real-time-capable kernel (`wall_clock` / `real_time`) — an external process
    /// cannot obey a virtual clock.
    #[serde(default)]
    pub bridges: Vec<BridgeSpec>,
    /// Shared contended media (managed Wi-Fi cells) that links join by name — see
    /// [`SharedChannel`](crate::SharedChannel).
    #[serde(default)]
    pub channels: Vec<ChannelSpec>,
    /// How `[[face]]` UDP peer links between config-booted nodes are carried (default: a
    /// production UDP peer link on a LAN).
    #[serde(default)]
    pub peer_links: Option<PeerLinkSpec>,
}

/// A shared, airtime-serialised medium:
///
/// ```toml
/// [[channels]]
/// name = "cell"
/// rate_bps = 24000000        # effective PHY rate
/// frame_overhead_us = 150    # per-frame MAC/PHY overhead (default 150)
/// max_backlog_ms = 200       # queued airtime before tail-drop (default 200)
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelSpec {
    pub name: String,
    pub rate_bps: u64,
    #[serde(default = "default_frame_overhead_us")]
    pub frame_overhead_us: u64,
    #[serde(default)]
    pub max_backlog_ms: Option<u64>,
}

fn default_frame_overhead_us() -> u64 {
    150
}

/// The link config-derived UDP peer faces ride:
///
/// ```toml
/// [peer_links]
/// delay_ms = 2
/// loss_rate = 0.05
/// loss_frame_bytes = 1500   # optional: loss_rate is that of a 1500 B frame; smaller lose less
/// channel = "cell"          # optional [[channels]] name
/// lp_reliability = true     # default true: the fleet enables it per face
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerLinkSpec {
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub jitter_ms: u64,
    #[serde(default)]
    pub loss_rate: f64,
    #[serde(default)]
    pub bandwidth_bps: u64,
    #[serde(default)]
    pub channel: Option<String>,
    /// `loss_rate` is quoted for a frame of this many IP bytes (see
    /// [`FaceProfile::with_loss_frame_bytes`](crate::FaceProfile::with_loss_frame_bytes)).
    #[serde(default)]
    pub loss_frame_bytes: Option<usize>,
    #[serde(default = "default_true")]
    pub lp_reliability: bool,
}

fn default_true() -> bool {
    true
}

/// A declarable UDP bridge to an external NDN endpoint (NFD / ndnd / NDNts / a device):
///
/// ```toml
/// [[bridges]]
/// node  = 0
/// local = "127.0.0.1:0"          # fixed port if the peer must dial back
/// peer  = "127.0.0.1:6363"
/// route = "/interop"             # optional FIB route over the bridge face
/// mtu   = 1200                   # optional send-MTU clamp (NDNLPv2-fragments above it)
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BridgeSpec {
    pub node: usize,
    pub local: String,
    pub peer: String,
    #[serde(default)]
    pub route: Option<String>,
    #[serde(default)]
    pub mtu: Option<u64>,
}

/// A broadcast FIB route over a node's radio face.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadioRouteSpec {
    pub node: usize,
    pub prefix: String,
}

/// Choose a forwarding strategy for a prefix on a node (like NFD's strategy-choice table). A
/// `multicast` strategy fans each Interest to every eligible next-hop, so a fully disjoint backup
/// path survives a dead upstream — the declarative failover knob.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StrategyChoiceSpec {
    pub node: usize,
    /// The namespace this choice governs. Defaults to `/` (node-wide).
    #[serde(default = "default_strategy_prefix")]
    pub prefix: String,
    /// NFD short strategy name: `"best-route"` (default engine behavior) or `"multicast"`.
    pub strategy: String,
}

fn default_strategy_prefix() -> String {
    "/".to_string()
}

/// The recorded execution model (the caller still supplies the concrete kernel to
/// [`build`](Scenario::build); this is intent + what a top-level runner dispatches on).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KernelSpec {
    #[default]
    WallClock,
    Virtual {
        // No per-kernel seed here: the scenario-level `seed` (ScenarioSpec::seed, applied at
        // Simulation::seed) is the single source of randomness. A prior `seed` field on this variant was
        // silently ignored (build never read it) — a reproducibility footgun — so it was removed.
        #[serde(default)]
        epoch_ns: Option<u64>,
    },
    /// Real-time governor: real pace (hosts real devices) + a logical scenario-relative clock.
    RealTime {
        #[serde(default)]
        epoch_ns: Option<u64>,
    },
    /// Discrete-event executor: a from-scratch deterministic event queue (no tokio). Runs
    /// event-stepped in virtual time — the same replay guarantees as `virtual`, but on ndn-lab's
    /// own scheduler rather than tokio's paused clock. `epoch_ns` seeds the virtual `now()` origin.
    Des {
        #[serde(default)]
        epoch_ns: Option<u64>,
    },
}

impl KernelSpec {
    pub fn is_virtual(&self) -> bool {
        matches!(self, KernelSpec::Virtual { .. })
    }

    pub fn is_des(&self) -> bool {
        matches!(self, KernelSpec::Des { .. })
    }
}

/// The world's RF environment.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnvSpec {
    #[default]
    FreeSpace,
    /// Constant excess attenuation everywhere (dB).
    Uniform { db: f64 },
}

/// Shared radio medium config (nodes opt in via `NodeSpec.radio`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RadioMediumSpec {
    #[serde(default)]
    pub propagation: PropSpec,
    #[serde(default)]
    pub seed: u64,
    /// Line-of-sight obstacles (buildings/terrain). When present, the propagation model is wrapped
    /// in an [`ObstructedPropagation`](crate::ObstructedPropagation): a frame whose path crosses one
    /// is attenuated/blocked. Pairs with co-sim mobility — a drone flying behind a building drops.
    #[serde(default)]
    pub obstacles: Vec<ObstacleSpec>,
    /// Attenuation (dB) per obstacle crossed (default 200 = a hard blocker; use ~10 for foliage).
    #[serde(default)]
    pub obstruction_loss_db: Option<f64>,
}

/// An axis-aligned box obstacle, by two opposite corners `[x, y, z]` (metres).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct ObstacleSpec {
    pub min: [f64; 3],
    pub max: [f64; 3],
}

/// A propagation model.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PropSpec {
    FreeSpacePathLoss {
        #[serde(default = "default_tx_power")]
        tx_power_dbm: f64,
        #[serde(default = "default_freq")]
        freq_hz: f64,
        #[serde(default = "default_sensitivity")]
        rx_sensitivity_dbm: f64,
    },
    RangeThreshold {
        #[serde(default = "default_range")]
        range_m: f64,
        #[serde(default = "default_tx_power")]
        tx_power_dbm: f64,
    },
}

fn default_tx_power() -> f64 {
    20.0
}
fn default_freq() -> f64 {
    2.4e9
}
fn default_sensitivity() -> f64 {
    -85.0
}
fn default_range() -> f64 {
    100.0
}

impl Default for PropSpec {
    fn default() -> Self {
        PropSpec::FreeSpacePathLoss {
            tx_power_dbm: default_tx_power(),
            freq_hz: default_freq(),
            rx_sensitivity_dbm: default_sensitivity(),
        }
    }
}

impl PropSpec {
    fn build(&self) -> Arc<dyn PropagationModel> {
        match *self {
            PropSpec::FreeSpacePathLoss {
                tx_power_dbm,
                freq_hz,
                rx_sensitivity_dbm,
            } => Arc::new(FreeSpacePathLoss {
                tx_power_dbm,
                freq_hz,
                rx_sensitivity_dbm,
            }),
            PropSpec::RangeThreshold {
                range_m,
                tx_power_dbm,
            } => Arc::new(RangeThreshold {
                range_m,
                tx_power_dbm,
            }),
        }
    }
}

/// One node: a default-config forwarder, or — with `config` + `addr` — one booted from an
/// ndn-fwd TOML the way the deployed forwarder boots (see [`Simulation::add_node_from_config`]).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeSpec {
    /// Defaults to the config file's stem for a config-booted node.
    #[serde(default)]
    pub label: Option<String>,
    /// World position `[x, y, z]` metres.
    #[serde(default)]
    pub position: Option<[f64; 3]>,
    /// Constant velocity `[vx, vy, vz]` m/s (linear mobility from `position`).
    #[serde(default)]
    pub velocity: Option<[f64; 3]>,
    /// Attach a radio face on the shared medium (requires `[radio]`).
    #[serde(default)]
    pub radio: bool,
    /// Apps to run on this node (producers/consumers).
    #[serde(default)]
    pub apps: Vec<crate::app::AppSpec>,
    /// Path to an ndn-fwd TOML config (relative to the scenario file under
    /// [`from_toml_file`](Scenario::from_toml_file)). Requires `addr`.
    #[serde(default)]
    pub config: Option<String>,
    /// The node's IP identity: other nodes' `[[face]] remote`s resolve against it.
    #[serde(default)]
    pub addr: Option<String>,
}

/// A wired link between two nodes (durations in ms; `0` = none).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ScenarioLink {
    pub a: usize,
    pub b: usize,
    /// Face type from the catalogue (`"udp"`, `"tcp"`, `"quic"`, `"ble"`, …). When set, the link
    /// uses that type's preset behavior (kind/MTU/loss/ordering) and the `*_ms`/`loss`/`bandwidth`
    /// fields are ignored; omit it for the production UDP peer link carrying those fields.
    #[serde(default)]
    pub face: Option<String>,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub jitter_ms: u64,
    #[serde(default)]
    pub loss_rate: f64,
    #[serde(default)]
    pub bandwidth_bps: u64,
    /// A [`channels`](Scenario::channels) name: the link contends for that medium's airtime.
    #[serde(default)]
    pub channel: Option<String>,
}

/// A FIB route: `prefix` at `node` toward `nexthop` (over the link between them).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouteSpec {
    pub node: usize,
    pub prefix: String,
    pub nexthop: usize,
}

impl Scenario {
    pub fn from_toml(s: &str) -> Result<Self> {
        Ok(toml::from_str(s)?)
    }
    pub fn to_toml(&self) -> Result<String> {
        Ok(toml::to_string_pretty(self)?)
    }
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Load a scenario file, resolving its relative paths (node `config`s, `mobility_trace`)
    /// against the file's directory — so a scenario runs the same from any working directory.
    pub fn from_toml_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read scenario {}", path.display()))?;
        let mut scenario =
            Self::from_toml(&text).with_context(|| format!("parse scenario {}", path.display()))?;
        scenario.resolve_paths(path.parent().unwrap_or(Path::new(".")));
        Ok(scenario)
    }

    /// Rewrite every relative path in the document (node `config`s, `mobility_trace`) as
    /// `base_dir.join(path)`. Absolute paths are left alone.
    pub fn resolve_paths(&mut self, base_dir: &Path) {
        let resolve = |p: &mut String| {
            if Path::new(p.as_str()).is_relative() {
                *p = base_dir.join(p.as_str()).to_string_lossy().into_owned();
            }
        };
        if let Some(trace) = &mut self.mobility_trace {
            resolve(trace);
        }
        for node in &mut self.nodes {
            if let Some(config) = &mut node.config {
                resolve(config);
            }
        }
    }

    /// Turn the document into a ready-to-[`start`](Simulation::start) [`Simulation`] on `kernel`.
    /// For a `virtual` scenario, call this *inside* `VirtualKernel::run` with that kernel; for
    /// `wall_clock`, pass a [`WallClockKernel`](crate::WallClockKernel).
    pub fn build(&self, kernel: Arc<dyn SimKernel>) -> Result<Simulation> {
        let channels: std::collections::HashMap<&str, Arc<crate::SharedChannel>> = self
            .channels
            .iter()
            .map(|c| {
                let mut ch = crate::SharedChannel::new(
                    c.name.clone(),
                    c.rate_bps.max(1),
                    std::time::Duration::from_micros(c.frame_overhead_us),
                );
                if let Some(ms) = c.max_backlog_ms {
                    ch = ch.with_max_backlog(std::time::Duration::from_millis(ms));
                }
                (c.name.as_str(), Arc::new(ch))
            })
            .collect();
        let channel = |name: &str| {
            channels
                .get(name)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("unknown channel {name:?}"))
        };

        let mut sim = Simulation::new().kernel(kernel).seed(self.seed);
        if let Some(p) = &self.peer_links {
            let mut profile = crate::FaceProfile::udp()
                .with_link(link_config(
                    p.delay_ms,
                    p.jitter_ms,
                    p.loss_rate,
                    p.bandwidth_bps,
                ))
                .with_lp_reliability(p.lp_reliability);
            if let Some(name) = &p.channel {
                profile = profile.on_channel(channel(name)?);
            }
            if let Some(bytes) = p.loss_frame_bytes {
                profile = profile.with_loss_frame_bytes(bytes);
            }
            sim = sim.with_peer_link(profile);
        }

        if let Some(radio) = &self.radio {
            let base = radio.propagation.build();
            let prop: Arc<dyn crate::medium::PropagationModel> = if radio.obstacles.is_empty() {
                base
            } else {
                let obstacles = radio
                    .obstacles
                    .iter()
                    .map(|o| {
                        crate::Obstacle::from_corners(
                            Position::xyz(o.min[0], o.min[1], o.min[2]),
                            Position::xyz(o.max[0], o.max[1], o.max[2]),
                        )
                    })
                    .collect();
                let mut op = crate::ObstructedPropagation::new(base, obstacles);
                if let Some(loss) = radio.obstruction_loss_db {
                    op = op.with_loss_db(loss);
                }
                Arc::new(op)
            };
            sim = sim.with_radio_medium(prop, radio.seed);
        } else if self.nodes.iter().any(|n| n.radio) {
            bail!("a node is marked `radio` but no [radio] medium is configured");
        }

        if let EnvSpec::Uniform { db } = self.environment {
            sim.environment(Arc::new(UniformAttenuation(db)));
        }

        for (i, spec) in self.nodes.iter().enumerate() {
            let pos = spec.position.map(|[x, y, z]| Position::xyz(x, y, z));
            let id = if let Some(path) = &spec.config {
                if spec.radio {
                    bail!("nodes[{i}]: a config-booted node cannot also be a `radio` node");
                }
                let addr = spec
                    .addr
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("nodes[{i}]: `config` requires `addr`"))?
                    .parse()
                    .with_context(|| format!("nodes[{i}].addr"))?;
                let cfg = ndn_config::ForwarderConfig::from_file(Path::new(path))
                    .with_context(|| format!("nodes[{i}]: load ndn-fwd config {path}"))?;
                let label = spec.label.clone().unwrap_or_else(|| {
                    Path::new(path)
                        .file_stem()
                        .map_or_else(|| format!("node#{i}"), |s| s.to_string_lossy().into_owned())
                });
                let id = sim.add_node_from_config(label, cfg, addr);
                if let Some(p) = pos {
                    sim.place_node(id, p);
                }
                id
            } else if spec.radio {
                sim.add_radio_node(EngineConfig::default(), pos.unwrap_or(Position::ORIGIN))
            } else {
                let id = sim.add_node(EngineConfig::default());
                if let Some(p) = pos {
                    sim.place_node(id, p);
                }
                id
            };
            if let Some([vx, vy, vz]) = spec.velocity {
                sim.set_node_mobility(
                    id,
                    Arc::new(LinearMobility {
                        start: pos.unwrap_or(Position::ORIGIN),
                        velocity: (vx, vy, vz),
                    }),
                );
            }
            for app in &spec.apps {
                sim.add_app(id, app.clone());
            }
        }

        for l in &self.links {
            self.check_node(l.a)?;
            self.check_node(l.b)?;
            let profile = match &l.face {
                Some(name) => crate::FaceProfile::from_name(name)
                    .ok_or_else(|| anyhow::anyhow!("unknown face type {name:?}"))?,
                None => crate::FaceProfile::udp().with_link(link_config(
                    l.delay_ms,
                    l.jitter_ms,
                    l.loss_rate,
                    l.bandwidth_bps,
                )),
            };
            let profile = match &l.channel {
                Some(name) => profile.on_channel(channel(name)?),
                None => profile,
            };
            sim.link_profiled(NodeId(l.a), NodeId(l.b), profile);
        }

        for r in &self.routes {
            self.check_node(r.node)?;
            self.check_node(r.nexthop)?;
            sim.add_route(NodeId(r.node), &r.prefix, NodeId(r.nexthop));
        }

        for r in &self.radio_routes {
            self.check_node(r.node)?;
            sim.add_radio_route(NodeId(r.node), &r.prefix);
        }

        for sc in &self.strategies {
            self.check_node(sc.node)?;
            sim.add_strategy(NodeId(sc.node), &sc.prefix, &sc.strategy);
        }

        if let Some(path) = &self.mobility_trace {
            let json = std::fs::read_to_string(path)
                .with_context(|| format!("read mobility trace {path:?}"))?;
            let trace = crate::cosim::MobilityTrace::from_json(&json)?;
            for (node, model) in trace.into_models() {
                sim.set_node_mobility(node, model);
            }
        }

        Ok(sim)
    }

    /// Attach the scenario's declared [`bridges`](Scenario::bridges) to the running fabric:
    /// a real UDP face per spec (+ optional FIB route, + optional send-MTU clamp). Call after
    /// [`start`](Simulation::start); a no-op when no bridges are declared.
    ///
    /// **Kernel fence:** external endpoints live on real time, so this refuses to run under a
    /// `des`/`virtual` kernel — the same doctrine [`bridge`](crate::bridge) fixes.
    pub async fn apply_bridges(&self, fabric: &crate::RunningSimulation) -> Result<()> {
        if self.bridges.is_empty() {
            return Ok(());
        }
        match self.kernel {
            KernelSpec::WallClock | KernelSpec::RealTime { .. } => {}
            _ => bail!(
                "scenario declares [[bridges]] but a virtual-time kernel: external endpoints \
                 cannot obey a virtual clock — use kernel.kind = \"wall_clock\" or \"real_time\""
            ),
        }
        for (i, b) in self.bridges.iter().enumerate() {
            let node = NodeId(b.node);
            let local = b
                .local
                .parse()
                .with_context(|| format!("bridges[{i}].local"))?;
            let peer = b
                .peer
                .parse()
                .with_context(|| format!("bridges[{i}].peer"))?;
            let face = fabric.bridge_udp_mtu(node, local, peer, b.mtu).await?;
            if let Some(route) = &b.route {
                let prefix = route
                    .parse()
                    .with_context(|| format!("bridges[{i}].route"))?;
                fabric
                    .engine_of(node)
                    .ok_or_else(|| anyhow::anyhow!("bridges[{i}]: no node {node}"))?
                    .fib()
                    .add_nexthop(&prefix, face, 10);
            }
        }
        Ok(())
    }

    fn check_node(&self, idx: usize) -> Result<()> {
        if idx >= self.nodes.len() {
            bail!(
                "scenario references node {idx} but only {} declared",
                self.nodes.len()
            );
        }
        Ok(())
    }
}

/// A [`LinkConfig`](crate::LinkConfig) from a spec's millisecond fields.
fn link_config(
    delay_ms: u64,
    jitter_ms: u64,
    loss_rate: f64,
    bandwidth_bps: u64,
) -> crate::LinkConfig {
    crate::LinkConfig {
        delay: std::time::Duration::from_millis(delay_ms),
        jitter: std::time::Duration::from_millis(jitter_ms),
        loss_rate,
        bandwidth_bps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[kernel]
kind = "virtual"
seed = 7

[[nodes]]
label = "a"
position = [0.0, 0.0, 0.0]

[[nodes]]
label = "b"
position = [50.0, 0.0, 0.0]

[[links]]
a = 0
b = 1
delay_ms = 10

[[routes]]
node = 0
prefix = "/app"
nexthop = 1
"#;

    #[test]
    fn toml_round_trips() {
        let scenario = Scenario::from_toml(SAMPLE).unwrap();
        assert_eq!(scenario.nodes.len(), 2);
        assert_eq!(scenario.links.len(), 1);
        assert!(scenario.kernel.is_virtual());

        // Re-serialize and re-parse → structurally identical (JSON as the stable comparison).
        let again = Scenario::from_toml(&scenario.to_toml().unwrap()).unwrap();
        assert_eq!(scenario.to_json().unwrap(), again.to_json().unwrap());
    }

    #[test]
    fn des_kernel_round_trips() {
        let src = r#"
[kernel]
kind = "des"
epoch_ns = 42

[[nodes]]
label = "a"
"#;
        let scenario = Scenario::from_toml(src).unwrap();
        assert!(scenario.kernel.is_des());
        assert!(!scenario.kernel.is_virtual());
        assert!(matches!(
            scenario.kernel,
            KernelSpec::Des { epoch_ns: Some(42) }
        ));
        // Re-serialize and re-parse → structurally identical.
        let again = Scenario::from_toml(&scenario.to_toml().unwrap()).unwrap();
        assert_eq!(scenario.to_json().unwrap(), again.to_json().unwrap());
    }

    #[test]
    fn radio_node_without_medium_is_rejected() {
        let s = Scenario {
            nodes: vec![NodeSpec {
                radio: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let k: Arc<dyn SimKernel> = Arc::new(crate::WallClockKernel::new());
        assert!(s.build(k).is_err());
    }

    #[test]
    fn route_to_missing_node_is_rejected() {
        let s = Scenario {
            nodes: vec![NodeSpec::default()],
            routes: vec![RouteSpec {
                node: 0,
                prefix: "/x".into(),
                nexthop: 9,
            }],
            ..Default::default()
        };
        let k: Arc<dyn SimKernel> = Arc::new(crate::WallClockKernel::new());
        assert!(s.build(k).is_err());
    }
}
