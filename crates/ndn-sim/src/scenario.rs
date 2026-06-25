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
//! one directly). Round-trips: `from_toml`/`to_toml`, `from_json`/`to_json`.
//!
//! Not yet captured (documented gaps): per-node `EngineConfig` (not serde — nodes use the
//! default), app lifecycle (spawn_app — its own follow-on), and waypoint mobility (linear only).

use std::sync::Arc;

use anyhow::{Result, bail};
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
}

/// The recorded execution model (the caller still supplies the concrete kernel to
/// [`build`](Scenario::build); this is intent + what a top-level runner dispatches on).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KernelSpec {
    #[default]
    WallClock,
    Virtual {
        #[serde(default)]
        seed: u64,
        #[serde(default)]
        epoch_ns: Option<u64>,
    },
    /// Real-time governor: real pace (hosts real devices) + a logical scenario-relative clock.
    RealTime {
        #[serde(default)]
        epoch_ns: Option<u64>,
    },
}

impl KernelSpec {
    pub fn is_virtual(&self) -> bool {
        matches!(self, KernelSpec::Virtual { .. })
    }
}

/// The world's RF environment.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EnvSpec {
    #[default]
    FreeSpace,
    /// Constant excess attenuation everywhere (dB).
    Uniform {
        db: f64,
    },
}

/// Shared radio medium config (nodes opt in via `NodeSpec.radio`).
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RadioMediumSpec {
    #[serde(default)]
    pub propagation: PropSpec,
    #[serde(default)]
    pub seed: u64,
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
            PropSpec::FreeSpacePathLoss { tx_power_dbm, freq_hz, rx_sensitivity_dbm } => {
                Arc::new(FreeSpacePathLoss { tx_power_dbm, freq_hz, rx_sensitivity_dbm })
            }
            PropSpec::RangeThreshold { range_m, tx_power_dbm } => {
                Arc::new(RangeThreshold { range_m, tx_power_dbm })
            }
        }
    }
}

/// One node. Engine config is the default (per-node config isn't serde yet).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NodeSpec {
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
}

/// A wired link between two nodes (durations in ms; `0` = none).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct ScenarioLink {
    pub a: usize,
    pub b: usize,
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub jitter_ms: u64,
    #[serde(default)]
    pub loss_rate: f64,
    #[serde(default)]
    pub bandwidth_bps: u64,
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

    /// Turn the document into a ready-to-[`start`](Simulation::start) [`Simulation`] on `kernel`.
    /// For a `virtual` scenario, call this *inside* `VirtualKernel::run` with that kernel; for
    /// `wall_clock`, pass a [`WallClockKernel`](crate::WallClockKernel).
    pub fn build(&self, kernel: Arc<dyn SimKernel>) -> Result<Simulation> {
        let mut sim = Simulation::new().kernel(kernel);

        if let Some(radio) = &self.radio {
            sim = sim.with_radio_medium(radio.propagation.build(), radio.seed);
        } else if self.nodes.iter().any(|n| n.radio) {
            bail!("a node is marked `radio` but no [radio] medium is configured");
        }

        if let EnvSpec::Uniform { db } = self.environment {
            sim.environment(Arc::new(UniformAttenuation(db)));
        }

        for spec in &self.nodes {
            let pos = spec.position.map(|[x, y, z]| Position::xyz(x, y, z));
            let id = if spec.radio {
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
        }

        for l in &self.links {
            self.check_node(l.a)?;
            self.check_node(l.b)?;
            sim.link(
                NodeId(l.a),
                NodeId(l.b),
                crate::LinkConfig {
                    delay: std::time::Duration::from_millis(l.delay_ms),
                    jitter: std::time::Duration::from_millis(l.jitter_ms),
                    loss_rate: l.loss_rate,
                    bandwidth_bps: l.bandwidth_bps,
                },
            );
        }

        for r in &self.routes {
            self.check_node(r.node)?;
            self.check_node(r.nexthop)?;
            sim.add_route(NodeId(r.node), &r.prefix, NodeId(r.nexthop));
        }

        Ok(sim)
    }

    fn check_node(&self, idx: usize) -> Result<()> {
        if idx >= self.nodes.len() {
            bail!("scenario references node {idx} but only {} declared", self.nodes.len());
        }
        Ok(())
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
    fn radio_node_without_medium_is_rejected() {
        let s = Scenario {
            nodes: vec![NodeSpec { radio: true, ..Default::default() }],
            ..Default::default()
        };
        let k: Arc<dyn SimKernel> = Arc::new(crate::WallClockKernel::new());
        assert!(s.build(k).is_err());
    }

    #[test]
    fn route_to_missing_node_is_rejected() {
        let s = Scenario {
            nodes: vec![NodeSpec::default()],
            routes: vec![RouteSpec { node: 0, prefix: "/x".into(), nexthop: 9 }],
            ..Default::default()
        };
        let k: Arc<dyn SimKernel> = Arc::new(crate::WallClockKernel::new());
        assert!(s.build(k).is_err());
    }
}
