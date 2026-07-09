//! One-glob convenience imports for embedding ndn-lab in your own test or tool.
//!
//! ```rust
//! use ndn_sim::prelude::*;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let mut sim = Simulation::new();
//! let a = sim.add_node(EngineConfig::default());
//! let b = sim.add_node(EngineConfig::default());
//! sim.link(a, b, LinkConfig::lan());
//! sim.add_route(a, "/demo", b);
//! let fabric = sim.start().await?;
//! fabric.shutdown().await;
//! # Ok(())
//! # }
//! ```
//!
//! This pulls in the everyday vocabulary — the builder, kernels, control plane, scenarios,
//! validation, co-simulation, world, the radio MAC + LoRa, the IP plane + its routing algorithms,
//! metric series, the Keel render surface, and analysis. For the long tail (individual
//! propagation/interference models, scene renderers, the OTLP exporter) reach into the crate root or
//! the specific module.
//!
//! **Name note — two `FreeSpace`s.** [`crate::world::FreeSpace`] is a propagation *Environment*
//! (world/obstruction model); [`crate::phy::FreeSpace`] is a `PropagationBackend` (distance→loss for
//! a [`RadioLinkConfig`](crate::RadioLinkConfig)). Different roles, same word — so neither is in this
//! prelude; reach the one you want by its full module path.

// Re-exported so `use ndn_sim::prelude::*` also brings the engine config the builder needs.
pub use ndn_engine::builder::EngineConfig;

// Builder + live fabric + control surface.
pub use crate::{AppHandle, AppId, AppSpec, FlowStats, TrafficPattern};
pub use crate::{Clock, Fabric, FabricControl, NodeId, RunningSimulation, Simulation, Strategy};
pub use crate::{FaceKind, FaceStats, RouteExplanation};
pub use crate::{LinkConfig, NodeProfile};
// Targeted faults (delay-without-drop / reorder) + the field-failure scenario kit.
pub use crate::{FrameMatcher, HoldRule};
#[cfg(not(target_arch = "wasm32"))]
pub use crate::fieldkit;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::liveness;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::ceiling;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::adversary;

// Kernels — the execution + time engine.
pub use crate::{DesKernel, RealTimeKernel, SimKernel, WallClockKernel};
#[cfg(not(target_arch = "wasm32"))]
pub use crate::{SteppableKernel, VirtualKernel};

// Declarative artifacts: whole-sim scenarios (+ the `topo` generators) + validation specs.
#[cfg(not(target_arch = "wasm32"))]
pub use crate::{
    Property, ValidationReport, ValidationSpec, run_validation, run_validation_against,
};
pub use crate::{Scenario, ScenarioLink, Stepper, topo};

// The control plane + its command/query vocabulary (drives every transport: in-proc/NDN/RPC/MCP).
pub use crate::SimMcp;
pub use crate::{ControlPlane, SimCommand, SimQuery, SimRequest, SimResponse};

// World, radio, and co-simulation.
pub use crate::{
    CosimActuator, MobilitySource, MobilityTrace, NodeState, VehicleCommand, udp_json_feed,
};
pub use crate::{Environment, MobilityModel, Position, World};
pub use crate::{PropagationModel, RadioBus, SimRadioFace, WirelessMedium};

// The radio MAC + LoRa: a shared medium instead of point-to-point links.
pub use crate::{RadioLinkConfig, Wifi, WifiMode, WifiOperatingMode};
pub use crate::{LoraLinkConfig, SpreadingFactor};

// The deterministic IP plane + its pluggable routing (for NDN-vs-IP benchmarks).
pub use crate::{IpNetwork, NetworkKind, RoutingAlgorithm};
pub use crate::{Aodv, DistanceVector, Dsr, Gpsr, GreedyGeographic, Olsr, ShortestPath};

// Telemetry: virtual-time metric series (the OTLP exporter itself stays long-tail).
pub use crate::{FabricGauges, MetricsLog, MetricsSample, sample_engine};

// The Keel: telemetry types describe themselves; renderers compete for intents.
pub use crate::{Floor, KeelView, Rendered, SceneView, Surface, Verdict};

// Analysis + observability (the "why").
pub use crate::{Explanation, RunCapture, SimTracer, diff_runs, explain_link};
