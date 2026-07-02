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
//! validation, co-simulation, radio, world, and analysis. For the long tail (individual
//! propagation/interference models, scene renderers, OTLP export) reach into the crate root or the
//! specific module.

// Re-exported so `use ndn_sim::prelude::*` also brings the engine config the builder needs.
pub use ndn_engine::builder::EngineConfig;

// Builder + live fabric + control surface.
pub use crate::{Fabric, FabricControl, NodeId, RunningSimulation, Simulation};
pub use crate::{LinkConfig, NodeProfile};
pub use crate::{AppHandle, AppId, AppSpec};

// Kernels — the execution + time engine.
pub use crate::{DesKernel, RealTimeKernel, SimKernel, WallClockKernel};
#[cfg(not(target_arch = "wasm32"))]
pub use crate::{SteppableKernel, VirtualKernel};

// Declarative artifacts: whole-sim scenarios + validation specs.
pub use crate::{Scenario, ScenarioLink};
#[cfg(not(target_arch = "wasm32"))]
pub use crate::{Property, ValidationReport, ValidationSpec, run_validation, run_validation_against};

// The control plane + its command/query vocabulary (drives every transport: in-proc/NDN/RPC/MCP).
pub use crate::{ControlPlane, SimCommand, SimQuery, SimRequest, SimResponse};
pub use crate::SimMcp;

// World, radio, and co-simulation.
pub use crate::{Environment, MobilityModel, Position, World};
pub use crate::{PropagationModel, RadioBus, SimRadioFace, WirelessMedium};
pub use crate::{CosimActuator, MobilitySource, MobilityTrace, NodeState, VehicleCommand, udp_json_feed};

// Analysis + observability (the "why").
pub use crate::{Explanation, RunCapture, SimTracer, diff_runs, explain_link};
