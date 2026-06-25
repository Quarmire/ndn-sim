//! **ndn-lab** — in-process NDN network simulation / emulation hub.
//!
//! (Crate name stays `ndn-sim`; the tool is **ndn-lab**.) Multi-node networks of *real*
//! `ForwarderEngine`s run on a pluggable [`SimKernel`] (wall-clock now; virtual / parallel
//! later — the engine's clock flows entirely through the runtime seam). The
//! [`Simulation`] builder declares an initial topology; [`RunningSimulation`] is the live
//! headless **fabric** handle that implements [`FabricControl`] (spawn / remove / connect /
//! route / introspect at runtime) with a [`SimTracer`] capturing engine events.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ndn_sim::{Simulation, LinkConfig};
//! use ndn_engine::builder::EngineConfig;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let mut sim = Simulation::new();                 // default WallClockKernel
//! let n1 = sim.add_node(EngineConfig::default());
//! let n2 = sim.add_node(EngineConfig::default());
//! sim.link(n1, n2, LinkConfig::lan());
//! sim.add_route(n1, "/prefix", n2);
//!
//! let fabric = sim.start().await?;
//! // interact via fabric.engine_of(n1); live ops via fabric.spawn_node / connect / route
//! fabric.shutdown().await;
//! # Ok(())
//! # }
//! ```
//!
//! ## Components
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`kernel`]   | `SimKernel` / `WallClockKernel` / `VirtualKernel` — the execution + time engine (the dial) |
//! | [`profile`]  | `NodeProfile` — named node template |
//! | [`control`]  | `FabricControl` — the one control + introspection surface |
//! | [`control_plane`] | `ControlPlane` — declarative JSON commands/queries over NDN / RPC / in-proc |
//! | [`mcp`]      | `SimMcp` — Model Context Protocol tools projecting the control plane |
//! | [`scene`]    | `SceneSnapshot` + SVG renderers — the `world_snapshot()` a GUI client draws |
//! | [`sim_face`] | `SimFace` — channel-backed face with delay/loss/bandwidth emulation |
//! | [`sim_link`] | `SimLink` — connected face pairs (the wired *static channel*) |
//! | [`world`]    | `World` / `MobilityModel` / `Environment` — *where* nodes are and how they move |
//! | [`medium`]   | `WirelessMedium` / `PropagationModel` — position-driven broadcast delivery |
//! | [`link_model`] | `LinkModel` — RSSI/SNR → MCS → per-frame delivery (the 802.11n logical link) |
//! | [`radio`]    | `RadioBus` / `SimRadioFace` — the named-radio simulated face (engine `Face`) |
//! | [`telemetry`] | `MetricsLog` / `SimSpanEmitter` — Runtime-clocked metric gauges + OTLP spans |
//! | [`topology`] | `Simulation` builder + `RunningSimulation` live fabric |
//! | [`tracer`]   | `SimTracer` — structured event capture for analysis |

#![allow(missing_docs)]

pub mod control;
pub mod control_plane;
pub mod kernel;
pub mod link_model;
pub mod mcp;
pub mod medium;
pub mod profile;
pub mod radio;
pub mod scene;
pub mod sim_face;
pub mod sim_link;
pub mod telemetry;
pub mod topology;
pub mod tracer;
pub mod world;

pub use control::{FabricControl, LinkInfo, NodeInfo, TopologySnapshot};
pub use control_plane::{
    ControlPlane, LinkSpec, SimCommand, SimNotification, SimQuery, SimRequest, SimResponse,
};
pub use kernel::{SimKernel, WallClockKernel};
#[cfg(not(target_arch = "wasm32"))]
pub use kernel::VirtualKernel;
pub use link_model::{LinkModel, NOISE_FLOOR_DBM};
pub use mcp::SimMcp;
pub use radio::{RadioBus, RadioMcs, RadioRx, SimRadioFace};
pub use scene::{
    SceneBounds, SceneLink, SceneNode, ScenePoint, SceneSnapshot, render_sparkline,
    render_topology_svg,
};
pub use medium::{
    Delivery, FreeSpacePathLoss, InterferenceModel, NoInterference, PropagationModel,
    RangeThreshold, ReceivedFrame, TxContext, WirelessMedium,
};
pub use profile::NodeProfile;
pub use sim_face::SimFace;
pub use sim_link::{LinkConfig, SimLink};
pub use telemetry::{MetricsLog, MetricsSample, SimSpanEmitter, sample_engine};
pub use topology::{NodeId, RunningSimulation, Simulation};
pub use tracer::{EventKind, SimEvent, SimTracer};
pub use world::{
    Environment, FreeSpace, LinearMobility, MobilityModel, Position, StaticMobility,
    UniformAttenuation, WaypointMobility, World, WorldView,
};

/// The live fabric handle (alias for [`RunningSimulation`]) — the ndn-lab name.
pub type Fabric = RunningSimulation;
