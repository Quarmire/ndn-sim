//! **ndn-lab** — in-process NDN network simulation / emulation hub.
//!
//! (Crate name stays `ndn-sim`; the tool is **ndn-lab**.) Multi-node networks of *real*
//! `ForwarderEngine`s run on a pluggable [`SimKernel`] (wall-clock now; virtual / parallel
//! later — the engine's clock flows entirely through the runtime seam). The
//! [`Simulation`] builder declares an initial topology; [`RunningSimulation`] is the live
//! headless **fabric** handle that implements [`FabricControl`] (spawn / remove / connect /
//! route / introspect at runtime) with a [`SimTracer`] capturing engine events.
//!
//! ## Two ways in
//!
//! **1. The Rust builder** — declare a topology, `start()`, then interact live. Import everyday
//! types from the [`prelude`]:
//!
//! ```rust,no_run
//! use ndn_sim::prelude::*;
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
//! **2. A declarative [`Scenario`]** — the whole network as one diff-able TOML/JSON artifact,
//! runnable from the `ndn-lab` CLI or built in-process. This example actually runs:
//!
//! ```rust
//! use ndn_sim::Scenario;
//!
//! let scenario = Scenario::from_toml(r#"
//!     [kernel]
//!     kind = "des"          # deterministic discrete-event executor
//!     [[nodes]]
//!     label = "consumer"
//!     [[nodes]]
//!     label = "producer"
//!     [[links]]
//!     a = 0
//!     b = 1
//! "#).unwrap();
//! assert_eq!(scenario.nodes.len(), 2);
//! ```
//!
//! ## The four capability axes
//!
//! - **Kernels** ([`DesKernel`], [`VirtualKernel`], [`WallClockKernel`], [`RealTimeKernel`]) — from a
//!   deterministic event queue (bit-reproducible replay) to real-time (hosts live devices).
//! - **Validation** ([`ValidationSpec`], [`run_validation`]) — scenario + fault schedule + property
//!   assertions + seed sweeps + regression baselines; `ndn-lab check` is a CI gate.
//! - **Co-simulation** ([`cosim`], [`udp_json_feed`], [`MobilitySource`]) — external simulators
//!   (ArduPilot SITL / Gazebo / Bevy) drive node motion; `cosim` commands actuate them back.
//! - **Observability** ([`analysis::explain_link`], [`diff_runs`], [`OtlpExporter`]) — causal "why"
//!   over radio delivery, cross-run diff, and OTLP/Jaeger export.
//!
//! The [`ControlPlane`] projects all of this over one JSON surface (in-process / NDN-native / TCP /
//! WebSocket), and [`SimMcp`] projects *that* as Model Context Protocol tools for agents.
//!
//! ## Components
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`kernel`]   | `SimKernel` / `WallClock` / `Virtual` / `RealTime` / `Steppable` — the execution + time engine |
//! | [`profile`]  | `NodeProfile` — named node template |
//! | [`control`]  | `FabricControl` — the one control + introspection surface |
//! | [`app`]      | `AppSpec` / `AppHandle` — declarative producers/consumers on a node |
//! | [`control_plane`] | `ControlPlane` — declarative JSON commands/queries over NDN / RPC / in-proc |
//! | [`replay`]   | `Recording` — journal live commands → replay a session deterministically |
//! | [`mcp`]      | `SimMcp` — Model Context Protocol tools projecting the control plane |
//! | [`scene`]    | `SceneSnapshot` + SVG renderers — the `world_snapshot()` a GUI client draws |
//! | [`otel_export`] | `OtlpExporter` — forward virtual-clocked spans/metrics to an OTLP/HTTP collector |
//! | [`span_capture`] | `SpanLog` — capture the engine's own tracing spans on the virtual clock |
//! | [`bridge`]   | real UDP faces on a node — external device / NFD / NDNts interop (slice 9) |
//! | [`scenario`] | `Scenario` — a whole sim as one diff-able TOML/JSON artifact → `Simulation` |
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

pub mod analysis;
pub mod app;
pub mod bridge;
#[cfg(not(target_arch = "wasm32"))]
pub mod compare;
pub mod control;
pub mod control_plane;
pub mod cosim;
pub mod des;
pub mod geometry;
pub mod ip;
pub mod kernel;
pub mod link_model;
pub mod lora;
#[cfg(feature = "mavlink")]
pub mod mavlink;
pub mod mcp;
pub mod medium;
pub mod otel_export;
pub mod phy;
pub mod prelude;
pub mod profile;
pub mod radio;
pub mod replay;
pub mod routing;
pub mod scenario;
pub mod scene;
pub mod sim_face;
pub mod sim_link;
pub mod span_capture;
pub mod stepper;
pub mod telemetry;
pub mod topo;
pub mod topology;
pub mod wifi;
pub mod tracer;
#[cfg(not(target_arch = "wasm32"))]
pub mod validate;
pub mod world;

pub use analysis::{
    AppDelta, Explanation, LinkDelta, LinkVerdict, MetricDelta, RadioDelivery, RadioLog,
    RunCapture, RunDiff, diff_runs, explain_link,
};
pub use app::{AppHandle, AppId, AppSpec, FlowStats, TrafficPattern};
#[cfg(not(target_arch = "wasm32"))]
pub use compare::{ComparisonSpec, ProtocolComparison, compare_ndn_vs_ip};
pub use control::{FabricControl, LinkInfo, NodeInfo, TopologySnapshot};
pub use control_plane::{
    ControlPlane, LinkSpec, SimCommand, SimNotification, SimQuery, SimRequest, SimResponse,
    TelemetryFrame,
};
pub use cosim::{
    ChannelSource, CosimActuator, FeedReader, Lockstep, MobilitySource, MobilityTrace, NodeState,
    SampledMobility, ScriptedSource, SteppableSource, VehicleCommand, drive_cosim, udp_json_feed,
};
pub use des::{DesKernel, DesSession};
pub use geometry::{Obstacle, ObstructedPropagation};
pub use ip::{
    IpNetwork, IpNode, IpNodeStats, IpPacket, Ipv4, RadioLinkConfig, RunningIpNode, ip_link,
};
pub use routing::{
    Aodv, DistanceVector, Dsr, GreedyGeographic, NetworkKind, RoutingAlgorithm, RoutingCategory,
    ShortestPath, TopologyView,
};
#[cfg(not(target_arch = "wasm32"))]
pub use kernel::{
    DEFAULT_RUN_CEILING, StepSession, SteppableKernel, VirtualKernel, VirtualTimeExceeded,
};
pub use kernel::{RealTimeKernel, SimKernel, WallClockKernel};
pub use link_model::{LinkModel, NOISE_FLOOR_DBM};
pub use lora::{CodingRate, DutyCycle, LoraConfig, SpreadingFactor, adr_select};
pub use mcp::SimMcp;
pub use medium::{
    CarrierSenseInterference, Delivery, DeliveryReason, FreeSpacePathLoss, InterferenceModel,
    NoInterference, PerfectPropagation, PropagationModel, RangeThreshold, ReceivedFrame, TxContext,
    WirelessMedium,
};
pub use otel_export::OtlpExporter;
// NB: `phy::FreeSpace` (a PropagationBackend) is intentionally not re-exported at the crate root —
// it would collide with `world::FreeSpace` (an Environment). Reach it via `ndn_sim::phy::FreeSpace`.
pub use phy::{
    Antenna, AntennaPlacement, Channel, DefaultInterference, Dipole, Directional,
    InterferenceBackend, Isotropic, LogDistance, PropagationBackend, Radio, RadioEnvironment,
    RadioPlatform,
};
pub use profile::NodeProfile;
pub use radio::{RadioBus, RadioMcs, RadioRx, SimRadioFace};
pub use replay::{RecordedCommand, Recording};
pub use scenario::{
    EnvSpec, KernelSpec, NodeSpec, ObstacleSpec, PropSpec, RadioMediumSpec, RadioRouteSpec,
    RouteSpec, Scenario, ScenarioLink, StrategyChoiceSpec,
};
pub use scene::{
    RadioLink, SceneBounds, SceneLink, SceneNode, ScenePoint, SceneSnapshot, render_sparkline,
    render_topology_svg,
};
pub use sim_face::SimFace;
pub use sim_link::{FaceProfile, LinkConfig, SimLink};
pub use span_capture::{CapturedSpan, EngineSpanLayer, SpanLog, capture_engine_spans};
pub use stepper::Stepper;
pub use telemetry::{
    MetricsDiff, MetricsLog, MetricsSample, SimSpanEmitter, compare_metrics, sample_engine,
};
pub use topology::{
    Clock, FaceKind, FaceStats, NodeId, RouteExplanation, RouteNexthop, RunningSimulation,
    Simulation, Strategy,
};
pub use wifi::{
    AccessCategory, FixedRate, MinstrelHt, RateControl, TxOutcome, Wifi, WifiMode,
    WifiOperatingMode, broadcast_airtime, frame_airtime,
};
pub use tracer::{EventKind, SimEvent, SimTracer};
#[cfg(not(target_arch = "wasm32"))]
pub use validate::{
    Agg, Baseline, BaselineCheck, CheckKernel, Cmp, Direction, Fault, FlowField, MetricField,
    Observation, Probe, Property, PropertyResult, RegressionResult, RunReport, ScheduledFault,
    ValidationReport, ValidationSpec, run_validation, run_validation_against,
};
pub use world::{
    Environment, FreeSpace, LinearMobility, MobilityModel, Position, StaticMobility,
    UniformAttenuation, WaypointMobility, World, WorldView,
};

/// The live fabric handle (alias for [`RunningSimulation`]) — the ndn-lab name.
pub type Fabric = RunningSimulation;
