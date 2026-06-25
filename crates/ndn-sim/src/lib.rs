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
//! | [`kernel`]   | `SimKernel` / `WallClockKernel` — the execution + time engine (the dial) |
//! | [`profile`]  | `NodeProfile` — named node template |
//! | [`control`]  | `FabricControl` — the one control + introspection surface |
//! | [`sim_face`] | `SimFace` — channel-backed face with delay/loss/bandwidth emulation |
//! | [`sim_link`] | `SimLink` — creates connected face pairs with link properties |
//! | [`topology`] | `Simulation` builder + `RunningSimulation` live fabric |
//! | [`tracer`]   | `SimTracer` — structured event capture for analysis |

#![allow(missing_docs)]

pub mod control;
pub mod kernel;
pub mod profile;
pub mod sim_face;
pub mod sim_link;
pub mod topology;
pub mod tracer;

pub use control::{FabricControl, LinkInfo, NodeInfo, TopologySnapshot};
pub use kernel::{SimKernel, WallClockKernel};
#[cfg(not(target_arch = "wasm32"))]
pub use kernel::VirtualKernel;
pub use profile::NodeProfile;
pub use sim_face::SimFace;
pub use sim_link::{LinkConfig, SimLink};
pub use topology::{NodeId, RunningSimulation, Simulation};
pub use tracer::{EventKind, SimEvent, SimTracer};

/// The live fabric handle (alias for [`RunningSimulation`]) — the ndn-lab name.
pub type Fabric = RunningSimulation;
