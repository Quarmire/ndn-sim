//! # ndn-sim — In-process NDN network simulation
//!
//! Provides [`SimFace`], [`SimLink`], and a [`Simulation`] topology builder
//! for constructing multi-node NDN networks entirely in-process. Unlike
//! Mini-NDN (which orchestrates real processes via Mininet), simulations run
//! in a single Tokio runtime with configurable link properties.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ndn_sim::{Simulation, LinkConfig, NodeId};
//! use ndn_engine::builder::EngineConfig;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let mut sim = Simulation::new();
//! let n1 = sim.add_node(EngineConfig::default());
//! let n2 = sim.add_node(EngineConfig::default());
//! sim.link(n1, n2, LinkConfig::lan());
//! sim.add_route(n1, "/prefix", n2);
//!
//! let running = sim.start().await?;
//! // ... run experiment using running.engine(n1), running.engine(n2) ...
//! running.shutdown().await;
//! # Ok(())
//! # }
//! ```
//!
//! ## Components
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`sim_face`] | `SimFace` — channel-backed face with delay/loss/bandwidth emulation |
//! | [`sim_link`] | `SimLink` — creates connected face pairs with link properties |
//! | [`topology`] | `Simulation` — multi-node topology builder and runner |
//! | [`tracer`]   | `SimTracer` — structured event capture for analysis |

#![allow(missing_docs)]

pub mod sim_face;
pub mod sim_link;
pub mod topology;
pub mod tracer;

pub use sim_face::SimFace;
pub use sim_link::{LinkConfig, SimLink};
pub use topology::{NodeId, RunningSimulation, Simulation};
pub use tracer::{EventKind, SimEvent, SimTracer};
