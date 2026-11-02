//! Conformance cases for the `ndn-data` contract.
//!
//! The data-layer study played twelve use cases through its model and left three items open; a
//! fourth (a reader keeping up with a writer that never pauses) came out of slice 1. Each
//! is written here as a deterministic ndn-sim scenario against the [`ndn_data::DataLayer`] trait:
//! real forwarders on a virtual-time kernel, devices that go offline, per-device wall clocks that
//! lie ([`ndn_sim::ClockSkew`]), and a thief holding a copy of a stolen device's key. Every case
//! asserts the invariant it guards — the "fix" of its use case — not wording or exact counts.
//!
//! An implementation plugs in as a [`Provider`]; the runner
//! (`cargo run -p ndn-data-conformance -- --json <path>`) knows one, [`Reference`] — `ndn-data`'s
//! own [`Device`](ndn_data::Device). A case runs when its provider supports every [`Feature`] it
//! needs and is otherwise reported [`Status::NotImplemented`], naming what is missing. The cases
//! are not `#[test]`s: they run only from the runner, so a plain `cargo test` checks the harness
//! itself (devices going offline, clock skew, the report).
//!
//! Each run also records cost — round trips, bytes, signatures, copies, time to converge and
//! person gestures ([`Cost`]) — so the Results page can show what each slice pays.

pub mod case;
pub mod cases;
pub mod feature;
pub mod provider;
pub mod reference;
pub mod report;
pub mod runner;
pub mod world;

pub use case::{Case, CaseFuture, Failure};
pub use feature::Feature;
pub use provider::{DeviceSpec, NodeRole, Provider, Tally};
pub use reference::Reference;
pub use report::{CaseResult, Cost, Report, Status};
pub use runner::{run_all, run_case, run_only};
pub use world::{Dev, Net, Plan, World};
