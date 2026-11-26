//! Conformance cases for the data-layer contract, run on `ndn-heap` and `ndn-invite`.
//!
//! The data-layer study played twelve use cases through its model and left three items open; a
//! fourth (a reader keeping up with a writer that never pauses) came out of slice 1. Each
//! is written here as a deterministic ndn-sim scenario:
//! real forwarders on a virtual-time kernel, devices that go offline, per-device wall clocks that
//! lie ([`ndn_sim::ClockSkew`]), and a thief holding a copy of a stolen device's key. Every case
//! asserts the invariant it guards — the "fix" of its use case — not wording or exact counts.
//!
//! The cases are written once against the neutral [`Spaces`] trait (a space, paths in it, plain
//! data types) and the neutral verbs of [`invite`] (offer, join, the grants a host is told of, the
//! spaces a device joined, the calls its host's link layer was asked), whose recording core is
//! [`host::IntroduceCore`]. One implementation runs them: `ndn-heap`'s `Node`
//! ([`NewReference`]) and `ndn-invite`'s host (through `new_invite`). The channel cases
//! (`c19`–`c41`) drive [`Channels`], `ndn-heap`'s live channels over the forwarders' side tables
//! (its `adversary` feature seals a frame or a checkpoint as a compromised key holder would),
//! beside the durability and chain cases (`d9`–`d16`, `q1`–`q6`), which are written over
//! `Spaces`.
//! The suite once ran on a
//! second implementation, the `ndn-data` crate; that crate is removed (see
//! `ndn-rs/docs/specs/history/`) and so are the six cases that only it could run.
//!
//! An implementation plugs in as a [`Provider`]; the runner
//! (`cargo run --release -p ndn-data-conformance -- --json <path>`) runs the one provider,
//! `ndn-heap`, with no flag (`--provider ndn-heap` is accepted). A case runs when its provider
//! supports every [`Feature`] it needs and is otherwise reported [`Status::NotImplemented`],
//! naming what is missing. The cases are not `#[test]`s: they run only from the runner, so a plain
//! `cargo test` checks the harness itself (devices going offline, clock skew, the report).
//!
//! Each run also records cost — round trips, bytes, signatures, copies, time to converge and
//! person gestures ([`Cost`]) — so the Results page can show what each slice pays.
//!
//! A case's cost and measures are the same every run, alone or in the suite: the kernel is
//! virtual, the sync jitter is seeded before each case, and nothing on the way picks in hash or
//! random order. `--check-determinism` checks it, running each case again alone in a fresh
//! process and failing on any difference ([`differences`]).
//!
//! `--faulty` runs every case on ndf's faulty network ([`ndn_sim::FAULTY`]: drop 0.2, dup 0.1,
//! forge 0.05, delay 400 ms, reorder 0.1, blocks 1500 ms), `--faults SPEC` on another profile and
//! `--fault-seed N` with another seed ([`Network`]): every packet arriving at a device from its
//! link meets the profile, seeded per link, so a faulty run is as deterministic as a clean one.
//! Every case must pass on it (spec `docs/specs/history/data-layer-remainder.md` §18).

pub mod case;
pub mod cases;
pub mod channel;
pub mod crash_store;
pub mod feature;
pub mod host;
pub mod invite;
mod new_channels;
pub mod new_invite;
pub mod new_reference;
pub mod provider;
pub mod report;
pub mod runner;
pub mod spaces;
pub mod world;
pub mod world_common;

pub use case::{Case, CaseFuture, Failure};
pub use channel::{ChannelEvent, ChannelEvidence, ChannelItems, ChannelTrust, Channels};
pub use feature::Feature;
pub use invite::{GrantEvent, GrantLog, JoinedList};
pub use new_reference::NewReference;
pub use provider::{Certs, DeviceSpec, Grants, Image, NodeRole, Provider, Tally};
pub use report::{CaseResult, Cost, NetworkReport, Report, Status};
pub use runner::{Network, differences, run_all, run_case, run_only};
pub use spaces::{
    AlertKind, EntryRead, RefusalKind, SpaceAlert, SpaceChange, SpaceChanges, SpaceEntry,
    SpaceEntryKey, SpaceEpoch, SpaceEvent, SpaceItem, SpaceMembers, SpaceShare, Spaces,
};
pub use world::{Dev, Fwd, Net, Plan, SideCounts, World};
