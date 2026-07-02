//! # Co-simulation: drive the World from an external source (axis 3, slice 3a)
//!
//! Today the World is driven by a **pull, closed-form** [`MobilityModel`](crate::MobilityModel):
//! `position(t) -> Position`. That is deterministic and replayable — perfect for scripted tests, and
//! useless for co-simulation, because you cannot ask an autopilot "where will you be at t=57.3s". An
//! external system (ArduPilot SITL, Gazebo, a game engine) **pushes** where it *is*, live.
//!
//! This module adds the complementary **push** seam:
//!
//! - [`MobilitySource`] — a live source of timed node kinematics ([`NodeState`]). Adapters
//!   (MAVLink/SITL, gz-transport, …) implement it; [`ChannelSource`] bridges any task that produces
//!   states, and [`ScriptedSource`] emits a fixed timeline (demos + deterministic tests).
//! - [`drive_cosim`] — the governor loop: poll the source, apply each state to the World live
//!   (`world.place`, which bumps the world generation so the radio re-reads positions), and record
//!   the stream into a [`MobilityTrace`].
//!
//! ## Clock model (mode B — timestamp-slaved follower)
//! The external system is the clock master; the sim follows. On the [`RealTimeKernel`] governor the
//! driver runs at real pace so a live SITL feed lines up; on a virtual/DES kernel a [`ScriptedSource`]
//! that paces itself through the ambient clock makes the whole loop deterministic and testable.
//!
//! ## The bridge back to determinism (axis 2)
//! A live co-sim run is not bit-reproducible (real-time external input). So it never *is* the CI
//! artifact — it *produces* one: the recorded [`MobilityTrace`] becomes a set of deterministic
//! [`SampledMobility`] models (the pull seam again), replayed identically on DES and gated by the
//! axis-2 validator. Fly it live to discover the scenario; replay the trace to prove it forever.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use ndn_runtime::Runtime;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::topology::NodeId;
use crate::world::{MobilityModel, Position, World};

/// A timed kinematic state for one node, in scenario-relative seconds. The unit of a co-sim feed.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeState {
    pub node: NodeId,
    /// Source timestamp — seconds since the scenario epoch (mode B slaves the sim clock to this).
    pub t_secs: f64,
    pub position: Position,
    /// Optional velocity `[vx, vy, vz]` m/s (carried for dead-reckoning / analysis; not required).
    #[serde(default)]
    pub velocity: Option<[f64; 3]>,
}

/// A live source of node kinematics — the push seam. An adapter (SITL/Gazebo/Bevy) implements it.
pub trait MobilitySource: Send {
    /// Return every state available at logical time `now_secs` that hasn't been returned yet
    /// (non-blocking; may be empty). `now_secs` is the driver's elapsed scenario time.
    fn poll(&mut self, now_secs: f64) -> Vec<NodeState>;
    /// Finite sources (a scripted timeline, a closed feed) report `true` once exhausted; a live
    /// source stays `false` until its channel closes.
    fn is_done(&self) -> bool {
        false
    }
}

/// A [`MobilitySource`] fed by any task through a channel — the bridge an external adapter writes to.
/// The SITL adapter (3b) spawns a MAVLink reader that sends [`NodeState`]s into the sender half.
pub struct ChannelSource {
    rx: mpsc::UnboundedReceiver<NodeState>,
    closed: bool,
}

impl ChannelSource {
    /// Create the source and its sender. Drop the sender to signal end-of-feed.
    pub fn new() -> (mpsc::UnboundedSender<NodeState>, Self) {
        let (tx, rx) = mpsc::unbounded_channel();
        (tx, Self { rx, closed: false })
    }
}

impl MobilitySource for ChannelSource {
    fn poll(&mut self, _now_secs: f64) -> Vec<NodeState> {
        // A live feed carries its own timing; drain whatever has arrived.
        let mut out = Vec::new();
        loop {
            match self.rx.try_recv() {
                Ok(s) => out.push(s),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    self.closed = true;
                    break;
                }
            }
        }
        out
    }
    fn is_done(&self) -> bool {
        self.closed
    }
}

/// A [`MobilitySource`] that replays a fixed timeline — emits each state once logical time reaches
/// its `t_secs`. Used for demos and deterministic tests (paces through the ambient clock on DES).
pub struct ScriptedSource {
    states: Vec<NodeState>,
    cursor: usize,
}

impl ScriptedSource {
    /// `states` are sorted by `t_secs`.
    pub fn new(mut states: Vec<NodeState>) -> Self {
        states.sort_by(|a, b| a.t_secs.total_cmp(&b.t_secs));
        Self { states, cursor: 0 }
    }
}

impl MobilitySource for ScriptedSource {
    fn poll(&mut self, now_secs: f64) -> Vec<NodeState> {
        let mut out = Vec::new();
        while self.cursor < self.states.len() && self.states[self.cursor].t_secs <= now_secs {
            out.push(self.states[self.cursor]);
            self.cursor += 1;
        }
        out
    }
    fn is_done(&self) -> bool {
        self.cursor >= self.states.len()
    }
}

/// A source whose external physics the **sim advances** (lockstep — clock mode C). Unlike a live
/// [`MobilitySource`] that pushes at its own pace, the driver hands a stepped source the target time
/// and it integrates to that instant. Because the sim owns the clock, a stepped source is
/// **deterministic** — it runs reproducibly on DES and gates directly, with no record→replay needed.
/// This is the seam a stepped physics engine (Gazebo's step mode, a Bevy-headless fixed timestep)
/// plugs into: a `GazeboSource` would `advance_to` by issuing world-step commands and reading poses.
pub trait SteppableSource: Send {
    /// Advance the external simulation to `t_secs` (scenario-relative) and return the resulting node
    /// states. Called with monotonically non-decreasing times.
    fn advance_to(&mut self, t_secs: f64) -> Vec<NodeState>;
    /// Whether the run has reached its end at `t_secs` (default: never — an open-ended physics sim).
    fn is_done(&self, t_secs: f64) -> bool {
        let _ = t_secs;
        false
    }
}

/// Adapt a [`SteppableSource`] into a [`MobilitySource`] so [`drive_cosim`] drives it — the sim's
/// clock (virtual on DES, real on the governor) becomes the physics clock. `poll(now)` steps the
/// source to `now`, so on DES the whole co-simulation is deterministic.
pub struct Lockstep<S> {
    source: S,
    done: bool,
}

impl<S: SteppableSource> Lockstep<S> {
    pub fn new(source: S) -> Self {
        Self { source, done: false }
    }
}

impl<S: SteppableSource> MobilitySource for Lockstep<S> {
    fn poll(&mut self, now_secs: f64) -> Vec<NodeState> {
        let states = self.source.advance_to(now_secs);
        self.done = self.source.is_done(now_secs);
        states
    }
    fn is_done(&self) -> bool {
        self.done
    }
}

/// A recorded co-sim run — a time-ordered stream of node states. Serialize to JSON, commit it, and
/// replay it deterministically via [`into_models`](MobilityTrace::into_models).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MobilityTrace {
    pub states: Vec<NodeState>,
}

impl MobilityTrace {
    pub fn record(&mut self, s: NodeState) {
        self.states.push(s);
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).context("parse mobility trace JSON")
    }
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize mobility trace JSON")
    }

    /// Collapse the trace into one deterministic [`SampledMobility`] model per node — the pull seam,
    /// so a replay is an ordinary scenario (no source, no governor) that runs identically on DES.
    pub fn into_models(&self) -> BTreeMap<NodeId, Arc<dyn MobilityModel>> {
        let mut per_node: BTreeMap<NodeId, Vec<(f64, Position)>> = BTreeMap::new();
        for s in &self.states {
            per_node.entry(s.node).or_default().push((s.t_secs, s.position));
        }
        per_node
            .into_iter()
            .map(|(node, mut samples)| {
                samples.sort_by(|a, b| a.0.total_cmp(&b.0));
                let model: Arc<dyn MobilityModel> = Arc::new(SampledMobility { samples });
                (node, model)
            })
            .collect()
    }
}

/// A [`MobilityModel`] over recorded `(t_secs, position)` samples: linear interpolation between the
/// bracketing samples, clamped to the endpoints. Deterministic — the replay leg of co-simulation.
pub struct SampledMobility {
    samples: Vec<(f64, Position)>,
}

impl SampledMobility {
    pub fn new(mut samples: Vec<(f64, Position)>) -> Self {
        samples.sort_by(|a, b| a.0.total_cmp(&b.0));
        Self { samples }
    }
}

impl MobilityModel for SampledMobility {
    fn position(&self, t_secs: f64) -> Position {
        match self.samples.as_slice() {
            [] => Position::ORIGIN,
            [one] => one.1,
            samples => {
                // Before the first / after the last sample ⇒ clamp.
                if t_secs <= samples[0].0 {
                    return samples[0].1;
                }
                if t_secs >= samples[samples.len() - 1].0 {
                    return samples[samples.len() - 1].1;
                }
                // Find the bracketing pair and lerp.
                let hi = samples.partition_point(|(t, _)| *t <= t_secs);
                let (t0, p0) = samples[hi - 1];
                let (t1, p1) = samples[hi];
                let f = if t1 > t0 { (t_secs - t0) / (t1 - t0) } else { 0.0 };
                Position::xyz(
                    p0.x + (p1.x - p0.x) * f,
                    p0.y + (p1.y - p0.y) * f,
                    p0.z + (p1.z - p0.z) * f,
                )
            }
        }
    }
}

/// The governor loop: poll `source`, apply each [`NodeState`] to `world` live, record the stream,
/// and (on a paced kernel) tick the ambient clock by `tick`. Returns the recorded [`MobilityTrace`]
/// when the source is exhausted or `cancel` fires.
///
/// Kernel-agnostic: on the [`RealTimeKernel`] governor it runs at real pace for a live feed; on a
/// virtual/DES kernel with a [`ScriptedSource`] the whole loop is deterministic.
pub async fn drive_cosim(
    world: Arc<World>,
    epoch_ns: u64,
    runtime: Arc<dyn Runtime>,
    mut source: Box<dyn MobilitySource>,
    tick: Duration,
    cancel: CancellationToken,
) -> MobilityTrace {
    let mut trace = MobilityTrace::default();
    loop {
        if cancel.is_cancelled() {
            break;
        }
        let now_secs = runtime.unix_nanos().saturating_sub(epoch_ns) as f64 / 1e9;
        for s in source.poll(now_secs) {
            world.place(s.node, s.position);
            trace.record(s);
        }
        if source.is_done() {
            break;
        }
        runtime.sleep(tick).await;
    }
    trace
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampled_mobility_interpolates_and_clamps() {
        let m = SampledMobility::new(vec![
            (0.0, Position::xy(0.0, 0.0)),
            (10.0, Position::xy(100.0, 0.0)),
        ]);
        assert_eq!(m.position(-1.0), Position::xy(0.0, 0.0)); // clamp low
        assert_eq!(m.position(5.0), Position::xy(50.0, 0.0)); // midpoint lerp
        assert_eq!(m.position(99.0), Position::xy(100.0, 0.0)); // clamp high
    }

    #[test]
    fn scripted_source_emits_on_schedule() {
        let mut s = ScriptedSource::new(vec![
            NodeState { node: NodeId(0), t_secs: 1.0, position: Position::xy(0.0, 0.0), velocity: None },
            NodeState { node: NodeId(0), t_secs: 2.0, position: Position::xy(1.0, 0.0), velocity: None },
        ]);
        assert!(s.poll(0.5).is_empty());
        assert_eq!(s.poll(1.5).len(), 1);
        assert!(!s.is_done());
        assert_eq!(s.poll(9.0).len(), 1);
        assert!(s.is_done());
    }

    #[test]
    fn trace_json_round_trips() {
        let mut t = MobilityTrace::default();
        t.record(NodeState { node: NodeId(2), t_secs: 3.0, position: Position::xyz(1.0, 2.0, 3.0), velocity: Some([1.0, 0.0, 0.0]) });
        let again = MobilityTrace::from_json(&t.to_json().unwrap()).unwrap();
        assert_eq!(again.states, t.states);
        assert_eq!(again.into_models().len(), 1);
    }
}
