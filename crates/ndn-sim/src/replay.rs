//! Session recording + replay (ndn-lab).
//!
//! A [`Scenario`](crate::Scenario) captures a sim's *initial* state; a [`Recording`] adds the
//! **live command journal** — every [`SimCommand`] issued through the [`ControlPlane`], with its
//! virtual timestamp — so a hand-driven (or MCP/GUI-driven) session is fully reproducible: build
//! the scenario, replay the journal, get the same run back. Pairs with the determinism gate (a
//! `VirtualKernel` replay reproduces the session bit-for-bit) and unblocks "record a session,
//! share the file, replay it" + `compare_runs`.
//!
//! Capture: [`ControlPlane::start_recording`](crate::ControlPlane::start_recording) (or
//! `start_recording_with(scenario)` to embed the initial state) journals every executed command;
//! [`ControlPlane::recording`](crate::ControlPlane::recording) snapshots it. Replay: build a fresh
//! fabric (from `recording.scenario` if present), wrap it in a `ControlPlane`, and call
//! [`Recording::replay`].

use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::ControlPlane;
use crate::control_plane::SimCommand;
use crate::scenario::Scenario;

/// One journaled command and the virtual time it was issued.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordedCommand {
    /// Kernel-clock time the command was issued (virtual under a `VirtualKernel`).
    pub at_ns: u64,
    pub command: SimCommand,
}

/// A replayable session: the initial scenario (optional) + the ordered command journal.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Recording {
    /// The initial state, if the recording was started with a scenario (self-contained replay).
    #[serde(default)]
    pub scenario: Option<Scenario>,
    pub commands: Vec<RecordedCommand>,
}

impl Recording {
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Number of journaled commands.
    pub fn len(&self) -> usize {
        self.commands.len()
    }
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Re-apply the journal to `control` (which should wrap a *fresh* fabric — from
    /// `self.scenario` if present). With `paced`, sleeps the recorded inter-command virtual deltas
    /// (faithful cadence — deterministic under a `VirtualKernel`); otherwise applies as fast as
    /// possible, reproducing the end state. Errors from individual commands are ignored (a replay
    /// reproduces what happened, including no-ops).
    pub async fn replay(&self, control: &ControlPlane, paced: bool) -> Result<()> {
        let mut prev: Option<u64> = None;
        for rc in &self.commands {
            if paced {
                if let Some(p) = prev {
                    let delta = rc.at_ns.saturating_sub(p);
                    if delta > 0 {
                        tokio::time::sleep(Duration::from_nanos(delta)).await;
                    }
                }
                prev = Some(rc.at_ns);
            }
            let _ = control.execute(rc.command.clone()).await;
        }
        Ok(())
    }
}
