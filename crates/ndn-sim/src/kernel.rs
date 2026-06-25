//! `SimKernel` — the execution/time engine the fabric runs on (ndn-lab).
//!
//! The kernel is the seam that makes "simulation vs emulation" a *dial* rather than two
//! tools: every node's `ForwarderEngine` is built with the kernel's [`Runtime`], so the
//! kernel owns the clock and task spawning. Swapping the kernel swaps the entire time model
//! without touching nodes, faces, or apps.
//!
//! - [`WallClockKernel`] (this slice) = the production `TokioRuntime`: real time,
//!   emulation-grade, can talk to real devices/other NDN impls. The default.
//! - A future `VirtualKernel` will supply a virtual-time runtime + event scheduler for
//!   deterministic, faster-than-real, single-steppable runs. Because the engine's clock now
//!   flows entirely through the [`Runtime`] seam (ndn-lab slices 0a–0c), it can drop in here
//!   with no engine changes.

use std::sync::Arc;

use ndn_runtime::Runtime;

/// The execution engine a [`Fabric`](crate::RunningSimulation) runs on. Provides the
/// [`Runtime`] every node is built with (clock + spawn). Pluggable so the time model
/// (wall-clock now; virtual / parallel later) is a choice, not a fork.
pub trait SimKernel: Send + Sync {
    /// The runtime each node's engine is constructed with. All node time reads (PIT/CS
    /// expiry, freshness, deadlines) and task spawns flow through it.
    fn runtime(&self) -> Arc<dyn Runtime>;

    /// Short label for telemetry / introspection (e.g. `"wall-clock"`).
    fn name(&self) -> &'static str;
}

/// The default kernel: real wall-clock time over the production `TokioRuntime`. This is the
/// emulation end of the continuum — realistic async/timing, and the only kernel that can
/// host real external devices or other NDN implementations over real transports.
pub struct WallClockKernel {
    runtime: Arc<dyn Runtime>,
}

impl WallClockKernel {
    pub fn new() -> Self {
        Self {
            runtime: ndn_runtime::default_runtime(),
        }
    }
}

impl Default for WallClockKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl SimKernel for WallClockKernel {
    fn runtime(&self) -> Arc<dyn Runtime> {
        Arc::clone(&self.runtime)
    }
    fn name(&self) -> &'static str {
        "wall-clock"
    }
}
