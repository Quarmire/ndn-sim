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

// ---- Virtual-time kernel (deterministic, faster-than-real) -------------------------------

/// Default virtual epoch (ns) — a fixed point so absolute timestamps look like real epoch
/// time and are reproducible. ≈ 2023-11-14.
const DEFAULT_VIRTUAL_EPOCH_NS: u64 = 1_700_000_000_000_000_000;

/// **Virtual-time kernel**: runs the whole fabric on a *paused, single-threaded* Tokio
/// runtime so logical time auto-advances when every task is idle. Result: **deterministic,
/// reproducible, faster-than-real-time** runs — the same scenario + seed replays identically
/// and a scenario with seconds of virtual link delay finishes in milliseconds of wall time.
///
/// How it composes with the rest of ndn-lab:
/// - The engine's clock already flows entirely through the [`Runtime`] seam (slices 0a–0c),
///   so [`runtime`](VirtualKernel::runtime) returns a [`VirtualRuntime`] whose `now`/
///   `unix_nanos` are *logical* (tokio's paused clock only virtualizes its own `time`, not
///   the engine's `web_time`/epoch — hence the wrapper).
/// - `SimFace` link delay/bandwidth use `tokio::time`, which is virtual under the paused
///   runtime — so link delays become virtual for free.
/// - Single-threaded + the seeded `SimFace` RNG (slice 0) ⇒ deterministic ordering.
///
/// Usage: build + drive the fabric *inside* [`run`](VirtualKernel::run) (it owns the paused
/// runtime). Call it from a plain `#[test]`, **not** `#[tokio::test]` (no nested runtime).
#[cfg(not(target_arch = "wasm32"))]
pub struct VirtualKernel {
    epoch_base_ns: u64,
    runtime: std::sync::OnceLock<Arc<dyn Runtime>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl VirtualKernel {
    /// A virtual kernel with the default epoch.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            epoch_base_ns: DEFAULT_VIRTUAL_EPOCH_NS,
            runtime: std::sync::OnceLock::new(),
        })
    }

    /// A virtual kernel whose logical wall-clock starts at `epoch_base_ns` (ns since Unix
    /// epoch). Fixed value ⇒ reproducible absolute timestamps.
    pub fn with_epoch_ns(epoch_base_ns: u64) -> Arc<Self> {
        Arc::new(Self {
            epoch_base_ns,
            runtime: std::sync::OnceLock::new(),
        })
    }

    fn ensure_runtime(&self) -> Arc<dyn Runtime> {
        self.runtime
            .get_or_init(|| {
                // Captured inside the paused runtime context (see `run`), so this is the
                // virtual base. All engines share this one clock.
                Arc::new(VirtualRuntime {
                    start: tokio::time::Instant::now(),
                    epoch_base_ns: self.epoch_base_ns,
                })
            })
            .clone()
    }

    /// Build a fresh paused single-threaded runtime, then run `f` (which builds and drives
    /// the fabric) to completion on it. Virtual time auto-advances whenever all tasks are
    /// idle, so the closure returns as fast as the CPU allows. The kernel handed to `f` is
    /// this one — pass it to `Simulation::kernel`.
    pub fn run<F, Fut, T>(self: &Arc<Self>, f: F) -> T
    where
        F: FnOnce(Arc<dyn SimKernel>) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("paused current-thread runtime");
        let me = Arc::clone(self);
        rt.block_on(async move {
            me.ensure_runtime(); // initialize the virtual clock inside the runtime context
            f(me.clone() as Arc<dyn SimKernel>).await
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl SimKernel for VirtualKernel {
    fn runtime(&self) -> Arc<dyn Runtime> {
        self.ensure_runtime()
    }
    fn name(&self) -> &'static str {
        "virtual"
    }
}

/// The [`Runtime`] a [`VirtualKernel`] hands to engines: spawn/sleep ride the paused Tokio
/// runtime (so sleeps are virtual + auto-advancing), and `now`/`unix_nanos` report *logical*
/// time derived from tokio's paused monotonic clock.
#[cfg(not(target_arch = "wasm32"))]
struct VirtualRuntime {
    /// Captured at clock init inside the paused runtime; `elapsed()` is virtual.
    start: tokio::time::Instant,
    epoch_base_ns: u64,
}

#[cfg(not(target_arch = "wasm32"))]
impl ndn_runtime::Spawn for VirtualRuntime {
    fn spawn(&self, fut: ndn_runtime::BoxFuture) {
        tokio::spawn(fut);
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl ndn_runtime::Sleep for VirtualRuntime {
    fn sleep(&self, dur: std::time::Duration) -> ndn_runtime::BoxFuture {
        Box::pin(tokio::time::sleep(dur))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl ndn_runtime::Now for VirtualRuntime {
    fn now(&self) -> ndn_runtime::Instant {
        // tokio's paused monotonic clock → a std/`web_time` Instant carrying virtual time.
        tokio::time::Instant::now().into_std()
    }
    fn unix_nanos(&self) -> u64 {
        // Logical epoch = base + virtual elapsed (deterministic; never reads the real clock).
        self.epoch_base_ns
            .saturating_add(self.start.elapsed().as_nanos() as u64)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Runtime for VirtualRuntime {}
