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

// ---- Real-time governor (the sim↔emulation continuum bridge) ------------------------------

/// **Real-time governor**: runs on a normal (non-paused) Tokio runtime — real time, real I/O, so
/// it can host real external devices over real sockets (the [`bridge`](crate::bridge)) — *but*
/// presents a **logical, scenario-relative clock** through the [`Runtime`] seam: `unix_nanos` is
/// `epoch_base + real-elapsed-since-start`, not the absolute system clock.
///
/// This is the missing keystone of the continuum. [`WallClockKernel`] (absolute system time) and
/// [`VirtualKernel`] (virtual time that *jumps* idle gaps, so real I/O can't interleave) are the
/// two ends; the governor is the middle — real pace so a real device participates, unified
/// logical timestamps so telemetry reads the same scenario-relative time the virtual run would.
/// Timing isn't bit-reproducible (real pacing), but the clock *source* and timestamp *base* are
/// the scenario's, not the wall's. Used like [`WallClockKernel`] — no `run` wrapper.
pub struct RealTimeKernel {
    epoch_base_ns: u64,
    runtime: std::sync::OnceLock<Arc<dyn Runtime>>,
}

impl RealTimeKernel {
    /// A governor with the default logical epoch.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            epoch_base_ns: DEFAULT_VIRTUAL_EPOCH_NS,
            runtime: std::sync::OnceLock::new(),
        })
    }

    /// A governor whose logical clock starts at `epoch_base_ns`.
    pub fn with_epoch_ns(epoch_base_ns: u64) -> Arc<Self> {
        Arc::new(Self {
            epoch_base_ns,
            runtime: std::sync::OnceLock::new(),
        })
    }
}

impl SimKernel for RealTimeKernel {
    fn runtime(&self) -> Arc<dyn Runtime> {
        self.runtime
            .get_or_init(|| {
                Arc::new(RealTimeRuntime {
                    start: ndn_runtime::Instant::now(),
                    epoch_base_ns: self.epoch_base_ns,
                })
            })
            .clone()
    }
    fn name(&self) -> &'static str {
        "real-time"
    }
}

/// The [`Runtime`] a [`RealTimeKernel`] hands to engines: spawn/sleep on the real Tokio runtime
/// (real pace), but `unix_nanos` is logical (epoch + real elapsed), so all engines share one
/// scenario-relative clock instead of reading the absolute system clock independently.
struct RealTimeRuntime {
    start: ndn_runtime::Instant,
    epoch_base_ns: u64,
}

impl ndn_runtime::Spawn for RealTimeRuntime {
    fn spawn(&self, fut: ndn_runtime::BoxFuture) {
        tokio::spawn(fut);
    }
}

impl ndn_runtime::Sleep for RealTimeRuntime {
    fn sleep(&self, dur: std::time::Duration) -> ndn_runtime::BoxFuture {
        Box::pin(tokio::time::sleep(dur))
    }
}

impl ndn_runtime::Now for RealTimeRuntime {
    fn now(&self) -> ndn_runtime::Instant {
        ndn_runtime::Instant::now()
    }
    fn unix_nanos(&self) -> u64 {
        self.epoch_base_ns
            .saturating_add(self.start.elapsed().as_nanos() as u64)
    }
}

impl Runtime for RealTimeRuntime {}

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
    ///
    /// Guarded by a default [`DEFAULT_RUN_CEILING`] of virtual time: a workload that never finishes
    /// (a convergence predicate that never holds) **panics with a clear message** instead of hanging
    /// forever. Use [`run_capped`](Self::run_capped) for a custom budget and a `Result` instead.
    pub fn run<F, Fut, T>(self: &Arc<Self>, f: F) -> T
    where
        F: FnOnce(Arc<dyn SimKernel>) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        self.run_capped(DEFAULT_RUN_CEILING, f).unwrap_or_else(|e| {
            panic!(
                "VirtualKernel::run exceeded the {}s virtual-time ceiling — a convergence \
                 predicate that never holds? Use run_capped() for a custom budget, or fix the \
                 workload so it terminates.",
                e.cap.as_secs()
            )
        })
    }

    /// Like [`run`](Self::run) but bail with [`VirtualTimeExceeded`] once `max_virtual` of virtual
    /// time elapses before `f` finishes — turning a never-converging run into a clean failure with
    /// no output-less hang. Put your convergence loop inside `f` (`while !converged { sleep(dt).await
    /// }`); if it never converges, the sleeping advances virtual time until the cap fires.
    pub fn run_capped<F, Fut, T>(
        self: &Arc<Self>,
        max_virtual: std::time::Duration,
        f: F,
    ) -> Result<T, VirtualTimeExceeded>
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
            let fut = f(me.clone() as Arc<dyn SimKernel>);
            tokio::pin!(fut);
            tokio::select! {
                r = &mut fut => Ok(r),
                _ = tokio::time::sleep(max_virtual) => Err(VirtualTimeExceeded { cap: max_virtual }),
            }
        })
    }
}

/// The default virtual-time budget [`VirtualKernel::run`] allows before it declares a hang (1 hour
/// of *virtual* time — near-instant in wall-clock, but far beyond any real convergence run).
pub const DEFAULT_RUN_CEILING: std::time::Duration = std::time::Duration::from_secs(3600);

/// A [`VirtualKernel::run_capped`] run that didn't finish within its virtual-time budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtualTimeExceeded {
    /// The budget that was exceeded.
    pub cap: std::time::Duration,
}

impl std::fmt::Display for VirtualTimeExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "virtual-time budget of {:?} exceeded before the run finished",
            self.cap
        )
    }
}

impl std::error::Error for VirtualTimeExceeded {}

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

// ---- Steppable kernel (explicit virtual-time control: pause / step / run_until) -----------

/// **Steppable kernel**: the same deterministic virtual clock as [`VirtualKernel`], but time
/// advances only when *you say so* — `advance` / `run_for` / `run_until`, with "pause" being
/// simply "don't advance". This is the controllable-time substrate the GUI scrubber and a
/// single-stepping debugger need.
///
/// **What this is, honestly.** It does *not* replace Tokio with a from-scratch discrete-event
/// executor — it can't, because the engine, apps, and faces are built on Tokio primitives
/// (`tokio::time`/`timeout`/`sync`) that only a Tokio runtime can drive. Instead it drives
/// Tokio's *paused* clock (a deterministic virtual-time source) with **explicit advancement**
/// instead of auto-advance. So you get: deterministic virtual time + pause + forward stepping by
/// time quantum + run-until-T. You do *not* get (yet): event-granular single-step (advancement is
/// by time, not one event), backward `seek` (needs state checkpointing), or per-partition PDES
/// clocks (needs a multi-clock executor). Same-instant event ordering is still Tokio's
/// (empirically stable — see the determinism gate).
///
/// Usage: open a [`StepSession`] (it owns the paused runtime), build the fabric inside it via
/// [`block_on`](StepSession::block_on), then drive time with [`advance`](StepSession::advance).
#[cfg(not(target_arch = "wasm32"))]
pub struct SteppableKernel {
    epoch_base_ns: u64,
    runtime: std::sync::OnceLock<Arc<dyn Runtime>>,
}

#[cfg(not(target_arch = "wasm32"))]
impl SteppableKernel {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            epoch_base_ns: DEFAULT_VIRTUAL_EPOCH_NS,
            runtime: std::sync::OnceLock::new(),
        })
    }

    pub fn with_epoch_ns(epoch_base_ns: u64) -> Arc<Self> {
        Arc::new(Self {
            epoch_base_ns,
            runtime: std::sync::OnceLock::new(),
        })
    }

    fn ensure_runtime(&self) -> Arc<dyn Runtime> {
        self.runtime
            .get_or_init(|| {
                Arc::new(VirtualRuntime {
                    start: tokio::time::Instant::now(),
                    epoch_base_ns: self.epoch_base_ns,
                })
            })
            .clone()
    }

    /// Open a stepping session: builds the paused single-threaded runtime and initializes the
    /// virtual clock inside it. The returned [`StepSession`] owns the runtime; drive time through
    /// it. Call from a plain `#[test]` (it owns the runtime; not `#[tokio::test]`).
    pub fn session(self: &Arc<Self>) -> StepSession {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .expect("paused current-thread runtime");
        let me = Arc::clone(self);
        rt.block_on(async {
            me.ensure_runtime();
        });
        StepSession { rt, kernel: me }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl SimKernel for SteppableKernel {
    fn runtime(&self) -> Arc<dyn Runtime> {
        self.ensure_runtime()
    }
    fn name(&self) -> &'static str {
        "steppable"
    }
}

/// A live stepping session over a [`SteppableKernel`] — owns the paused runtime and the
/// explicit time controls. Build the fabric with [`block_on`](Self::block_on); advance with
/// [`advance`](Self::advance) / [`run_for`](Self::run_for) / [`run_until`](Self::run_until);
/// "pause" = stop advancing; inspect fabric state (synchronously) between steps.
#[cfg(not(target_arch = "wasm32"))]
pub struct StepSession {
    rt: tokio::runtime::Runtime,
    kernel: Arc<SteppableKernel>,
}

#[cfg(not(target_arch = "wasm32"))]
impl StepSession {
    /// The kernel to hand to [`Simulation::kernel`](crate::Simulation::kernel).
    pub fn kernel(&self) -> Arc<dyn SimKernel> {
        Arc::clone(&self.kernel) as Arc<dyn SimKernel>
    }

    /// Run an async action to completion (auto-advancing virtual time as needed) — for setup
    /// (`Simulation::start`) and for issuing actions whose result you need now (a one-shot fetch,
    /// `shutdown`).
    pub fn block_on<F: std::future::Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    /// **Advance virtual time by `step`**, running everything that happens in that window
    /// (app loops, face deliveries, engine timers). Returns when the clock reaches now+`step`.
    /// This is the explicit time control: call it to step; don't call it to pause.
    ///
    /// Implemented by driving the paused runtime over a `sleep(step)`: under `start_paused`,
    /// `block_on` runs every ready task and auto-advances the clock to the next timer until the
    /// sleep fires at now+`step` — so all background tasks within the window run, and time stops
    /// exactly at the target (nothing past `step` fires). Between calls nothing is polled = paused.
    pub fn advance(&self, step: std::time::Duration) {
        self.rt
            .block_on(async move { tokio::time::sleep(step).await });
    }

    /// Alias for [`advance`](Self::advance) — run the sim forward by `d`.
    pub fn run_for(&self, d: std::time::Duration) {
        self.advance(d);
    }

    /// Advance until the virtual clock reaches `target_ns` (no-op if already past it).
    pub fn run_until(&self, target_ns: u64) {
        let now = self.now_ns();
        if target_ns > now {
            self.advance(std::time::Duration::from_nanos(target_ns - now));
        }
    }

    /// The current virtual time (ns since the logical epoch). Read inside the runtime context
    /// (the paused clock is only valid there).
    pub fn now_ns(&self) -> u64 {
        let kernel = Arc::clone(&self.kernel);
        self.rt
            .block_on(async move { kernel.runtime().unix_nanos() })
    }
}
