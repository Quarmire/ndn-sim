//! A from-scratch **discrete-event executor** (ndn-lab): the corner-remover.
//!
//! Earlier kernels ride Tokio's paused clock, which caps what's possible (no event-granular
//! single-step, no time-travel, one global clock — no PDES). This is a real deterministic
//! single-threaded async executor with its own **event queue** and virtual clock, implementing
//! the [`Runtime`] seam directly. It advances time by *events*, not quanta: when no task is
//! runnable it jumps the clock to the next scheduled timer — so it gives event-granular stepping
//! and a foundation for per-partition (PDES) clocks and state-checkpoint time-travel.
//!
//! It can drive **any** code that lives on the `Runtime` seam plus executor-agnostic primitives
//! (`tokio::sync`, `tokio::select!`). Running the *full* engine on it additionally needs the
//! engine/app `tokio::time::{sleep,timeout}` sites migrated onto the seam (the measured backlog —
//! ~20 sites + `Runtime::timeout`/`interval`); this module is the executor those migrate toward.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use ndn_runtime::{BoxFuture, Instant, Runtime};

use crate::kernel::SimKernel;

/// Default logical epoch (ns) — matches the other virtual kernels so timestamps are comparable.
const DEFAULT_EPOCH_NS: u64 = 1_700_000_000_000_000_000;

/// A pending timer: fire `waker` once virtual time reaches `deadline`. `seq` breaks ties
/// deterministically (insertion order).
struct TimerEntry {
    deadline: u64,
    seq: u64,
    waker: Waker,
}
impl PartialEq for TimerEntry {
    fn eq(&self, o: &Self) -> bool {
        (self.deadline, self.seq) == (o.deadline, o.seq)
    }
}
impl Eq for TimerEntry {}
impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for TimerEntry {
    fn cmp(&self, o: &Self) -> std::cmp::Ordering {
        (self.deadline, self.seq).cmp(&(o.deadline, o.seq))
    }
}

struct Inner {
    now_ns: u64,
    tasks: Vec<Option<BoxFuture>>,
    ready: VecDeque<usize>,
    free: Vec<usize>,
    timers: BinaryHeap<Reverse<TimerEntry>>,
    seq: u64,
}

/// The deterministic single-threaded event-loop executor + virtual clock.
pub struct Executor {
    inner: Mutex<Inner>,
    /// Real anchor so `now()` can hand back a monotonic `Instant` that advances with virtual time.
    base: Instant,
    epoch_base_ns: u64,
}

impl Executor {
    fn new(epoch_base_ns: u64) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                now_ns: 0,
                tasks: Vec::new(),
                ready: VecDeque::new(),
                free: Vec::new(),
                timers: BinaryHeap::new(),
                seq: 0,
            }),
            base: Instant::now(),
            epoch_base_ns,
        })
    }

    fn now_ns(&self) -> u64 {
        self.inner.lock().unwrap().now_ns
    }

    fn spawn(self: &Arc<Self>, fut: BoxFuture) {
        let mut g = self.inner.lock().unwrap();
        let id = if let Some(i) = g.free.pop() {
            g.tasks[i] = Some(fut);
            i
        } else {
            g.tasks.push(Some(fut));
            g.tasks.len() - 1
        };
        g.ready.push_back(id);
    }

    fn task_waker(self: &Arc<Self>, id: usize) -> Waker {
        Waker::from(Arc::new(TaskWaker {
            exec: Arc::clone(self),
            id,
        }))
    }

    /// Poll every ready task to quiescence (draining wakes produced along the way). Returns
    /// whether any task was polled.
    fn poll_ready(self: &Arc<Self>) -> bool {
        let mut any = false;
        loop {
            let id = {
                let mut g = self.inner.lock().unwrap();
                g.ready.pop_front()
            };
            let Some(id) = id else { break };
            // Take the future out so its poll can re-enter the executor (spawn/sleep) lock-free.
            let fut = {
                let mut g = self.inner.lock().unwrap();
                g.tasks.get_mut(id).and_then(|s| s.take())
            };
            let Some(mut fut) = fut else { continue };
            any = true;
            let waker = self.task_waker(id);
            let mut cx = Context::from_waker(&waker);
            match fut.as_mut().poll(&mut cx) {
                Poll::Ready(()) => {
                    let mut g = self.inner.lock().unwrap();
                    if id < g.tasks.len() {
                        g.tasks[id] = None;
                    }
                    g.free.push(id);
                }
                Poll::Pending => {
                    let mut g = self.inner.lock().unwrap();
                    g.tasks[id] = Some(fut);
                }
            }
        }
        any
    }

    /// Jump the clock to the next timer instant and wake every timer due at (or before) it.
    /// Returns the new virtual time, or `None` if there are no timers (quiescent).
    fn advance_to_next_event(self: &Arc<Self>) -> Option<u64> {
        let wakers = {
            let mut g = self.inner.lock().unwrap();
            let deadline = g.timers.peek()?.0.deadline;
            if deadline > g.now_ns {
                g.now_ns = deadline;
            }
            let now = g.now_ns;
            let mut wakers = Vec::new();
            while let Some(Reverse(t)) = g.timers.peek() {
                if t.deadline <= now {
                    wakers.push(g.timers.pop().unwrap().0.waker);
                } else {
                    break;
                }
            }
            wakers
        };
        for w in wakers {
            w.wake();
        }
        Some(self.now_ns())
    }

    /// Drive until `done()` holds or the system is quiescent (no ready tasks, no timers).
    fn drive_until(self: &Arc<Self>, done: impl Fn() -> bool) {
        loop {
            self.poll_ready();
            if done() {
                return;
            }
            if self.advance_to_next_event().is_none() {
                return; // deadlock / all done
            }
        }
    }
}

struct TaskWaker {
    exec: Arc<Executor>,
    id: usize,
}
impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.exec.inner.lock().unwrap().ready.push_back(self.id);
    }
}

/// A [`Runtime`] backed by the [`Executor`]: spawn/sleep/now all ride the event queue + virtual
/// clock. `tokio::sync` + `tokio::select!` work unchanged (executor-agnostic); `tokio::time` does
/// not (it needs Tokio's driver — that's the migration).
struct DesRuntime {
    exec: Arc<Executor>,
}

impl ndn_runtime::Spawn for DesRuntime {
    fn spawn(&self, fut: BoxFuture) {
        self.exec.spawn(fut);
    }
}
impl ndn_runtime::Sleep for DesRuntime {
    fn sleep(&self, dur: Duration) -> BoxFuture {
        let deadline = self.exec.now_ns().saturating_add(dur.as_nanos() as u64);
        Box::pin(DesSleep {
            exec: Arc::clone(&self.exec),
            deadline,
            registered: false,
        })
    }
}
impl ndn_runtime::Now for DesRuntime {
    fn now(&self) -> Instant {
        self.base_plus(self.exec.now_ns())
    }
    fn unix_nanos(&self) -> u64 {
        self.exec.epoch_base_ns.saturating_add(self.exec.now_ns())
    }
}
impl DesRuntime {
    fn base_plus(&self, ns: u64) -> Instant {
        let t = self.exec.base.checked_add(Duration::from_nanos(ns));
        // A run long enough to overflow the Instant base (~584 years of virtual ns) collapses now() to
        // base — losing monotonicity while unix_nanos() keeps advancing. Never in a real run; assert so a
        // test that somehow reaches it fails loudly instead of silently rewinding the Instant clock.
        debug_assert!(t.is_some(), "virtual time {ns}ns overflowed the Instant base");
        t.unwrap_or(self.exec.base)
    }
}
impl Runtime for DesRuntime {}

/// A virtual sleep on the event queue: registers a timer once, Ready when the clock passes it.
struct DesSleep {
    exec: Arc<Executor>,
    deadline: u64,
    registered: bool,
}
impl Future for DesSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        let s = self.get_mut();
        let mut g = s.exec.inner.lock().unwrap();
        if g.now_ns >= s.deadline {
            return Poll::Ready(());
        }
        if !s.registered {
            let seq = g.seq;
            g.seq += 1;
            g.timers.push(Reverse(TimerEntry {
                deadline: s.deadline,
                seq,
                waker: cx.waker().clone(),
            }));
            s.registered = true;
        }
        Poll::Pending
    }
}

/// The discrete-event kernel. Batch runs go through [`run`](DesKernel::run); event-granular
/// control through a [`DesSession`].
pub struct DesKernel {
    epoch_base_ns: u64,
    exec: OnceLock<Arc<Executor>>,
}

impl DesKernel {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            epoch_base_ns: DEFAULT_EPOCH_NS,
            exec: OnceLock::new(),
        })
    }

    pub fn with_epoch_ns(epoch_base_ns: u64) -> Arc<Self> {
        Arc::new(Self {
            epoch_base_ns,
            exec: OnceLock::new(),
        })
    }

    fn executor(&self) -> Arc<Executor> {
        self.exec
            .get_or_init(|| Executor::new(self.epoch_base_ns))
            .clone()
    }

    /// Run `f` to completion on the event queue, returning its output. The closure receives this
    /// kernel (pass it to [`Simulation::kernel`](crate::Simulation::kernel) to build a fabric on
    /// the event queue); `f` and anything it spawns must be `Send + 'static`, like `Runtime::spawn`.
    pub fn run<F, Fut, T>(self: &Arc<Self>, f: F) -> T
    where
        F: FnOnce(Arc<dyn SimKernel>) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let exec = self.executor();
        let rt: Arc<dyn Runtime> = Arc::new(DesRuntime {
            exec: Arc::clone(&exec),
        });
        // Route ndn-app's rt::{sleep,timeout,spawn} through the event queue while we drive, so
        // app-driven fabrics (consumers/producers) run on DES, not tokio.
        let _ambient = ndn_app::rt::set_current_runtime(Arc::clone(&rt));
        let me: Arc<dyn SimKernel> = self.clone();
        let out: Arc<Mutex<Option<T>>> = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&out);
        exec.spawn(Box::pin(async move {
            let v = f(me).await;
            *slot.lock().unwrap() = Some(v);
        }));
        exec.drive_until(|| out.lock().unwrap().is_some());
        out.lock()
            .unwrap()
            .take()
            .expect("DES main future did not complete (deadlock)")
    }

    /// Open an event-granular stepping session (owns the event queue). Installs the DES runtime
    /// as this thread's ambient runtime (for `ndn-app` fetch/serve) for the session's lifetime.
    pub fn session(self: &Arc<Self>) -> DesSession {
        let exec = self.executor();
        let ambient = ndn_app::rt::set_current_runtime(Arc::new(DesRuntime {
            exec: Arc::clone(&exec),
        }));
        DesSession {
            exec,
            epoch_base_ns: self.epoch_base_ns,
            _ambient: ambient,
        }
    }
}

impl SimKernel for DesKernel {
    fn runtime(&self) -> Arc<dyn Runtime> {
        Arc::new(DesRuntime {
            exec: self.executor(),
        })
    }
    fn name(&self) -> &'static str {
        "des"
    }
}

/// Event-granular control over a running event queue: [`block_on`](Self::block_on) to build /
/// issue actions, [`step`](Self::step) to advance to the **next event instant** (true
/// single-step, not a time quantum), [`run_until`](Self::run_until), and [`now_ns`](Self::now_ns).
pub struct DesSession {
    exec: Arc<Executor>,
    epoch_base_ns: u64,
    /// Keeps this thread's ambient runtime pointed at the DES executor for the session lifetime.
    _ambient: ndn_app::rt::RuntimeGuard,
}

impl DesSession {
    /// The DES runtime to hand to code (e.g. `Simulation::kernel` once the engine is migrated).
    pub fn runtime(&self) -> Arc<dyn Runtime> {
        Arc::new(DesRuntime {
            exec: Arc::clone(&self.exec),
        })
    }

    /// Drive a future to completion (running any tasks/timers it needs), returning its output.
    pub fn block_on<Fut, T>(&self, fut: Fut) -> T
    where
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let out: Arc<Mutex<Option<T>>> = Arc::new(Mutex::new(None));
        let slot = Arc::clone(&out);
        self.exec.spawn(Box::pin(async move {
            *slot.lock().unwrap() = Some(fut.await);
        }));
        self.exec.drive_until(|| out.lock().unwrap().is_some());
        out.lock()
            .unwrap()
            .take()
            .expect("block_on future did not complete (deadlock)")
    }

    /// Advance to the **next scheduled event**: run ready tasks, jump the clock to the next timer
    /// instant, wake it, run the resulting tasks. Returns the new virtual time (ns since epoch).
    /// This is event-granular single-step — what the tokio-paused kernels cannot do.
    pub fn step(&self) -> u64 {
        self.exec.poll_ready();
        self.exec.advance_to_next_event();
        self.exec.poll_ready();
        self.now_ns()
    }

    /// Step until the clock reaches `target_ns` (epoch-relative) or the system is quiescent.
    pub fn run_until(&self, target_ns: u64) {
        while self.now_ns() < target_ns {
            self.exec.poll_ready();
            if self.exec.advance_to_next_event().is_none() {
                break;
            }
            self.exec.poll_ready();
        }
    }

    pub fn now_ns(&self) -> u64 {
        self.epoch_base_ns.saturating_add(self.exec.now_ns())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_a_timed_channel_graph_to_completion() {
        let out = DesKernel::new().run(|k| async move {
            let rt = k.runtime();
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
            // A spawned task sleeps 1 s (virtual) then sends the clock time it woke at.
            let producer = Arc::clone(&rt);
            rt.spawn(Box::pin(async move {
                producer.sleep(Duration::from_secs(1)).await;
                let _ = tx.send(producer.unix_nanos());
            }));
            let woke_at = rx.recv().await.unwrap();
            (woke_at, rt.unix_nanos())
        });
        // The receiver observed ~1 s of virtual time elapse on the event queue.
        assert!(
            out.0 >= 1_700_000_001_000_000_000,
            "producer woke after 1 s virtual: {}",
            out.0
        );
        assert!(out.1 >= out.0, "main observes the advanced clock");
    }

    #[test]
    fn replays_deterministically() {
        // Three tasks sleeping different amounts append to a log; the order is by wake time and
        // must be identical across runs (event-queue determinism, not scheduler luck).
        let run = || {
            DesKernel::new().run(|k| async move {
                let rt = k.runtime();
                let log = Arc::new(Mutex::new(Vec::<u64>::new()));
                for ms in [30u64, 10, 20] {
                    let rt = Arc::clone(&rt);
                    let log = Arc::clone(&log);
                    rt.clone().spawn(Box::pin(async move {
                        rt.sleep(Duration::from_millis(ms)).await;
                        log.lock().unwrap().push(ms);
                    }));
                }
                // Let them all fire.
                rt.sleep(Duration::from_millis(100)).await;
                log.lock().unwrap().clone()
            })
        };
        let a = run();
        let b = run();
        assert_eq!(a, b, "identical replay");
        assert_eq!(a, vec![10, 20, 30], "woke in event-time order");
    }

    #[test]
    fn steps_event_by_event() {
        let kernel = DesKernel::new();
        let session = kernel.session();
        let fired = Arc::new(Mutex::new(Vec::<u64>::new()));

        // Schedule three timers at 1s / 2s / 3s.
        let rt = session.runtime();
        for s in [1u64, 2, 3] {
            let rt2 = Arc::clone(&rt);
            let fired = Arc::clone(&fired);
            rt.spawn(Box::pin(async move {
                rt2.sleep(Duration::from_secs(s)).await;
                fired.lock().unwrap().push(s);
            }));
        }

        // Each step advances to exactly the next event instant.
        let base = session.now_ns();
        session.step();
        assert_eq!(
            *fired.lock().unwrap(),
            vec![1],
            "step 1 → only the t=1s event"
        );
        assert_eq!(session.now_ns(), base + 1_000_000_000);
        session.step();
        assert_eq!(*fired.lock().unwrap(), vec![1, 2]);
        session.step();
        assert_eq!(*fired.lock().unwrap(), vec![1, 2, 3]);
        assert_eq!(session.now_ns(), base + 3_000_000_000);
    }
}
