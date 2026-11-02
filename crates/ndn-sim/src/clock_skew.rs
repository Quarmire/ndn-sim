//! Per-node **clock skew**: a node whose wall clock is wrong.
//!
//! Every engine reads absolute time through its runtime's
//! [`unix_nanos`](ndn_runtime::Now::unix_nanos) (Interest deadlines, Data freshness, certificate
//! validity, and whatever an application dates). A node declared with a [`ClockSkew`] gets a
//! runtime whose `unix_nanos` reads the fabric's true clock plus a fixed offset and a rate error
//! (drift), so one simulation can hold a laptop five minutes fast, a phone an hour slow and a thief
//! whose clock says last week. Only the wall clock is skewed: the monotonic clock (`now`, `sleep`)
//! and therefore link delays, timers and the kernel's virtual time are untouched, exactly as a
//! mis-set real clock leaves its machine's tick rate alone.
//!
//! Declare it per node with [`NodeProfile::with_clock_skew`](crate::NodeProfile::with_clock_skew)
//! or [`Simulation::set_clock_skew`](crate::Simulation::set_clock_skew); change it on the live
//! fabric with [`RunningSimulation::set_clock_skew`](crate::RunningSimulation::set_clock_skew)
//! (a clock step), and read any node's clock with
//! [`RunningSimulation::node_clock`](crate::RunningSimulation::node_clock). Nodes without a
//! declared skew run on the kernel's runtime directly and pay nothing.

use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;

use ndn_runtime::{BoxFuture, Runtime};

/// How wrong a node's wall clock is: `offset_ns` (positive = ahead of true time) plus a rate error
/// of `drift_ppm` parts per million (positive = runs fast), accumulated from the moment the skew
/// is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ClockSkew {
    /// Fixed offset from true time, in nanoseconds; positive = the clock is ahead.
    pub offset_ns: i64,
    /// Rate error in parts per million; positive = the clock runs fast.
    pub drift_ppm: i64,
}

impl ClockSkew {
    /// No error: the node reads true time (but its skew can be changed later on the live fabric).
    pub const NONE: Self = Self {
        offset_ns: 0,
        drift_ppm: 0,
    };

    /// A clock `by` ahead of true time.
    pub fn ahead(by: Duration) -> Self {
        Self {
            offset_ns: i64::try_from(by.as_nanos()).unwrap_or(i64::MAX),
            drift_ppm: 0,
        }
    }

    /// A clock `by` behind true time.
    pub fn behind(by: Duration) -> Self {
        Self {
            offset_ns: -i64::try_from(by.as_nanos()).unwrap_or(i64::MAX),
            drift_ppm: 0,
        }
    }

    /// This skew, also drifting by `ppm` parts per million (positive = fast).
    pub fn drifting(self, ppm: i64) -> Self {
        Self {
            drift_ppm: ppm,
            ..self
        }
    }

    /// The skewed reading of `true_ns`, for a skew applied when true time was `anchor_ns`.
    fn apply(&self, true_ns: u64, anchor_ns: u64) -> u64 {
        let elapsed = i128::from(true_ns) - i128::from(anchor_ns);
        let drift = elapsed * i128::from(self.drift_ppm) / 1_000_000;
        let skewed = i128::from(true_ns) + i128::from(self.offset_ns) + drift;
        skewed.clamp(0, i128::from(u64::MAX)) as u64
    }
}

/// The runtime a skewed node's engine runs on: the kernel's runtime for spawning, sleeping and
/// monotonic time, with [`ClockSkew`] applied to the wall clock.
pub(crate) struct SkewedRuntime {
    inner: Arc<dyn Runtime>,
    /// `(skew, true time when it was applied)`.
    state: Mutex<(ClockSkew, u64)>,
}

impl SkewedRuntime {
    pub(crate) fn new(inner: Arc<dyn Runtime>, skew: ClockSkew) -> Arc<Self> {
        let anchor = inner.unix_nanos();
        Arc::new(Self {
            inner,
            state: Mutex::new((skew, anchor)),
        })
    }

    /// Replace the skew from now on: the clock steps to `true + offset` and drifts from here.
    pub(crate) fn set(&self, skew: ClockSkew) {
        let anchor = self.inner.unix_nanos();
        *self.state.lock() = (skew, anchor);
    }

    /// The skew in force.
    pub(crate) fn skew(&self) -> ClockSkew {
        self.state.lock().0
    }
}

impl ndn_runtime::Spawn for SkewedRuntime {
    fn spawn(&self, fut: BoxFuture) {
        self.inner.spawn(fut);
    }
}

impl ndn_runtime::Sleep for SkewedRuntime {
    fn sleep(&self, dur: Duration) -> BoxFuture {
        self.inner.sleep(dur)
    }
}

impl ndn_runtime::Now for SkewedRuntime {
    fn now(&self) -> ndn_runtime::Instant {
        self.inner.now()
    }

    fn unix_nanos(&self) -> u64 {
        let true_ns = self.inner.unix_nanos();
        let (skew, anchor) = *self.state.lock();
        skew.apply(true_ns, anchor)
    }
}

/// The runtime a node is built on: the kernel's own, or — when the node declares a skew — a
/// [`SkewedRuntime`] over it, returned too so the fabric can adjust it later.
pub(crate) fn node_runtime(
    kernel: Arc<dyn Runtime>,
    skew: Option<ClockSkew>,
) -> (Arc<dyn Runtime>, Option<Arc<SkewedRuntime>>) {
    match skew {
        Some(s) => {
            let skewed = SkewedRuntime::new(kernel, s);
            (Arc::clone(&skewed) as Arc<dyn Runtime>, Some(skewed))
        }
        None => (kernel, None),
    }
}

impl Runtime for SkewedRuntime {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_and_drift_compose() {
        let s = ClockSkew::behind(Duration::from_secs(7 * 24 * 3600)).drifting(100);
        let anchor = 1_700_000_000_000_000_000;
        // At the anchor only the offset shows.
        assert_eq!(
            s.apply(anchor, anchor),
            anchor - 7 * 24 * 3600 * 1_000_000_000
        );
        // 1000 s later, +100 ppm adds 100 ms.
        let later = anchor + 1_000_000_000_000;
        assert_eq!(
            s.apply(later, anchor),
            later - 7 * 24 * 3600 * 1_000_000_000 + 100_000_000
        );
    }

    #[test]
    fn readings_never_wrap() {
        assert_eq!(ClockSkew::behind(Duration::from_secs(10)).apply(5, 5), 0);
        assert_eq!(ClockSkew::ahead(Duration::MAX).apply(u64::MAX, 0), u64::MAX);
    }
}
