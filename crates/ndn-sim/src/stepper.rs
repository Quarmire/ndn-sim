//! Interactive DES stepping — drive a fabric on the [`DesKernel`](crate::DesKernel) event queue and
//! advance it **one event at a time**, inspecting the state between steps. The debugger surface the
//! tokio-paused kernels can't offer (they auto-advance over any idle window; they can't stop *at*
//! the next event).
//!
//! A [`Stepper`] owns a [`DesSession`](crate::des::DesSession) plus the fabric built on it. Because
//! the DES executor is a single-threaded event loop, stepping is synchronous: [`step`](Stepper::step)
//! runs the ready tasks, jumps the virtual clock to the next scheduled event, and stops — so a REPL
//! (`ndn-lab step <scenario>`) can pause between events, print the topology / metrics / positions,
//! and continue, all deterministically and reproducibly.
//!
//! ```rust
//! use ndn_sim::{DesKernel, Scenario, Stepper};
//!
//! let scenario = Scenario::from_toml(r#"
//!     [kernel]
//!     kind = "des"
//!     [[nodes]]
//!     label = "a"
//!     [[nodes]]
//!     label = "b"
//!     [[links]]
//!     a = 0
//!     b = 1
//! "#).unwrap();
//!
//! let mut stepper = Stepper::build(DesKernel::new(), scenario).unwrap();
//! stepper.step();                       // advance to the next event
//! stepper.run_for_ms(50);               // advance 50 ms of virtual time
//! assert!(stepper.elapsed_ms() >= 50);
//! assert_eq!(stepper.fabric().topology().nodes.len(), 2);
//! ```

use std::sync::Arc;

use anyhow::Result;

use crate::des::{DesKernel, DesSession};
use crate::scenario::Scenario;
use crate::topology::RunningSimulation;

/// A fabric built on a DES session, drivable event-by-event.
pub struct Stepper {
    session: DesSession,
    fabric: RunningSimulation,
    start_ns: u64,
}

impl Stepper {
    /// Build `scenario` on the event queue of `kernel` and return a stepper poised at t=0. The
    /// fabric's engines/apps are spawned but not yet advanced — call [`step`](Self::step) /
    /// [`run_for_ms`](Self::run_for_ms) to drive them. The scenario's declared kernel is ignored;
    /// interactive stepping always uses this DES kernel.
    pub fn build(kernel: Arc<DesKernel>, scenario: Scenario) -> Result<Self> {
        let session = kernel.session();
        let k: Arc<dyn crate::kernel::SimKernel> = kernel;
        // Build + start the fabric on the DES executor (block_on drives just the build to
        // completion; the engines' background tasks stay parked on timers for us to step).
        let fabric =
            session.block_on(async move { anyhow::Ok(scenario.build(k)?.start().await?) })?;
        let start_ns = session.now_ns();
        Ok(Self {
            session,
            fabric,
            start_ns,
        })
    }

    /// Advance to the **next scheduled event** and return the new virtual time (ns since epoch). If
    /// the system is quiescent (no pending timers) the clock is unchanged.
    pub fn step(&self) -> u64 {
        self.session.step()
    }

    /// Advance `ms` milliseconds of virtual time (stepping through every event in the window).
    /// Returns the new virtual time (ns).
    pub fn run_for_ms(&self, ms: u64) -> u64 {
        let target = self
            .session
            .now_ns()
            .saturating_add(ms.saturating_mul(1_000_000));
        self.session.run_until(target);
        self.session.now_ns()
    }

    /// Advance to `ms` milliseconds **since the session started**. Returns the new virtual time (ns).
    pub fn run_until_ms(&self, ms_from_start: u64) -> u64 {
        self.session.run_until(
            self.start_ns
                .saturating_add(ms_from_start.saturating_mul(1_000_000)),
        );
        self.session.now_ns()
    }

    /// Current virtual time (ns since epoch).
    pub fn now_ns(&self) -> u64 {
        self.session.now_ns()
    }

    /// Virtual time elapsed since the session started (ms).
    pub fn elapsed_ms(&self) -> u64 {
        (self.now_ns().saturating_sub(self.start_ns)) / 1_000_000
    }

    /// The fabric under the stepper — query it (`topology()`, `snapshot_metrics()`,
    /// `scene_snapshot()`, `app_successes()`) between steps.
    pub fn fabric(&self) -> &RunningSimulation {
        &self.fabric
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topo;

    /// A generated line with a producer + consumer: stepping the DES session forwards real traffic,
    /// and the same scenario steps identically twice (event-queue determinism).
    fn line_with_apps() -> Scenario {
        use crate::app::AppSpec;
        let mut s = topo::line(2);
        s.nodes[0].apps.push(AppSpec::Producer {
            prefix: "/demo".into(),
            content: Some("hi".into()),
            freshness_ms: Some(4000),
        });
        s.nodes[1].apps.push(AppSpec::Consumer {
            prefix: "/demo".into(),
            count: 3,
            interval_ms: 100,
            lifetime_ms: Some(2000),
        });
        topo::add_routes_toward(&mut s, "/demo", 0);
        s
    }

    #[test]
    fn stepping_advances_the_clock_and_forwards_traffic() {
        let stepper = Stepper::build(DesKernel::new(), line_with_apps()).unwrap();
        assert_eq!(stepper.fabric().topology().nodes.len(), 2);
        assert_eq!(stepper.elapsed_ms(), 0, "poised at t=0 before stepping");

        // Drive a second of virtual time; the consumer (app 1) should fetch from the producer.
        stepper.run_for_ms(1000);
        assert!(stepper.elapsed_ms() >= 1000, "the virtual clock advanced");
        let fetched = stepper
            .fabric()
            .app_successes(crate::app::AppId(1))
            .unwrap_or(0);
        assert!(
            fetched >= 1,
            "the consumer fetched over the stepped session, got {fetched}"
        );
    }

    #[test]
    fn single_step_stops_at_the_next_event() {
        let stepper = Stepper::build(DesKernel::new(), line_with_apps()).unwrap();
        let t0 = stepper.now_ns();
        let t1 = stepper.step();
        assert!(t1 >= t0, "a single step does not run backward");
    }

    #[test]
    fn stepping_is_deterministic() {
        let run = || {
            let stepper = Stepper::build(DesKernel::new(), line_with_apps()).unwrap();
            stepper.run_for_ms(1500);
            (
                stepper.elapsed_ms(),
                stepper
                    .fabric()
                    .app_successes(crate::app::AppId(1))
                    .unwrap_or(0),
            )
        };
        assert_eq!(run(), run(), "a stepped DES session replays identically");
    }
}
