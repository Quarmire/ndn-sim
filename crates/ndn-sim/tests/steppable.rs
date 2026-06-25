//! Steppable kernel (ndn-lab): explicit virtual-time control — pause / step / run_until — the
//! controllable-time substrate for the GUI scrubber and single-stepping. Time advances only when
//! the session is told to; "pause" is "don't advance".

use std::time::Duration;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{AppId, AppSpec, LinkConfig, RunningSimulation, StepSession, SteppableKernel};

/// Build a fabric (producer + an infinite 100 ms consumer) on the session's steppable kernel.
async fn build(session: &StepSession) -> RunningSimulation {
    let mut sim = ndn_sim::Simulation::new().kernel(session.kernel());
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    sim.link(a, b, LinkConfig { delay: Duration::from_millis(1), ..LinkConfig::default() });
    sim.add_route(a, "/svc", b);
    sim.add_app(b, AppSpec::Producer { prefix: "/svc".into(), content: Some("ok".into()) }); // id 0
    sim.add_app(a, AppSpec::Consumer { prefix: "/svc".into(), count: 0, interval_ms: 100 }); // id 1
    sim.start().await.unwrap()
}

#[test]
fn advances_in_controlled_steps_and_pauses() {
    let kernel = SteppableKernel::new();
    let session = kernel.session();
    let fabric = session.block_on(build(&session));
    let consumer = AppId(1);

    // Step 1 s of virtual time → ~10 fetches (interval 100 ms).
    session.run_for(Duration::from_secs(1));
    let s1 = fabric.app_successes(consumer).unwrap();
    assert!(s1 >= 5, "stepping 1 s drove ~10 fetches, got {s1}");

    // Step again → the sim advanced further.
    session.run_for(Duration::from_secs(1));
    let s2 = fabric.app_successes(consumer).unwrap();
    assert!(s2 > s1, "second step advanced the sim: {s1} → {s2}");

    // Pause: no advance ⇒ virtual time frozen even as real wall time passes.
    let paused = fabric.app_successes(consumer).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(fabric.app_successes(consumer).unwrap(), paused, "paused = frozen");

    session.block_on(fabric.shutdown());
}

#[test]
fn stepping_is_deterministic() {
    let run = || {
        let kernel = SteppableKernel::new();
        let session = kernel.session();
        let fabric = session.block_on(build(&session));
        session.run_for(Duration::from_secs(2));
        let s = fabric.app_successes(AppId(1)).unwrap();
        session.block_on(fabric.shutdown());
        s
    };
    assert_eq!(run(), run(), "same stepping replays the identical fetch count");
}

#[test]
fn run_until_reaches_the_target_time() {
    let kernel = SteppableKernel::new();
    let session = kernel.session();
    let start = session.now_ns();
    let target = start + 5_000_000_000; // +5 s
    session.run_until(target);
    assert!(session.now_ns() >= target, "run_until advanced to the target virtual time");
    // Idempotent: already past target ⇒ no-op.
    let after = session.now_ns();
    session.run_until(target);
    assert_eq!(session.now_ns(), after);
}
