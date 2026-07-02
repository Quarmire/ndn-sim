//! Co-simulation (axis 3, slice 3a): a live [`MobilitySource`] drives the World and records a
//! [`MobilityTrace`]; the recorded trace replays **deterministically** on DES and drives real radio
//! forwarding. This is the live→record→replay bridge — the whole point of the seam.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{
    AppSpec, DesKernel, Lockstep, MobilityTrace, NodeId, NodeState, Position, RangeThreshold,
    ScriptedSource, SimKernel, Simulation, SteppableSource,
};
use tokio_util::sync::CancellationToken;

/// A stepped physics source: forward-Euler integration of a node under constant acceleration. Its
/// state is carried between steps (not a closed form) — exactly what a lockstep engine looks like.
struct AccelSource {
    node: NodeId,
    pos: Position,
    vel: [f64; 3],
    accel: [f64; 3],
    t_prev: f64,
    until: f64,
}

impl SteppableSource for AccelSource {
    fn advance_to(&mut self, t_secs: f64) -> Vec<NodeState> {
        let dt = t_secs - self.t_prev;
        self.t_prev = t_secs;
        for i in 0..3 {
            self.vel[i] += self.accel[i] * dt;
        }
        self.pos = Position::xyz(
            self.pos.x + self.vel[0] * dt,
            self.pos.y + self.vel[1] * dt,
            self.pos.z + self.vel[2] * dt,
        );
        vec![NodeState { node: self.node, t_secs, position: self.pos, velocity: Some(self.vel) }]
    }
    fn is_done(&self, t_secs: f64) -> bool {
        t_secs >= self.until
    }
}

/// A live scripted source flies a radio node from origin outward; the driver applies each state to
/// the World and records the stream. Deterministic on the DES kernel.
#[test]
fn live_source_drives_the_world_and_records_a_trace() {
    let (final_pos, recorded) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new()
            .kernel(k)
            .with_radio_medium(Arc::new(RangeThreshold { range_m: 50.0, tx_power_dbm: 20.0 }), 1);
        let a = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let fabric = sim.start().await.unwrap();

        let source = ScriptedSource::new(vec![
            NodeState { node: a, t_secs: 1.0, position: Position::xy(100.0, 0.0), velocity: None },
            NodeState { node: a, t_secs: 2.0, position: Position::xy(200.0, 0.0), velocity: None },
        ]);
        let trace = fabric
            .drive_mobility(Box::new(source), Duration::from_millis(100), CancellationToken::new())
            .await;

        let pos = fabric.world().snapshot(5.0).position(a).unwrap();
        fabric.shutdown().await;
        (pos, trace.states.len())
    });

    assert_eq!(recorded, 2, "both scripted states were applied + recorded");
    assert_eq!(final_pos, Position::xy(200.0, 0.0), "the world tracked the live source");
}

/// Replay a recorded flight (consumer flies out of radio range mid-run) and fetch before and after.
/// Returns `(near_ok, far_ok)`.
fn replay_flight() -> (bool, bool) {
    DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new()
            .kernel(k)
            .with_radio_medium(Arc::new(RangeThreshold { range_m: 50.0, tx_power_dbm: 20.0 }), 1);
        let prod = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let cons = sim.add_radio_node(EngineConfig::default(), Position::xy(10.0, 0.0));
        sim.add_app(
            prod,
            AppSpec::Producer { prefix: "/svc".into(), content: Some("hi".into()), freshness_ms: None },
        );
        let fabric = sim.start().await.unwrap();

        // A recorded flight: the consumer starts in range (10 m) and flies to 200 m (out of range).
        let mut trace = MobilityTrace::default();
        trace.record(NodeState { node: cons, t_secs: 0.0, position: Position::xy(10.0, 0.0), velocity: None });
        trace.record(NodeState { node: cons, t_secs: 30.0, position: Position::xy(200.0, 0.0), velocity: None });
        fabric.install_trace(&trace);

        fabric.route_over_radio(cons, &"/svc".parse::<Name>().unwrap()).unwrap();
        let mut consumer = fabric.engine_of(cons).unwrap().app_consumer(CancellationToken::new());

        // In range at t≈0 → the producer hears the Interest and answers.
        let near = consumer
            .fetch_with(InterestBuilder::new("/svc/0".parse::<Name>().unwrap()).lifetime(Duration::from_secs(4)))
            .await
            .is_ok();

        // Fly out of range (advance virtual time past the last trace sample).
        ndn_app::rt::sleep(Duration::from_secs(35)).await;
        let far = consumer
            .fetch_with(InterestBuilder::new("/svc/1".parse::<Name>().unwrap()).lifetime(Duration::from_secs(4)))
            .await
            .is_ok();

        fabric.shutdown().await;
        (near, far)
    })
}

#[test]
fn replayed_trace_drives_radio_forwarding() {
    let (near, far) = replay_flight();
    assert!(near, "in range at the start of the flight, the fetch succeeds");
    assert!(!far, "out of range after the flight, the fetch fails");
}

#[test]
fn replayed_trace_is_deterministic() {
    assert_eq!(replay_flight(), replay_flight(), "a recorded flight replays identically on DES");
}

/// A LOCKSTEP stepped physics source (mode C) drives the World deterministically — the sim owns the
/// clock, so no record→replay is needed for reproducibility. Proves the seam a stepped engine
/// (Gazebo / Bevy-headless) plugs into.
#[test]
fn lockstep_stepped_source_drives_the_world_deterministically() {
    let run = || {
        DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
            let mut sim = Simulation::new()
                .kernel(k)
                .with_radio_medium(Arc::new(RangeThreshold { range_m: 50.0, tx_power_dbm: 20.0 }), 1);
            let n = sim.add_radio_node(ndn_engine::builder::EngineConfig::default(), Position::ORIGIN);
            let fabric = sim.start().await.unwrap();
            let source = Lockstep::new(AccelSource {
                node: n,
                pos: Position::ORIGIN,
                vel: [0.0, 0.0, 0.0],
                accel: [2.0, 0.0, 0.0], // accelerate along +x
                t_prev: 0.0,
                until: 5.0,
            });
            let trace = fabric
                .drive_mobility(Box::new(source), Duration::from_millis(100), CancellationToken::new())
                .await;
            let pos = fabric.world().snapshot(6.0).position(n).unwrap();
            fabric.shutdown().await;
            (pos.x, trace.states.len())
        })
    };
    let (x, states) = run();
    // Under a=2 m/s² for ~5 s the node accelerates well past 20 m along +x (Euler-approx).
    assert!(x > 20.0, "stepped physics advanced the node along +x, got x={x}");
    assert!(states > 10, "the stepped run recorded a trace");
    assert_eq!(run(), (x, states), "the lockstep run is deterministic on DES");
}

/// A `Scenario` can reference a recorded trace file declaratively; `build` installs it as
/// deterministic per-node motion. This is the CLI bridge (`ndn-lab check` gates a replayed flight).
#[test]
fn scenario_mobility_trace_installs_replay() {
    use ndn_sim::Scenario;

    // Write a trace where node 0 flies (0,0) → (100,0) over 10 s.
    let mut trace = MobilityTrace::default();
    trace.record(NodeState { node: ndn_sim::NodeId(0), t_secs: 0.0, position: Position::xy(0.0, 0.0), velocity: None });
    trace.record(NodeState { node: ndn_sim::NodeId(0), t_secs: 10.0, position: Position::xy(100.0, 0.0), velocity: None });
    let path = std::env::temp_dir().join("ndn-lab-test-trace.json");
    std::fs::write(&path, trace.to_json().unwrap()).unwrap();

    let toml = format!(
        r#"
mobility_trace = "{}"
[kernel]
kind = "des"
[[nodes]]
label = "a"
[[nodes]]
label = "b"
"#,
        path.display()
    );
    let scenario = Scenario::from_toml(&toml).unwrap();
    let pos = DesKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
        let fabric = scenario.build(k).unwrap().start().await.unwrap();
        let p = fabric.world().snapshot(5.0).position(ndn_sim::NodeId(0)).unwrap();
        fabric.shutdown().await;
        p
    });
    // Midpoint of the flight at t=5 s.
    assert_eq!(pos, Position::xy(50.0, 0.0), "the declarative trace drives the node's position");
}

/// The world-state history sampler captures a run's trajectory (positions over time) — the archive
/// for correlating failures against where a node was, or for replay.
#[test]
fn position_sampler_archives_the_trajectory() {
    let (samples, moved) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new()
            .kernel(k)
            .with_radio_medium(Arc::new(RangeThreshold { range_m: 200.0, tx_power_dbm: 20.0 }), 1);
        let node = sim.add_radio_node(ndn_engine::builder::EngineConfig::default(), Position::xy(0.0, 0.0));
        let fabric = sim.start().await.unwrap();
        // Fly the node from origin to (100,0).
        let mut trace = MobilityTrace::default();
        trace.record(NodeState { node, t_secs: 0.0, position: Position::xy(0.0, 0.0), velocity: None });
        trace.record(NodeState { node, t_secs: 4.0, position: Position::xy(100.0, 0.0), velocity: None });
        fabric.install_trace(&trace);

        let cancel = CancellationToken::new();
        let history = fabric.spawn_position_sampler(Duration::from_millis(200), cancel.clone());
        ndn_app::rt::sleep(Duration::from_secs(4)).await;
        cancel.cancel();
        let (samples, delta) = {
            let h = history.lock().unwrap();
            let first = h.states.first().map(|s| s.position.x).unwrap_or(0.0);
            let last = h.states.last().map(|s| s.position.x).unwrap_or(0.0);
            (h.states.len(), last - first)
        };
        fabric.shutdown().await;
        (samples, delta)
    });
    assert!(samples > 5, "the sampler recorded a trajectory, got {samples} samples");
    assert!(moved > 50.0, "the archived trajectory shows the node moving along +x, moved {moved}");
}
