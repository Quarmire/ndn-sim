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
    AppSpec, DesKernel, MobilityTrace, NodeState, Position, RangeThreshold, ScriptedSource,
    SimKernel, Simulation,
};
use tokio_util::sync::CancellationToken;

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
