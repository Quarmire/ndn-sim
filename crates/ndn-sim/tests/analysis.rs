//! Causal analysis (axis 4): observability that *explains*. A drone flies behind a building, some
//! fetches fail, and `explain_link` says *why* — "line of sight blocked by an obstacle" — grounded
//! in the recorded radio evidence. Composes axes 2 (a property fails), 3 (LoS geometry + mobility),
//! and 4 (the causal explanation). Deterministic on DES.

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{
    AppId, AppSpec, DeliveryReason, DesKernel, LinkVerdict, MobilityTrace, NodeState, Obstacle,
    ObstructedPropagation, Position, RangeThreshold, SimKernel, Simulation, explain_link,
};

fn run() -> (u64, ndn_sim::Explanation) {
    DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        // A wall between the producer and the drone's outbound path (range never limits: 200 m).
        let wall = Obstacle::from_corners(Position::xyz(20.0, -20.0, 0.0), Position::xyz(25.0, 20.0, 30.0));
        let prop = ObstructedPropagation::new(
            Arc::new(RangeThreshold { range_m: 200.0, tx_power_dbm: 20.0 }),
            vec![wall],
        );
        let mut sim = Simulation::new().kernel(k).with_radio_medium(Arc::new(prop), 1);
        let prod = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let drone = sim.add_radio_node(EngineConfig::default(), Position::xy(10.0, 0.0));
        sim.add_app(prod, AppSpec::Producer { prefix: "/svc".into(), content: Some("x".into()), freshness_ms: None });
        sim.add_app(
            drone,
            AppSpec::Consumer { prefix: "/svc".into(), count: 20, interval_ms: 300, lifetime_ms: Some(300) },
        );
        sim.add_radio_route(drone, "/svc");
        let fabric = sim.start().await.unwrap();

        // Turn on causal capture, then fly the drone behind the wall and keep it there.
        let log = fabric.capture_radio().expect("radio medium present");
        let mut trace = MobilityTrace::default();
        trace.record(NodeState { node: drone, t_secs: 0.0, position: Position::xy(10.0, 0.0), velocity: None });
        trace.record(NodeState { node: drone, t_secs: 2.0, position: Position::xy(60.0, 0.0), velocity: None });
        trace.record(NodeState { node: drone, t_secs: 12.0, position: Position::xy(60.0, 0.0), velocity: None });
        fabric.install_trace(&trace);

        ndn_app::rt::sleep(Duration::from_secs(9)).await;
        let successes = fabric.app_successes(AppId(1)).unwrap_or(0);
        // "Why couldn't the drone reach the producer?" — over the recorded radio evidence.
        let explanation = explain_link(&log, drone, prod);
        fabric.shutdown().await;
        (successes, explanation)
    })
}

#[test]
fn explains_why_the_drone_lost_the_link() {
    let (successes, e) = run();
    // Axis 2: the building blocks delivery, so the drone does NOT complete all 20.
    assert!(successes < 20, "the building should block some fetches, got {successes}/20");
    // Axis 4: and we can say WHY, from the recorded evidence — not just that it failed.
    assert_eq!(
        e.dominant_cause,
        Some(DeliveryReason::Obstructed),
        "the dominant cause should be obstruction:\n{}",
        e.detail
    );
    assert!(
        matches!(e.verdict, LinkVerdict::Failed | LinkVerdict::Intermittent),
        "verdict {:?}",
        e.verdict
    );
    assert!(e.detail.contains("line of sight"), "human explanation mentions LoS: {}", e.detail);
}

#[test]
fn analysis_is_deterministic() {
    let a = run();
    let b = run();
    assert_eq!(a.0, b.0);
    assert_eq!(a.1.dominant_cause, b.1.dominant_cause);
    assert_eq!((a.1.attempts, a.1.delivered), (b.1.attempts, b.1.delivered));
}

/// The causal "why" surfaces through the ControlPlane (so it rides WS / NDN / MCP): enable radio
/// capture, run, then `SimQuery::Explain` returns a grounded Explanation.
#[test]
fn explain_query_answers_through_the_control_plane() {
    use ndn_sim::{ControlPlane, SimQuery, SimResponse};
    let (successes, verdict_ok) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let wall = Obstacle::from_corners(Position::xyz(20.0, -20.0, 0.0), Position::xyz(25.0, 20.0, 30.0));
        let prop = ObstructedPropagation::new(
            Arc::new(RangeThreshold { range_m: 200.0, tx_power_dbm: 20.0 }),
            vec![wall],
        );
        let mut sim = Simulation::new().kernel(k).with_radio_medium(Arc::new(prop), 1);
        let prod = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let drone = sim.add_radio_node(EngineConfig::default(), Position::xy(60.0, 0.0)); // already behind
        sim.add_app(prod, AppSpec::Producer { prefix: "/svc".into(), content: Some("x".into()), freshness_ms: None });
        sim.add_app(drone, AppSpec::Consumer { prefix: "/svc".into(), count: 10, interval_ms: 300, lifetime_ms: Some(300) });
        sim.add_radio_route(drone, "/svc");
        let fabric = Arc::new(sim.start().await.unwrap());
        let control = ControlPlane::new(Arc::clone(&fabric));
        control.enable_radio_capture();
        ndn_app::rt::sleep(Duration::from_secs(4)).await;
        let successes = fabric.app_successes(AppId(1)).unwrap_or(0);
        let resp = control.query(SimQuery::Explain { from: 1, to: 0 });
        let verdict_ok = matches!(
            resp,
            SimResponse::Explanation(e) if e.dominant_cause == Some(DeliveryReason::Obstructed)
        );
        fabric.shutdown().await;
        (successes, verdict_ok)
    });
    assert_eq!(successes, 0, "fully behind the wall, nothing gets through");
    assert!(verdict_ok, "the control-plane Explain query names obstruction as the cause");
}

/// Capture a run where the drone either stays clear of the wall or flies behind it.
fn capture(behind: bool) -> ndn_sim::RunCapture {
    DesKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
        let wall = Obstacle::from_corners(Position::xyz(20.0, -20.0, 0.0), Position::xyz(25.0, 20.0, 30.0));
        let prop = ObstructedPropagation::new(
            Arc::new(RangeThreshold { range_m: 200.0, tx_power_dbm: 20.0 }),
            vec![wall],
        );
        let mut sim = Simulation::new().kernel(k).with_radio_medium(Arc::new(prop), 1);
        let prod = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let drone = sim.add_radio_node(EngineConfig::default(), Position::xy(10.0, 0.0));
        sim.add_app(prod, AppSpec::Producer { prefix: "/svc".into(), content: Some("x".into()), freshness_ms: None });
        sim.add_app(drone, AppSpec::Consumer { prefix: "/svc".into(), count: 15, interval_ms: 300, lifetime_ms: Some(300) });
        sim.add_radio_route(drone, "/svc");
        let fabric = sim.start().await.unwrap();
        let log = fabric.capture_radio().unwrap();
        let mut trace = MobilityTrace::default();
        trace.record(NodeState { node: drone, t_secs: 0.0, position: Position::xy(10.0, 0.0), velocity: None });
        // "clear" flies up (x stays 10, never crosses the wall at x∈20..25); "behind" flies to x=60.
        let (x, y) = if behind { (60.0, 0.0) } else { (10.0, 60.0) };
        trace.record(NodeState { node: drone, t_secs: 2.0, position: Position::xy(x, y), velocity: None });
        trace.record(NodeState { node: drone, t_secs: 12.0, position: Position::xy(x, y), velocity: None });
        fabric.install_trace(&trace);
        ndn_app::rt::sleep(Duration::from_secs(6)).await;
        let cap = fabric.capture_run(Some(&log));
        fabric.shutdown().await;
        cap
    })
}

#[test]
fn cross_run_diff_pinpoints_and_explains_the_regression() {
    use ndn_sim::diff_runs;
    let baseline = capture(false); // clear flight
    let candidate = capture(true); // flies behind the building
    let diff = diff_runs(&baseline, &candidate, 0.1);

    assert!(!diff.identical, "the runs differ");
    // The drone fetched fewer segments in the candidate.
    assert!(
        diff.app_deltas.iter().any(|a| a.candidate < a.baseline),
        "app fetched fewer: {:?}",
        diff.app_deltas
    );
    // The diff pinpoints the degraded radio link AND explains it (obstruction).
    let link = diff
        .link_deltas
        .iter()
        .find(|l| l.from == 1 && l.to == 0)
        .expect("the drone→producer link should show a delta");
    assert!(link.candidate_rate < link.baseline_rate, "delivery rate dropped: {link:?}");
    assert_eq!(
        link.candidate_cause,
        Some(DeliveryReason::Obstructed),
        "the candidate's failures are explained as obstruction:\n{}",
        diff.summary
    );
    assert!(diff.summary.contains("line of sight"), "summary explains why: {}", diff.summary);
}

#[test]
fn run_capture_json_round_trips() {
    let cap = capture(true);
    let again = ndn_sim::RunCapture::from_json(&cap.to_json().unwrap()).unwrap();
    let d = ndn_sim::diff_runs(&cap, &again, 0.0);
    assert!(d.identical, "a capture equals itself after JSON round-trip");
}

/// The control plane surfaces the packet-level radio flow (`recent_radio` / `why_did`), not just
/// lifecycle events — observability that shows the medium.
#[test]
fn control_plane_surfaces_radio_flow() {
    use ndn_sim::ControlPlane;
    let n = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let wall = Obstacle::from_corners(Position::xyz(20.0, -20.0, 0.0), Position::xyz(25.0, 20.0, 30.0));
        let prop = ObstructedPropagation::new(
            Arc::new(RangeThreshold { range_m: 200.0, tx_power_dbm: 20.0 }),
            vec![wall],
        );
        let mut sim = Simulation::new().kernel(k).with_radio_medium(Arc::new(prop), 1);
        let prod = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let drone = sim.add_radio_node(EngineConfig::default(), Position::xy(60.0, 0.0));
        sim.add_app(prod, AppSpec::Producer { prefix: "/svc".into(), content: Some("x".into()), freshness_ms: None });
        sim.add_app(drone, AppSpec::Consumer { prefix: "/svc".into(), count: 8, interval_ms: 300, lifetime_ms: Some(300) });
        sim.add_radio_route(drone, "/svc");
        let fabric = Arc::new(sim.start().await.unwrap());
        let control = ControlPlane::new(Arc::clone(&fabric));
        control.enable_radio_capture();
        ndn_app::rt::sleep(Duration::from_secs(3)).await;
        let radio = control.recent_radio(50);
        fabric.shutdown().await;
        radio.len()
    });
    assert!(n > 0, "radio delivery decisions are recorded and surfaced");
}
