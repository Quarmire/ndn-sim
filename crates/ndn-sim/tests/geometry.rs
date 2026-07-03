//! Geometry-aware radio under motion (axis 3, 3c) — the capstone where co-simulation (3a/3b) and the
//! line-of-sight backend (3c) compose: a drone flies clear → behind a building → clear, and its NDN
//! link **drops and recovers** purely from geometry. Deterministic on DES.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{
    AppSpec, DesKernel, MobilityTrace, NodeState, Obstacle, ObstructedPropagation, Position,
    RangeThreshold, SimKernel, Simulation,
};
use tokio_util::sync::CancellationToken;

/// Fly the drone clear → behind a wall → clear; fetch in each phase. Returns `(clear1, blocked, clear2)`.
fn los_flight() -> (bool, bool, bool) {
    DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        // A wall at x∈[20,25], y∈[-20,20], tall — well within radio range (200 m), so ONLY line of
        // sight decides delivery, never distance.
        let wall = Obstacle::from_corners(
            Position::xyz(20.0, -20.0, 0.0),
            Position::xyz(25.0, 20.0, 30.0),
        );
        let prop = ObstructedPropagation::new(
            Arc::new(RangeThreshold {
                range_m: 200.0,
                tx_power_dbm: 20.0,
            }),
            vec![wall],
        );
        let mut sim = Simulation::new()
            .kernel(k)
            .with_radio_medium(Arc::new(prop), 1);
        let prod = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let cons = sim.add_radio_node(EngineConfig::default(), Position::xy(10.0, 0.0));
        sim.add_app(
            prod,
            AppSpec::Producer {
                prefix: "/svc".into(),
                content: Some("los".into()),
                freshness_ms: None,
            },
        );
        let fabric = sim.start().await.unwrap();

        // Flight: clear (10,0) → behind the wall (40,0) → clear again by climbing over in y (40,60):
        // the segment (0,0)→(40,60) misses the wall's y-span.
        let mut trace = MobilityTrace::default();
        trace.record(NodeState {
            node: cons,
            t_secs: 0.0,
            position: Position::xy(10.0, 0.0),
            velocity: None,
        });
        trace.record(NodeState {
            node: cons,
            t_secs: 10.0,
            position: Position::xy(40.0, 0.0),
            velocity: None,
        });
        trace.record(NodeState {
            node: cons,
            t_secs: 20.0,
            position: Position::xy(40.0, 60.0),
            velocity: None,
        });
        fabric.install_trace(&trace);

        fabric
            .route_over_radio(cons, &"/svc".parse::<Name>().unwrap())
            .unwrap();
        let mut consumer = fabric
            .engine_of(cons)
            .unwrap()
            .app_consumer(CancellationToken::new());
        let interest = |i: u64| {
            let name: Name = format!("/svc/{i}").parse().unwrap();
            InterestBuilder::new(name).lifetime(Duration::from_secs(3))
        };

        // Phase 1 — clear line of sight.
        let clear1 = consumer.fetch_with(interest(0)).await.is_ok();
        // Phase 2 — behind the wall.
        ndn_app::rt::sleep(Duration::from_secs(10)).await;
        let blocked = consumer.fetch_with(interest(1)).await.is_ok();
        // Phase 3 — climbed clear of the wall.
        ndn_app::rt::sleep(Duration::from_secs(12)).await;
        let clear2 = consumer.fetch_with(interest(2)).await.is_ok();

        fabric.shutdown().await;
        (clear1, blocked, clear2)
    })
}

#[test]
fn line_of_sight_drops_and_recovers_the_link_under_motion() {
    let (clear1, blocked, clear2) = los_flight();
    assert!(clear1, "clear line of sight: fetch succeeds");
    assert!(
        !blocked,
        "behind the building: the link is blocked, fetch fails"
    );
    assert!(clear2, "flown clear of the building: the link recovers");
}

#[test]
fn los_flight_is_deterministic() {
    assert_eq!(
        los_flight(),
        los_flight(),
        "geometry-driven link changes replay identically on DES"
    );
}
