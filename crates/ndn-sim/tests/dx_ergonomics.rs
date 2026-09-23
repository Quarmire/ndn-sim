//! DX ergonomics (from real build-on-it feedback): the silent multi-app-face trap becomes legible
//! via `explain_route`, a typed `Strategy` fixes it, per-face `face_stats` answer "why didn't it
//! arrive", and `clock()` is a cheap capturable handle.

use std::sync::Arc;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{AppSpec, FaceKind, Simulation, Strategy};

/// Two producers on the same prefix on one node → two local app faces. Under best-route the
/// forwarder silently delivers each Interest to only one; `explain_route` flags exactly that.
#[tokio::test]
async fn explain_route_flags_the_silent_multi_app_face_trap() {
    let mut sim = Simulation::new();
    let n = sim.add_node(EngineConfig::default());
    sim.add_app(
        n,
        AppSpec::Producer {
            prefix: "/time".into(),
            content: Some("a".into()),
            freshness_ms: Some(1000),
        },
    );
    sim.add_app(
        n,
        AppSpec::Producer {
            prefix: "/time".into(),
            content: Some("b".into()),
            freshness_ms: Some(1000),
        },
    );
    let fabric = Arc::new(sim.start().await.unwrap());

    let ex = fabric
        .explain_route(n, &"/time/0".parse().unwrap())
        .unwrap();
    let app_faces = ex
        .nexthops
        .iter()
        .filter(|nh| nh.kind == FaceKind::App)
        .count();
    assert_eq!(
        app_faces, 2,
        "both producers registered a local app face: {ex:?}"
    );
    assert_eq!(ex.strategy, "best-route");
    assert!(
        ex.warning.is_some(),
        "the silent best-route trap is flagged: {ex:?}"
    );

    fabric.shutdown().await;
}

/// The typed `Strategy::Multicast` (no stringly-typed name) clears the trap: all local faces receive.
#[tokio::test]
async fn typed_multicast_strategy_clears_the_trap() {
    let mut sim = Simulation::new();
    let n = sim.add_node(EngineConfig::default());
    sim.add_app(
        n,
        AppSpec::Producer {
            prefix: "/time".into(),
            content: Some("a".into()),
            freshness_ms: Some(1000),
        },
    );
    sim.add_app(
        n,
        AppSpec::Producer {
            prefix: "/time".into(),
            content: Some("b".into()),
            freshness_ms: Some(1000),
        },
    );
    sim.add_strategy(n, "/time", Strategy::Multicast); // typed, not "multicast"
    let fabric = Arc::new(sim.start().await.unwrap());

    let ex = fabric
        .explain_route(n, &"/time/0".parse().unwrap())
        .unwrap();
    assert_eq!(ex.strategy, "multicast");
    assert!(
        ex.warning.is_none(),
        "multicast fans to all local faces, no trap: {ex:?}"
    );

    fabric.shutdown().await;
}

/// No FIB route → `explain_route` says so (Interests drop no-route), the #1 "recvs=0" cause.
#[tokio::test]
async fn explain_route_reports_no_route() {
    let mut sim = Simulation::new();
    let n = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());

    let ex = fabric
        .explain_route(n, &"/nowhere/0".parse().unwrap())
        .unwrap();
    assert!(ex.matched_prefix.is_none() && ex.nexthops.is_empty());
    assert!(
        ex.warning.as_deref().unwrap_or("").contains("no-route"),
        "{ex:?}"
    );

    fabric.shutdown().await;
}

/// `face_stats` exposes per-face counters classified by kind; `clock()` is a cheap, clonable
/// handle on the kernel's virtual time.
///
/// Runs on the VirtualKernel: under the default wall-clock kernel two successive reads differ by
/// nanoseconds, which failed on Linux CI (coarser macOS clocks hid it).
#[test]
fn face_stats_and_clock_are_readable() {
    ndn_sim::VirtualKernel::new().run(|k| async move {
        let mut sim = Simulation::new().kernel(k).without_radio_interference();
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        sim.link(a, b, ndn_sim::LinkConfig::lan());
        sim.add_route(a, "/demo", b);
        let fabric = Arc::new(sim.start().await.unwrap());

        // Node a has one link face toward b.
        let stats = fabric.face_stats(a).unwrap();
        assert!(
            stats
                .iter()
                .any(|s| s.kind == FaceKind::Link { toward: b.0 }),
            "a's face toward b is classified as a link: {stats:?}"
        );

        // A clone reads the same clock, and the handle advances exactly with simulated time.
        let clock = fabric.clock();
        let t0 = clock.now_ns();
        assert_eq!(clock.clone().now_ns(), t0, "clone reads the same clock");
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        assert_eq!(
            clock.now_ns() - t0,
            250_000_000,
            "the clock follows virtual time"
        );

        fabric.shutdown().await;
    });
}
