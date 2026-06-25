//! Slice-3 integration: a [`World`] declared on the [`Simulation`] builder rides onto the
//! running fabric, where a [`WirelessMedium`] does position-driven, range-limited broadcast.
//! (Wiring this medium *into* an engine face is slice 4 — the named-radio face.)

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{
    NodeId, Position, RangeThreshold, Simulation, WaypointMobility, WirelessMedium, World,
};

#[tokio::test]
async fn fabric_carries_world_and_medium_fans_out_by_range() {
    let world = World::new().with_grid_cell(50.0);
    world.place(NodeId(0), Position::xy(0.0, 0.0));
    world.place(NodeId(1), Position::xy(40.0, 0.0)); // in range (100 m)
    world.place(NodeId(2), Position::xy(400.0, 0.0)); // out of range

    let mut sim = Simulation::new().world(world);
    let _a = sim.add_node(EngineConfig::default());
    let _b = sim.add_node(EngineConfig::default());
    let _c = sim.add_node(EngineConfig::default());
    let fabric = sim.start().await.unwrap();

    // The declared world is reachable on the live fabric.
    let world = fabric.world();
    let medium = WirelessMedium::new(
        world,
        Arc::new(RangeThreshold { range_m: 100.0, tx_power_dbm: 20.0 }),
        0,
    );
    let mut near = medium.attach(NodeId(1));
    let mut far = medium.attach(NodeId(2));

    let hit = medium.transmit(NodeId(0), bytes::Bytes::from_static(b"beacon"), 0);
    assert_eq!(hit.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![NodeId(1)]);

    assert_eq!(
        tokio::time::timeout(Duration::from_millis(50), near.recv())
            .await
            .unwrap()
            .unwrap()
            .bytes,
        &b"beacon"[..]
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), far.recv()).await.is_err(),
        "out-of-range node hears nothing"
    );

    fabric.shutdown().await;
}

/// A scripted (waypoint) mover starts unreachable, then arrives into range — the medium's
/// per-transmit snapshot tracks it. Deterministic time so this is reproducible.
#[tokio::test(start_paused = true)]
async fn waypoint_mover_comes_into_range() {
    let world = World::new();
    world.place(NodeId(0), Position::xy(0.0, 0.0));
    world.set_mobility(
        NodeId(1),
        Arc::new(WaypointMobility {
            waypoints: vec![
                (0.0, Position::xy(300.0, 0.0)), // far
                (10.0, Position::xy(0.0, 0.0)),  // arrives at the origin by t=10s
            ],
        }),
    );
    let medium = WirelessMedium::new(
        Arc::new(world),
        Arc::new(RangeThreshold { range_m: 100.0, tx_power_dbm: 20.0 }),
        0,
    );
    medium.attach(NodeId(1));

    // t=0s: at 300 m ⇒ silent.
    assert!(medium.transmit(NodeId(0), bytes::Bytes::from_static(b"a"), 0).is_empty());
    // t=8s: interpolated to 300·(1 − 0.8) = 60 m ⇒ in range.
    let hit = medium.transmit(NodeId(0), bytes::Bytes::from_static(b"b"), 8_000_000_000);
    assert_eq!(hit.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![NodeId(1)]);
}
