//! Slice-3 integration: a [`World`] declared on the [`Simulation`] builder rides onto the
//! running fabric, where the shared radio medium ([`RadioBus`]) does position-driven,
//! range-limited broadcast against it — and tracks scripted motion per transmit.

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{NodeId, Position, RadioBus, RangeThreshold, Simulation, WaypointMobility, World};

fn range_100m() -> Arc<RangeThreshold> {
    Arc::new(RangeThreshold {
        range_m: 100.0,
        tx_power_dbm: 20.0,
    })
}

/// The in-range receivers of one transmit (delivered or not — the propagation verdict).
fn heard_by(out: &[(NodeId, f64, bool)]) -> Vec<NodeId> {
    let mut v: Vec<NodeId> = out.iter().map(|(n, _, _)| *n).collect();
    v.sort_by_key(|n| n.0);
    v
}

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

    // The declared world is reachable on the live fabric, and a medium built over it sees the
    // declared placement.
    let bus = RadioBus::new(fabric.world(), range_100m(), 0, 1);
    let mut near = bus.attach(NodeId(1));
    let mut far = bus.attach(NodeId(2));

    // MCS 0 at −4 dBm RSSI (40 m on a 100 m disc) is far above every decode threshold.
    let out = bus.transmit(NodeId(0), 0, bytes::Bytes::from_static(b"beacon"), 0);
    assert_eq!(heard_by(&out), vec![NodeId(1)]);

    assert_eq!(
        tokio::time::timeout(Duration::from_millis(50), near.recv())
            .await
            .unwrap()
            .unwrap()
            .bytes,
        &b"beacon"[..]
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), far.recv())
            .await
            .is_err(),
        "out-of-range node hears nothing"
    );

    fabric.shutdown().await;
}

/// A scripted (waypoint) mover starts unreachable, then arrives into range — the medium's
/// per-transmit world snapshot tracks it. Deterministic time so this is reproducible.
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
    let bus = RadioBus::new(Arc::new(world), range_100m(), 0, 1);
    bus.attach(NodeId(1));

    // t=0s: at 300 m ⇒ silent.
    let out = bus.transmit(NodeId(0), 0, bytes::Bytes::from_static(b"a"), 0);
    assert!(heard_by(&out).is_empty());
    // t=8s: interpolated to 300·(1 − 0.8) = 60 m ⇒ in range.
    let out = bus.transmit(NodeId(0), 0, bytes::Bytes::from_static(b"b"), 8_000_000_000);
    assert_eq!(heard_by(&out), vec![NodeId(1)]);
}
