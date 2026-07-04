//! Mobility-driven IP re-routing (Tier-B, the MANET/VANET/FANET regime): node movement makes links
//! form and break (unit-disk-graph connectivity), and the routing protocol re-converges to adapt —
//! deterministic on DES.

use std::sync::Arc;
use std::time::Duration;

use ndn_sim::{DesKernel, FaceProfile, IpNetwork, LinkConfig, Position, ShortestPath, SimKernel};

/// Three nodes, radio range 60 m. As they move, the reachable topology changes and shortest-path
/// routing re-converges: A→C goes via relay B, then C is stranded when B flies off, then A→C becomes
/// a direct 1-hop link when C moves into range (lower RTT).
#[test]
fn routing_adapts_to_node_movement() {
    let range = 60.0;
    let (via_relay, isolated, direct, rtt_relay, rtt_direct) =
        DesKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
            let rt = k.runtime();
            let prof = FaceProfile::internal().with_link(LinkConfig::lan());

            // Phase 1: A(0) — B(1) — C(2) in a line; A↔C are out of range.
            let p1 = vec![Position::xy(0.0, 0.0), Position::xy(50.0, 0.0), Position::xy(110.0, 0.0)];
            let net = IpNetwork::from_positions(rt, p1, range, &prof, &ShortestPath);
            let s1 = net
                .node(0)
                .ping(net.addr(2), 4, 16, Duration::from_millis(2), Duration::from_millis(300))
                .await;

            // Phase 2: B flies far away — with no relay and A↔C still out of range, C is isolated.
            net.reconnect(
                &[Position::xy(0.0, 0.0), Position::xy(0.0, 500.0), Position::xy(110.0, 0.0)],
                range,
                &ShortestPath,
            );
            let s2 = net
                .node(0)
                .ping(net.addr(2), 4, 16, Duration::from_millis(2), Duration::from_millis(200))
                .await;

            // Phase 3: C moves next to A — a direct 1-hop link forms; routing uses it.
            net.reconnect(
                &[Position::xy(0.0, 0.0), Position::xy(0.0, 500.0), Position::xy(50.0, 0.0)],
                range,
                &ShortestPath,
            );
            let s3 = net
                .node(0)
                .ping(net.addr(2), 4, 16, Duration::from_millis(2), Duration::from_millis(300))
                .await;

            (s1.received, s2.received, s3.received, s1.mean_rtt_ms(), s3.mean_rtt_ms())
        });

    assert!(via_relay >= 3, "phase 1: A→C delivered via relay B ({via_relay})");
    assert_eq!(isolated, 0, "phase 2: B flew off, C is unreachable");
    assert!(direct >= 3, "phase 3: C in range, direct delivery ({direct})");
    assert!(
        rtt_direct < rtt_relay,
        "the direct 1-hop path has lower RTT than the 2-hop relay: {rtt_direct} vs {rtt_relay}"
    );
}

/// Hands-free: a background router reads the World's live mobility and re-converges on its own. Node
/// 1 flies away from node 0 (LinearMobility); once it passes out of radio range the link breaks and
/// the route disappears — no manual reconnect.
#[test]
fn world_driven_router_tracks_mobility() {
    use ndn_sim::{LinearMobility, NodeId, World};
    use tokio_util::sync::CancellationToken;

    let (near, far) = DesKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let prof = FaceProfile::internal().with_link(LinkConfig::lan());

        // World: node 0 static at origin; node 1 starts 30 m away and flies off at 20 m/s.
        let world = Arc::new(World::new());
        world.place(NodeId(0), Position::xy(0.0, 0.0));
        world.set_mobility(
            NodeId(1),
            Arc::new(LinearMobility { start: Position::xy(30.0, 0.0), velocity: (20.0, 0.0, 0.0) }),
        );

        let net = Arc::new(IpNetwork::from_positions(
            Arc::clone(&rt),
            vec![Position::xy(0.0, 0.0), Position::xy(30.0, 0.0)],
            60.0,
            &prof,
            &ShortestPath,
        ));
        net.spawn_router(
            Arc::clone(&world),
            60.0,
            Duration::from_millis(200),
            Arc::new(ShortestPath),
            CancellationToken::new(),
        );

        // In range at t≈0.
        let near = net
            .node(0)
            .ping(net.addr(1), 3, 16, Duration::from_millis(2), Duration::from_millis(200))
            .await;
        // Let it fly out of range (past 60 m ⇒ after ~1.5 s).
        ndn_app::rt::sleep(Duration::from_secs(3)).await;
        let far = net
            .node(0)
            .ping(net.addr(1), 3, 16, Duration::from_millis(2), Duration::from_millis(200))
            .await;

        (near.received, far.received)
    });
    assert!(near >= 2, "delivered while node 1 was in range: {near}");
    assert_eq!(far, 0, "node 1 flew out of range; the router dropped the broken link: {far}");
}
