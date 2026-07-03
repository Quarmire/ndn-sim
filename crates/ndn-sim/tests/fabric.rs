//! Slice-1 fabric tests (ndn-lab): the control plane (spawn / remove / connect / route /
//! topology) + the tracer, and an end-to-end Interest/Data exchange across two nodes.
//!
//! Security note: these use a node's *default* engine config, which installs a real
//! accept-all validator (`TrustSchema::accept_all`) — signatures are still cryptographically
//! verified (the producer's Data is DigestSha256-signed and the digest is checked); the
//! trust *schema* is permissive only because no trust context is configured. Nothing here
//! disables security; a scenario that wants to exercise trust configures a SecurityManager.

use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_sim::{EventKind, FabricControl, LinkConfig, NodeProfile, Simulation};
use tokio_util::sync::CancellationToken;

/// The slice-1 deliverable: a running fabric is controllable at runtime — spawn a node,
/// connect it, route through it, remove a node — and reports a consistent topology, with the
/// tracer capturing engine face events. No data exchange; this exercises the new fabric code.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fabric_control_spawn_connect_route_remove_and_topology() {
    let mut sim = Simulation::new();
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    sim.link(a, b, LinkConfig::lan());
    let fabric = sim.start().await.unwrap();

    // The fabric is drivable through the object-safe control trait (the seam GUI/MCP use).
    let ctrl: &dyn FabricControl = &fabric;
    assert_eq!(ctrl.nodes(), 2);

    assert_eq!(fabric.nodes(), 2);
    let topo = fabric.topology();
    assert_eq!(topo.nodes.len(), 2);
    assert_eq!(
        topo.links.len(),
        2,
        "one symmetric link = two directed faces"
    );

    // Live-spawn a third node, connect + route it through the running fabric.
    let c = fabric
        .spawn_node(NodeProfile::new("edge"))
        .await
        .expect("spawn");
    assert_eq!(fabric.nodes(), 3);
    fabric.connect(b, c, LinkConfig::lan()).expect("connect");
    fabric
        .route(b, &"/c".parse().unwrap(), c)
        .expect("route via fresh link");
    assert!(fabric.face_between(b, c).is_some());
    assert!(fabric.face_between(c, b).is_some());
    let topo = fabric.topology();
    assert_eq!(topo.nodes.len(), 3);
    assert_eq!(topo.links.len(), 4);
    assert!(
        topo.nodes.iter().any(|n| n.label == "edge"),
        "profile label kept"
    );

    // Remove a node: it and its links drop.
    fabric.remove_node(c).await.expect("remove");
    assert_eq!(fabric.nodes(), 2);
    assert!(fabric.face_between(b, c).is_none());

    // The tracer captured engine FaceUp events (links bring faces up) + control events.
    let events = fabric.tracer().events();
    assert!(
        events.iter().any(|e| e.kind == EventKind::FaceUp),
        "tracer must capture engine FaceUp events from links"
    );
    assert!(
        events
            .iter()
            .any(|e| e.kind == EventKind::Custom("node-spawn".into())),
        "tracer must capture the live spawn"
    );

    fabric.shutdown().await;
}

/// End-to-end: a consumer on node A fetches a name a producer serves on node B, across a
/// SimLink. Proves the fabric carries real Interest/Data through real engines, with the
/// producer's digest signature genuinely verified by A's validator.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_node_interest_data_roundtrip() {
    let mut sim = Simulation::new();
    let consumer_node = sim.add_node(EngineConfig::default());
    let producer_node = sim.add_node(EngineConfig::default());
    sim.link(consumer_node, producer_node, LinkConfig::lan());
    sim.add_route(consumer_node, "/app", producer_node);
    let fabric = sim.start().await.unwrap();

    // Producer on node B serves /app, echoing the request name with a fixed payload.
    let p_engine = fabric.engine_of(producer_node).unwrap();
    let producer = p_engine.register_producer("/app", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|interest, responder| async move {
                let _ = responder
                    .respond((*interest.name).clone(), bytes::Bytes::from_static(b"pong"))
                    .await;
            })
            .await;
    });
    // Let the serve loop reach its first recv before we send.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Consumer on node A fetches /app/ping; the Interest routes A→B, Data returns B→A.
    let c_engine = fabric.engine_of(consumer_node).unwrap();
    let mut consumer = c_engine.app_consumer(CancellationToken::new());
    let data = tokio::time::timeout(Duration::from_secs(2), consumer.fetch("/app/ping"))
        .await
        .expect("fetch did not time out")
        .expect("fetch ok");
    assert_eq!(
        data.content().map(|c| c.as_ref()),
        Some(&b"pong"[..]),
        "consumer received the producer's Data across the fabric"
    );

    fabric.shutdown().await;
}
