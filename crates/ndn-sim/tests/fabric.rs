//! Slice-1 fabric tests (ndn-lab): the control plane (spawn / remove / connect / route /
//! topology) + the tracer, and an end-to-end Interest/Data exchange across two nodes.
//!
//! Security note: these use a node's *default* profile, `SecurityProfile::Default` with no
//! security manager, which fails closed: key-signed Data crossing a link is refused
//! `untrusted-root`. The producers here answer DigestSha256-signed Data, whose digest the
//! validator checks; nothing disables security. A scenario that exercises trust gives its nodes
//! anchors, or chooses `AcceptSigned`/`Disabled` explicitly (`NodeProfile::with_security_profile`).

use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::name;
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
    let producer = p_engine.register_producer(name!("/app"), CancellationToken::new());
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
    let data = tokio::time::timeout(Duration::from_secs(2), consumer.fetch(name!("/app/ping")))
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

/// A consumer on `consumer` fetches `/app/ping`, which a producer on another node answers with
/// Data signed by a key nobody certified, across a production (UDP, non-local) link.
async fn fetch_key_signed_across_a_link(
    consumer: NodeProfile,
) -> Result<ndn_packet::Data, ndn_app::AppError> {
    use ndn_packet::SignatureType;
    use ndn_security::{Ed25519Signer, Signer};

    let mut sim = Simulation::new();
    let consumer_node = sim.add_node_profile(consumer);
    let producer_node = sim.add_node(EngineConfig::default());
    sim.link(consumer_node, producer_node, LinkConfig::lan());
    sim.add_route(consumer_node, "/app", producer_node);
    let fabric = sim.start().await.unwrap();

    let p_engine = fabric.engine_of(producer_node).unwrap();
    let producer = p_engine.register_producer(name!("/app"), CancellationToken::new());
    tokio::spawn(async move {
        let signer = Ed25519Signer::from_seed(&[3; 32], name!("/app/KEY/k"));
        let _ = producer
            .serve(move |interest, responder| {
                let wire = ndn_packet::encode::DataBuilder::new((*interest.name).clone(), b"pong")
                    .sign_sync(
                        SignatureType::SignatureEd25519,
                        Some(signer.key_name()),
                        |region| signer.sign_sync(region).unwrap(),
                    );
                async move {
                    let _ = responder.respond_bytes(wire).await;
                }
            })
            .await;
    });
    tokio::time::sleep(Duration::from_millis(20)).await;

    let c_engine = fabric.engine_of(consumer_node).unwrap();
    let mut consumer = c_engine.app_consumer(CancellationToken::new());
    let got = tokio::time::timeout(Duration::from_secs(2), consumer.fetch(name!("/app/ping")))
        .await
        .expect("answered (Data or refusal) before the timeout");
    fabric.shutdown().await;
    got
}

/// A plain node is `Default` with no security manager: it fails closed, refusing key-signed
/// Data from a link `untrusted-root` at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plain_node_refuses_key_signed_data_from_a_link() {
    let got = fetch_key_signed_across_a_link(NodeProfile::new("consumer")).await;
    assert!(
        matches!(
            got,
            Err(ndn_app::AppError::Refused {
                reason: ndn_packet::Refusal::UntrustedRoot
            })
        ),
        "got {got:?}"
    );
}

/// A node whose profile disables validation explicitly takes the same Data.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_with_validation_disabled_takes_key_signed_data_from_a_link() {
    let got = fetch_key_signed_across_a_link(
        NodeProfile::new("consumer").with_security_profile(ndn_security::SecurityProfile::Disabled),
    )
    .await
    .expect("Data delivered");
    assert_eq!(got.content().map(|c| c.as_ref()), Some(&b"pong"[..]));
}
