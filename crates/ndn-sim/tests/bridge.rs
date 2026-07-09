//! Slice-9 integration (ndn-lab): the interop bridge. An *external* forwarder (standing in for
//! NFD / NDNts / a phone app) exchanges a **signed** Interest/Data with a simulated fabric node
//! over the **real NDN wire** (localhost UDP) — the fabric becomes a mixed network of simulated
//! nodes + a foreign endpoint. Wall-clock kernel (a real socket = real time).

use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::{EngineBuilder, EngineConfig};
use ndn_face::net::UdpFace;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{NodeId, Simulation};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn external_forwarder_fetches_from_a_simulated_node_over_udp() {
    // The simulated fabric with one node that will serve /ext.
    let mut sim = Simulation::new();
    let node = sim.add_node(EngineConfig::default());
    let fabric = sim.start().await.unwrap();

    // An external forwarder (not part of the fabric) — as if NFD/NDNts on another host.
    let (external, ext_handle) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .unwrap();

    // Pre-bind both UDP sockets so each can target the other's ephemeral port.
    let sock_fabric = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_ext = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_fabric = sock_fabric.local_addr().unwrap();
    let addr_ext = sock_ext.local_addr().unwrap();

    // Bridge: a real UDP face on the fabric node, pointing at the external forwarder.
    let _bridge_face = fabric
        .bridge_udp_socket(node, sock_fabric, addr_ext)
        .unwrap();

    // The external forwarder's UDP face back toward the fabric node, + a route over it.
    let ext_face = external.faces().alloc_id();
    external.add_face(
        UdpFace::from_socket(ext_face, sock_ext, addr_fabric),
        CancellationToken::new(),
    );
    external
        .fib()
        .add_nexthop(&"/ext".parse::<Name>().unwrap(), ext_face, 10);

    // The simulated node serves /ext.
    let producer = fabric
        .engine_of(node)
        .unwrap()
        .register_producer("/ext", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r
                    .respond((*i.name).clone(), bytes::Bytes::from_static(b"world"))
                    .await;
            })
            .await;
    });

    // The external forwarder's consumer fetches across the sim boundary over real UDP.
    let mut consumer = external.app_consumer(CancellationToken::new());
    let builder = InterestBuilder::new("/ext/hello".parse::<Name>().unwrap())
        .lifetime(Duration::from_secs(10));
    let data = consumer
        .fetch_with(builder)
        .await
        .expect("fetch over the UDP bridge");
    assert_eq!(
        data.content().map(|c| c.to_vec()).unwrap_or_default(),
        b"world"
    );

    ext_handle.shutdown().await;
    fabric.shutdown().await;
}

#[tokio::test]
async fn bridge_udp_listener_requires_a_fixed_port() {
    let mut sim = Simulation::new();
    let node = sim.add_node(EngineConfig::default());
    let fabric = sim.start().await.unwrap();
    // An ephemeral (:0) listener is rejected — peers must know where to dial in.
    let err = fabric.bridge_udp_listener(
        node,
        "127.0.0.1:0".parse().unwrap(),
        CancellationToken::new(),
    );
    assert!(err.is_err());
    // A non-existent node is rejected too.
    assert!(
        fabric
            .bridge_udp_listener(
                NodeId(999),
                "127.0.0.1:6363".parse().unwrap(),
                CancellationToken::new()
            )
            .is_err()
    );
    fabric.shutdown().await;
}

/// `[[bridges]]` in a Scenario: the external peer is *declared*, not hand-wired. The scenario's
/// node bridges (with a route + an MTU clamp) to an external forwarder; a fetch crosses the wire.
/// Also checks the fence: a virtual-time scenario declaring bridges must refuse to apply them.
#[tokio::test]
async fn scenario_declared_bridge_attaches_and_routes() {
    use ndn_sim::Scenario;

    // The external endpoint (as if ndnd/NFD on a known port) serving /ext.
    let (external, ext_handle) = EngineBuilder::new(EngineConfig::default())
        .build()
        .await
        .unwrap();
    let sock_ext = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_ext = sock_ext.local_addr().unwrap();
    let producer = external.register_producer("/ext", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r
                    .respond((*i.name).clone(), bytes::Bytes::from_static(b"declared"))
                    .await;
            })
            .await;
    });

    // The scenario declares the bridge: fixed local port so the peer can answer.
    let local_port = 17431u16;
    let scenario = Scenario::from_toml(&format!(
        r#"
        [[nodes]]
        label = "edge"
        [[bridges]]
        node  = 0
        local = "127.0.0.1:{local_port}"
        peer  = "127.0.0.1:{}"
        route = "/ext"
        mtu   = 1200
        "#,
        addr_ext.port()
    ))
    .unwrap();
    let fabric = scenario
        .build(std::sync::Arc::new(ndn_sim::WallClockKernel::new()))
        .unwrap()
        .start()
        .await
        .unwrap();
    scenario.apply_bridges(&fabric).await.unwrap();

    // The external forwarder's face back toward the declared local port.
    let ext_face = external.faces().alloc_id();
    external.add_face(
        UdpFace::from_socket(
            ext_face,
            sock_ext,
            format!("127.0.0.1:{local_port}").parse().unwrap(),
        ),
        CancellationToken::new(),
    );

    // Fetch across the declared bridge (route came from the TOML).
    let mut consumer = fabric
        .engine_of(NodeId(0))
        .unwrap()
        .app_consumer(CancellationToken::new());
    let data = consumer
        .fetch_with(
            InterestBuilder::new("/ext/hello".parse::<Name>().unwrap())
                .lifetime(Duration::from_secs(10)),
        )
        .await
        .expect("fetch over the scenario-declared bridge");
    assert_eq!(data.content().map(|c| c.to_vec()).unwrap_or_default(), b"declared");

    // The fence: a virtual-time scenario declaring bridges refuses to apply them
    // (checked on the scenario's kernel spec, before any face is touched).
    let bad = Scenario::from_toml(
        r#"
        [kernel]
        kind = "virtual"
        [[nodes]]
        label = "n"
        [[bridges]]
        node = 0
        local = "127.0.0.1:0"
        peer = "127.0.0.1:6363"
        "#,
    )
    .unwrap();
    let err = bad.apply_bridges(&fabric).await;
    assert!(err.is_err(), "virtual-time bridges must be refused");

    ext_handle.shutdown().await;
    fabric.shutdown().await;
}
