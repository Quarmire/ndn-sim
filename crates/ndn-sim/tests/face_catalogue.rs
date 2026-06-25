//! Per-face behavioral catalogue (ndn-lab, review gap 7): a SimFace now presents its face *type*
//! — the engine sees the right FaceKind/LinkType/send_mtu, and delivery is reliable-stream
//! (no loss, in-order) or lossy datagram per type. Previously every link was one wired type.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_transport::{FaceId, FaceKind, LinkType, Transport};
use ndn_sim::{FaceProfile, LinkConfig, Scenario, SimLink, WallClockKernel};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn profiles_report_distinct_engine_visible_behavior() {
    let (udp, _) = SimLink::pair_profiled(FaceId(1), FaceId(2), &FaceProfile::udp(), 8);
    assert_eq!(udp.kind(), FaceKind::Udp);
    assert_eq!(udp.send_mtu(), Some(1420));
    assert_eq!(udp.link_type(), LinkType::PointToPoint);

    let (tcp, _) = SimLink::pair_profiled(FaceId(3), FaceId(4), &FaceProfile::tcp(), 8);
    assert_eq!(tcp.kind(), FaceKind::Tcp);
    assert_eq!(tcp.send_mtu(), None, "stream — no per-frame MTU");

    let (ble, _) = SimLink::pair_profiled(FaceId(5), FaceId(6), &FaceProfile::ble(), 8);
    assert_eq!(ble.kind(), FaceKind::Bluetooth);
    assert_eq!(ble.send_mtu(), Some(245), "tiny ext-adv frames");

    let (nan, _) = SimLink::pair_profiled(FaceId(7), FaceId(8), &FaceProfile::nan(), 8);
    assert_eq!(nan.link_type(), LinkType::AdHoc);

    assert!(FaceProfile::from_name("quic").is_some());
    assert!(FaceProfile::from_name("nonsense").is_none());
}

#[tokio::test]
async fn reliable_stream_never_drops_and_stays_in_order() {
    // TCP profile with adversarial loss + jitter: a reliable stream ignores both.
    let profile = FaceProfile::tcp().with_link(LinkConfig {
        delay: Duration::from_millis(1),
        jitter: Duration::from_millis(5),
        loss_rate: 1.0, // would drop everything on a datagram face
        bandwidth_bps: 0,
    });
    let (a, b) = SimLink::pair_profiled(FaceId(1), FaceId(2), &profile, 64);

    for i in 0..10u8 {
        a.send_bytes(Bytes::copy_from_slice(&[i])).await.unwrap();
    }
    let mut got = Vec::new();
    for _ in 0..10 {
        got.push(b.recv_bytes().await.unwrap()[0]);
    }
    assert_eq!(got, (0..10).collect::<Vec<u8>>(), "reliable: all delivered, in order");
}

#[tokio::test]
async fn datagram_drops_under_loss() {
    let profile = FaceProfile::udp().with_link(LinkConfig {
        loss_rate: 1.0,
        ..LinkConfig::default()
    });
    let (a, b) = SimLink::pair_profiled(FaceId(1), FaceId(2), &profile, 64);
    for _ in 0..10 {
        a.send_bytes(Bytes::from_static(b"x")).await.unwrap();
    }
    // Datagram + 100% loss ⇒ nothing arrives.
    assert!(
        tokio::time::timeout(Duration::from_millis(100), b.recv_bytes()).await.is_err(),
        "datagram face drops under loss"
    );
}

#[tokio::test]
async fn scenario_typed_link_runs() {
    // A scenario declaring a TCP link between two nodes exchanges signed Data.
    let toml = r#"
[[nodes]]
label = "a"
[[nodes]]
label = "b"
[[links]]
a = 0
b = 1
face = "tcp"
[[routes]]
node = 0
prefix = "/app"
nexthop = 1
"#;
    let fabric = Scenario::from_toml(toml)
        .unwrap()
        .build(Arc::new(WallClockKernel::new()))
        .unwrap()
        .start()
        .await
        .unwrap();

    let producer = fabric
        .engine_of(ndn_sim::NodeId(1))
        .unwrap()
        .register_producer("/app", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r.respond((*i.name).clone(), bytes::Bytes::from_static(b"tcp")).await;
            })
            .await;
    });
    let mut consumer = fabric.engine_of(ndn_sim::NodeId(0)).unwrap().app_consumer(CancellationToken::new());
    let builder = InterestBuilder::new("/app/0".parse::<Name>().unwrap()).lifetime(Duration::from_secs(10));
    let data = consumer.fetch_with(builder).await.expect("fetch over the TCP-typed link");
    assert_eq!(data.content().map(|c| c.to_vec()).unwrap_or_default(), b"tcp");

    fabric.shutdown().await;
}
