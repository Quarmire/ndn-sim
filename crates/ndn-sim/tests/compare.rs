//! NDN-vs-IP comparison (Tier-B, IP-4): the same scenario through both planes, compared with the
//! same FlowStats — and the marquee NDN advantage, in-network caching, made concrete.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{
    AppId, AppSpec, ComparisonSpec, DesKernel, FaceProfile, IpNetwork, Ipv4, LinkConfig, NodeId,
    SimKernel, Simulation, TrafficPattern, compare_ndn_vs_ip,
};
use tokio_util::sync::CancellationToken;

/// Both planes deliver the same CBR workload over the same 4-node line, and the harness reports
/// each side's FlowStats + wire bytes.
#[test]
fn ndn_and_ip_deliver_the_same_workload() {
    let spec = ComparisonSpec {
        n: 4,
        links: vec![(0, 1), (1, 2), (2, 3)],
        source: 0,
        dest: 3,
        pattern: TrafficPattern::Cbr { interval_ms: 10 },
        count: 10,
        payload_len: 64,
        link_delay: Duration::from_millis(2),
        duration_ms: 3000,
    };
    let cmp = compare_ndn_vs_ip(&spec);
    println!("{}", cmp.summary());

    assert!(cmp.ndn.received >= 8, "NDN delivered the workload: {:?}", cmp.ndn);
    assert!(cmp.ip.received >= 8, "IP delivered the workload: {:?}", cmp.ip);
    assert!(cmp.ndn.mean_rtt_ms() > 0.0 && cmp.ip.mean_rtt_ms() > 0.0, "both measured RTT");
    assert!(cmp.ndn_wire_bytes > 0 && cmp.ip_wire_bytes > 0, "both measured wire bytes");
}

/// The caching contrast: two consumers fetch the SAME content through a shared relay. NDN serves the
/// second consumer from the relay's cache — the producer sees each object once. IP has no such cache,
/// so the server answers every request. Concretely: NDN producer load ≈ half of IP server load.
#[test]
fn ndn_caching_halves_producer_load_vs_ip() {
    const K: u64 = 10;

    // --- NDN: producer(0) — relay(1) — {consumerA(2), consumerB(3)} ---
    let ndn_producer_served = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new().kernel(k);
        let p = sim.add_node(EngineConfig::default());
        let r = sim.add_node(EngineConfig::default());
        let ca = sim.add_node(EngineConfig::default());
        let cb = sim.add_node(EngineConfig::default());
        sim.link(p, r, LinkConfig::lan());
        sim.link(r, ca, LinkConfig::lan());
        sim.link(r, cb, LinkConfig::lan());
        sim.add_app(
            p,
            AppSpec::Producer {
                prefix: "/demo".into(),
                content: Some("payload".into()),
                freshness_ms: Some(60_000), // stays cacheable for the whole run
            },
        );
        sim.add_route(ca, "/demo", r);
        sim.add_route(cb, "/demo", r);
        sim.add_route(r, "/demo", p);
        let fabric = sim.start().await.unwrap();

        // Consumer A fetches /demo/0..K (warms the relay cache), then B fetches the SAME names.
        let mut cons_a = fabric.engine_of(ca).unwrap().app_consumer(CancellationToken::new());
        let mut cons_b = fabric.engine_of(cb).unwrap().app_consumer(CancellationToken::new());
        for consumer in [&mut cons_a, &mut cons_b] {
            for i in 0..K {
                let name = format!("/demo/{i}").parse::<Name>().unwrap();
                let _ = consumer
                    .fetch_with(InterestBuilder::new(name).lifetime(Duration::from_secs(2)))
                    .await;
            }
        }
        // The producer app is AppId(0) (first app spawned).
        let served = fabric.app_successes(AppId(0)).unwrap_or(0);
        fabric.shutdown().await;
        served
    });

    // --- IP: server(0) — relay(1) — {client(2), client(3)}, both ping the server ---
    let ip_server_delivered = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let prof = FaceProfile::internal().with_link(LinkConfig::lan());
        let net = IpNetwork::from_links(rt, 4, &[(0, 1), (1, 2), (2, 3)], &prof);
        let server = net.addr(0);
        for client in [2usize, 3] {
            let _ = net
                .node(client)
                .ping(server, K as u32, 7, Duration::from_millis(2), Duration::from_secs(2))
                .await;
        }
        // Requests that reached the server (no cache exists, so every request is served).
        let _ = NodeId(0); // (silence unused import in some builds)
        let _ = Ipv4::new(0, 0, 0, 0);
        net.node(0).stats().delivered
    });

    // NDN: the producer served each of the K objects ~once (cache hit for consumer B).
    assert!(
        ndn_producer_served <= K + 2,
        "NDN producer served each object ~once (cache), got {ndn_producer_served}"
    );
    // IP: the server answered every request from both clients (no cache) — ~2K.
    assert!(
        ip_server_delivered >= 2 * K - 2,
        "IP server answered every request, got {ip_server_delivered}"
    );
    // The whole point: NDN's cache roughly halves producer load versus IP.
    assert!(
        (ndn_producer_served as f64) < 0.75 * (ip_server_delivered as f64),
        "NDN caching cut producer load below IP: NDN={ndn_producer_served} IP={ip_server_delivered}"
    );
}
