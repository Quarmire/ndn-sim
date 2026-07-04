//! In-sim IP plane (Tier-B, slice 1): a multi-hop IP line forwards packets by destination and a
//! ping round-trips end-to-end, measured with the same FlowStats the NDN plane uses — deterministic
//! on DES. This is the substrate for apples-to-apples NDN-vs-IP comparison.

use std::sync::Arc;
use std::time::Duration;

use ndn_sim::{DesKernel, FaceProfile, IpNode, Ipv4, LinkConfig, SimKernel, ip_link};

/// consumer(10.0.0.1) — relay(.2) — producer(.3): ping across two hops; the relay forwards both the
/// requests and the echoed replies; RTT ≈ 4·link-delay.
#[test]
fn ip_line_forwards_and_pings_end_to_end() {
    let (stats, relay_forwarded) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let (a1, a2, a3) = (Ipv4::new(10, 0, 0, 1), Ipv4::new(10, 0, 0, 2), Ipv4::new(10, 0, 0, 3));
        let prof = FaceProfile::internal().with_link(LinkConfig::lan()); // 1 ms datagram link

        let (f12, f21) = ip_link(Arc::clone(&rt), &prof, 256, 0);
        let (f23, f32) = ip_link(Arc::clone(&rt), &prof, 256, 1);

        // node 1: default route toward node 2.
        let mut n1 = IpNode::new(a1, Arc::clone(&rt));
        let n1_to2 = n1.attach(f12);
        n1.route(Ipv4::new(0, 0, 0, 0), 0, n1_to2);

        // node 2 (relay): /32 routes to each endpoint.
        let mut n2 = IpNode::new(a2, Arc::clone(&rt));
        let n2_to1 = n2.attach(f21);
        let n2_to3 = n2.attach(f23);
        n2.route(a1, 32, n2_to1);
        n2.route(a3, 32, n2_to3);

        // node 3: default route back toward node 2.
        let mut n3 = IpNode::new(a3, Arc::clone(&rt));
        let n3_to2 = n3.attach(f32);
        n3.route(Ipv4::new(0, 0, 0, 0), 0, n3_to2);

        let n1 = n1.start();
        let n2 = n2.start();
        let _n3 = n3.start();

        let stats = n1
            .ping(a3, 10, 64, Duration::from_millis(5), Duration::from_secs(1))
            .await;
        (stats, n2.stats().forwarded)
    });

    assert_eq!(stats.sent, 10);
    assert!(stats.received >= 9, "pings echoed end-to-end over IP forwarding: {stats:?}");
    // 2 hops each way over a 1 ms link → RTT ≈ 4 ms.
    let rtt = stats.mean_rtt_ms();
    assert!((2.0..20.0).contains(&rtt), "IP round-trip measured, got {rtt} ms");
    // The relay forwarded every request AND every reply (≈ 2 per successful ping).
    assert!(relay_forwarded >= 18, "relay forwarded requests + replies: {relay_forwarded}");
}

/// A no-route destination is dropped (dropped_no_route), and delivery is deterministic across runs.
#[test]
fn ip_no_route_drops_and_is_deterministic() {
    let run = || {
        DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
            let rt = k.runtime();
            let (a1, a2) = (Ipv4::new(10, 0, 0, 1), Ipv4::new(10, 0, 0, 2));
            let prof = FaceProfile::internal().with_link(LinkConfig::lan());
            let (f12, f21) = ip_link(Arc::clone(&rt), &prof, 256, 0);

            let mut n1 = IpNode::new(a1, Arc::clone(&rt));
            let via = n1.attach(f12);
            // Only a route to a2 — pinging a3 has no route at node 2.
            n1.route(Ipv4::new(0, 0, 0, 0), 0, via);

            let mut n2 = IpNode::new(a2, Arc::clone(&rt));
            n2.attach(f21);
            // node 2 has NO route to 10.0.0.9 → it drops.

            let n1 = n1.start();
            let n2 = n2.start();
            let stats = n1
                .ping(Ipv4::new(10, 0, 0, 9), 5, 16, Duration::from_millis(2), Duration::from_millis(200))
                .await;
            (stats.received, stats.lost, n2.stats().dropped_no_route)
        })
    };
    let (received, lost, dropped) = run();
    assert_eq!(received, 0, "unreachable destination is never answered");
    assert_eq!(lost, 5, "every ping timed out");
    assert!(dropped >= 5, "the relay dropped the unroutable packets: {dropped}");
    assert_eq!(run(), (received, lost, dropped), "IP forwarding replays identically on DES");
}

/// An IpNetwork auto-installs shortest-path routes (BFS) — a 5-node line pings end-to-end with no
/// hand-wired routing. RTT ≈ 8·link-delay (4 hops each way).
#[test]
fn ip_network_auto_routes_a_line() {
    use ndn_sim::IpNetwork;
    let (recv, rtt_ms) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let prof = FaceProfile::internal().with_link(LinkConfig::lan());
        let net = IpNetwork::from_links(rt, 5, &[(0, 1), (1, 2), (2, 3), (3, 4)], &prof);
        let stats = net
            .node(0)
            .ping(net.addr(4), 8, 32, Duration::from_millis(2), Duration::from_secs(1))
            .await;
        (stats.received, stats.mean_rtt_ms())
    });
    assert!(recv >= 7, "auto-routed line delivered end-to-end: {recv}");
    assert!((5.0..25.0).contains(&rtt_ms), "RTT ≈ 8 ms over 4 hops, got {rtt_ms}");
}

/// `run_flow` drives the IP plane with the SAME TrafficPattern the NDN plane uses; and an IpNetwork
/// builds straight from a `Scenario`'s graph (the same-topology bridge for NDN-vs-IP).
#[test]
fn ip_run_flow_over_scenario_graph() {
    use ndn_sim::{IpNetwork, TrafficPattern, topo};
    let recv = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let prof = FaceProfile::internal().with_link(LinkConfig::lan());
        let scenario = topo::line(4); // 4-node line as a Scenario
        let net = IpNetwork::from_scenario(rt, &scenario, &prof);
        let stats = net
            .node(0)
            .run_flow(net.addr(3), TrafficPattern::Cbr { interval_ms: 5 }, 10, 16, Duration::from_secs(1))
            .await;
        stats.received
    });
    assert!(recv >= 9, "run_flow over a scenario-built IP network delivered: {recv}");
}
