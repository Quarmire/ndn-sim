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

/// Distance-vector routing (RIP/DSDV-class) picks the shortest path — a square with a diagonal
/// routes 0→2 over the 1-hop diagonal (RTT ≈ 2 ms), not the 2-hop rim.
#[test]
fn distance_vector_routes_over_the_shortcut() {
    use ndn_sim::{DistanceVector, IpNetwork};
    let (recv, rtt) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let prof = FaceProfile::internal().with_link(LinkConfig::lan());
        let net = IpNetwork::from_links_with(
            rt,
            4,
            &[(0, 1), (1, 2), (2, 3), (3, 0), (0, 2)],
            None,
            &prof,
            &DistanceVector::default(),
        );
        let stats = net
            .node(0)
            .ping(net.addr(2), 6, 16, Duration::from_millis(2), Duration::from_secs(1))
            .await;
        (stats.received, stats.mean_rtt_ms())
    });
    assert!(recv >= 5, "distance-vector delivered: {recv}");
    assert!(rtt < 3.5, "DV took the 1-hop diagonal (≈2 ms), got {rtt} ms");
}

/// GPSR greedy geographic routing delivers along a line purely by node position (VANET/FANET-class).
#[test]
fn geographic_routing_delivers_by_position() {
    use ndn_sim::{GreedyGeographic, IpNetwork, Position};
    let recv = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let prof = FaceProfile::internal().with_link(LinkConfig::lan());
        let positions = vec![
            Position::xy(0.0, 0.0),
            Position::xy(10.0, 0.0),
            Position::xy(20.0, 0.0),
            Position::xy(30.0, 0.0),
        ];
        let net = IpNetwork::from_links_with(
            rt,
            4,
            &[(0, 1), (1, 2), (2, 3)],
            Some(positions),
            &prof,
            &GreedyGeographic,
        );
        let stats = net
            .node(0)
            .ping(net.addr(3), 6, 16, Duration::from_millis(2), Duration::from_secs(1))
            .await;
        stats.received
    });
    assert!(recv >= 5, "GPSR greedy delivered along the line by position: {recv}");
}

/// Reactive routing (AODV/DSR, RFC 3561/4728): discovers routes on demand yet delivers over the same
/// min-hop path a proactive protocol would — and for a single flow on the line its modelled control
/// overhead is a fraction of link-state's periodic flooding (the on-demand advantage).
#[test]
fn reactive_routing_delivers_and_costs_less_for_one_flow() {
    use ndn_sim::{Aodv, IpNetwork, RoutingAlgorithm, ShortestPath, TopologyView};
    let (recv, aodv_overhead, sp_overhead) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let prof = FaceProfile::internal().with_link(LinkConfig::lan());
        let links = [(0, 1), (1, 2), (2, 3), (3, 4)];
        let net = IpNetwork::from_links_with(rt, 5, &links, None, &prof, &Aodv);
        let stats = net
            .node(0)
            .ping(net.addr(4), 8, 32, Duration::from_millis(2), Duration::from_secs(1))
            .await;
        // Same graph, one active flow: contrast the control overhead of reactive vs proactive.
        let view = TopologyView::from_links(5, &links);
        let one_flow = 1;
        (stats.received, Aodv.control_overhead(&view, one_flow), ShortestPath.control_overhead(&view, one_flow))
    });
    assert!(recv >= 7, "AODV discovered the route and delivered end-to-end: {recv}");
    assert!(
        aodv_overhead < sp_overhead,
        "one flow ⇒ on-demand AODV chatter ({aodv_overhead} B) < proactive link-state ({sp_overhead} B)"
    );
}

/// IP runs over LoRa: a multi-km link that only a high spreading factor can close delivers a flow,
/// and its per-packet latency is dominated by LoRa's very long airtime (unlike Wi-Fi).
#[test]
fn ip_runs_over_a_long_range_lora_link() {
    use ndn_sim::{IpNetwork, LoraLinkConfig, Position, ShortestPath, SpreadingFactor};
    let (recv, rtt_ms) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        // Two nodes 3 km apart — SF12 (below-noise) closes it; range gate 10 km.
        let positions = vec![Position::xy(0.0, 0.0), Position::xy(3000.0, 0.0)];
        let cfg = LoraLinkConfig::new(10_000.0, SpreadingFactor::Sf12);
        let net = IpNetwork::from_positions_lora(rt, positions, &cfg, &ShortestPath);
        let stats = net
            .node(0)
            .ping(net.addr(1), 6, 16, Duration::from_secs(5), Duration::from_secs(30))
            .await;
        (stats.received, stats.mean_rtt_ms())
    });
    assert!(recv >= 4, "IP delivered over the 3 km LoRa link: {recv}");
    // LoRa SF12 airtime is hundreds of ms each way ⇒ RTT is far beyond any Wi-Fi link.
    assert!(rtt_ms > 500.0, "LoRa's long airtime dominates the round-trip: {rtt_ms} ms");
}

/// GPSR perimeter recovery delivers across a concave void that pure greedy geographic drops: source 0
/// is a local minimum (both neighbours farther from the dest), so `GreedyGeographic` never routes it,
/// but `Gpsr` routes around the void via the right-hand rule.
#[test]
fn gpsr_delivers_across_a_void_that_greedy_drops() {
    use ndn_sim::{Gpsr, GreedyGeographic, IpNetwork, Position};
    let (greedy_recv, gpsr_recv) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let prof = FaceProfile::internal().with_link(LinkConfig::lan());
        let links = [(0, 1), (0, 2), (1, 3), (3, 4)];
        let positions = vec![
            Position::xy(0.0, 0.0),
            Position::xy(-1.0, -1.0),
            Position::xy(1.0, -1.0),
            Position::xy(-1.0, 10.0),
            Position::xy(0.0, 10.0),
        ];
        // Greedy-only: 0 stalls at the void ⇒ no delivery to node 4.
        let g = IpNetwork::from_links_with(Arc::clone(&rt), 5, &links, Some(positions.clone()), &prof, &GreedyGeographic);
        let greedy = g.node(0).ping(g.addr(4), 4, 32, Duration::from_millis(2), Duration::from_millis(300)).await.received;
        // GPSR: perimeter recovery routes around the void.
        let net = IpNetwork::from_links_with(rt, 5, &links, Some(positions), &prof, &Gpsr);
        let gpsr = net.node(0).ping(net.addr(4), 4, 32, Duration::from_millis(2), Duration::from_secs(1)).await.received;
        (greedy, gpsr)
    });
    assert_eq!(greedy_recv, 0, "pure greedy geographic drops at the void");
    assert!(gpsr_recv >= 3, "GPSR perimeter recovery delivers around the void: {gpsr_recv}");
}

/// Adaptive routing: a diamond has two disjoint paths 0→3. Shortest-path routes via node 1; cutting
/// the 1–3 link drops the flow (stale route), and reroute_with recomputes over the surviving
/// topology so delivery resumes via node 2. The core of routing that reacts to topology change.
#[test]
fn ip_reroutes_around_a_cut_link() {
    use ndn_sim::{IpNetwork, ShortestPath};
    let (before, during, after) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let prof = FaceProfile::internal().with_link(LinkConfig::lan());
        let net = IpNetwork::from_links(rt, 4, &[(0, 1), (1, 3), (0, 2), (2, 3)], &prof);
        let dst = net.addr(3);
        let before = net
            .node(0)
            .ping(dst, 3, 16, Duration::from_millis(2), Duration::from_millis(300))
            .await
            .received;

        net.set_link(1, 3, false); // cut the active path — routes are now stale
        let during = net
            .node(0)
            .ping(dst, 3, 16, Duration::from_millis(2), Duration::from_millis(300))
            .await
            .received;

        net.reroute_with(&ShortestPath); // adapt to the new topology
        let after = net
            .node(0)
            .ping(dst, 3, 16, Duration::from_millis(2), Duration::from_millis(300))
            .await
            .received;

        (before, during, after)
    });
    assert!(before >= 2, "delivered before the cut: {before}");
    assert_eq!(during, 0, "cut link + stale route drops the flow");
    assert!(after >= 2, "re-routing around the cut restored delivery: {after}");
}
