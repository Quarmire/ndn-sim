//! Measured workloads (Tier-B): traffic-pattern apps record protocol-neutral FlowStats — RTT, loss,
//! and goodput — the benchmark foundation both the NDN plane and (later) the in-sim IP plane share.

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{AppId, AppSpec, DesKernel, LinkConfig, SimKernel, Simulation, TrafficPattern};

fn producer(prefix: &str, payload_len: usize) -> AppSpec {
    AppSpec::Producer {
        prefix: prefix.into(),
        content: Some("x".repeat(payload_len)),
        freshness_ms: Some(4000),
    }
}

/// A CBR traffic source over a 50 ms WAN link: every request round-trips ~100 ms, so mean RTT,
/// goodput, and byte totals are all measured — not just a success count.
#[test]
fn cbr_traffic_source_measures_rtt_and_throughput() {
    let stats = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new().kernel(k);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        sim.link(a, b, LinkConfig::wan()); // 50 ms one-way
        sim.add_route(a, "/demo", b);
        sim.add_app(b, producer("/demo", 100)); // app 0
        sim.add_app(
            a,
            AppSpec::TrafficSource {
                prefix: "/demo".into(),
                pattern: TrafficPattern::Cbr { interval_ms: 10 },
                count: 20,
                lifetime_ms: Some(2000),
            },
        ); // app 1
        let fabric = sim.start().await.unwrap();
        ndn_app::rt::sleep(Duration::from_secs(4)).await;
        let s = fabric.flow_stats(AppId(1)).unwrap();
        fabric.shutdown().await;
        s
    });

    assert_eq!(stats.sent, 20, "issued every request: {stats:?}");
    assert!(stats.received >= 18, "most round-tripped: {stats:?}");
    // ~100 ms RTT over a 50 ms one-way link (allow slack for processing).
    let rtt = stats.mean_rtt_ms();
    assert!((90.0..300.0).contains(&rtt), "mean RTT ≈ 100 ms, got {rtt}");
    assert!(stats.throughput_bps() > 0.0, "goodput measured: {stats:?}");
    assert!(stats.bytes >= 100 * 18, "content bytes accumulated: {}", stats.bytes);
}

/// A Poisson source draws the same request stream twice under the same seed (reproducible on DES).
#[test]
fn poisson_source_is_deterministic() {
    let run = || {
        DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
            let mut sim = Simulation::new().kernel(k);
            let a = sim.add_node(EngineConfig::default());
            let b = sim.add_node(EngineConfig::default());
            sim.link(a, b, LinkConfig::lan());
            sim.add_route(a, "/p", b);
            sim.add_app(b, producer("/p", 20));
            sim.add_app(
                a,
                AppSpec::TrafficSource {
                    prefix: "/p".into(),
                    pattern: TrafficPattern::Poisson { mean_interval_ms: 20, seed: 7 },
                    count: 30,
                    lifetime_ms: Some(1000),
                },
            );
            let fabric = sim.start().await.unwrap();
            ndn_app::rt::sleep(Duration::from_secs(5)).await;
            let s = fabric.flow_stats(AppId(1)).unwrap();
            fabric.shutdown().await;
            (s.sent, s.received, s.bytes, s.rtt_sum_ns)
        })
    };
    assert_eq!(run(), run(), "a Poisson workload replays identically on DES");
}

/// A lossy link surfaces as loss in the flow stats (single-shot fetches don't retransmit).
#[test]
fn lossy_link_shows_loss() {
    let stats = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new().kernel(k);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        sim.link(
            a,
            b,
            LinkConfig { delay: Duration::from_millis(5), loss_rate: 0.4, ..Default::default() },
        );
        sim.add_route(a, "/lossy", b);
        sim.add_app(b, producer("/lossy", 10));
        sim.add_app(
            a,
            AppSpec::TrafficSource {
                prefix: "/lossy".into(),
                pattern: TrafficPattern::Cbr { interval_ms: 5 },
                count: 30,
                lifetime_ms: Some(200),
            },
        );
        let fabric = sim.start().await.unwrap();
        ndn_app::rt::sleep(Duration::from_secs(30)).await;
        let s = fabric.flow_stats(AppId(1)).unwrap();
        fabric.shutdown().await;
        s
    });

    assert!(stats.sent >= 28, "most requests issued: {stats:?}");
    assert!(stats.lost > 0, "the 40%-loss link produced timeouts: {stats:?}");
    assert!(stats.loss_rate() > 0.0 && stats.loss_rate() < 1.0, "loss rate in (0,1): {stats:?}");
}

/// A benchmark gate: a ValidationSpec asserts a workload's mean RTT and delivery via Flow probes —
/// `ndn-lab check` territory, and the shape an NDN-vs-IP comparison will gate on.
#[test]
fn flow_probes_gate_a_workload() {
    use ndn_sim::{ValidationSpec, run_validation};
    let spec = ValidationSpec::from_toml(
        r#"
duration_ms = 3000
kernels = ["des"]

[scenario.kernel]
kind = "des"

[[scenario.nodes]]
label = "consumer"
[[scenario.nodes.apps]]
app = "traffic_source"
prefix = "/demo"
count = 15
[scenario.nodes.apps.pattern]
pattern = "cbr"
interval_ms = 20

[[scenario.nodes]]
label = "producer"
[[scenario.nodes.apps]]
app = "producer"
prefix = "/demo"
content = "hello"
freshness_ms = 4000

[[scenario.links]]
a = 0
b = 1
delay_ms = 10

[[scenario.routes]]
node = 0
prefix = "/demo"
nexthop = 1

[[properties]]
name = "mean RTT under 100 ms"
probe = { kind = "flow", app = 0, field = "mean_rtt_ms" }
cmp = "lt"
value = 100.0

[[properties]]
name = "delivered at least 12 of 15"
probe = { kind = "flow", app = 0, field = "received" }
cmp = "ge"
value = 12.0
"#,
    )
    .unwrap();
    let report = run_validation(&spec).unwrap();
    assert!(report.passed, "the workload met its RTT + delivery gates: {report:?}");
}
