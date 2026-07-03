//! Determinism gate (ndn-lab): the standing reproducibility invariant, asserted — not just
//! observed on a toy case. A multi-node scenario (real `ForwarderEngine`s, concurrent traffic,
//! link delays, a metric gauge emitter) is run **twice** under fresh `VirtualKernel`s, and the
//! full ordered output — metric series + tracer event timeline — must be **byte-identical**.
//!
//! Because it drives real engines, this is an *engine*-determinism gate: any `Instant::now()` /
//! `SystemTime::now()` that sneaks past the `Runtime` seam into the forwarding path, or any
//! same-virtual-instant ordering that isn't stable, shows up here as a diff. Wire it into CI on
//! both repos so the invariant fails loudly when it rots, rather than degrading silently.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{
    LinkConfig, MetricsLog, MetricsSample, SimKernel, Simulation, VirtualKernel, compare_metrics,
};
use tokio_util::sync::CancellationToken;

/// Full observable output of one run: the metric series + the ordered tracer event timeline
/// (node, kind, virtual timestamp).
type RunTrace = (Vec<MetricsSample>, Vec<(usize, String, u64)>);

/// A 3-node line A—B—C: A and C both fetch /svc from B concurrently (same instant), while a
/// 1 s gauge emitter samples for 4 virtual seconds. Real signed Data, real verification.
async fn scenario(kernel: Arc<dyn SimKernel>) -> RunTrace {
    let mut sim = Simulation::new().kernel(kernel);
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    let c = sim.add_node(EngineConfig::default());
    let link = LinkConfig {
        delay: Duration::from_millis(10),
        ..LinkConfig::default()
    };
    sim.link(a, b, link.clone());
    sim.link(c, b, link);
    sim.add_route(a, "/svc", b);
    sim.add_route(c, "/svc", b);
    let fabric = sim.start().await.unwrap();

    let producer = fabric
        .engine_of(b)
        .unwrap()
        .register_producer("/svc", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r
                    .respond((*i.name).clone(), bytes::Bytes::from_static(b"ok"))
                    .await;
            })
            .await;
    });

    let log = MetricsLog::new();
    let cancel = CancellationToken::new();
    fabric.spawn_gauge_emitter(Duration::from_secs(1), Arc::clone(&log), cancel.clone());

    // A and C fetch the same name at the same virtual instant — concurrent arrivals at B.
    let mut ca = fabric
        .engine_of(a)
        .unwrap()
        .app_consumer(CancellationToken::new());
    let mut cc = fabric
        .engine_of(c)
        .unwrap()
        .app_consumer(CancellationToken::new());
    let mk = || {
        InterestBuilder::new("/svc/x".parse::<Name>().unwrap()).lifetime(Duration::from_secs(20))
    };
    let (ra, rc) = tokio::join!(ca.fetch_with(mk()), cc.fetch_with(mk()));
    ra.unwrap();
    rc.unwrap();

    tokio::time::sleep(Duration::from_millis(4500)).await;
    cancel.cancel();

    let mut events: Vec<(usize, String, u64)> = fabric
        .tracer()
        .events()
        .iter()
        .map(|e| (e.node, e.kind.to_string(), e.timestamp_us))
        .collect();
    events.sort();
    let samples = log.samples();
    fabric.shutdown().await;
    (samples, events)
}

#[test]
fn scenario_replays_byte_identical_under_virtual_time() {
    let first = VirtualKernel::new().run(scenario);
    let second = VirtualKernel::new().run(scenario);

    // Metric series identical (the determinism oracle)…
    let diff = compare_metrics(&first.0, &second.0);
    assert!(
        diff.identical,
        "metric series diverged: {:?}",
        diff.divergences
    );

    // …and the ordered tracer timeline identical (catches same-instant ordering drift that a
    // metrics-only compare would miss).
    assert_eq!(
        first.1, second.1,
        "tracer event timeline diverged across runs"
    );

    // Sanity: the run actually did something (not vacuously identical).
    assert!(!first.0.is_empty(), "gauge emitter produced samples");
    assert!(first.0.iter().any(|s| s.in_interests > 0), "traffic flowed");
}
