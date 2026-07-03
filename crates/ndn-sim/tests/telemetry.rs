//! Slice-5 integration (ndn-lab): telemetry under the [`VirtualKernel`] — the gauge emitter
//! samples engine metrics at deterministic *virtual* instants, and OTLP span timestamps come
//! from the virtual clock. Both replay bit-for-bit. Security unchanged (real verification).

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_observability::{SpanPublisher, SpanRetention};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{
    LinkConfig, MetricsLog, MetricsSample, SimKernel, SimSpanEmitter, Simulation, VirtualKernel,
};
use tokio_util::sync::CancellationToken;

/// Run a fixed scenario (A fetches /app/ping from B over a 10 ms link), then let a 1 s gauge
/// emitter collect 5 virtual-time samples. Returns the full sample series.
async fn metrics_scenario(kernel: Arc<dyn SimKernel>) -> Vec<MetricsSample> {
    let mut sim = Simulation::new().kernel(kernel.clone());
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    sim.link(
        a,
        b,
        LinkConfig {
            delay: Duration::from_millis(10),
            ..LinkConfig::default()
        },
    );
    sim.add_route(a, "/app", b);
    let fabric = sim.start().await.unwrap();

    let producer = fabric
        .engine_of(b)
        .unwrap()
        .register_producer("/app", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r
                    .respond((*i.name).clone(), bytes::Bytes::from_static(b"pong"))
                    .await;
            })
            .await;
    });

    // Drive one exchange so the counters actually move.
    let mut consumer = fabric
        .engine_of(a)
        .unwrap()
        .app_consumer(CancellationToken::new());
    let builder = InterestBuilder::new("/app/ping".parse::<Name>().unwrap())
        .lifetime(Duration::from_secs(30));
    consumer.fetch_with(builder).await.expect("fetch");

    // Sample every 1 s of virtual time; advance 5.5 s ⇒ exactly 5 ticks.
    let log = MetricsLog::new();
    let cancel = CancellationToken::new();
    fabric.spawn_gauge_emitter(Duration::from_secs(1), Arc::clone(&log), cancel.clone());
    tokio::time::sleep(Duration::from_millis(5500)).await;
    cancel.cancel();

    let samples = log.samples();
    fabric.shutdown().await;
    samples
}

#[test]
fn gauge_emitter_series_is_virtual_timed_reflects_traffic_and_replays() {
    let first = VirtualKernel::new().run(metrics_scenario);
    let second = VirtualKernel::new().run(metrics_scenario);

    assert_eq!(
        first, second,
        "the metric series replays identically under virtual time"
    );

    // 2 nodes × 5 ticks.
    assert_eq!(
        first.len(),
        10,
        "5 ticks for each of 2 nodes, got {}",
        first.len()
    );

    // The exchange moved real counters: somewhere an Interest went out and Data came back.
    assert!(
        first.iter().any(|s| s.out_interests > 0) && first.iter().any(|s| s.in_data > 0),
        "metrics reflect the Interest/Data exchange"
    );

    // Per node, consecutive samples are exactly one interval (1 s) apart in *virtual* time.
    let node0: Vec<u64> = first
        .iter()
        .filter(|s| s.node.0 == 0)
        .map(|s| s.virtual_time_ns)
        .collect();
    assert_eq!(node0.len(), 5);
    for w in node0.windows(2) {
        assert_eq!(
            w[1] - w[0],
            1_000_000_000,
            "samples 1 s of virtual time apart"
        );
    }
}

#[test]
fn span_timestamps_track_virtual_time_and_replay() {
    let capture = |kernel: Arc<dyn SimKernel>| async move {
        let rt = kernel.runtime();
        // Advance virtual time, then emit a span "now".
        tokio::time::sleep(Duration::from_secs(3)).await;
        let publisher = SpanPublisher::new(
            "/sim/obs".parse::<Name>().unwrap(),
            SpanRetention::default(),
        );
        let emitter = SimSpanEmitter::new(publisher, rt.clone());
        let span = emitter.event_now("radio.tx", vec![]);
        // The span's timestamp is the virtual clock value at emit time.
        (span.start_unix_nano, rt.unix_nanos())
    };

    let (ts_a, now_a) = VirtualKernel::new().run(capture);
    let (ts_b, now_b) = VirtualKernel::new().run(capture);

    assert_eq!(
        ts_a, now_a,
        "span timestamp == virtual clock, not wall-clock"
    );
    assert_eq!(ts_a, ts_b, "and it replays identically across runs");
    assert_eq!(now_a, now_b);
}
