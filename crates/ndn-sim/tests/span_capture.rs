//! Engine-tracing → virtual span store (ndn-lab, review gap 6): the engine's own forwarding spans
//! land in a virtual-clocked [`SpanLog`], and `why_did` returns them as a causal trace.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{
    CapturedSpan, ControlPlane, LinkConfig, SimKernel, SimMcp, SpanLog, Simulation, VirtualKernel,
    capture_engine_spans,
};
use tokio_util::sync::CancellationToken;

/// Build a 2-node fabric on `k`, run one fetch (drives the forwarding pipeline).
async fn exchange(k: Arc<dyn SimKernel>) -> ndn_sim::RunningSimulation {
    let mut sim = Simulation::new().kernel(k);
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    sim.link(a, b, LinkConfig { delay: Duration::from_millis(5), ..LinkConfig::default() });
    sim.add_route(a, "/app", b);
    let fabric = sim.start().await.unwrap();

    let producer = fabric.engine_of(b).unwrap().register_producer("/app", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r.respond((*i.name).clone(), bytes::Bytes::from_static(b"x")).await;
            })
            .await;
    });
    let mut consumer = fabric.engine_of(a).unwrap().app_consumer(CancellationToken::new());
    let builder = InterestBuilder::new("/app/0".parse::<Name>().unwrap()).lifetime(Duration::from_secs(20));
    consumer.fetch_with(builder).await.expect("fetch");
    fabric
}

#[test]
fn engine_spans_captured_on_the_virtual_clock() {
    let entries: Vec<CapturedSpan> = VirtualKernel::new().run(|k| async move {
        let log = SpanLog::new();
        let _guard = capture_engine_spans(k.runtime(), Arc::clone(&log));
        let fabric = exchange(k).await;
        fabric.shutdown().await;
        log.entries()
    });

    assert!(!entries.is_empty(), "engine emitted spans/events into the log");
    // Timestamps are virtual (the engine's clock), not wall-clock.
    assert!(
        entries.iter().all(|e| e.virtual_time_ns >= 1_700_000_000_000_000_000),
        "all captured spans carry virtual timestamps"
    );
    // The forwarding taxonomy is present — the causal gold, not just lifecycle events.
    assert!(
        entries.iter().any(|e| e.target.starts_with("fwd") || e.target.starts_with("engine")),
        "captured the engine's forwarding spans (targets: {:?})",
        entries.iter().map(|e| e.target.as_str()).take(8).collect::<Vec<_>>()
    );
}

#[test]
fn why_did_returns_the_engine_causal_trace() {
    let trace_len = VirtualKernel::new().run(|k| async move {
        let log = SpanLog::new();
        let _guard = capture_engine_spans(k.runtime(), Arc::clone(&log));
        let fabric = Arc::new(exchange(k).await);
        let control = ControlPlane::new(Arc::clone(&fabric));
        control.set_span_log(Arc::clone(&log));
        let mcp = SimMcp::new(control);

        let v = mcp.call_tool("why_did", &serde_json::json!({ "limit": 50 })).await.unwrap();
        let n = v["engine_spans"].as_array().map(|a| a.len()).unwrap_or(0);
        // Sanity: the engine_spans carry the captured trace fields.
        assert!(n == 0 || v["engine_spans"][0]["target"].is_string());
        fabric.shutdown().await;
        n
    });
    assert!(trace_len > 0, "why_did surfaced the engine causal trace, not just a flat event log");
}
