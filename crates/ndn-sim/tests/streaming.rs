//! Live telemetry streaming + OTLP export (axis 4, 4c). Proves the emitter fans metric frames to a
//! live subscriber AND exports them to an OTLP/HTTP collector (validated against a mock collector,
//! so it's a real end-to-end check without needing Grafana/Jaeger running).

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{ControlPlane, RealTimeKernel, Simulation};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn telemetry_stream_delivers_live_frames() {
    let mut sim = Simulation::new().kernel(RealTimeKernel::new());
    sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));

    let mut rx = control.subscribe_telemetry();
    let cancel = control.spawn_telemetry(Duration::from_millis(40), None);

    // Two consecutive frames arrive, each carrying the node's metrics, with non-decreasing time.
    let f1 = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
    let f2 = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await.unwrap().unwrap();
    assert_eq!(f1.metrics.len(), 1, "one node's metrics per frame");
    assert!(f2.t_ns >= f1.t_ns, "frame time is non-decreasing");

    cancel.cancel();
    fabric.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_export_reaches_a_collector() {
    // A mock OTLP/HTTP collector: accept one POST, capture it, reply 200.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = tx.send(req);
        }
    });

    let mut sim = Simulation::new().kernel(RealTimeKernel::new());
    sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));
    let cancel = control.spawn_telemetry(Duration::from_millis(30), Some(addr.to_string()));

    // The collector receives an OTLP metrics POST.
    let req = tokio::time::timeout(Duration::from_secs(3), rx).await.unwrap().unwrap();
    assert!(req.starts_with("POST /v1/metrics"), "OTLP metrics POST, got: {}", &req[..req.len().min(60)]);
    assert!(req.contains("resourceMetrics"), "carries an OTLP ResourceMetrics document");
    assert!(req.contains("ndn.pit.depth"), "carries the pit-depth gauge");

    cancel.cancel();
    fabric.shutdown().await;
}

/// Captured engine spans set on the control plane are exported to the OTLP collector's /v1/traces.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn otlp_span_export_reaches_the_collector() {
    use ndn_sim::{CapturedSpan, SpanLog};

    // A mock collector that accepts several POSTs and reports the first /v1/traces it sees.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { break };
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            if req.starts_with("POST /v1/traces") && let Some(tx) = tx.take() {
                let _ = tx.send(req);
            }
        }
    });

    let mut sim = Simulation::new().kernel(RealTimeKernel::new());
    sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));

    // Populate a span log (as engine-span capture would) and attach it.
    let log = SpanLog::new();
    log.record(CapturedSpan {
        virtual_time_ns: 42,
        kind: "span",
        level: "DEBUG".into(),
        target: "fwd.pipeline".into(),
        name: "interest.forward".into(),
        message: String::new(),
        span_id: Some(1),
        parent_span_id: None,
    });
    control.set_span_log(Arc::clone(&log));

    let cancel = control.spawn_telemetry(Duration::from_millis(30), Some(addr.to_string()));
    let req = tokio::time::timeout(Duration::from_secs(3), rx).await.unwrap().unwrap();
    assert!(req.contains("resourceSpans"), "OTLP trace document present");
    assert!(req.contains("interest.forward"), "carries the captured span");

    cancel.cancel();
    fabric.shutdown().await;
}

/// A WebSocket client receives live telemetry frames pushed by the control plane (axis 4c over WS).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_clients_receive_live_telemetry() {
    use futures::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let mut sim = Simulation::new().kernel(RealTimeKernel::new());
    sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));
    let ws_addr = control.serve_ws("127.0.0.1:0", CancellationToken::new()).await.unwrap();
    let cancel = control.spawn_telemetry(Duration::from_millis(40), None);

    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{ws_addr}")).await.unwrap();
    let mut got = false;
    for _ in 0..30 {
        match tokio::time::timeout(Duration::from_millis(300), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) if t.contains("\"telemetry\"") => {
                got = true;
                break;
            }
            Ok(Some(_)) => continue,
            _ => continue,
        }
    }
    assert!(got, "WS client received a live telemetry frame");
    cancel.cancel();
    fabric.shutdown().await;
}
