//! Live telemetry streaming + OTLP export (axis 4, 4c). Proves the emitter fans metric frames to a
//! live subscriber AND exports them to an OTLP/HTTP collector (validated against a mock collector,
//! so it's a real end-to-end check without needing Grafana/Jaeger running).

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{ControlPlane, RealTimeKernel, Simulation};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
