//! Follow-on integration (ndn-lab): the OTLP/HTTP exporter forwards metrics to a collector. A
//! mock OTLP collector (a tiny TCP server) receives the POST and we assert the OTLP/JSON body.

use std::sync::Arc;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{ControlPlane, MetricsLog, OtlpExporter, SimResponse, Simulation};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

/// A one-shot mock OTLP/HTTP collector: accept one connection, read the request (headers +
/// Content-Length body), reply 200, and hand the captured body back.
async fn mock_collector() -> (std::net::SocketAddr, oneshot::Receiver<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        // Read until we have headers + the declared Content-Length body.
        let mut content_len: Option<usize> = None;
        let mut header_end: Option<usize> = None;
        loop {
            let n = stream.read(&mut tmp).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if header_end.is_none()
                && let Some(pos) = find_subslice(&buf, b"\r\n\r\n")
            {
                header_end = Some(pos + 4);
                let headers = String::from_utf8_lossy(&buf[..pos]).to_lowercase();
                for line in headers.lines() {
                    if let Some(v) = line.strip_prefix("content-length:") {
                        content_len = v.trim().parse().ok();
                    }
                }
            }
            if let (Some(h), Some(cl)) = (header_end, content_len)
                && buf.len() >= h + cl
            {
                break;
            }
        }
        let body = header_end
            .map(|h| String::from_utf8_lossy(&buf[h..]).into_owned())
            .unwrap_or_default();
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await;
        let _ = stream.flush().await;
        let _ = tx.send(body);
    });
    (addr, rx)
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[tokio::test]
async fn exports_metrics_to_a_mock_otlp_collector() {
    // A fabric + a couple of metric samples via the control plane.
    let mut sim = Simulation::new();
    let _a = sim.add_node(EngineConfig::default());
    let _b = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));
    let SimResponse::Metrics(samples) = control.query(ndn_sim::SimQuery::Metrics) else {
        panic!("metrics");
    };
    assert_eq!(samples.len(), 2);

    let (addr, rx) = mock_collector().await;
    let exporter = OtlpExporter::new(addr.to_string());
    let status = exporter.export_metrics(&samples).await.unwrap();
    assert_eq!(status, 200, "collector accepted the OTLP POST");

    let body = rx.await.unwrap();
    assert!(body.contains("resourceMetrics"), "OTLP-shaped body");
    assert!(body.contains("ndn.cs.hit_rate") && body.contains("ndn.pit.depth"));
    assert!(body.contains(r#""service.name""#) && body.contains("ndn-lab"));

    // A MetricsLog series exports just as well.
    let log = MetricsLog::new();
    log.record_all(samples);
    let _ = log; // (illustrative — the exporter takes any &[MetricsSample])

    fabric.shutdown().await;
}
