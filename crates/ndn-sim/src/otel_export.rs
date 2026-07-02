//! OTLP/HTTP exporter (ndn-lab follow-on): forward sim telemetry — virtual-clocked spans and
//! metric gauges — to a real OpenTelemetry collector.
//!
//! Closes the slice-5 "bridge to a collector" follow-on. The workspace has no OpenTelemetry
//! dependency and its OTLP is hand-rolled, so this stays dependency-light: it builds **OTLP/JSON**
//! payloads (the JSON encoding OTLP/HTTP collectors accept at `/v1/traces` and `/v1/metrics`) and
//! POSTs them over a minimal HTTP/1.1 client on `tokio::net` — no reqwest, no protobuf codegen.
//!
//! Timestamps come straight from the [`Span`]s / [`MetricsSample`]s, so under a
//! [`VirtualKernel`](crate::VirtualKernel) the exported trace/metric stream carries *virtual*
//! time and is reproducible. Caveat: the JSON is OTLP-structured and round-trips through a mock
//! collector in tests, but is not validated against every vendor's collector.

use ndn_observability::{AttrValue, Span, SpanKind};
use serde_json::{Value, json};

use crate::telemetry::MetricsSample;

/// Exports OTLP/JSON to an OTLP/HTTP collector at `host:port` (e.g. the default `127.0.0.1:4318`).
pub struct OtlpExporter {
    addr: String,
    service_name: String,
}

impl OtlpExporter {
    /// Target the collector listening at `addr` (`host:port`, no scheme).
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into(), service_name: "ndn-lab".to_string() }
    }

    pub fn with_service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = name.into();
        self
    }

    /// The OTLP/JSON `ResourceSpans` document for `spans`.
    pub fn spans_payload(&self, spans: &[Span]) -> String {
        let span_json: Vec<Value> = spans.iter().map(span_to_json).collect();
        json!({
            "resourceSpans": [{
                "resource": self.resource(),
                "scopeSpans": [{
                    "scope": { "name": "ndn-lab" },
                    "spans": span_json
                }]
            }]
        })
        .to_string()
    }

    /// The OTLP/JSON `ResourceMetrics` document for `samples` (one gauge series per metric,
    /// each data point tagged with the node id).
    pub fn metrics_payload(&self, samples: &[MetricsSample]) -> String {
        let metrics = json!([
            gauge("ndn.cs.hit_rate", samples, |s| json!(s.cs_hit_rate())),
            gauge("ndn.pit.depth", samples, |s| json!(s.pit_depth)),
            gauge("ndn.face.in_bytes", samples, |s| json!(s.in_bytes)),
            gauge("ndn.face.out_bytes", samples, |s| json!(s.out_bytes)),
            gauge("ndn.face.out_drops", samples, |s| json!(s.out_drops)),
        ]);
        json!({
            "resourceMetrics": [{
                "resource": self.resource(),
                "scopeMetrics": [{
                    "scope": { "name": "ndn-lab" },
                    "metrics": metrics
                }]
            }]
        })
        .to_string()
    }

    fn resource(&self) -> Value {
        json!({
            "attributes": [
                { "key": "service.name", "value": { "stringValue": self.service_name } }
            ]
        })
    }

    /// POST spans to `<addr>/v1/traces`. Returns the collector's HTTP status code.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn export_spans(&self, spans: &[Span]) -> std::io::Result<u16> {
        http_post_json(&self.addr, "/v1/traces", &self.spans_payload(spans)).await
    }

    /// The OTLP/JSON `ResourceSpans` document for captured engine spans (the [`SpanLog`] entries),
    /// so the sim's own fwd.pipeline / fwd.pit / radio spans flow to Jaeger.
    pub fn captured_spans_payload(&self, spans: &[crate::span_capture::CapturedSpan]) -> String {
        let span_json: Vec<Value> =
            spans.iter().enumerate().map(|(i, s)| captured_span_to_json(s, i)).collect();
        json!({
            "resourceSpans": [{
                "resource": self.resource(),
                "scopeSpans": [{ "scope": { "name": "ndn-lab" }, "spans": span_json }]
            }]
        })
        .to_string()
    }

    /// POST captured engine spans to `<addr>/v1/traces`.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn export_captured_spans(
        &self,
        spans: &[crate::span_capture::CapturedSpan],
    ) -> std::io::Result<u16> {
        http_post_json(&self.addr, "/v1/traces", &self.captured_spans_payload(spans)).await
    }

    /// POST metrics to `<addr>/v1/metrics`. Returns the collector's HTTP status code.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn export_metrics(&self, samples: &[MetricsSample]) -> std::io::Result<u16> {
        http_post_json(&self.addr, "/v1/metrics", &self.metrics_payload(samples)).await
    }
}

fn gauge(name: &str, samples: &[MetricsSample], f: impl Fn(&MetricsSample) -> Value) -> Value {
    let points: Vec<Value> = samples
        .iter()
        .map(|s| {
            json!({
                "timeUnixNano": s.virtual_time_ns.to_string(),
                "asDouble": f(s),
                "attributes": [
                    { "key": "node", "value": { "intValue": s.node.0.to_string() } }
                ]
            })
        })
        .collect();
    json!({ "name": name, "gauge": { "dataPoints": points } })
}

/// Fixed 16-byte trace id ("ndn-lab" ASCII, padded) so a run's captured spans share one trace.
const NDNLAB_TRACE_ID: [u8; 16] =
    [0x6e, 0x64, 0x6e, 0x2d, 0x6c, 0x61, 0x62, 0, 0, 0, 0, 0, 0, 0, 0, 1];

fn captured_span_to_json(s: &crate::span_capture::CapturedSpan, idx: usize) -> Value {
    // Captured spans are point-in-time; give each a deterministic span id from its index.
    let span_id = ((idx as u64) + 1).to_be_bytes();
    json!({
        "traceId": hex(&NDNLAB_TRACE_ID),
        "spanId": hex(&span_id),
        "name": s.name,
        "kind": 1, // SPAN_KIND_INTERNAL
        "startTimeUnixNano": s.virtual_time_ns.to_string(),
        "endTimeUnixNano": s.virtual_time_ns.to_string(),
        "attributes": [
            { "key": "target", "value": { "stringValue": s.target } },
            { "key": "level", "value": { "stringValue": s.level } },
            { "key": "message", "value": { "stringValue": s.message } },
        ]
    })
}

fn span_to_json(s: &Span) -> Value {
    let attrs: Vec<Value> = s.attributes.iter().map(|a| attr_to_json(&a.key, &a.value)).collect();
    json!({
        "traceId": hex(&s.trace_id),
        "spanId": hex(&s.span_id),
        "name": s.name,
        "kind": kind_code(s.kind),
        "startTimeUnixNano": s.start_unix_nano.to_string(),
        "endTimeUnixNano": s.end_unix_nano.to_string(),
        "attributes": attrs
    })
}

fn attr_to_json(key: &str, value: &AttrValue) -> Value {
    let v = match value {
        AttrValue::String(s) => json!({ "stringValue": s }),
        AttrValue::Int(i) => json!({ "intValue": i.to_string() }),
        AttrValue::Bool(b) => json!({ "boolValue": b }),
    };
    json!({ "key": key, "value": v })
}

fn kind_code(kind: SpanKind) -> i32 {
    kind as i32
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A minimal HTTP/1.1 JSON POST (Connection: close). Returns the response status code.
#[cfg(not(target_arch = "wasm32"))]
async fn http_post_json(addr: &str, path: &str, body: &str) -> std::io::Result<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await?;
    let host = addr;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    // Parse "HTTP/1.1 <code> ..." from the status line.
    let status = std::str::from_utf8(&response)
        .ok()
        .and_then(|s| s.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_observability::Attr;

    fn sample(node: usize, t: u64) -> MetricsSample {
        MetricsSample {
            node: crate::NodeId(node),
            virtual_time_ns: t,
            faces: 1,
            in_interests: 2,
            out_interests: 0,
            in_data: 0,
            out_data: 1,
            in_bytes: 100,
            out_bytes: 50,
            out_drops: 0,
            cs_hits: 1,
            cs_misses: 1,
            cs_inserts: 1,
            cs_evictions: 0,
            cs_entries: 1,
            cs_bytes: 50,
            pit_depth: 3,
        }
    }

    #[test]
    fn spans_payload_is_otlp_shaped() {
        let exporter = OtlpExporter::new("127.0.0.1:4318");
        let span = Span {
            trace_id: [0xab; 16],
            span_id: [0x01; 8],
            parent_span_id: None,
            name: "radio.tx".into(),
            kind: SpanKind::Internal,
            start_unix_nano: 1000,
            end_unix_nano: 2000,
            attributes: vec![Attr::int("rx", 3)],
            status_code: ndn_observability::StatusCode::Unset,
            status_message: String::new(),
        };
        let payload = exporter.spans_payload(&[span]);
        let v: Value = serde_json::from_str(&payload).unwrap();
        let s = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(s["name"], "radio.tx");
        assert_eq!(s["traceId"], "abababababababababababababababab");
        assert_eq!(s["startTimeUnixNano"], "1000"); // int64 as string per OTLP/JSON
        assert_eq!(s["attributes"][0]["key"], "rx");
        assert_eq!(s["attributes"][0]["value"]["intValue"], "3");
    }

    #[test]
    fn captured_spans_payload_is_otlp_shaped() {
        let exporter = OtlpExporter::new("127.0.0.1:4318");
        let span = crate::span_capture::CapturedSpan {
            virtual_time_ns: 1234,
            kind: "span",
            level: "INFO".into(),
            target: "fwd.pit".into(),
            name: "pit.insert".into(),
            message: String::new(),
        };
        let payload = exporter.captured_spans_payload(&[span]);
        let v: Value = serde_json::from_str(&payload).unwrap();
        let s = &v["resourceSpans"][0]["scopeSpans"][0]["spans"][0];
        assert_eq!(s["name"], "pit.insert");
        assert_eq!(s["startTimeUnixNano"], "1234");
        assert!(s["attributes"].as_array().unwrap().iter().any(|a| a["key"] == "target"));
    }

    #[test]
    fn metrics_payload_carries_gauges_per_node() {
        let exporter = OtlpExporter::new("127.0.0.1:4318");
        let payload = exporter.metrics_payload(&[sample(0, 5_000), sample(1, 5_000)]);
        let v: Value = serde_json::from_str(&payload).unwrap();
        let metrics = v["resourceMetrics"][0]["scopeMetrics"][0]["metrics"].as_array().unwrap();
        assert!(metrics.iter().any(|m| m["name"] == "ndn.cs.hit_rate"));
        let pit = metrics.iter().find(|m| m["name"] == "ndn.pit.depth").unwrap();
        let points = pit["gauge"]["dataPoints"].as_array().unwrap();
        assert_eq!(points.len(), 2, "one point per node");
        assert_eq!(points[0]["asDouble"], 3);
        assert_eq!(points[0]["timeUnixNano"], "5000");
    }
}
