//! Telemetry (ndn-lab slice 5): **Runtime-clocked** metric gauges + OTLP spans.
//!
//! The one non-obvious OTel constraint for a simulator: under a
//! [`VirtualKernel`](crate::VirtualKernel), every telemetry timestamp must be **virtual time**
//! (read from the kernel [`Runtime`]), not wall-clock — otherwise traces aren't reproducible
//! and don't line up with sim events. Both pieces here take their clock from the Runtime, so a
//! scenario's metrics and spans replay bit-for-bit.
//!
//! Three sample families, all reusing what exists rather than adding an OpenTelemetry dependency,
//! and all flowing to the same [`OtlpExporter`](crate::otel_export::OtlpExporter):
//! - [`MetricsSample`] + [`MetricsLog`] + the fabric's gauge emitter snapshot a node's live
//!   engine counters (CS hit-rate, PIT depth, per-face throughput/drops) on a Runtime-driven
//!   cadence — the pull-only NFD datasets turned into a virtual-time series.
//! - [`IpMetricsSample`] does the same for the IP forwarding plane (forwarded / delivered / drops
//!   / tx bytes), and [`FabricGauges`] covers the medium/network-wide scalars (shared-radio
//!   airtime, AP handoffs, association overhead) — so IP-over-radio metrics export like the engine's
//!   rather than living only behind ad-hoc accessors.
//! - [`SimSpanEmitter`] builds [`ndn_observability::Span`]s (the workspace's hand-rolled OTLP
//!   span, the same schema production emits) with virtual `start`/`end` timestamps and serves
//!   them over NDN via [`SpanPublisher`]. The existing `NdnObservabilityLayer` can't be
//!   clock-injected, so the sim constructs spans directly — same wire, virtual clock.
//!
//! **Telemetry checklist for a new subsystem** (keep the story consistent): if it holds runtime
//! state a user would want to compare across runs, add it to a `*MetricsSample`/`FabricGauges`
//! snapshot *and* an `OtlpExporter` gauge — don't leave it reachable only through a bespoke accessor.
//!
//! Deferred (greenfield, not in ndn-rs): forwarding OTLP-over-NDN to a real collector
//! ("ndn-otel-bridge" does not exist) and OTLP *metric* protobufs. The reproducibility
//! constraint — the actual slice-5 risk — is solved here.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use ndn_engine::ForwarderEngine;
use ndn_observability::{Attr, Span, SpanKind, SpanPublisher, StatusCode};
use ndn_runtime::Runtime;

use crate::NodeId;

/// A point-in-time snapshot of one node's engine metrics, stamped with **virtual** time.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetricsSample {
    pub node: NodeId,
    /// Kernel-clock time of the sample (virtual under a `VirtualKernel`).
    pub virtual_time_ns: u64,
    pub faces: u64,
    pub in_interests: u64,
    pub out_interests: u64,
    pub in_data: u64,
    pub out_data: u64,
    pub in_bytes: u64,
    pub out_bytes: u64,
    /// Egress queue-full drops, summed across faces.
    pub out_drops: u64,
    pub cs_hits: u64,
    pub cs_misses: u64,
    pub cs_inserts: u64,
    pub cs_evictions: u64,
    pub cs_entries: u64,
    pub cs_bytes: u64,
    pub pit_depth: u64,
}

impl MetricsSample {
    /// Content Store hit-rate `hits / (hits + misses)`, or `0.0` with no lookups yet.
    pub fn cs_hit_rate(&self) -> f64 {
        let total = self.cs_hits + self.cs_misses;
        if total == 0 {
            0.0
        } else {
            self.cs_hits as f64 / total as f64
        }
    }
}

/// Snapshot one node's live engine counters at the engine's current (virtual) time.
pub fn sample_engine(node: NodeId, engine: &ForwarderEngine) -> MetricsSample {
    let cs = engine.cs();
    let stats = cs.stats();

    let (mut in_i, mut out_i, mut in_d, mut out_d) = (0u64, 0u64, 0u64, 0u64);
    let (mut in_b, mut out_b, mut drops) = (0u64, 0u64, 0u64);
    let states = engine.face_states();
    for e in states.iter() {
        let c = &e.value().counters;
        in_i += c.in_interests.load(Ordering::Relaxed);
        out_i += c.out_interests.load(Ordering::Relaxed);
        in_d += c.in_data.load(Ordering::Relaxed);
        out_d += c.out_data.load(Ordering::Relaxed);
        in_b += c.in_bytes.load(Ordering::Relaxed);
        out_b += c.out_bytes.load(Ordering::Relaxed);
        drops += c.out_drops.load(Ordering::Relaxed);
    }

    MetricsSample {
        node,
        virtual_time_ns: engine.runtime().unix_nanos(),
        faces: engine.faces().len() as u64,
        in_interests: in_i,
        out_interests: out_i,
        in_data: in_d,
        out_data: out_d,
        in_bytes: in_b,
        out_bytes: out_b,
        out_drops: drops,
        cs_hits: stats.hits,
        cs_misses: stats.misses,
        cs_inserts: stats.inserts,
        cs_evictions: stats.evictions,
        cs_entries: cs.len() as u64,
        cs_bytes: cs.current_bytes() as u64,
        pit_depth: engine.pit().len() as u64,
    }
}

/// A point-in-time snapshot of one **IP node**'s forwarding counters, stamped with virtual time —
/// the IP-plane analogue of [`MetricsSample`], so IP metrics ride the same [`MetricsLog`] +
/// [`OtlpExporter`](crate::otel_export::OtlpExporter) path as the NDN engine's.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IpMetricsSample {
    pub node: NodeId,
    pub virtual_time_ns: u64,
    pub forwarded: u64,
    pub delivered: u64,
    pub dropped_no_route: u64,
    pub dropped_ttl: u64,
    pub tx_bytes: u64,
}

/// Medium/network-wide gauges that aren't per-node: the shared-radio airtime and the AP-mode
/// roaming cost. One snapshot for a whole `RadioBus` / `IpNetwork` at a virtual instant, so these —
/// previously only reachable via ad-hoc accessors — also flow to the OTLP exporter.
#[derive(Clone, Copy, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[derive(ndn_manifest_derive::Manifest)]
#[manifest(ty = "fabric-gauges", describes = "ndn-lab/run/fabric-gauges")]
pub struct FabricGauges {
    /// Kernel-clock time of the sample (ns).
    pub virtual_time_ns: u64,
    /// Total airtime consumed on the shared radio medium (ns) — `RadioBus::total_airtime`.
    pub radio_airtime_ns: u64,
    /// (Re)associations across all stations — `IpNetwork::handoff_count` (AP-mode roaming).
    pub handoffs: u64,
    /// Accumulated association-handshake time (ns) — `IpNetwork::association_overhead`.
    pub association_overhead_ns: u64,
}

/// The result of comparing two metric series (two runs) — for determinism checks and A/B
/// regression analysis (the `compare_runs` substrate).
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MetricsDiff {
    /// `true` iff the two series match sample-for-sample (same length, same fields).
    pub identical: bool,
    /// Human-readable divergences (`node@time field: a != b`), capped for readability.
    pub divergences: Vec<String>,
}

/// Compare two metric series (e.g. two runs of the same scenario). Sorts each by
/// `(node, virtual_time)`, zips, and reports field-level divergences — the basis for a
/// determinism check or an A/B `compare_runs`. Identical inputs ⇒ `identical = true`.
pub fn compare_metrics(baseline: &[MetricsSample], candidate: &[MetricsSample]) -> MetricsDiff {
    let key = |s: &MetricsSample| (s.node.0, s.virtual_time_ns);
    let mut a = baseline.to_vec();
    let mut b = candidate.to_vec();
    a.sort_by_key(key);
    b.sort_by_key(key);

    let mut divergences = Vec::new();
    if a.len() != b.len() {
        divergences.push(format!("sample count: {} != {}", a.len(), b.len()));
    }
    for (x, y) in a.iter().zip(b.iter()) {
        if x != y {
            divergences.push(format!(
                "node {}@{}ns: cs_hits {}/{} pit {}/{} out_data {}/{} in_bytes {}/{}",
                x.node.0,
                x.virtual_time_ns,
                x.cs_hits,
                y.cs_hits,
                x.pit_depth,
                y.pit_depth,
                x.out_data,
                y.out_data,
                x.in_bytes,
                y.in_bytes,
            ));
        }
    }
    let identical = divergences.is_empty();
    divergences.truncate(50);
    MetricsDiff {
        identical,
        divergences,
    }
}

/// A thread-safe, append-only series of [`MetricsSample`]s — the destination for the fabric's
/// gauge emitter. Drain or query after (or during) a run.
#[derive(Default)]
pub struct MetricsLog {
    samples: Mutex<Vec<MetricsSample>>,
}

impl MetricsLog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record(&self, sample: MetricsSample) {
        self.samples.lock().unwrap().push(sample);
    }

    pub fn record_all(&self, samples: impl IntoIterator<Item = MetricsSample>) {
        self.samples.lock().unwrap().extend(samples);
    }

    pub fn samples(&self) -> Vec<MetricsSample> {
        self.samples.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.samples.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.lock().unwrap().is_empty()
    }

    pub fn for_node(&self, node: NodeId) -> Vec<MetricsSample> {
        self.samples
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.node == node)
            .cloned()
            .collect()
    }
}

/// Emits OTLP [`Span`]s with **virtual** timestamps (from the kernel [`Runtime`]) and serves
/// them over NDN through a [`SpanPublisher`] — the same span schema and wire as production,
/// only the clock differs. Trace/span ids are allocated from deterministic counters so a
/// scenario's span stream replays identically.
pub struct SimSpanEmitter {
    publisher: Arc<SpanPublisher>,
    clock: Arc<dyn Runtime>,
    next_trace: AtomicU64,
    next_span: AtomicU64,
}

impl SimSpanEmitter {
    pub fn new(publisher: Arc<SpanPublisher>, clock: Arc<dyn Runtime>) -> Self {
        Self {
            publisher,
            clock,
            next_trace: AtomicU64::new(1),
            next_span: AtomicU64::new(1),
        }
    }

    pub fn publisher(&self) -> &Arc<SpanPublisher> {
        &self.publisher
    }

    fn trace_id(&self) -> [u8; 16] {
        let n = self.next_trace.fetch_add(1, Ordering::Relaxed);
        let mut id = [0u8; 16];
        id[8..].copy_from_slice(&n.to_be_bytes());
        id
    }

    fn span_id(&self) -> [u8; 8] {
        self.next_span.fetch_add(1, Ordering::Relaxed).to_be_bytes()
    }

    /// Build, publish, and return a completed span over the virtual interval
    /// `[start_ns, end_ns]`. Caller supplies virtual timestamps (e.g. captured around the
    /// work via [`Runtime::unix_nanos`]).
    pub fn span(
        &self,
        name: impl Into<String>,
        kind: SpanKind,
        start_ns: u64,
        end_ns: u64,
        attributes: Vec<Attr>,
    ) -> Span {
        let span = Span {
            trace_id: self.trace_id(),
            span_id: self.span_id(),
            parent_span_id: None,
            name: name.into(),
            kind,
            start_unix_nano: start_ns,
            end_unix_nano: end_ns,
            attributes,
            status_code: StatusCode::Unset,
            status_message: String::new(),
        };
        self.publisher.publish(&span);
        span
    }

    /// A zero-duration span at the current virtual instant — for point sim events (a radio
    /// transmit, a mobility tick). The timestamp is the kernel clock, so it's reproducible.
    pub fn event_now(&self, name: impl Into<String>, attributes: Vec<Attr>) -> Span {
        let now = self.clock.unix_nanos();
        self.span(name, SpanKind::Internal, now, now, attributes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_observability::SpanRetention;
    use ndn_packet::Name;
    use ndn_runtime::{BoxFuture, Instant};
    use std::str::FromStr;

    // A trivial fixed-clock Runtime for unit-testing virtual timestamps without a kernel.
    struct FixedClock(u64);
    impl ndn_runtime::Spawn for FixedClock {
        fn spawn(&self, _f: BoxFuture) {}
    }
    impl ndn_runtime::Sleep for FixedClock {
        fn sleep(&self, _d: std::time::Duration) -> BoxFuture {
            Box::pin(async {})
        }
    }
    impl ndn_runtime::Now for FixedClock {
        fn now(&self) -> Instant {
            Instant::now()
        }
        fn unix_nanos(&self) -> u64 {
            self.0
        }
    }
    impl Runtime for FixedClock {}

    #[test]
    fn span_timestamps_come_from_the_injected_clock() {
        let clock: Arc<dyn Runtime> = Arc::new(FixedClock(42_000));
        let publisher = SpanPublisher::new(
            Name::from_str("/sim/obs").unwrap(),
            SpanRetention::default(),
        );
        let emitter = SimSpanEmitter::new(Arc::clone(&publisher), clock);

        let span = emitter.event_now("radio.tx", vec![Attr::int("rx", 3)]);
        // The timestamp is the *virtual* clock value (42_000 ns), not a wall-clock epoch.
        assert_eq!(span.start_unix_nano, 42_000);
        assert_eq!(span.end_unix_nano, 42_000);
        assert_eq!(publisher.len(), 1, "span served over NDN");
    }

    fn sample(node: usize, t: u64, hits: u64) -> MetricsSample {
        MetricsSample {
            node: NodeId(node),
            virtual_time_ns: t,
            faces: 1,
            in_interests: 0,
            out_interests: 0,
            in_data: 0,
            out_data: 0,
            in_bytes: 0,
            out_bytes: 0,
            out_drops: 0,
            cs_hits: hits,
            cs_misses: 0,
            cs_inserts: 0,
            cs_evictions: 0,
            cs_entries: 0,
            cs_bytes: 0,
            pit_depth: 0,
        }
    }

    #[test]
    fn compare_metrics_detects_identity_and_divergence() {
        let a = vec![sample(0, 100, 5), sample(1, 100, 7)];
        let same = vec![sample(1, 100, 7), sample(0, 100, 5)]; // reordered, same content
        assert!(
            compare_metrics(&a, &same).identical,
            "order-independent identity"
        );

        let diff = vec![sample(0, 100, 5), sample(1, 100, 9)]; // node 1 hits differ
        let d = compare_metrics(&a, &diff);
        assert!(!d.identical);
        assert!(d.divergences.iter().any(|s| s.contains("node 1")));
    }

    #[test]
    fn span_and_trace_ids_are_deterministic() {
        let clock: Arc<dyn Runtime> = Arc::new(FixedClock(0));
        let make = || {
            let publisher = SpanPublisher::new(
                Name::from_str("/sim/obs").unwrap(),
                SpanRetention::default(),
            );
            let e = SimSpanEmitter::new(publisher, Arc::clone(&clock));
            let a = e.event_now("a", vec![]);
            let b = e.event_now("b", vec![]);
            (a.trace_id, a.span_id, b.trace_id, b.span_id)
        };
        assert_eq!(make(), make(), "id allocation replays identically");
    }
}
