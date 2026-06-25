//! Telemetry (ndn-lab slice 5): **Runtime-clocked** metric gauges + OTLP spans.
//!
//! The one non-obvious OTel constraint for a simulator: under a
//! [`VirtualKernel`](crate::VirtualKernel), every telemetry timestamp must be **virtual time**
//! (read from the kernel [`Runtime`]), not wall-clock — otherwise traces aren't reproducible
//! and don't line up with sim events. Both pieces here take their clock from the Runtime, so a
//! scenario's metrics and spans replay bit-for-bit.
//!
//! Two pieces, both reusing what exists rather than adding an OpenTelemetry dependency:
//! - [`MetricsSample`] + [`MetricsLog`] + the fabric's gauge emitter snapshot a node's live
//!   engine counters (CS hit-rate, PIT depth, per-face throughput/drops) on a Runtime-driven
//!   cadence — the pull-only NFD datasets turned into a virtual-time series.
//! - [`SimSpanEmitter`] builds [`ndn_observability::Span`]s (the workspace's hand-rolled OTLP
//!   span, the same schema production emits) with virtual `start`/`end` timestamps and serves
//!   them over NDN via [`SpanPublisher`]. The existing `NdnObservabilityLayer` can't be
//!   clock-injected, so the sim constructs spans directly — same wire, virtual clock.
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
#[derive(Clone, Debug, PartialEq, Eq)]
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

    #[test]
    fn span_and_trace_ids_are_deterministic() {
        let clock: Arc<dyn Runtime> = Arc::new(FixedClock(0));
        let make = || {
            let publisher =
                SpanPublisher::new(Name::from_str("/sim/obs").unwrap(), SpanRetention::default());
            let e = SimSpanEmitter::new(publisher, Arc::clone(&clock));
            let a = e.event_now("a", vec![]);
            let b = e.event_now("b", vec![]);
            (a.trace_id, a.span_id, b.trace_id, b.span_id)
        };
        assert_eq!(make(), make(), "id allocation replays identically");
    }
}
