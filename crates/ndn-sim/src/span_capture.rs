//! Engine-tracing → virtual span store (ndn-lab follow-on, review gap 6).
//!
//! The engine already emits rich `tracing` spans/events under a fixed target taxonomy
//! (`fwd.pipeline`, `fwd.pit`, `face.system`, `security`, …) — the debugging gold that answers
//! "why was this Interest dropped". But nothing fed them into the sim's clock, so `why_did` was a
//! flat lifecycle-event log, not a causal trace. This bridges them: a [`tracing_subscriber::Layer`]
//! captures the engine's spans/events and timestamps each with the **kernel clock** (virtual under
//! a [`VirtualKernel`](crate::VirtualKernel)), into a queryable [`SpanLog`].
//!
//! Per ndn-rs convention (libraries never install a global subscriber), capture is **scoped**:
//! [`capture_engine_spans`] returns a thread-local subscriber guard. Under the single-threaded
//! `VirtualKernel` runtime that covers every spawned engine task for the guard's lifetime, so the
//! captured trace is virtual-clocked and reproducible.

use std::sync::{Arc, Mutex};

use ndn_runtime::Runtime;
use serde::Serialize;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// One captured engine span-open or event, stamped with virtual time.
#[derive(Clone, Debug, Serialize)]
pub struct CapturedSpan {
    pub virtual_time_ns: u64,
    /// `"span"` (a span opened) or `"event"` (a log line).
    pub kind: &'static str,
    pub level: String,
    /// The tracing target (taxonomy bucket, e.g. `fwd.pipeline`).
    pub target: String,
    /// Span name (for `"span"`), or the enclosing span's name (for `"event"`).
    pub name: String,
    /// The event message (empty for span-opens).
    pub message: String,
}

/// A thread-safe, append-only log of captured engine spans/events.
#[derive(Default)]
pub struct SpanLog {
    entries: Mutex<Vec<CapturedSpan>>,
}

impl SpanLog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Append a captured span (used by the [`EngineSpanLayer`] and by producers of sim-level spans).
    pub fn record(&self, span: CapturedSpan) {
        self.entries.lock().unwrap().push(span);
    }

    pub fn entries(&self) -> Vec<CapturedSpan> {
        self.entries.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }

    /// The most recent `limit` entries (the causal context `why_did` returns).
    pub fn recent(&self, limit: usize) -> Vec<CapturedSpan> {
        let entries = self.entries.lock().unwrap();
        let start = entries.len().saturating_sub(limit);
        entries[start..].to_vec()
    }

    /// Entries whose target starts with `prefix` (e.g. `"fwd"`).
    pub fn for_target(&self, prefix: &str) -> Vec<CapturedSpan> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.target.starts_with(prefix))
            .cloned()
            .collect()
    }
}

/// Pulls the `message` field out of a tracing event.
#[derive(Default)]
struct MessageVisitor {
    message: String,
}
impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}

/// A [`tracing_subscriber::Layer`] that records engine spans/events into a [`SpanLog`], stamped
/// with the kernel's (virtual) clock instead of wall-clock.
pub struct EngineSpanLayer {
    clock: Arc<dyn Runtime>,
    log: Arc<SpanLog>,
}

impl EngineSpanLayer {
    pub fn new(clock: Arc<dyn Runtime>, log: Arc<SpanLog>) -> Self {
        Self { clock, log }
    }
}

impl<S> Layer<S> for EngineSpanLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: Context<'_, S>,
    ) {
        let md = attrs.metadata();
        self.log.record(CapturedSpan {
            virtual_time_ns: self.clock.unix_nanos(),
            kind: "span",
            level: md.level().to_string(),
            target: md.target().to_string(),
            name: md.name().to_string(),
            message: String::new(),
        });
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let md = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let span_name = ctx
            .event_span(event)
            .map(|s| s.name().to_string())
            .unwrap_or_default();
        self.log.record(CapturedSpan {
            virtual_time_ns: self.clock.unix_nanos(),
            kind: "event",
            level: md.level().to_string(),
            target: md.target().to_string(),
            name: span_name,
            message: visitor.message,
        });
    }
}

/// Install engine-span capture for the current thread, returning a guard that stops capture when
/// dropped. Call it at the top of a [`VirtualKernel::run`](crate::VirtualKernel::run) body (or any
/// run): under the single-threaded runtime it covers every engine task spawned while the guard is
/// alive. `clock` should be the kernel's runtime so timestamps are virtual.
#[must_use = "capture stops when the returned guard is dropped"]
pub fn capture_engine_spans(
    clock: Arc<dyn Runtime>,
    log: Arc<SpanLog>,
) -> tracing::subscriber::DefaultGuard {
    let subscriber = tracing_subscriber::registry().with(EngineSpanLayer::new(clock, log));
    tracing::subscriber::set_default(subscriber)
}
