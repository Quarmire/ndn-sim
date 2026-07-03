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
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

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
    /// The tracing span id (for `"span"` kind), so captured spans link into a causal tree. `None`
    /// for `"event"` entries (events aren't spans).
    #[serde(default)]
    pub span_id: Option<u64>,
    /// The id of the enclosing span, if any — the parent link. For a `"span"` this is its parent
    /// span; for an `"event"` it's the span the event fired inside. `None` at the root.
    #[serde(default)]
    pub parent_span_id: Option<u64>,
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
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let md = attrs.metadata();
        // The registry resolves the parent (explicit `parent:` or the contextual current span).
        let parent_span_id = ctx
            .span(id)
            .and_then(|s| s.parent())
            .map(|p| p.id().into_u64());
        self.log.record(CapturedSpan {
            virtual_time_ns: self.clock.unix_nanos(),
            kind: "span",
            level: md.level().to_string(),
            target: md.target().to_string(),
            name: md.name().to_string(),
            message: String::new(),
            span_id: Some(id.into_u64()),
            parent_span_id,
        });
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let md = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let enclosing = ctx.event_span(event);
        let span_name = enclosing
            .as_ref()
            .map(|s| s.name().to_string())
            .unwrap_or_default();
        let parent_span_id = enclosing.as_ref().map(|s| s.id().into_u64());
        self.log.record(CapturedSpan {
            virtual_time_ns: self.clock.unix_nanos(),
            kind: "event",
            level: md.level().to_string(),
            target: md.target().to_string(),
            name: span_name,
            message: visitor.message,
            span_id: None,
            parent_span_id,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A nested span opened inside another captures the parent link, and an event inside the child
    /// points at the child span — so the captured trace forms a tree, not a flat list.
    #[test]
    fn nested_spans_capture_parent_links() {
        let log = SpanLog::new();
        {
            let _guard = capture_engine_spans(ndn_runtime::default_runtime(), Arc::clone(&log));
            let outer = tracing::info_span!("outer");
            let _o = outer.enter();
            let inner = tracing::info_span!("inner");
            let _i = inner.enter();
            tracing::info!("hello from inner");
        }

        let entries = log.entries();
        let outer = entries
            .iter()
            .find(|e| e.name == "outer" && e.kind == "span")
            .unwrap();
        let inner = entries
            .iter()
            .find(|e| e.name == "inner" && e.kind == "span")
            .unwrap();
        assert!(outer.parent_span_id.is_none(), "the outer span is a root");
        assert_eq!(
            inner.parent_span_id, outer.span_id,
            "the inner span links to the outer as its parent"
        );

        let event = entries.iter().find(|e| e.kind == "event").unwrap();
        assert_eq!(
            event.parent_span_id, inner.span_id,
            "the event points at the span it fired inside"
        );
    }
}
