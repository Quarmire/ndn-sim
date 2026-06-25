//! `SimTracer` — in-memory packet-event recorder for simulation analysis with
//! filter helpers and JSON serialisation.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Instant;

use ndn_runtime::Runtime;

/// A recorded simulation event.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SimEvent {
    /// Microseconds since simulation start.
    pub timestamp_us: u64,
    /// Node index where the event occurred.
    pub node: usize,
    /// Face ID involved (if applicable).
    pub face: Option<u32>,
    /// Event classification.
    pub kind: EventKind,
    /// NDN name involved.
    pub name: String,
    /// Optional detail string (e.g. "cache-hit", "nack:NoRoute").
    pub detail: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub enum EventKind {
    InterestIn,
    InterestOut,
    DataIn,
    DataOut,
    CacheHit,
    CacheInsert,
    PitInsert,
    PitSatisfy,
    PitExpire,
    NackIn,
    NackOut,
    FaceUp,
    FaceDown,
    StrategyDecision,
    Custom(String),
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InterestIn => write!(f, "interest-in"),
            Self::InterestOut => write!(f, "interest-out"),
            Self::DataIn => write!(f, "data-in"),
            Self::DataOut => write!(f, "data-out"),
            Self::CacheHit => write!(f, "cache-hit"),
            Self::CacheInsert => write!(f, "cache-insert"),
            Self::PitInsert => write!(f, "pit-insert"),
            Self::PitSatisfy => write!(f, "pit-satisfy"),
            Self::PitExpire => write!(f, "pit-expire"),
            Self::NackIn => write!(f, "nack-in"),
            Self::NackOut => write!(f, "nack-out"),
            Self::FaceUp => write!(f, "face-up"),
            Self::FaceDown => write!(f, "face-down"),
            Self::StrategyDecision => write!(f, "strategy-decision"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

/// Thread-safe event recorder. One per simulation; share references across
/// components, drain after the run.
pub struct SimTracer {
    start: Instant,
    /// When set (the fabric passes the kernel's runtime), event timestamps come from the
    /// kernel clock — *virtual* (and thus reproducible) under a `VirtualKernel`, real under
    /// the wall-clock kernel. `None` ⇒ wall-clock elapsed since construction (standalone use).
    clock: Option<Arc<dyn Runtime>>,
    epoch_base_us: u64,
    events: Mutex<Vec<SimEvent>>,
}

impl SimTracer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            clock: None,
            epoch_base_us: 0,
            events: Mutex::new(Vec::new()),
        }
    }

    /// A tracer whose timestamps come from `clock` (the fabric's kernel runtime), measured
    /// relative to "now" so a run starts at t≈0 — deterministic under a `VirtualKernel`.
    pub fn with_clock(clock: Arc<dyn Runtime>) -> Self {
        let epoch_base_us = clock.unix_nanos() / 1_000;
        Self {
            start: Instant::now(),
            clock: Some(clock),
            epoch_base_us,
            events: Mutex::new(Vec::new()),
        }
    }

    /// Microseconds since the tracer started, on the kernel clock when present (virtual under
    /// a `VirtualKernel`), else wall-clock.
    fn elapsed_us(&self) -> u64 {
        match &self.clock {
            Some(rt) => (rt.unix_nanos() / 1_000).saturating_sub(self.epoch_base_us),
            None => self.start.elapsed().as_micros() as u64,
        }
    }

    pub fn record(&self, event: SimEvent) {
        self.events.lock().unwrap().push(event);
    }

    /// Record an event with automatic timestamping.
    pub fn record_now(
        &self,
        node: usize,
        face: Option<u32>,
        kind: EventKind,
        name: impl Into<String>,
        detail: Option<String>,
    ) {
        let ts = self.elapsed_us();
        self.record(SimEvent {
            timestamp_us: ts,
            node,
            face,
            kind,
            name: name.into(),
            detail,
        });
    }

    pub fn events(&self) -> Vec<SimEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.lock().unwrap().is_empty()
    }

    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }

    pub fn events_for_node(&self, node: usize) -> Vec<SimEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.node == node)
            .cloned()
            .collect()
    }

    pub fn events_of_kind(&self, kind: &EventKind) -> Vec<SimEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| &e.kind == kind)
            .cloned()
            .collect()
    }

    /// Serialise all events as a JSON array.
    pub fn to_json(&self) -> String {
        let events = self.events.lock().unwrap();
        let mut output = String::new();
        output.push('[');
        for (i, event) in events.iter().enumerate() {
            if i > 0 {
                output.push(',');
            }
            output.push('\n');
            output.push_str(&format!(
                r#"  {{"t":{},"node":{},"face":{},"kind":"{}","name":"{}""#,
                event.timestamp_us,
                event.node,
                event.face.map_or("null".to_string(), |f| f.to_string()),
                event.kind,
                event.name,
            ));
            if let Some(ref detail) = event.detail {
                output.push_str(&format!(r#","detail":"{detail}""#));
            }
            output.push('}');
        }
        output.push_str("\n]");
        output
    }
}

impl Default for SimTracer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracer_records_and_retrieves() {
        let tracer = SimTracer::new();
        tracer.record_now(0, Some(1), EventKind::InterestIn, "/test", None);
        tracer.record_now(1, Some(2), EventKind::DataOut, "/test", Some("ok".into()));

        assert_eq!(tracer.len(), 2);
        let events = tracer.events();
        assert_eq!(events[0].kind, EventKind::InterestIn);
        assert_eq!(events[1].detail.as_deref(), Some("ok"));
    }

    #[test]
    fn filter_by_node() {
        let tracer = SimTracer::new();
        tracer.record_now(0, None, EventKind::FaceUp, "/", None);
        tracer.record_now(1, None, EventKind::FaceUp, "/", None);
        tracer.record_now(0, None, EventKind::InterestIn, "/test", None);

        let node0 = tracer.events_for_node(0);
        assert_eq!(node0.len(), 2);
    }

    #[test]
    fn json_output() {
        let tracer = SimTracer::new();
        tracer.record(SimEvent {
            timestamp_us: 100,
            node: 0,
            face: Some(1),
            kind: EventKind::CacheHit,
            name: "/test".into(),
            detail: None,
        });
        let json = tracer.to_json();
        assert!(json.contains("cache-hit"));
        assert!(json.contains("/test"));
    }
}
