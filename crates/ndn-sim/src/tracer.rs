//! `SimTracer` — structured event capture for simulation analysis.
//!
//! A lightweight event recorder that captures packet-level events during
//! simulation runs. Events are stored in memory for post-hoc analysis,
//! filtering, and serialization to JSON.
//!
//! # Usage
//!
//! ```rust,no_run
//! use ndn_sim::tracer::{SimTracer, SimEvent, EventKind};
//!
//! let tracer = SimTracer::new();
//!
//! // Record events during simulation...
//! tracer.record(SimEvent {
//!     timestamp_us: 1000,
//!     node: 0,
//!     face: Some(1),
//!     kind: EventKind::InterestIn,
//!     name: "/ndn/test/data".into(),
//!     detail: None,
//! });
//!
//! // Analyze after simulation
//! let events = tracer.events();
//! let json = tracer.to_json();
//! ```

use std::sync::Mutex;
use std::time::Instant;

/// A recorded simulation event.
#[derive(Clone, Debug)]
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

/// Classification of simulation events.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// Interest received on a face.
    InterestIn,
    /// Interest forwarded out a face.
    InterestOut,
    /// Data received on a face.
    DataIn,
    /// Data sent out a face.
    DataOut,
    /// Content Store cache hit.
    CacheHit,
    /// Content Store insert.
    CacheInsert,
    /// PIT entry created.
    PitInsert,
    /// PIT entry satisfied.
    PitSatisfy,
    /// PIT entry expired.
    PitExpire,
    /// Nack received.
    NackIn,
    /// Nack sent.
    NackOut,
    /// Face created.
    FaceUp,
    /// Face destroyed.
    FaceDown,
    /// Strategy decision.
    StrategyDecision,
    /// Custom event.
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

/// Thread-safe event recorder for simulation runs.
///
/// Create one per simulation, pass references to components that need to
/// record events, then retrieve the full event log after the run.
pub struct SimTracer {
    start: Instant,
    events: Mutex<Vec<SimEvent>>,
}

impl SimTracer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }

    /// Record a pre-built event.
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
        let ts = self.start.elapsed().as_micros() as u64;
        self.record(SimEvent {
            timestamp_us: ts,
            node,
            face,
            kind,
            name: name.into(),
            detail,
        });
    }

    /// Get a snapshot of all recorded events.
    pub fn events(&self) -> Vec<SimEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Number of recorded events.
    pub fn len(&self) -> usize {
        self.events.lock().unwrap().len()
    }

    /// Whether any events have been recorded.
    pub fn is_empty(&self) -> bool {
        self.events.lock().unwrap().is_empty()
    }

    /// Clear all recorded events.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }

    /// Filter events by node.
    pub fn events_for_node(&self, node: usize) -> Vec<SimEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.node == node)
            .cloned()
            .collect()
    }

    /// Filter events by kind.
    pub fn events_of_kind(&self, kind: &EventKind) -> Vec<SimEvent> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| &e.kind == kind)
            .cloned()
            .collect()
    }

    /// Serialize all events to JSON lines format.
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
