//! # Causal analysis (axis 4) — observability that *explains*, not just shows
//!
//! The observability primitives (span capture, the event tracer, metrics, OTLP export) can *show*
//! what happened. The gap this closes: *why* did it happen? The #1 failure mode in a co-simulated
//! radio scenario — a frame dropped because a drone flew out of range or behind a building — was
//! previously only an ephemeral `trace!` log. Here it becomes **evidence**: every radio delivery
//! decision is recorded with its [`DeliveryReason`], and [`explain_link`] walks that evidence to
//! answer "why couldn't node A reach node B?" grounded in the physical state (reason, distance, RSSI).
//!
//! Attach a [`RadioLog`] with [`RunningSimulation::capture_radio`](crate::RunningSimulation::capture_radio),
//! run the scenario, then ask.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::medium::DeliveryReason;
use crate::topology::NodeId;

/// One recorded radio delivery attempt — the causal record for a `(from → to)` frame.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct RadioDelivery {
    pub t_ns: u64,
    pub from: NodeId,
    pub to: NodeId,
    pub delivered: bool,
    pub reason: DeliveryReason,
    pub rssi_dbm: f64,
    pub distance_m: f64,
}

/// An append-only log of radio delivery decisions. Attach it to a running fabric via
/// [`capture_radio`](crate::RunningSimulation::capture_radio); query it after (or during) a run.
#[derive(Default)]
pub struct RadioLog {
    records: Mutex<Vec<RadioDelivery>>,
}

impl RadioLog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
    pub fn record(&self, d: RadioDelivery) {
        self.records.lock().unwrap().push(d);
    }
    pub fn records(&self) -> Vec<RadioDelivery> {
        self.records.lock().unwrap().clone()
    }
    pub fn len(&self) -> usize {
        self.records.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.records.lock().unwrap().is_empty()
    }
    /// Every recorded delivery attempt from `from` to `to`.
    pub fn for_pair(&self, from: NodeId, to: NodeId) -> Vec<RadioDelivery> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.from == from && r.to == to)
            .copied()
            .collect()
    }
}

/// The overall outcome of a link over a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkVerdict {
    /// Every attempt arrived.
    Delivered,
    /// Some arrived, some didn't.
    Intermittent,
    /// Attempts were made but none arrived.
    Failed,
    /// No frame ever reached within radio range (out of range the whole time).
    NoSignal,
}

/// A causal explanation of a radio link's behaviour — the "why" grounded in recorded evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Explanation {
    pub question: String,
    pub verdict: LinkVerdict,
    /// The dominant *failure* cause (`None` when delivered or no attempts).
    pub dominant_cause: Option<DeliveryReason>,
    pub attempts: usize,
    pub delivered: usize,
    /// A human sentence.
    pub detail: String,
}

/// Explain the radio link `a → b` over `log`: the dominant outcome + a sentence grounded in the
/// recorded reason, distance, and RSSI — the axis-4 "why did this fetch fail?" answer.
pub fn explain_link(log: &RadioLog, a: NodeId, b: NodeId) -> Explanation {
    let question = format!("could node {} reach node {} over the radio?", a.0, b.0);
    let recs = log.for_pair(a, b);
    if recs.is_empty() {
        return Explanation {
            question,
            verdict: LinkVerdict::NoSignal,
            dominant_cause: Some(DeliveryReason::OutOfRange),
            attempts: 0,
            delivered: 0,
            detail: format!(
                "no frame from node {} ever reached within radio range of node {} — out of range throughout",
                a.0, b.0
            ),
        };
    }
    let attempts = recs.len();
    let delivered = recs.iter().filter(|r| r.delivered).count();

    // Tally the failure causes and pick the dominant one.
    let mut causes: BTreeMap<DeliveryReason, usize> = BTreeMap::new();
    for r in recs.iter().filter(|r| !r.delivered) {
        *causes.entry(r.reason).or_default() += 1;
    }
    let dominant_cause = causes.iter().max_by_key(|(_, n)| **n).map(|(r, _)| *r);

    let verdict = if delivered == attempts {
        LinkVerdict::Delivered
    } else if delivered > 0 {
        LinkVerdict::Intermittent
    } else {
        LinkVerdict::Failed
    };

    // A representative failing record (the last one) for distance/RSSI context.
    let last_fail = recs.iter().rev().find(|r| !r.delivered);
    let detail = match (verdict, dominant_cause, last_fail) {
        (LinkVerdict::Delivered, _, _) => format!(
            "node {} reached node {} on all {attempts} attempts",
            a.0, b.0
        ),
        (_, Some(cause), Some(r)) => format!(
            "node {} → node {}: {delivered}/{attempts} frames delivered; dominant cause = {} (at ~{:.0} m, RSSI ~{:.0} dBm)",
            a.0, b.0, cause.describe(), r.distance_m, r.rssi_dbm
        ),
        _ => format!("node {} → node {}: {delivered}/{attempts} frames delivered", a.0, b.0),
    };

    Explanation { question, verdict, dominant_cause, attempts, delivered, detail }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(from: usize, to: usize, delivered: bool, reason: DeliveryReason) -> RadioDelivery {
        RadioDelivery {
            t_ns: 0,
            from: NodeId(from),
            to: NodeId(to),
            delivered,
            reason,
            rssi_dbm: -70.0,
            distance_m: 50.0,
        }
    }

    #[test]
    fn explains_the_dominant_failure_cause() {
        let log = RadioLog::default();
        log.record(rec(1, 0, true, DeliveryReason::Delivered));
        log.record(rec(1, 0, false, DeliveryReason::Obstructed));
        log.record(rec(1, 0, false, DeliveryReason::Obstructed));
        log.record(rec(1, 0, false, DeliveryReason::Erased));
        let e = explain_link(&log, NodeId(1), NodeId(0));
        assert_eq!(e.verdict, LinkVerdict::Intermittent);
        assert_eq!(e.dominant_cause, Some(DeliveryReason::Obstructed));
        assert_eq!((e.attempts, e.delivered), (4, 1));
    }

    #[test]
    fn absence_of_records_is_out_of_range() {
        let log = RadioLog::default();
        let e = explain_link(&log, NodeId(2), NodeId(3));
        assert_eq!(e.verdict, LinkVerdict::NoSignal);
        assert_eq!(e.dominant_cause, Some(DeliveryReason::OutOfRange));
    }
}
