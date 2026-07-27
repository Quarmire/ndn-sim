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
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RadioDelivery {
    pub t_ns: u64,
    pub from: NodeId,
    pub to: NodeId,
    pub delivered: bool,
    pub reason: DeliveryReason,
    pub rssi_dbm: f64,
    pub distance_m: f64,
    /// Frame length in bytes — carried so the log can produce delivered-bits/s (goodput), not just
    /// a delivery fraction. Without it the quantitative side of the log is blind to throughput.
    pub frame_len: usize,
}

/// Aggregate throughput/goodput over a window of the log, in bits per second, plus the delivery
/// fraction the goodput is a fraction of. `offered` is every attempted frame's bits; `goodput` is
/// only the delivered ones. Computed over the `[first_t, last_t]` span the records actually cover.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Throughput {
    pub offered_bps: f64,
    pub goodput_bps: f64,
    pub delivery_fraction: f64,
    pub span_ns: u64,
}

/// Compute [`Throughput`] over a filtered set of records (e.g. one `(from,to)` pair, or all of them).
/// Returns `None` if fewer than two records (no time span to divide by).
pub fn throughput(recs: &[RadioDelivery]) -> Option<Throughput> {
    if recs.len() < 2 {
        return None;
    }
    let first = recs.iter().map(|r| r.t_ns).min()?;
    let last = recs.iter().map(|r| r.t_ns).max()?;
    let span_ns = last.saturating_sub(first).max(1);
    let secs = span_ns as f64 / 1e9;
    let offered_bits: u64 = recs.iter().map(|r| r.frame_len as u64 * 8).sum();
    let delivered_bits: u64 =
        recs.iter().filter(|r| r.delivered).map(|r| r.frame_len as u64 * 8).sum();
    let attempts = recs.len() as f64;
    let delivered = recs.iter().filter(|r| r.delivered).count() as f64;
    Some(Throughput {
        offered_bps: offered_bits as f64 / secs,
        goodput_bps: delivered_bits as f64 / secs,
        delivery_fraction: delivered / attempts,
        span_ns,
    })
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
            a.0,
            b.0,
            cause.describe(),
            r.distance_m,
            r.rssi_dbm
        ),
        _ => format!(
            "node {} → node {}: {delivered}/{attempts} frames delivered",
            a.0, b.0
        ),
    };

    Explanation {
        question,
        verdict,
        dominant_cause,
        attempts,
        delivered,
        detail,
    }
}

// ---------------------------------------------------------------------------
// Cross-run diff (axis 4, 4b) — pinpoint AND explain where two runs diverge
// ---------------------------------------------------------------------------

use crate::telemetry::MetricsSample;

/// A run's observable outputs, captured for later comparison. Serialize it, commit it, diff it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RunCapture {
    /// Terminal per-node metrics.
    pub metrics: Vec<MetricsSample>,
    /// Successful fetches by app spawn-index.
    pub app_successes: BTreeMap<usize, u64>,
    /// Recorded radio delivery decisions (empty unless capture was enabled).
    #[serde(default)]
    pub radio: Vec<RadioDelivery>,
}

impl RunCapture {
    pub fn from_json(s: &str) -> anyhow::Result<Self> {
        serde_json::from_str(s).map_err(Into::into)
    }
    pub fn to_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Delivery rate on link `from → to` and its dominant failure cause (over recorded evidence).
    fn link_rate(&self, from: NodeId, to: NodeId) -> Option<(f64, Option<DeliveryReason>, usize)> {
        let recs: Vec<&RadioDelivery> = self
            .radio
            .iter()
            .filter(|r| r.from == from && r.to == to)
            .collect();
        if recs.is_empty() {
            return None;
        }
        let delivered = recs.iter().filter(|r| r.delivered).count();
        let mut causes: BTreeMap<DeliveryReason, usize> = BTreeMap::new();
        for r in recs.iter().filter(|r| !r.delivered) {
            *causes.entry(r.reason).or_default() += 1;
        }
        let dominant = causes.iter().max_by_key(|(_, n)| **n).map(|(r, _)| *r);
        Some((delivered as f64 / recs.len() as f64, dominant, recs.len()))
    }

    /// Every radio link `(from, to)` that appears in the capture.
    fn links(&self) -> std::collections::BTreeSet<(NodeId, NodeId)> {
        self.radio.iter().map(|r| (r.from, r.to)).collect()
    }
}

/// A per-app fetch-success change between two runs.
#[derive(Clone, Debug, Serialize)]
pub struct AppDelta {
    pub app: usize,
    pub baseline: u64,
    pub candidate: u64,
}

/// A radio link whose delivery rate changed — with the candidate run's dominant failure cause.
#[derive(Clone, Debug, Serialize)]
pub struct LinkDelta {
    pub from: usize,
    pub to: usize,
    pub baseline_rate: f64,
    pub candidate_rate: f64,
    /// Why the candidate's frames failed (the dominant recorded cause).
    pub candidate_cause: Option<DeliveryReason>,
}

/// A per-node counter that changed beyond tolerance.
#[derive(Clone, Debug, Serialize)]
pub struct MetricDelta {
    pub node: usize,
    pub field: &'static str,
    pub baseline: i64,
    pub candidate: i64,
}

/// The structured, explained difference between two runs.
#[derive(Clone, Debug, Serialize)]
pub struct RunDiff {
    pub identical: bool,
    pub app_deltas: Vec<AppDelta>,
    /// Links whose delivery rate moved by more than `link_tolerance`, worst first.
    pub link_deltas: Vec<LinkDelta>,
    pub metric_deltas: Vec<MetricDelta>,
    /// A ranked, human-readable summary.
    pub summary: String,
}

/// Diff two runs and *explain* where they diverge: app-success changes, radio links that degraded
/// (with the causal reason from the candidate), and per-node counter deltas. `link_tolerance` is the
/// minimum delivery-rate change (0.0–1.0) worth reporting.
pub fn diff_runs(baseline: &RunCapture, candidate: &RunCapture, link_tolerance: f64) -> RunDiff {
    // App-success deltas.
    let mut app_deltas = Vec::new();
    let apps: std::collections::BTreeSet<usize> = baseline
        .app_successes
        .keys()
        .chain(candidate.app_successes.keys())
        .copied()
        .collect();
    for app in apps {
        let b = baseline.app_successes.get(&app).copied().unwrap_or(0);
        let c = candidate.app_successes.get(&app).copied().unwrap_or(0);
        if b != c {
            app_deltas.push(AppDelta {
                app,
                baseline: b,
                candidate: c,
            });
        }
    }

    // Radio link delivery-rate deltas (with the candidate's dominant cause).
    let mut link_deltas = Vec::new();
    let links: std::collections::BTreeSet<(NodeId, NodeId)> = baseline
        .links()
        .union(&candidate.links())
        .copied()
        .collect();
    for (from, to) in links {
        let br = baseline
            .link_rate(from, to)
            .map(|(r, _, _)| r)
            .unwrap_or(0.0);
        let (cr, cause) = candidate
            .link_rate(from, to)
            .map(|(r, cause, _)| (r, cause))
            .unwrap_or((0.0, None));
        if (br - cr).abs() > link_tolerance {
            link_deltas.push(LinkDelta {
                from: from.0,
                to: to.0,
                baseline_rate: br,
                candidate_rate: cr,
                candidate_cause: cause,
            });
        }
    }
    // Worst degradation first.
    link_deltas.sort_by(|a, b| {
        (a.candidate_rate - a.baseline_rate)
            .partial_cmp(&(b.candidate_rate - b.baseline_rate))
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Per-node counter deltas over the meaningful fields.
    let metric_deltas = diff_metrics(&baseline.metrics, &candidate.metrics);

    let identical = app_deltas.is_empty() && link_deltas.is_empty() && metric_deltas.is_empty();
    let summary = summarize(&app_deltas, &link_deltas, &metric_deltas, identical);

    RunDiff {
        identical,
        app_deltas,
        link_deltas,
        metric_deltas,
        summary,
    }
}

/// A named counter accessor over a metrics sample.
type Field = (&'static str, fn(&MetricsSample) -> i64);

fn diff_metrics(base: &[MetricsSample], cand: &[MetricsSample]) -> Vec<MetricDelta> {
    let fields: &[Field] = &[
        ("in_data", |s| s.in_data as i64),
        ("out_data", |s| s.out_data as i64),
        ("out_drops", |s| s.out_drops as i64),
        ("cs_hits", |s| s.cs_hits as i64),
        ("cs_misses", |s| s.cs_misses as i64),
        ("pit_depth", |s| s.pit_depth as i64),
    ];
    let by_node = |m: &[MetricsSample]| -> BTreeMap<usize, MetricsSample> {
        m.iter().map(|s| (s.node.0, s.clone())).collect()
    };
    let (b, c) = (by_node(base), by_node(cand));
    let nodes: std::collections::BTreeSet<usize> = b.keys().chain(c.keys()).copied().collect();
    let mut out = Vec::new();
    for node in nodes {
        let (bs, cs) = (b.get(&node), c.get(&node));
        for (field, get) in fields {
            let bv = bs.map(get).unwrap_or(0);
            let cv = cs.map(get).unwrap_or(0);
            if bv != cv {
                out.push(MetricDelta {
                    node,
                    field,
                    baseline: bv,
                    candidate: cv,
                });
            }
        }
    }
    out
}

fn summarize(
    apps: &[AppDelta],
    links: &[LinkDelta],
    metrics: &[MetricDelta],
    identical: bool,
) -> String {
    if identical {
        return "the two runs are identical".to_string();
    }
    let mut lines = Vec::new();
    for a in apps {
        lines.push(format!(
            "app {} fetched {} vs {} ({:+})",
            a.app,
            a.candidate,
            a.baseline,
            a.candidate as i64 - a.baseline as i64
        ));
    }
    for l in links {
        let cause = l
            .candidate_cause
            .map(|c| format!(" — {}", c.describe()))
            .unwrap_or_default();
        lines.push(format!(
            "radio {}→{}: delivery {:.0}% vs {:.0}%{}",
            l.from,
            l.to,
            l.candidate_rate * 100.0,
            l.baseline_rate * 100.0,
            cause
        ));
    }
    if !metrics.is_empty() {
        lines.push(format!("{} node counter(s) changed", metrics.len()));
    }
    lines.join("; ")
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
            frame_len: 100,
        }
    }

    #[test]
    fn throughput_splits_offered_from_goodput() {
        // Four 100-byte frames over a 3 ms span; two delivered. Offered counts all, goodput only the
        // delivered half, and the delivery fraction ties them together.
        let recs = vec![
            RadioDelivery { t_ns: 0, frame_len: 100, delivered: true, ..rec(1, 2, true, DeliveryReason::Delivered) },
            RadioDelivery { t_ns: 1_000_000, frame_len: 100, delivered: false, ..rec(1, 2, false, DeliveryReason::Collision) },
            RadioDelivery { t_ns: 2_000_000, frame_len: 100, delivered: true, ..rec(1, 2, true, DeliveryReason::Delivered) },
            RadioDelivery { t_ns: 3_000_000, frame_len: 100, delivered: false, ..rec(1, 2, false, DeliveryReason::Erased) },
        ];
        let t = throughput(&recs).expect("span");
        assert_eq!(t.span_ns, 3_000_000);
        assert_eq!(t.delivery_fraction, 0.5);
        // offered = 4·100·8 bits / 3 ms = 1.0667 Mb/s; goodput = half that.
        assert!((t.offered_bps - 1_066_666.6).abs() < 1.0, "offered={}", t.offered_bps);
        assert!((t.goodput_bps - t.offered_bps / 2.0).abs() < 1.0);
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
