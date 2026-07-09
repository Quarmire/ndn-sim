//! The **ceiling-finder** — instrument (a) of the field bench suite (skyfall
//! `FIELD-REPORT-2.md` §7; (c) the liveness watchdog is [`crate::liveness`], (b) the adversary
//! bench is separate). This is performance: find where the framework's numbers *bend*.
//!
//! ## The design crux: record numbers, assert SHAPES
//!
//! A bench that CI-asserts "X µs" is flaky across hardware and gets muted; one that asserts a
//! **shape** is a durable tripwire. So the scoreboard **records** absolute metrics (JSON,
//! seed per cell, for humans and bisection) while CI **asserts** only bounds of these kinds:
//!
//! - **growth bounds** ([`growth_bound`]): "per-event cost is flat vs history", "catch-up is
//!   roughly linear in backlog, not quadratic" — a ratio between two sweep points against a
//!   generous ceiling. Red-capable by construction: a deliberately O(history)-per-event
//!   consumer (the NS-4 field bug's shape) trips the flat bound.
//! - **knees** ([`find_knee`]): sweep a dimension (chains per node, peers per group) and
//!   report the first point where per-unit cost bends past a factor of the baseline — the
//!   number nobody has until it is *found*. A knee outside the sweep is reported honestly as
//!   "none ≤ N", never assumed.
//! - optional **baseline ratios** (a recorded scoreboard diffed by CI at generous ×
//!   tolerances) — the mechanism is the normative projection; wiring a committed baseline is
//!   the CI side's choice.
//!
//! ## What macro time means here
//!
//! Macro cells run real `ForwarderEngine`s on the deterministic `VirtualKernel`, so a
//! "duration" is **virtual time**: protocol shape — round trips, re-advertisement cadence,
//! pipelining, per-event modeled costs — not host CPU. That is exactly what makes the numbers
//! deterministic, seedable, and bisectable. Host-CPU per-op costs (encode/verify/gate) belong
//! to the **micro tier**: criterion benches living in the measured crates (ndf-core,
//! ndf-policy, render-contract, ndn-compute).
//!
//! Reuses instrument (c)'s framework rather than forking it: the same [`Ledger`] truth, the
//! same fieldkit consumers, the same seed-per-cell + normative-projection discipline
//! ([`PerfCell::normative`] mirrors `CellReport::normative` — verdicts are deterministic, raw
//! counters are diagnostic under tokio's unseeded `select!` RNG).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::fieldkit::TwoPhaseReplica;
use crate::liveness::Ledger;

/// One shape assertion's verdict — the only thing CI keys on.
#[derive(Debug, Clone, Serialize)]
pub struct BoundCheck {
    /// Stable bound id, e.g. `ingest-flat-vs-history`.
    pub name: String,
    /// What shape this asserts, human-readable.
    pub claim: String,
    /// The measured evidence (ratios, knee points) — diagnostic.
    pub detail: String,
    pub pass: bool,
}

/// A shape bound over two sweep points: when the driving dimension grew by `dim_factor`, the
/// metric may grow by at most `max_ratio`. Generous ceilings on purpose — the assertion is
/// qualitative ("flat", "linear-ish, not quadratic"), the recorded metrics carry the precision.
pub fn growth_bound(
    name: &str,
    claim: &str,
    low: (u64, f64),
    high: (u64, f64),
    max_ratio: f64,
) -> BoundCheck {
    let ratio = if low.1 > 0.0 { high.1 / low.1 } else { f64::INFINITY };
    BoundCheck {
        name: name.into(),
        claim: claim.into(),
        detail: format!(
            "metric {:.3} @ n={} → {:.3} @ n={} (ratio {:.2}, bound {max_ratio})",
            low.1, low.0, high.1, high.0, ratio
        ),
        pass: ratio <= max_ratio,
    }
}

/// Find the **knee** of a per-unit-cost curve: the first sweep point whose per-unit cost
/// exceeds `knee_factor ×` the first point's. `None` = linear (to within the factor) across
/// the whole sweep — report it as "no knee ≤ max(n)", never extrapolate one.
pub fn find_knee(series: &[(u64, f64)], knee_factor: f64) -> Option<u64> {
    let base = series.first()?.1;
    if base <= 0.0 {
        return None;
    }
    series
        .iter()
        .find(|(_, cost)| *cost > base * knee_factor)
        .map(|(n, _)| *n)
}

/// One perf cell's record: absolute metrics (recorded, never CI-asserted) + shape bounds (the
/// tripwire) + the seed that reproduces the run.
#[derive(Debug, Clone, Serialize)]
pub struct PerfCell {
    pub cell: String,
    pub seed: u64,
    /// Absolute numbers, for humans/bisection: virtual durations (ms), rates, curve points,
    /// percentiles, bytes. Diagnostic — a different host or tokio version may wiggle them.
    pub metrics: BTreeMap<String, f64>,
    /// The shape assertions — what CI trips on.
    pub bounds: Vec<BoundCheck>,
    /// All bounds pass.
    pub pass: bool,
}

impl PerfCell {
    pub fn new(cell: impl Into<String>, seed: u64) -> Self {
        Self {
            cell: cell.into(),
            seed,
            metrics: BTreeMap::new(),
            bounds: Vec::new(),
            pass: true,
        }
    }

    /// Record an absolute metric (diagnostic).
    pub fn metric(&mut self, name: impl Into<String>, value: f64) {
        self.metrics.insert(name.into(), value);
    }

    /// Add a shape bound's verdict (normative).
    pub fn bound(&mut self, check: BoundCheck) {
        self.pass &= check.pass;
        self.bounds.push(check);
    }

    /// The deterministic CI-tripwire projection: cell, seed, and each bound's verdict — no
    /// raw numbers (same discipline as `liveness::CellReport::normative`).
    pub fn normative(&self) -> String {
        let mut s = format!("{}|seed={}", self.cell, self.seed);
        for b in &self.bounds {
            s.push_str(&format!("|{}={}", b.name, b.pass));
        }
        s.push_str(&format!("|pass={}", self.pass));
        s
    }
}

/// The perf scoreboard — instrument (a)'s sibling of `liveness::Scoreboard`, same JSON/seed
/// conventions, one artifact per run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct PerfBoard {
    pub cells: Vec<PerfCell>,
}

impl PerfBoard {
    pub fn push(&mut self, cell: PerfCell) {
        self.cells.push(cell);
    }
    pub fn all_pass(&self) -> bool {
        self.cells.iter().all(|c| c.pass)
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("perf board serializes")
    }
}

/// Await the ledger's backlog for `replicas` reaching zero (sustained one extra tick), and
/// return the **virtual time** it took. The measurement primitive for ingest / late-join /
/// knee cells. Panics after `budget` — a ceiling cell is not a liveness test; a hang here is
/// a broken cell, and instrument (c) owns stall semantics.
pub async fn time_to_drain(ledger: &Ledger, replicas: &[String], budget: Duration) -> Duration {
    let start = tokio::time::Instant::now();
    let tick = Duration::from_millis(50);
    let mut zero_streak = 0u32;
    loop {
        tokio::time::sleep(tick).await;
        if ledger.backlog(replicas) == 0 {
            zero_streak += 1;
            if zero_streak >= 2 {
                // Subtract the confirmation ticks — they are probe overhead, not drain time.
                return start.elapsed().saturating_sub(tick * zero_streak);
            }
        } else {
            zero_streak = 0;
        }
        assert!(
            start.elapsed() < budget,
            "ceiling cell exceeded its budget while draining — this is a broken cell \
             (liveness/stall semantics live in instrument (c))"
        );
    }
}

/// A consumer loop for latency cells: fetch + store each advertised seq and stamp its arrival
/// (virtual) instant into `arrivals`. Percentiles come from pairing these with the publish
/// stamps the workload records.
pub async fn latency_catchup(
    replica: TwoPhaseReplica,
    ledger: Arc<Ledger>,
    replica_name: String,
    arrivals: Arc<std::sync::Mutex<BTreeMap<u64, tokio::time::Instant>>>,
) {
    let mut replica = replica;
    while let Some(update) = replica.handle.recv().await {
        for seq in update.low_seq..=update.high_seq {
            let Some(bytes) = replica.fetch(&update.name, seq).await else {
                break;
            };
            if ledger.record_stored(&replica_name, &update.publisher, seq, &bytes) {
                arrivals
                    .lock()
                    .unwrap()
                    .entry(seq)
                    .or_insert_with(tokio::time::Instant::now);
                ledger.record_reported(&replica_name);
            }
            let _ = replica.handle.ack(&update.publisher, seq).await;
            ledger.record_ack();
        }
    }
}

/// A percentile over an unsorted sample set (nearest-rank). `q` in [0,1].
pub fn percentile(samples: &mut [f64], q: f64) -> f64 {
    if samples.is_empty() {
        return f64::NAN;
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let rank = ((q * samples.len() as f64).ceil() as usize).clamp(1, samples.len());
    samples[rank - 1]
}
