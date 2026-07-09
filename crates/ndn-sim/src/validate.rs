//! # Validation / assertion platform (axis 2)
//!
//! Scenarios don't just *run* — they can *prove properties*. A [`ValidationSpec`] pairs a
//! [`Scenario`] with a declarative fault schedule and a set of [`Property`] assertions, then runs
//! the whole thing headless on a deterministic kernel and reports pass/fail.
//!
//! The pieces are all serializable, so a validation is a file you check into the repo and run in CI:
//!
//! ```toml
//! duration_ms = 3000
//! kernels     = ["des", "virtual"]      # prove it holds on BOTH executors
//!
//! [scenario.kernel]
//! kind = "des"
//! # ... the rest of a normal scenario (nodes/links/routes/radio) ...
//!
//! [[faults]]                            # kill the relay 1s in
//! at_ms = 1000
//! fault = { kind = "remove_node", node = 1 }
//!
//! [[properties]]                        # the consumer still completes
//! name  = "consumer fetches all 20 segments"
//! probe = { kind = "app_successes", app = 0 }
//! cmp   = "ge"
//! value = 20
//!
//! [[properties]]                        # and leaves no dangling PIT state
//! name  = "no PIT leak anywhere"
//! probe = { kind = "metric", field = "pit_depth", agg = "max" }
//! cmp   = "eq"
//! value = 0
//! ```
//!
//! Run it with `ndn-lab check spec.toml`, or from Rust via [`run_validation`].
//!
//! ## What this layer guarantees
//! - **Deterministic**: every run is on a [`DesKernel`](crate::DesKernel) /
//!   [`VirtualKernel`](crate::VirtualKernel) — the same input yields the same verdict.
//! - **Cross-executor agreement**: when more than one kernel is requested, the runner also checks
//!   that the counters *agree* across executors (ignoring wall-of-virtual-time). A divergence there
//!   is itself a finding — the two schedulers disagree about what the network did.
//! - **Fault injection on a virtual clock**: faults fire at exact virtual millisecond offsets, so a
//!   "kill the relay at t=1s" fault lands at the same logical instant on every run.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::app::{AppId, AppSpec};
use crate::scenario::Scenario;
use crate::sim_link::LinkConfig;
use crate::telemetry::{MetricsSample, compare_metrics};
use crate::topology::{NodeId, RunningSimulation};
use crate::{DesKernel, SimKernel, VirtualKernel};

// ---------------------------------------------------------------------------
// Probes — reduce the terminal fabric state to a scalar
// ---------------------------------------------------------------------------

/// A per-node counter field on a [`MetricsSample`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricField {
    InInterests,
    OutInterests,
    InData,
    OutData,
    OutDrops,
    InBytes,
    OutBytes,
    PitDepth,
    CsHits,
    CsMisses,
    CsInserts,
    CsEvictions,
    CsEntries,
    CsBytes,
    /// `cs_hits / (cs_hits + cs_misses)` for the selected node(s) — a ratio in `[0, 1]`.
    CsHitRate,
}

impl MetricField {
    fn read(self, s: &MetricsSample) -> f64 {
        match self {
            MetricField::InInterests => s.in_interests as f64,
            MetricField::OutInterests => s.out_interests as f64,
            MetricField::InData => s.in_data as f64,
            MetricField::OutData => s.out_data as f64,
            MetricField::OutDrops => s.out_drops as f64,
            MetricField::InBytes => s.in_bytes as f64,
            MetricField::OutBytes => s.out_bytes as f64,
            MetricField::PitDepth => s.pit_depth as f64,
            MetricField::CsHits => s.cs_hits as f64,
            MetricField::CsMisses => s.cs_misses as f64,
            MetricField::CsInserts => s.cs_inserts as f64,
            MetricField::CsEvictions => s.cs_evictions as f64,
            MetricField::CsEntries => s.cs_entries as f64,
            MetricField::CsBytes => s.cs_bytes as f64,
            MetricField::CsHitRate => s.cs_hit_rate(),
        }
    }
}

/// How to combine a [`MetricField`] across nodes when no single node is named.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Agg {
    /// Sum over all nodes (the default — network-wide totals).
    #[default]
    Sum,
    Max,
    Min,
    /// Arithmetic mean over all nodes.
    Mean,
}

/// A scalar reading over the terminal state of a run.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Probe {
    /// Successful fetches counted by the consumer app at scenario spawn-index `app`.
    AppSuccesses { app: usize },
    /// A [`MetricField`], read from node `node` (by scenario index) or aggregated across all nodes.
    Metric {
        field: MetricField,
        #[serde(default)]
        node: Option<usize>,
        #[serde(default)]
        agg: Agg,
    },
    /// A [`FlowField`] of the app at scenario spawn-index `app` — RTT / loss / goodput. The
    /// benchmark gate: assert "mean RTT < X ms" or "goodput > Y bps" over a workload.
    Flow { app: usize, field: FlowField },
}

/// A field of an app's [`FlowStats`](crate::app::FlowStats), for a [`Probe::Flow`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowField {
    Sent,
    Received,
    Lost,
    Bytes,
    /// Fraction of requests that timed out, in `[0,1]`.
    LossRate,
    /// Mean round-trip time, milliseconds.
    MeanRttMs,
    /// Max round-trip time, milliseconds.
    MaxRttMs,
    /// Goodput, bits/sec, over the receive window.
    ThroughputBps,
}

impl FlowField {
    fn read(self, s: &crate::app::FlowStats) -> f64 {
        match self {
            FlowField::Sent => s.sent as f64,
            FlowField::Received => s.received as f64,
            FlowField::Lost => s.lost as f64,
            FlowField::Bytes => s.bytes as f64,
            FlowField::LossRate => s.loss_rate(),
            FlowField::MeanRttMs => s.mean_rtt_ms(),
            FlowField::MaxRttMs => s.max_rtt_ms(),
            FlowField::ThroughputBps => s.throughput_bps(),
        }
    }
}

impl Probe {
    /// Evaluate against an [`Observation`]. `None` ⇒ the probe references something that wasn't
    /// observed (missing app / node), which a [`Property`] treats as a failure.
    pub fn eval(&self, obs: &Observation) -> Option<f64> {
        match self {
            Probe::AppSuccesses { app } => obs.app_successes.get(app).map(|&n| n as f64),
            Probe::Flow { app, field } => obs.flow_stats.get(app).map(|s| field.read(s)),
            Probe::Metric { field, node, agg } => match node {
                Some(idx) => obs
                    .metrics
                    .iter()
                    .find(|s| s.node.0 == *idx)
                    .map(|s| field.read(s)),
                None => {
                    if obs.metrics.is_empty() {
                        return None;
                    }
                    let vals = obs.metrics.iter().map(|s| field.read(s));
                    Some(match agg {
                        Agg::Sum => vals.sum(),
                        Agg::Max => vals.fold(f64::NEG_INFINITY, f64::max),
                        Agg::Min => vals.fold(f64::INFINITY, f64::min),
                        Agg::Mean => {
                            let n = obs.metrics.len() as f64;
                            vals.sum::<f64>() / n
                        }
                    })
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Properties — a comparison a run must satisfy
// ---------------------------------------------------------------------------

/// The comparison a [`Property`] applies between the observed probe value and its threshold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Cmp {
    Ge,
    Gt,
    Le,
    Lt,
    Eq,
    Ne,
}

impl Cmp {
    fn test(self, observed: f64, threshold: f64) -> bool {
        match self {
            Cmp::Ge => observed >= threshold,
            Cmp::Gt => observed > threshold,
            Cmp::Le => observed <= threshold,
            Cmp::Lt => observed < threshold,
            Cmp::Eq => observed == threshold,
            Cmp::Ne => observed != threshold,
        }
    }

    fn symbol(self) -> &'static str {
        match self {
            Cmp::Ge => ">=",
            Cmp::Gt => ">",
            Cmp::Le => "<=",
            Cmp::Lt => "<",
            Cmp::Eq => "==",
            Cmp::Ne => "!=",
        }
    }
}

/// A named assertion: `probe <cmp> value` must hold at the end of the run.
///
/// Under a seed sweep the assertion is checked on every seed. `hold_ratio` (default `1.0`) is the
/// fraction of seeds on which it must hold for the property to pass: `1.0` is an **invariant** (must
/// hold on every realization); a value like `0.9` makes it a **statistical** property (holds on at
/// least 90% of realizations) — the kind of claim a single deterministic run cannot make.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    pub probe: Probe,
    pub cmp: Cmp,
    pub value: f64,
    #[serde(default = "default_hold_ratio")]
    pub hold_ratio: f64,
}

fn default_hold_ratio() -> f64 {
    1.0
}

impl Property {
    /// Whether the property holds on one observation, plus the observed probe value.
    fn check(&self, obs: &Observation) -> (Option<f64>, bool) {
        let observed = self.probe.eval(obs);
        let held = observed
            .map(|o| self.cmp.test(o, self.value))
            .unwrap_or(false);
        (observed, held)
    }

    /// Aggregate the property across a sweep's observations into a verdict.
    fn evaluate(&self, obs: &[Observation]) -> PropertyResult {
        let mut values: Vec<f64> = Vec::new();
        let mut held = 0u64;
        for o in obs {
            let (observed, ok) = self.check(o);
            if let Some(v) = observed {
                values.push(v);
            }
            if ok {
                held += 1;
            }
        }
        let total = obs.len() as u64;
        let ratio = if total == 0 {
            0.0
        } else {
            held as f64 / total as f64
        };
        let (observed_min, observed_max, observed_mean) = if values.is_empty() {
            (None, None, None)
        } else {
            let min = values.iter().copied().fold(f64::INFINITY, f64::min);
            let max = values.iter().copied().fold(f64::NEG_INFINITY, f64::max);
            let mean = values.iter().sum::<f64>() / values.len() as f64;
            (Some(min), Some(max), Some(mean))
        };
        PropertyResult {
            name: self.name.clone(),
            cmp: self.cmp,
            threshold: self.value,
            hold_ratio: self.hold_ratio,
            held,
            total,
            observed_min,
            observed_max,
            observed_mean,
            passed: ratio >= self.hold_ratio,
        }
    }
}

// ---------------------------------------------------------------------------
// Faults — a scheduled perturbation applied at a virtual instant
// ---------------------------------------------------------------------------

/// A perturbation applied to the running fabric. Node/app indices are scenario spawn-order indices.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fault {
    /// Remove a node and every link attached to it (partition / node death).
    RemoveNode { node: usize },
    /// Stop the app at spawn-index `app` (producer/consumer churn).
    StopApp { app: usize },
    /// Start a new app on `node` (recovery / late join). Its index is appended after existing apps.
    SpawnApp { node: usize, app: AppSpec },
    /// Add a link between two nodes (heal a partition / add a backup path).
    Connect {
        a: usize,
        b: usize,
        #[serde(default)]
        delay_ms: u64,
        #[serde(default)]
        jitter_ms: u64,
        #[serde(default)]
        loss_rate: f64,
        #[serde(default)]
        bandwidth_bps: u64,
    },
    /// Install a FIB route (reroute after a topology change).
    Route {
        node: usize,
        prefix: String,
        nexthop: usize,
    },
    /// Teleport a node (mobility step — changes radio link quality on a shared medium).
    MoveNode {
        node: usize,
        x: f64,
        y: f64,
        #[serde(default)]
        z: f64,
    },
    /// Cut or restore an existing link between `a` and `b` (a link failure, then recovery) — unlike
    /// `RemoveNode` this preserves node state and FIB, modelling a flaky link.
    SetLink {
        a: usize,
        b: usize,
        /// `true` = restore, `false` = cut.
        up: bool,
    },
    /// Degrade an existing link: override its loss rate and/or add extra per-frame delay (congestion).
    DegradeLink {
        a: usize,
        b: usize,
        #[serde(default)]
        loss_rate: Option<f64>,
        #[serde(default)]
        delay_ms: Option<u64>,
    },
    /// Partition the network: cut every link crossing the boundary of `nodes`. Heal with [`Fault::Heal`].
    Partition { nodes: Vec<usize> },
    /// Heal all link faults (restore every cut/degraded link to its profile defaults).
    Heal,
}

impl Fault {
    async fn apply(&self, fabric: &RunningSimulation) -> Result<()> {
        match self {
            Fault::RemoveNode { node } => fabric.remove_node(NodeId(*node)).await,
            Fault::StopApp { app } => fabric.stop_app(AppId(*app)),
            Fault::SpawnApp { node, app } => {
                fabric.spawn_app(NodeId(*node), app.clone()).map(|_| ())
            }
            Fault::Connect {
                a,
                b,
                delay_ms,
                jitter_ms,
                loss_rate,
                bandwidth_bps,
            } => fabric.connect(
                NodeId(*a),
                NodeId(*b),
                LinkConfig {
                    delay: Duration::from_millis(*delay_ms),
                    jitter: Duration::from_millis(*jitter_ms),
                    loss_rate: *loss_rate,
                    bandwidth_bps: *bandwidth_bps,
                },
            ),
            Fault::Route {
                node,
                prefix,
                nexthop,
            } => {
                let name = prefix
                    .parse::<ndn_packet::Name>()
                    .with_context(|| format!("fault route prefix {prefix:?}"))?;
                fabric.route(NodeId(*node), &name, NodeId(*nexthop))
            }
            Fault::MoveNode { node, x, y, z } => {
                fabric.move_node(NodeId(*node), crate::world::Position::xyz(*x, *y, *z));
                Ok(())
            }
            Fault::SetLink { a, b, up } => fabric.set_link_up(NodeId(*a), NodeId(*b), *up),
            Fault::DegradeLink { a, b, loss_rate, delay_ms } => fabric.degrade_link(
                NodeId(*a),
                NodeId(*b),
                *loss_rate,
                delay_ms.map(Duration::from_millis),
            ),
            Fault::Partition { nodes } => {
                fabric.partition(&nodes.iter().map(|&n| NodeId(n)).collect::<Vec<_>>());
                Ok(())
            }
            Fault::Heal => {
                fabric.heal();
                Ok(())
            }
        }
    }
}

/// A [`Fault`] paired with the virtual-time offset (from run start) at which it fires. Reads as
/// `at_ms = 1000` alongside `fault = { kind = "remove_node", node = 1 }` in TOML.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScheduledFault {
    pub at_ms: u64,
    pub fault: Fault,
}

// ---------------------------------------------------------------------------
// Baselines — regression gates against a recorded reference
// ---------------------------------------------------------------------------

/// How a candidate value must relate to its recorded baseline.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Candidate must be at least `baseline * (1 - tolerance)` — a throughput floor (the default).
    #[default]
    AtLeast,
    /// Candidate must be at most `baseline * (1 + tolerance)` — an airtime/cost/latency ceiling.
    AtMost,
    /// Candidate must be within `±tolerance` of the baseline — a two-sided drift gate.
    Within,
}

impl Direction {
    fn holds(self, candidate: f64, baseline: f64, tolerance: f64) -> bool {
        match self {
            Direction::AtLeast => candidate >= baseline * (1.0 - tolerance),
            Direction::AtMost => candidate <= baseline * (1.0 + tolerance),
            Direction::Within => (candidate - baseline).abs() <= baseline.abs() * tolerance,
        }
    }

    fn symbol(self) -> &'static str {
        match self {
            Direction::AtLeast => "≥",
            Direction::AtMost => "≤",
            Direction::Within => "±",
        }
    }
}

fn default_tolerance() -> f64 {
    0.05
}

/// A regression gate: the mean of `probe` across the sweep must stay within `tolerance` of a
/// recorded baseline, in the given `direction`. The baseline *value* lives in a separate recorded
/// [`Baseline`] file (write it with `--record-baseline`); this only declares what to compare.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BaselineCheck {
    pub name: String,
    pub probe: Probe,
    /// Fractional tolerance (0.05 = 5%). Default 0.05.
    #[serde(default = "default_tolerance")]
    pub tolerance: f64,
    #[serde(default)]
    pub direction: Direction,
}

/// A recorded set of baseline values (one per [`BaselineCheck`] name) — the reference a later run is
/// gated against. Serialized to JSON, committed next to the spec.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    /// Baseline-check name → recorded value (mean of the probe across the sweep at record time).
    pub values: BTreeMap<String, f64>,
}

impl Baseline {
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).context("parse baseline JSON")
    }
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize baseline JSON")
    }
}

/// The verdict for one regression gate.
#[derive(Clone, Debug, Serialize)]
pub struct RegressionResult {
    pub name: String,
    pub direction: Direction,
    pub tolerance: f64,
    /// The recorded baseline value (`None` if the baseline file had no entry for this name).
    pub baseline: Option<f64>,
    /// The candidate value measured this run (`None` if the probe was never observable).
    pub candidate: Option<f64>,
    /// Signed percent change candidate-vs-baseline, for the human report.
    pub delta_pct: Option<f64>,
    pub passed: bool,
}

impl RegressionResult {
    pub fn summary(&self) -> String {
        let verdict = if self.passed { "PASS" } else { "FAIL" };
        match (self.baseline, self.candidate) {
            (Some(b), Some(c)) => {
                let delta = self.delta_pct.unwrap_or(0.0);
                format!(
                    "{verdict}  {} ({c:.2} vs baseline {b:.2}, {delta:+.1}%; {} {:.0}%)",
                    self.name,
                    self.direction.symbol(),
                    self.tolerance * 100.0,
                )
            }
            (None, _) => format!("{verdict}  {} (no baseline recorded)", self.name),
            (_, None) => format!("{verdict}  {} (candidate unobservable)", self.name),
        }
    }
}

// ---------------------------------------------------------------------------
// The spec + reports
// ---------------------------------------------------------------------------

/// Which deterministic executor(s) to prove the properties on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKernel {
    /// ndn-lab's from-scratch discrete-event executor.
    Des,
    /// The tokio paused-clock kernel.
    Virtual,
}

impl CheckKernel {
    fn name(self) -> &'static str {
        match self {
            CheckKernel::Des => "des",
            CheckKernel::Virtual => "virtual",
        }
    }
}

fn default_kernels() -> Vec<CheckKernel> {
    vec![CheckKernel::Des]
}

/// A complete, serializable validation: a scenario + fault schedule + properties, run headless.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationSpec {
    /// The network under test.
    pub scenario: Scenario,
    /// How long (virtual ms) to let the scenario run before sampling the terminal state.
    pub duration_ms: u64,
    /// Faults injected during the run (fired in `at_ms` order).
    #[serde(default)]
    pub faults: Vec<ScheduledFault>,
    /// The assertions every run must satisfy.
    pub properties: Vec<Property>,
    /// The executor(s) to prove them on. Default `["des"]`; add `"virtual"` for cross-executor
    /// agreement.
    #[serde(default = "default_kernels")]
    pub kernels: Vec<CheckKernel>,
    /// World seeds to sweep — each draws an independent random realization (loss/jitter/erasure).
    /// Default `[0]` (a single deterministic run). List several (e.g. `[0,1,2,3,4]`) to check
    /// statistical properties across realizations. A property's `hold_ratio` is measured over these.
    #[serde(default = "default_seeds")]
    pub seeds: Vec<u64>,
    /// Regression gates — each records a probe's sweep-mean as a baseline and, when a baseline file
    /// is supplied, fails if the candidate drifts beyond tolerance. Inert without a baseline file.
    #[serde(default)]
    pub baselines: Vec<BaselineCheck>,
}

fn default_seeds() -> Vec<u64> {
    vec![0]
}

impl ValidationSpec {
    pub fn from_toml(s: &str) -> Result<Self> {
        toml::from_str(s).context("parse validation spec TOML")
    }

    pub fn to_toml(&self) -> Result<String> {
        toml::to_string_pretty(self).context("serialize validation spec TOML")
    }

    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).context("parse validation spec JSON")
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("serialize validation spec JSON")
    }
}

/// The terminal state a run's properties are evaluated against.
#[derive(Clone, Debug, Default)]
pub struct Observation {
    /// Per-node metric samples at end of run.
    pub metrics: Vec<MetricsSample>,
    /// Successful-fetch counts by app spawn-index.
    pub app_successes: BTreeMap<usize, u64>,
    /// Full flow metrics (RTT / loss / goodput) by app spawn-index — the benchmark readout.
    pub flow_stats: BTreeMap<usize, crate::app::FlowStats>,
}

/// The verdict for one [`Property`], aggregated across a kernel's seed sweep.
#[derive(Clone, Debug, Serialize)]
pub struct PropertyResult {
    pub name: String,
    pub cmp: Cmp,
    pub threshold: f64,
    /// The required fraction of seeds on which the property must hold.
    pub hold_ratio: f64,
    /// Seeds on which the property held / total seeds run.
    pub held: u64,
    pub total: u64,
    /// Observed probe value range across the sweep (`None` if the probe was never observable).
    pub observed_min: Option<f64>,
    pub observed_max: Option<f64>,
    pub observed_mean: Option<f64>,
    pub passed: bool,
}

impl PropertyResult {
    /// A one-line human summary. Single-seed reads `PASS  name (20 >= 20)`; a sweep reads
    /// `PASS  name (held 5/5; obs 42..53 mean 48.6 >= 42)`.
    pub fn summary(&self) -> String {
        let verdict = if self.passed { "PASS" } else { "FAIL" };
        let obs = match (self.observed_min, self.observed_max, self.observed_mean) {
            (Some(mn), Some(mx), Some(mean)) if self.total > 1 => {
                format!("obs {mn}..{mx} mean {mean:.1}")
            }
            (Some(mn), _, _) => format!("{mn}"),
            _ => "<unobserved>".to_string(),
        };
        if self.total > 1 {
            format!(
                "{verdict}  {} (held {}/{}; {obs} {} {}, need {:.0}%)",
                self.name,
                self.held,
                self.total,
                self.cmp.symbol(),
                self.threshold,
                self.hold_ratio * 100.0,
            )
        } else {
            format!(
                "{verdict}  {} ({obs} {} {})",
                self.name,
                self.cmp.symbol(),
                self.threshold
            )
        }
    }
}

/// The result of one kernel's seed sweep.
#[derive(Clone, Debug, Serialize)]
pub struct RunReport {
    pub kernel: String,
    /// The seeds swept on this kernel.
    pub seeds: Vec<u64>,
    /// Property verdicts aggregated across the sweep.
    pub properties: Vec<PropertyResult>,
    pub passed: bool,
    /// Terminal metrics per seed (for cross-kernel agreement + inspection).
    #[serde(skip)]
    pub seed_metrics: Vec<(u64, Vec<MetricsSample>)>,
}

/// The overall verdict across all requested kernels.
#[derive(Clone, Debug, Serialize)]
pub struct ValidationReport {
    pub runs: Vec<RunReport>,
    /// `Some(true/false)` when >1 kernel ran: do the counters agree across executors?
    /// `None` when only one kernel ran.
    pub cross_kernel_agree: Option<bool>,
    /// Divergences behind a `cross_kernel_agree == Some(false)`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_kernel_divergences: Vec<String>,
    /// The candidate baseline values measured this run (probe sweep-means) — write this out with
    /// `--record-baseline`. Empty if the spec declares no `[[baselines]]`.
    pub measured_baseline: Baseline,
    /// Regression verdicts (empty unless a baseline was supplied to compare against).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub regressions: Vec<RegressionResult>,
    /// The bottom line: every property held on every kernel, the executors agreed, and no gate regressed.
    pub passed: bool,
}

impl ValidationReport {
    /// A multi-line human report suitable for CI logs.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for run in &self.runs {
            let sweep = if run.seeds.len() > 1 {
                format!(" ({} seeds)", run.seeds.len())
            } else {
                String::new()
            };
            out.push_str(&format!(
                "[{}]{sweep} {}\n",
                run.kernel,
                if run.passed { "PASS" } else { "FAIL" }
            ));
            for p in &run.properties {
                out.push_str(&format!("  {}\n", p.summary()));
            }
        }
        if let Some(agree) = self.cross_kernel_agree {
            out.push_str(&format!(
                "cross-executor agreement: {}\n",
                if agree { "PASS" } else { "FAIL" }
            ));
            for d in &self.cross_kernel_divergences {
                out.push_str(&format!("  diverge: {d}\n"));
            }
        }
        if !self.regressions.is_empty() {
            out.push_str("regression gates:\n");
            for r in &self.regressions {
                out.push_str(&format!("  {}\n", r.summary()));
            }
        }
        out.push_str(&format!(
            "OVERALL: {}\n",
            if self.passed { "PASS" } else { "FAIL" }
        ));
        out
    }
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

/// Run a validation headless and return the verdict. Deterministic: each run is on a DES/Virtual
/// kernel, faults fire at exact virtual instants, and (with >1 kernel) counters are cross-checked.
///
/// Call from a plain (non-tokio) context — each kernel owns its own runtime.
pub fn run_validation(spec: &ValidationSpec) -> Result<ValidationReport> {
    run_core(spec, None)
}

/// As [`run_validation`], but gate the run against a recorded [`Baseline`]: each `[[baselines]]`
/// check's candidate value is compared to the baseline within tolerance, and any regression fails
/// the overall verdict.
pub fn run_validation_against(
    spec: &ValidationSpec,
    baseline: &Baseline,
) -> Result<ValidationReport> {
    run_core(spec, Some(baseline))
}

fn run_core(spec: &ValidationSpec, baseline: Option<&Baseline>) -> Result<ValidationReport> {
    let kernels = if spec.kernels.is_empty() {
        default_kernels()
    } else {
        spec.kernels.clone()
    };
    let seeds = if spec.seeds.is_empty() {
        default_seeds()
    } else {
        spec.seeds.clone()
    };

    let mut runs = Vec::new();
    // Every observation across all (kernel, seed) — the population baselines are measured over.
    let mut all_obs: Vec<Observation> = Vec::new();
    for ck in &kernels {
        // Sweep every seed on this kernel; aggregate each property over the realizations.
        let mut observations: Vec<Observation> = Vec::with_capacity(seeds.len());
        let mut seed_metrics: Vec<(u64, Vec<MetricsSample>)> = Vec::with_capacity(seeds.len());
        for &seed in &seeds {
            let obs = run_once(spec, *ck, seed)?;
            seed_metrics.push((seed, obs.metrics.clone()));
            observations.push(obs);
        }
        let properties: Vec<PropertyResult> = spec
            .properties
            .iter()
            .map(|p| p.evaluate(&observations))
            .collect();
        let passed = properties.iter().all(|p| p.passed);
        all_obs.extend(observations.iter().cloned());
        runs.push(RunReport {
            kernel: ck.name().to_string(),
            seeds: seeds.clone(),
            properties,
            passed,
            seed_metrics,
        });
    }

    // Cross-executor agreement: for each seed, the counters must match across kernels (ignoring
    // virtual timestamps — the two schedulers advance the clock differently). A seed diverging
    // across executors is a finding: the two schedulers disagree about what the network did.
    let (cross_kernel_agree, cross_kernel_divergences) = if runs.len() > 1 {
        let base = &runs[0];
        let mut divergences = Vec::new();
        for r in &runs[1..] {
            for ((seed, base_m), (_, cand_m)) in base.seed_metrics.iter().zip(&r.seed_metrics) {
                let diff = compare_metrics(&normalize_time(base_m), &normalize_time(cand_m));
                if !diff.identical {
                    for d in diff.divergences {
                        divergences.push(format!(
                            "{} vs {} (seed {seed}): {d}",
                            base.kernel, r.kernel
                        ));
                    }
                }
            }
        }
        (Some(divergences.is_empty()), divergences)
    } else {
        (None, Vec::new())
    };

    // Measure each baseline check's candidate value = mean of its probe across the whole sweep.
    let mut measured_baseline = Baseline::default();
    let mut regressions = Vec::new();
    for bc in &spec.baselines {
        let candidate = mean_probe(&bc.probe, &all_obs);
        if let Some(c) = candidate {
            measured_baseline.values.insert(bc.name.clone(), c);
        }
        if let Some(base) = baseline {
            let recorded = base.values.get(&bc.name).copied();
            let passed = match (recorded, candidate) {
                (Some(b), Some(c)) => bc.direction.holds(c, b, bc.tolerance),
                _ => false, // missing baseline or unobservable candidate ⇒ fail (safe default)
            };
            let delta_pct = match (recorded, candidate) {
                (Some(b), Some(c)) if b != 0.0 => Some((c - b) / b * 100.0),
                _ => None,
            };
            regressions.push(RegressionResult {
                name: bc.name.clone(),
                direction: bc.direction,
                tolerance: bc.tolerance,
                baseline: recorded,
                candidate,
                delta_pct,
                passed,
            });
        }
    }

    let passed = runs.iter().all(|r| r.passed)
        && cross_kernel_agree.unwrap_or(true)
        && regressions.iter().all(|r| r.passed);
    Ok(ValidationReport {
        runs,
        cross_kernel_agree,
        cross_kernel_divergences,
        measured_baseline,
        regressions,
        passed,
    })
}

/// Mean of a probe over a set of observations (ignoring observations where it's unobservable).
fn mean_probe(probe: &Probe, obs: &[Observation]) -> Option<f64> {
    let vals: Vec<f64> = obs.iter().filter_map(|o| probe.eval(o)).collect();
    if vals.is_empty() {
        None
    } else {
        Some(vals.iter().sum::<f64>() / vals.len() as f64)
    }
}

/// Zero out `virtual_time_ns` so counter-level comparison ignores scheduler timing differences.
fn normalize_time(samples: &[MetricsSample]) -> Vec<MetricsSample> {
    samples
        .iter()
        .map(|s| {
            let mut s = s.clone();
            s.virtual_time_ns = 0;
            s
        })
        .collect()
}

/// Build + drive the scenario on one kernel at one `seed`, apply the fault schedule at virtual
/// instants, and capture the terminal [`Observation`].
fn run_once(spec: &ValidationSpec, kernel: CheckKernel, seed: u64) -> Result<Observation> {
    if !spec.scenario.bridges.is_empty() {
        anyhow::bail!(
            "validation runs are hermetic: [[bridges]] (external endpoints) are not allowed in a \
             check scenario — attach external peers via `ndn-lab run`/`serve` instead"
        );
    }
    let mut scenario = spec.scenario.clone();
    scenario.seed = seed;
    let faults = spec.faults.clone();
    let duration_ms = spec.duration_ms;

    let driver = move |k: Arc<dyn SimKernel>| async move {
        let fabric = scenario.build(k)?.start().await?;

        // Fire faults in virtual-time order, sleeping the ambient clock between them.
        let mut ordered = faults;
        ordered.sort_by_key(|f| f.at_ms);
        let mut elapsed_ms = 0u64;
        for sf in &ordered {
            let target = sf.at_ms.min(duration_ms);
            if target > elapsed_ms {
                ndn_app::rt::sleep(Duration::from_millis(target - elapsed_ms)).await;
                elapsed_ms = target;
            }
            sf.fault.apply(&fabric).await?;
        }
        if duration_ms > elapsed_ms {
            ndn_app::rt::sleep(Duration::from_millis(duration_ms - elapsed_ms)).await;
        }

        // Capture the terminal state.
        let metrics = fabric.snapshot_metrics();
        let mut app_successes = BTreeMap::new();
        let mut flow_stats = BTreeMap::new();
        for (id, _node, _kind) in fabric.apps() {
            if let Some(n) = fabric.app_successes(id) {
                app_successes.insert(id.0, n);
            }
            if let Some(s) = fabric.flow_stats(id) {
                flow_stats.insert(id.0, s);
            }
        }
        fabric.shutdown().await;
        anyhow::Ok(Observation {
            metrics,
            app_successes,
            flow_stats,
        })
    };

    match kernel {
        CheckKernel::Des => DesKernel::new().run(driver),
        CheckKernel::Virtual => VirtualKernel::new().run(driver),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 3-node line: consumer(0) ── relay(1) ── producer(2), consumer fetches /demo/0..19.
    const LINE: &str = r#"
duration_ms = 4000
kernels = ["des", "virtual"]

[scenario.kernel]
kind = "des"

[[scenario.nodes]]
label = "consumer"
[[scenario.nodes.apps]]
app = "consumer"
prefix = "/demo"
count = 20
interval_ms = 50

[[scenario.nodes]]
label = "relay"

[[scenario.nodes]]
label = "producer"
[[scenario.nodes.apps]]
app = "producer"
prefix = "/demo"
content = "hello"

[[scenario.links]]
a = 0
b = 1
delay_ms = 2

[[scenario.links]]
a = 1
b = 2
delay_ms = 2

[[scenario.routes]]
node = 0
prefix = "/demo"
nexthop = 1

[[scenario.routes]]
node = 1
prefix = "/demo"
nexthop = 2

[[properties]]
name = "consumer fetches all 20 segments"
probe = { kind = "app_successes", app = 0 }
cmp = "ge"
value = 20

[[properties]]
name = "no PIT leak anywhere"
probe = { kind = "metric", field = "pit_depth", agg = "max" }
cmp = "eq"
value = 0
"#;

    #[test]
    fn passing_properties_pass_on_both_kernels() {
        let spec = ValidationSpec::from_toml(LINE).unwrap();
        let report = run_validation(&spec).unwrap();
        assert!(report.passed, "expected PASS, got:\n{}", report.summary());
        assert_eq!(report.runs.len(), 2);
        assert_eq!(
            report.cross_kernel_agree,
            Some(true),
            "DES and Virtual should agree on counters"
        );
    }

    #[test]
    fn a_too_strict_property_fails() {
        let mut spec = ValidationSpec::from_toml(LINE).unwrap();
        spec.properties.push(Property {
            name: "impossible throughput".into(),
            probe: Probe::AppSuccesses { app: 0 },
            cmp: Cmp::Ge,
            value: 1_000_000.0,
            hold_ratio: 1.0,
        });
        let report = run_validation(&spec).unwrap();
        assert!(!report.passed, "expected FAIL:\n{}", report.summary());
    }

    #[test]
    fn spec_round_trips_toml() {
        let spec = ValidationSpec::from_toml(LINE).unwrap();
        let again = ValidationSpec::from_toml(&spec.to_toml().unwrap()).unwrap();
        assert_eq!(spec.to_json().unwrap(), again.to_json().unwrap());
    }

    /// A lossy link — the seed sweep should draw *different* realizations.
    const LOSSY: &str = r#"
duration_ms = 4000
kernels = ["des"]
seeds = [0, 1, 2, 3]

[scenario.kernel]
kind = "des"

[[scenario.nodes]]
label = "consumer"
[[scenario.nodes.apps]]
app = "consumer"
prefix = "/demo"
count = 20
interval_ms = 15
lifetime_ms = 150

[[scenario.nodes]]
label = "producer"
[[scenario.nodes.apps]]
app = "producer"
prefix = "/demo"
content = "x"

[[scenario.links]]
a = 0
b = 1
delay_ms = 2
loss_rate = 0.2

[[scenario.routes]]
node = 0
prefix = "/demo"
nexthop = 1

[[properties]]
name = "floor holds every realization"
probe = { kind = "app_successes", app = 0 }
cmp = "ge"
value = 5
hold_ratio = 1.0
"#;

    #[test]
    fn seed_sweep_varies_realizations_and_aggregates() {
        let spec = ValidationSpec::from_toml(LOSSY).unwrap();
        let report = run_validation(&spec).unwrap();
        let run = &report.runs[0];
        assert_eq!(run.seeds.len(), 4);
        let p = &run.properties[0];
        assert_eq!(p.total, 4, "one observation per seed");
        // Different seeds ⇒ different loss realizations ⇒ a non-degenerate spread.
        assert!(
            p.observed_min < p.observed_max,
            "seeds should vary the completed count, got {:?}..{:?}",
            p.observed_min,
            p.observed_max
        );
    }

    #[test]
    fn hold_ratio_makes_a_property_statistical() {
        let spec = ValidationSpec::from_toml(LOSSY).unwrap();
        let report = run_validation(&spec).unwrap();
        let mean = report.runs[0].properties[0].observed_mean.unwrap();
        // A threshold just above the mean fails as an invariant (some seeds miss it) but passes as a
        // statistical property that only a fraction of seeds must clear.
        let mut strict = ValidationSpec::from_toml(LOSSY).unwrap();
        strict.properties[0].value = mean + 1.0;
        strict.properties[0].hold_ratio = 1.0;
        assert!(
            !run_validation(&strict).unwrap().passed,
            "invariant above the mean should fail"
        );

        let mut lenient = ValidationSpec::from_toml(LOSSY).unwrap();
        lenient.properties[0].value = mean + 1.0;
        lenient.properties[0].hold_ratio = 0.25;
        assert!(
            run_validation(&lenient).unwrap().passed,
            "a 25%-of-seeds threshold above the mean should hold"
        );
    }

    #[test]
    fn direction_tolerance_semantics() {
        // at_least: within 5% below baseline is ok; further down is a regression.
        assert!(Direction::AtLeast.holds(96.0, 100.0, 0.05));
        assert!(!Direction::AtLeast.holds(94.0, 100.0, 0.05));
        // at_most: up to 10% above is ok; more is a regression.
        assert!(Direction::AtMost.holds(110.0, 100.0, 0.10));
        assert!(!Direction::AtMost.holds(111.0, 100.0, 0.10));
        // within: two-sided.
        assert!(Direction::Within.holds(103.0, 100.0, 0.05));
        assert!(!Direction::Within.holds(94.0, 100.0, 0.05));
    }

    #[test]
    fn baseline_json_round_trips() {
        let mut b = Baseline::default();
        b.values.insert("throughput".into(), 42.5);
        let again = Baseline::from_json(&b.to_json().unwrap()).unwrap();
        assert_eq!(again.values.get("throughput"), Some(&42.5));
    }

    #[test]
    fn probe_aggregates_over_nodes() {
        let obs = Observation {
            metrics: vec![],
            app_successes: BTreeMap::new(),
            ..Default::default()
        };
        // Empty metrics ⇒ unobservable aggregate.
        assert_eq!(
            Probe::Metric {
                field: MetricField::PitDepth,
                node: None,
                agg: Agg::Max
            }
            .eval(&obs),
            None
        );
    }
}
