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
}

impl Probe {
    /// Evaluate against an [`Observation`]. `None` ⇒ the probe references something that wasn't
    /// observed (missing app / node), which a [`Property`] treats as a failure.
    pub fn eval(&self, obs: &Observation) -> Option<f64> {
        match self {
            Probe::AppSuccesses { app } => obs.app_successes.get(app).map(|&n| n as f64),
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Property {
    pub name: String,
    pub probe: Probe,
    pub cmp: Cmp,
    pub value: f64,
}

impl Property {
    fn evaluate(&self, obs: &Observation) -> PropertyResult {
        let observed = self.probe.eval(obs);
        let passed = observed.map(|o| self.cmp.test(o, self.value)).unwrap_or(false);
        PropertyResult {
            name: self.name.clone(),
            observed,
            cmp: self.cmp,
            threshold: self.value,
            passed,
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
}

impl Fault {
    async fn apply(&self, fabric: &RunningSimulation) -> Result<()> {
        match self {
            Fault::RemoveNode { node } => fabric.remove_node(NodeId(*node)).await,
            Fault::StopApp { app } => fabric.stop_app(AppId(*app)),
            Fault::SpawnApp { node, app } => fabric.spawn_app(NodeId(*node), app.clone()).map(|_| ()),
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
}

/// The verdict for one [`Property`] on one run.
#[derive(Clone, Debug, Serialize)]
pub struct PropertyResult {
    pub name: String,
    /// The observed probe value, or `None` if the probe referenced a missing app/node.
    pub observed: Option<f64>,
    pub cmp: Cmp,
    pub threshold: f64,
    pub passed: bool,
}

impl PropertyResult {
    /// A one-line human summary, e.g. `PASS  consumer completes (20 >= 20)`.
    pub fn summary(&self) -> String {
        let verdict = if self.passed { "PASS" } else { "FAIL" };
        let observed = self
            .observed
            .map(|o| format!("{o}"))
            .unwrap_or_else(|| "<unobserved>".to_string());
        format!(
            "{verdict}  {} ({observed} {} {})",
            self.name,
            self.cmp.symbol(),
            self.threshold
        )
    }
}

/// The result of one run on one kernel.
#[derive(Clone, Debug, Serialize)]
pub struct RunReport {
    pub kernel: String,
    pub properties: Vec<PropertyResult>,
    pub passed: bool,
    /// Terminal metrics (for cross-kernel agreement + inspection).
    pub metrics: Vec<MetricsSample>,
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
    /// The bottom line: every property held on every kernel *and* (if >1) the executors agreed.
    pub passed: bool,
}

impl ValidationReport {
    /// A multi-line human report suitable for CI logs.
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for run in &self.runs {
            out.push_str(&format!(
                "[{}] {}\n",
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
    let kernels = if spec.kernels.is_empty() {
        default_kernels()
    } else {
        spec.kernels.clone()
    };

    let mut runs = Vec::new();
    for ck in &kernels {
        let obs = run_once(spec, *ck)?;
        let properties: Vec<PropertyResult> =
            spec.properties.iter().map(|p| p.evaluate(&obs)).collect();
        let passed = properties.iter().all(|p| p.passed);
        runs.push(RunReport {
            kernel: ck.name().to_string(),
            properties,
            passed,
            metrics: obs.metrics,
        });
    }

    // Cross-executor agreement: compare counters across kernels, ignoring virtual timestamps
    // (the two schedulers advance the clock differently; only the *counts* must agree).
    let (cross_kernel_agree, cross_kernel_divergences) = if runs.len() > 1 {
        let base = normalize_time(&runs[0].metrics);
        let mut divergences = Vec::new();
        for r in &runs[1..] {
            let diff = compare_metrics(&base, &normalize_time(&r.metrics));
            if !diff.identical {
                for d in diff.divergences {
                    divergences.push(format!("{} vs {}: {d}", runs[0].kernel, r.kernel));
                }
            }
        }
        (Some(divergences.is_empty()), divergences)
    } else {
        (None, Vec::new())
    };

    let passed = runs.iter().all(|r| r.passed) && cross_kernel_agree.unwrap_or(true);
    Ok(ValidationReport {
        runs,
        cross_kernel_agree,
        cross_kernel_divergences,
        passed,
    })
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

/// Build + drive the scenario on one kernel, apply the fault schedule at virtual instants, and
/// capture the terminal [`Observation`].
fn run_once(spec: &ValidationSpec, kernel: CheckKernel) -> Result<Observation> {
    let scenario = spec.scenario.clone();
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
        for (id, _node, _kind) in fabric.apps() {
            if let Some(n) = fabric.app_successes(id) {
                app_successes.insert(id.0, n);
            }
        }
        fabric.shutdown().await;
        anyhow::Ok(Observation {
            metrics,
            app_successes,
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
        assert_eq!(report.cross_kernel_agree, Some(true), "DES and Virtual should agree on counters");
    }

    #[test]
    fn a_too_strict_property_fails() {
        let mut spec = ValidationSpec::from_toml(LINE).unwrap();
        spec.properties.push(Property {
            name: "impossible throughput".into(),
            probe: Probe::AppSuccesses { app: 0 },
            cmp: Cmp::Ge,
            value: 1_000_000.0,
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

    #[test]
    fn probe_aggregates_over_nodes() {
        let obs = Observation {
            metrics: vec![],
            app_successes: BTreeMap::new(),
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
