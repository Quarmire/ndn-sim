//! What a run reports: per case its status and cost, as JSON for the Results page.

use serde::Serialize;

/// A case's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// The invariant held.
    Pass,
    /// The invariant did not hold, or a verb failed where it must not.
    Fail,
    /// No registered implementation covers the case's slice; the scenario did not run.
    NotImplemented,
}

/// What a case cost. `None` where nothing was measured (the case did not run).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Cost {
    /// Interests the devices sent onto links: each is one request/response round trip.
    pub round_trips: Option<u64>,
    /// Bytes sent onto every link, all nodes.
    pub bytes: Option<u64>,
    /// Signatures the implementation made.
    pub signatures: Option<u64>,
    /// Stored copies of versions across all holders at the end.
    pub copies: Option<u64>,
    /// Virtual time, in milliseconds, from the case's triggering step until its devices agreed.
    pub converge_ms: Option<u64>,
    /// Steps the person had to take beyond the story's own gestures (pointing at data, pointing
    /// at someone, throwing something away). The plan requires this to stay at the story's count.
    pub gestures: Option<u64>,
}

/// One case's line in the report.
#[derive(Clone, Debug, Serialize)]
pub struct CaseResult {
    /// `c1`…`c12`, `o1`…`o3`.
    pub id: &'static str,
    /// The use case's title.
    pub title: &'static str,
    /// The slice that makes it pass.
    pub slice: u8,
    /// The model changes it motivated.
    pub model: &'static [&'static str],
    /// The invariant it asserts.
    pub guards: &'static str,
    /// Its outcome.
    pub status: Status,
    /// Why: the failure, or why it did not run.
    pub detail: String,
    /// What it cost.
    pub cost: Cost,
    /// What the case measured beyond its cost, for an open question it answers.
    pub measured: Vec<Measure>,
}

/// One quantity a case measured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Measure {
    /// What was measured, in words.
    pub what: String,
    /// The value.
    pub value: u64,
    /// Its unit (`round trips`, `bytes`, `ms`, `signatures`, …).
    pub unit: &'static str,
}

/// Counts by status.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    /// Cases that passed.
    pub pass: usize,
    /// Cases that failed.
    pub fail: usize,
    /// Cases that did not run.
    pub not_implemented: usize,
}

/// A whole run.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// Always `ndn-data-conformance`.
    pub suite: &'static str,
    /// The implementation run, if any.
    pub provider: Option<String>,
    /// The kernel the scenarios run on.
    pub kernel: &'static str,
    /// Counts by status.
    pub totals: Totals,
    /// Every case, in study order.
    pub cases: Vec<CaseResult>,
}

impl Report {
    /// A report over `cases`, run against `provider`.
    pub fn new(provider: Option<String>, cases: Vec<CaseResult>) -> Self {
        let mut totals = Totals::default();
        for c in &cases {
            match c.status {
                Status::Pass => totals.pass += 1,
                Status::Fail => totals.fail += 1,
                Status::NotImplemented => totals.not_implemented += 1,
            }
        }
        Self {
            suite: "ndn-data-conformance",
            provider,
            kernel: "virtual",
            totals,
            cases,
        }
    }

    /// A plain-text table, one line per case.
    pub fn table(&self) -> String {
        let mut out = format!(
            "ndn-data conformance — provider: {}\n",
            self.provider.as_deref().unwrap_or("none")
        );
        for c in &self.cases {
            let status = match c.status {
                Status::Pass => "pass",
                Status::Fail => "FAIL",
                Status::NotImplemented => "not implemented",
            };
            out.push_str(&format!(
                "  {:<4} slice {}  {:<16} {}\n",
                c.id, c.slice, status, c.title
            ));
            if c.status != Status::Pass && !c.detail.is_empty() {
                out.push_str(&format!("         {}\n", c.detail));
            }
        }
        out.push_str(&format!(
            "{} pass, {} fail, {} not implemented\n",
            self.totals.pass, self.totals.fail, self.totals.not_implemented
        ));
        out
    }
}
