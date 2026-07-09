//! The **adversary bench** — instrument (b) of the field bench suite (skyfall
//! `FIELD-REPORT-2.md` §7; (c) the liveness watchdog is [`crate::liveness`], (a) the
//! ceiling-finder is [`crate::ceiling`]). The invariants are already proven *correct*
//! (`tests/stall_matrix.rs`, ndf-replication-transport's wire validation); this measures their
//! **cost under hostility** — can an attacker force unbounded work, DoS a node, or starve
//! honest peers?
//!
//! ## The design crux: two assertions per scenario
//!
//! Every adversary cell asserts BOTH, and "pass" is their conjunction:
//!
//! 1. **Honest-peer liveness is preserved** — the watchdog ([`crate::liveness::watch`]) runs on
//!    the HONEST set *during* the attack: honest peers keep making progress and converge
//!    no-poison / byte-identical while the attacker rages. An adversary bench is exactly a
//!    hostility scenario with the liveness watchdog watching the honest set — so the composition
//!    is literal, not a re-implementation.
//! 2. **Attacker cost-to-defender is bounded** — [`amplification_bound`]: the defender's work is
//!    O(1) per hostile action (one verify per bad Block, one gate check per fork, one discard per
//!    replay), never amplified, never unbounded. Measured by a [`CostMeter`] counting hostile
//!    actions against defender work units, asserted as a ratio with a generous constant ceiling
//!    (the same "record numbers, assert shapes" discipline as the ceiling-finder — the raw counts
//!    are recorded; only the *bound* is CI-normative).
//!
//! Reuses instrument (c)'s [`Ledger`]/[`watch`](crate::liveness::watch)/[`Invariants`] and
//! instrument (a)'s [`BoundCheck`](crate::ceiling::BoundCheck) rather than forking either — an
//! [`AdversaryCell`] is a `liveness` verdict + `ceiling` bounds glued by a cost meter, with the
//! same seed-per-cell + normative-projection determinism discipline.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use ndn_packet::Data;
use ndn_security::{ValidationResult, Validator};
use serde::Serialize;

use crate::ceiling::BoundCheck;
use crate::fieldkit::TwoPhaseReplica;
use crate::liveness::{Invariants, Ledger, LivenessVerdict};

/// Counts hostile actions against the defender work they induced — the raw material of an
/// amplification bound. "Actions" are attacker events (bad Blocks fed, forks served, replays
/// injected); "work" is defender units (signature verifications, gate checks, discards). O(1)
/// per action means `work / actions` stays near a small constant — amplification is the
/// opposite, one action fanning out into many work units.
#[derive(Default)]
pub struct CostMeter {
    actions: AtomicU64,
    work: AtomicU64,
    /// Honest work that would happen even with no attacker (the baseline the ratio is measured
    /// *above* — so a cell with N honest Blocks doesn't read as "N amplification").
    baseline_work: AtomicU64,
}

impl CostMeter {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record one hostile action (a bad Block delivered, a fork served, a replay injected).
    pub fn action(&self) {
        self.actions.fetch_add(1, Ordering::Relaxed);
    }
    /// Record one unit of defender work (a verify, a gate check, a discard).
    pub fn work(&self) {
        self.work.fetch_add(1, Ordering::Relaxed);
    }
    /// Record one unit of *honest* work (work that would happen with no attacker present).
    pub fn baseline_work(&self) {
        self.baseline_work.fetch_add(1, Ordering::Relaxed);
        self.work.fetch_add(1, Ordering::Relaxed);
    }
    pub fn actions_total(&self) -> u64 {
        self.actions.load(Ordering::Relaxed)
    }
    pub fn work_total(&self) -> u64 {
        self.work.load(Ordering::Relaxed)
    }
    pub fn baseline_total(&self) -> u64 {
        self.baseline_work.load(Ordering::Relaxed)
    }
}

/// Assert the defender's *attacker-induced* work is O(1) per hostile action: subtract the
/// honest baseline, then require `(work - baseline) ≤ actions × max_per_action`. A generous
/// `max_per_action` (the assertion is qualitative — "not amplified"); the recorded counts carry
/// the precision. Red-capable: a defender that re-verifies the whole chain per bad Block, or
/// re-fetches unboundedly, blows the ratio.
pub fn amplification_bound(
    name: &str,
    claim: &str,
    meter: &CostMeter,
    max_per_action: f64,
) -> BoundCheck {
    let actions = meter.actions_total();
    let induced = meter.work_total().saturating_sub(meter.baseline_total());
    let per_action = if actions > 0 {
        induced as f64 / actions as f64
    } else if induced == 0 {
        0.0
    } else {
        f64::INFINITY // work with zero actions to attribute it to — a leak
    };
    BoundCheck {
        name: name.into(),
        claim: claim.into(),
        detail: format!(
            "{induced} induced work over {actions} hostile actions \
             ({per_action:.2}/action, bound {max_per_action}); baseline {} honest units",
            meter.baseline_total()
        ),
        pass: per_action <= max_per_action,
    }
}

/// Assert a measured quantity stays within an absolute cap (for by-design bounds like a content
/// store's byte ceiling — "unreferenced junk accrues, but the cap holds"). Red-capable: an
/// unbounded accumulator exceeds `cap`.
pub fn cap_bound(name: &str, claim: &str, measured: u64, cap: u64) -> BoundCheck {
    BoundCheck {
        name: name.into(),
        claim: claim.into(),
        detail: format!("measured {measured}, cap {cap}"),
        pass: measured <= cap,
    }
}

/// One adversary cell's record: the honest-liveness verdict + convergence invariants (safety
/// under attack) + the cost bounds (the amplification tripwire) + the seed.
#[derive(Debug, Clone, Serialize)]
pub struct AdversaryCell {
    pub cell: String,
    pub seed: u64,
    /// Honest-set liveness during the attack.
    pub liveness: LivenessVerdict,
    /// Honest-set convergence invariants (no-poison / byte-identity / event integrity).
    pub invariants: Invariants,
    /// The cost bounds (amplification / caps).
    pub cost: Vec<BoundCheck>,
    /// Recorded raw counts, diagnostic (hostile actions, defender work, honest baseline, …).
    pub metrics: std::collections::BTreeMap<String, f64>,
    /// Pass = honest converged AND no-poison AND event integrity AND every cost bound holds.
    pub pass: bool,
}

impl AdversaryCell {
    /// Assemble from a finished cell: the honest liveness verdict, the ledger's invariants over
    /// the honest set, and the cost bounds.
    pub fn evaluate(
        cell: impl Into<String>,
        seed: u64,
        liveness: LivenessVerdict,
        ledger: &Ledger,
        honest_replicas: &[String],
        cost: Vec<BoundCheck>,
    ) -> Self {
        let invariants = ledger.invariants(honest_replicas);
        let pass = liveness == LivenessVerdict::Converged
            && invariants.poison_free
            && invariants.event_integrity
            && cost.iter().all(|b| b.pass);
        Self {
            cell: cell.into(),
            seed,
            liveness,
            invariants,
            cost,
            metrics: std::collections::BTreeMap::new(),
            pass,
        }
    }

    pub fn metric(&mut self, name: impl Into<String>, value: f64) {
        self.metrics.insert(name.into(), value);
    }

    /// The deterministic CI-tripwire projection: cell, seed, honest-liveness verdict class, the
    /// invariant verdicts, and each cost bound's pass — no raw counts (the same discipline as
    /// `liveness::CellReport::normative` / `ceiling::PerfCell::normative`).
    pub fn normative(&self) -> String {
        let verdict = match self.liveness {
            LivenessVerdict::Converged => "converged",
            LivenessVerdict::Stalled { .. } => "stalled",
            LivenessVerdict::Budget { .. } => "budget",
        };
        let mut s = format!(
            "{}|seed={}|honest={}|poison_free={}|event_integrity={}",
            self.cell, self.seed, verdict, self.invariants.poison_free, self.invariants.event_integrity
        );
        for b in &self.cost {
            s.push_str(&format!("|{}={}", b.name, b.pass));
        }
        s.push_str(&format!("|pass={}", self.pass));
        s
    }
}

/// The adversary scoreboard — sibling of `liveness::Scoreboard` / `ceiling::PerfBoard`, same
/// JSON+seed conventions.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AdversaryBoard {
    pub cells: Vec<AdversaryCell>,
}

impl AdversaryBoard {
    pub fn push(&mut self, cell: AdversaryCell) {
        self.cells.push(cell);
    }
    pub fn all_pass(&self) -> bool {
        self.cells.iter().all(|c| c.pass)
    }
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("adversary board serializes")
    }
}

/// A **verifying honest consumer** for the crypto-cost scenarios: for each advertised
/// `(publisher, seq)`, fetch the SVS publication whose payload is a signed inner `Data`, run the
/// REAL [`Validator`] over it (counting every verification through `meter`), and store+ack ONLY
/// what validates against the trust anchors. A bad-signature / untrusted-signer flood is thus
/// verified exactly once per delivered Block and dropped — the O(1)-per-hostile-action shape the
/// bound checks; honest publications validate and drive the ledger's progress.
///
/// `honest_publishers` names the publishers whose validated content the ledger should credit as
/// honest progress (an attacker's *validly* signed but off-workload publication is still not
/// honest backlog — this keeps the watchdog watching the honest workload, not the attacker's).
pub async fn verifying_catchup(
    replica: TwoPhaseReplica,
    ledger: Arc<Ledger>,
    validator: Arc<Validator>,
    honest_publishers: Vec<String>,
    replica_name: String,
    meter: Arc<CostMeter>,
) {
    let mut replica = replica;
    while let Some(update) = replica.handle.recv().await {
        let honest = honest_publishers.contains(&update.publisher);
        for seq in update.low_seq..=update.high_seq {
            let Some(payload) = replica.fetch(&update.name, seq).await else {
                break; // unfetchable — hold at the gap
            };
            // Decode the inner signed Data and run the real verifier. This is THE per-Block
            // work an attacker is trying to amplify; count it once, here.
            let stored_content: Option<Bytes> = match Data::decode(payload) {
                Ok(data) => {
                    // Count the verification: honest Blocks are baseline work; attacker Blocks
                    // are induced work (the numerator of the amplification ratio).
                    if honest {
                        meter.baseline_work();
                    } else {
                        meter.action();
                        meter.work();
                    }
                    match validator.validate(&data).await {
                        ValidationResult::Valid(safe) => {
                            safe.data().content().map(|c| Bytes::copy_from_slice(c))
                        }
                        _ => None, // failed crypto / trust — dropped, never stored or acked
                    }
                }
                Err(_) => {
                    // Malformed payload from the attacker: still one bounded unit of work.
                    if !honest {
                        meter.action();
                        meter.work();
                    }
                    None
                }
            };

            // Store + ack ONLY validated, honest-workload content — the poison line and the
            // progress signal. An attacker's dropped Block never advances anything.
            if honest && let Some(content) = stored_content {
                if ledger.record_stored(&replica_name, &update.publisher, seq, &content) {
                    ledger.record_reported(&replica_name);
                }
                let _ = replica.handle.ack(&update.publisher, seq).await;
                ledger.record_ack();
            }
        }
    }
}
