//! The **liveness watchdog** — instrument (c) of the field bench suite (skyfall
//! `FIELD-REPORT-2.md` §7; instruments (a) ceiling-finder and (b) adversary bench are separate).
//!
//! Every bug the field found — NS-6 (reorder→mispair), NS-7 (burst deadlock), NS-8 (restart
//! starvation), NS-9 (step-timeout event loss) — shared ONE signature: **progress stops,
//! nothing errors.** This module makes "stopped making progress" a first-class failure, with
//! a dual assertion per scenario cell:
//!
//! 1. **The progress watchdog** ([`watch`]): a stall is *an interval of length T with nonzero
//!    backlog somewhere and zero acks anywhere*. Deliberately **end-state-agnostic** — backlog
//!    is the live gap between what publishers have authored so far and what replicas hold
//!    (the system's own running knowledge), never a test's "expected N". That is what lets it
//!    catch an unknown-future stall, the thing no per-test assertion caught in the field. It
//!    generalizes [`fieldkit::drive_until_or_stall`](crate::fieldkit::drive_until_or_stall)
//!    from a per-test check to a matrix invariant.
//! 2. **Convergence invariants** ([`Ledger::invariants`]): *no-poison / byte-identity* (every
//!    Block a replica stored is byte-identical to what its publisher authored — a mispaired
//!    reply that converges to the wrong bytes fails here, not at the watchdog) and *event
//!    integrity* (every stored Block was reported to the caller — a cancelled step that loses
//!    events while the store moves fails here; the field symptom was a view sitting stale on a
//!    store that had converged).
//!
//! [`CellReport`]/[`Scoreboard`] serialize the verdicts as JSON with the cell's **seed** — a
//! deterministic `VirtualKernel` run means every failure is a seed you hand a debugger. CI
//! tracks the scoreboard as a tripwire (qualitative pass/stall per cell), not a perf number —
//! that's instrument (a)'s job.
//!
//! The matrix itself — topologies × faults, the four historical-bug rows, and the
//! red-capability gates proving the watchdog and invariants actually bite — lives in
//! `tests/stall_matrix.rs`, composed from [`fieldkit`](crate::fieldkit) primitives
//! (`hold_link`, `TwoPhaseReplica`, `RestartablePublisher`, `publish_backlog`).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use serde::Serialize;

use crate::fieldkit::TwoPhaseReplica;

/// The shared truth ledger for one scenario cell: what publishers have authored (live, as the
/// workload runs), what each replica has stored, what each replica has *reported* to its
/// caller, and a global monotone ack counter. All watchdog and invariant signals derive from
/// this — no expected end-state anywhere.
#[derive(Default)]
pub struct Ledger {
    /// Authored truth: `(publisher, seq) → bytes`, recorded the moment a publication is put.
    published: Mutex<HashMap<(String, u64), Bytes>>,
    /// Stored copies: `(replica, publisher, seq) → bytes`.
    stored: Mutex<HashMap<(String, String, u64), Bytes>>,
    /// Per-replica count of stored Blocks *reported back to the caller* (the NS-9 signal:
    /// a store that moved without its caller learning is an integrity failure, not liveness).
    reported: Mutex<HashMap<String, u64>>,
    /// Global monotone ack counter — any replica acking anything ticks it.
    acks: AtomicU64,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an authored publication (call as the workload publishes — this is what makes
    /// backlog live rather than an end-state).
    pub fn record_published(&self, publisher: &str, seq: u64, bytes: &[u8]) {
        self.published
            .lock()
            .unwrap()
            .insert((publisher.to_string(), seq), Bytes::copy_from_slice(bytes));
    }

    /// Record a replica storing a publication. **First-binding**: the first bytes stored under
    /// a key are what the replica committed and acked — a later re-fetch must not launder a
    /// poisoned entry (the field's mispair was permanent precisely because the acked seq was
    /// never re-fetched; a harness that overwrote would self-heal the evidence). Returns
    /// `true` if newly stored.
    pub fn record_stored(&self, replica: &str, publisher: &str, seq: u64, bytes: &Bytes) -> bool {
        use std::collections::hash_map::Entry;
        match self
            .stored
            .lock()
            .unwrap()
            .entry((replica.to_string(), publisher.to_string(), seq))
        {
            Entry::Vacant(v) => {
                v.insert(bytes.clone());
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Record one ack (any replica, any seq — the watchdog only needs "somebody progressed").
    pub fn record_ack(&self) {
        self.acks.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a replica **reported** a stored Block to its caller.
    pub fn record_reported(&self, replica: &str) {
        *self
            .reported
            .lock()
            .unwrap()
            .entry(replica.to_string())
            .or_insert(0) += 1;
    }

    fn acks_total(&self) -> u64 {
        self.acks.load(Ordering::Relaxed)
    }

    /// How many Blocks `replica` currently holds (diagnostic; also drives the NS-4 red-gate
    /// consumer's O(history) cost model).
    pub fn stored_count(&self, replica: &str) -> u64 {
        self.stored
            .lock()
            .unwrap()
            .keys()
            .filter(|(r, _, _)| r == replica)
            .count() as u64
    }

    /// Total payload bytes `replica` holds — the macro "bytes per held Block" metric.
    pub fn stored_bytes(&self, replica: &str) -> u64 {
        self.stored
            .lock()
            .unwrap()
            .iter()
            .filter(|((r, _, _), _)| r == replica)
            .map(|(_, b)| b.len() as u64)
            .sum()
    }

    /// The live global backlog: over every `(replica, publisher)` pair that exists in the
    /// cell, how many authored publications that replica does not yet hold. `replicas` names
    /// the nodes expected to replicate (the cell's topology knowledge, not an end-state).
    pub fn backlog(&self, replicas: &[String]) -> u64 {
        let published = self.published.lock().unwrap();
        let stored = self.stored.lock().unwrap();
        let mut missing = 0u64;
        for (p, s) in published.keys() {
            for r in replicas {
                if !stored.contains_key(&(r.clone(), p.clone(), *s)) {
                    missing += 1;
                }
            }
        }
        missing
    }

    /// Evaluate the convergence invariants (the safety half of the dual assertion).
    pub fn invariants(&self, replicas: &[String]) -> Invariants {
        let published = self.published.lock().unwrap();
        let stored = self.stored.lock().unwrap();
        let reported = self.reported.lock().unwrap();

        // No-poison / byte-identity: every stored Block matches its authored bytes. (Replica
        // agreement follows: all replicas equal the same authored truth.)
        let mut poisoned = Vec::new();
        for ((r, p, s), bytes) in stored.iter() {
            match published.get(&(p.clone(), *s)) {
                Some(authored) if authored == bytes => {}
                Some(_) => poisoned.push(format!("{r} holds WRONG bytes for {p}#{s}")),
                None => poisoned.push(format!("{r} holds {p}#{s} which was never authored")),
            }
        }

        // Event integrity: everything stored was reported to the caller.
        let mut unreported = Vec::new();
        for r in replicas {
            let stored_n = stored.keys().filter(|(rr, _, _)| rr == r).count() as u64;
            let reported_n = reported.get(r).copied().unwrap_or(0);
            if reported_n < stored_n {
                unreported.push(format!(
                    "{r}: store moved to {stored_n} but only {reported_n} reported — \
                     {} event(s) lost",
                    stored_n - reported_n
                ));
            }
        }

        Invariants {
            poison_free: poisoned.is_empty(),
            event_integrity: unreported.is_empty(),
            violations: poisoned.into_iter().chain(unreported).collect(),
        }
    }
}

/// The safety half of a cell's dual assertion.
#[derive(Debug, Clone, Serialize)]
pub struct Invariants {
    /// Every stored Block is byte-identical to its authored publication.
    pub poison_free: bool,
    /// Every stored Block was reported to the replica's caller (no NS-9 event loss).
    pub event_integrity: bool,
    /// Human-readable violations (empty when both hold).
    pub violations: Vec<String>,
}

/// What the watchdog saw (the liveness half of a cell's dual assertion).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum LivenessVerdict {
    /// Backlog reached zero everywhere and stayed there — the cell converged.
    Converged,
    /// An interval of `stall window` passed with nonzero backlog somewhere and zero acks
    /// anywhere — the silent-stall signature, live.
    Stalled {
        /// Global backlog at the moment the watchdog fired.
        backlog: u64,
        /// Total acks recorded when progress froze.
        acks: u64,
    },
    /// The virtual-time budget ran out while acks were still trickling — not a silent stall,
    /// but the cell did not converge either. A distinct failure (usually an undersized budget
    /// or a pathologically slow path worth its own look).
    Budget {
        /// Global backlog when the budget expired.
        backlog: u64,
    },
}

/// Watch the ledger until the cell converges, stalls, or exhausts `budget` (virtual time).
///
/// Stall detection is END-STATE-AGNOSTIC: it never asks "did we reach N", only "has an
/// interval of `stall_window` passed in which some backlog existed *throughout* and no ack
/// happened *anywhere*". Convergence is backlog == 0 sustained over one tick (a publisher
/// mid-burst keeps backlog nonzero, so a green verdict can't fire early while the workload is
/// still authoring — publishing itself is progress only if replicas then drain it).
pub async fn watch(
    ledger: &Ledger,
    replicas: &[String],
    stall_window: Duration,
    budget: Duration,
) -> LivenessVerdict {
    let tick = (stall_window / 10).max(Duration::from_millis(10));
    let mut idle = Duration::ZERO;
    let mut spent = Duration::ZERO;
    let mut last_acks = ledger.acks_total();
    let mut zero_streak = 0u32;
    loop {
        tokio::time::sleep(tick).await;
        spent += tick;
        let backlog = ledger.backlog(replicas);
        let acks = ledger.acks_total();

        if backlog == 0 {
            zero_streak += 1;
            // Min-progress floor: an EMPTY workload (or a publisher's inter-burst lull) has zero backlog
            // from t0 and would otherwise report Converged with nothing delivered. Require some delivery
            // (acks > 0) before calling it converged — a network that never did anything hasn't converged.
            if zero_streak >= 2 && acks > 0 {
                return LivenessVerdict::Converged;
            }
        } else {
            zero_streak = 0;
        }

        if acks == last_acks && backlog > 0 {
            idle += tick;
            if idle >= stall_window {
                return LivenessVerdict::Stalled { backlog, acks };
            }
        } else {
            idle = Duration::ZERO;
            last_acks = acks;
        }

        if spent >= budget {
            return LivenessVerdict::Budget { backlog };
        }
    }
}

/// How a ledgered consumer fetches an advertised publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchMode {
    /// The stock name-paired `Consumer::fetch` (post-NS-6a).
    Stock,
    /// KNOWN-BAD reference (the pre-NS-6a shape): pair the reply to the request by ARRIVAL
    /// ORDER. Exists so the NS-6 matrix row can prove, live, that the byte-identity invariant
    /// catches the mispair class — a fault that can't redden a known-bad stack is a shell.
    ArrivalPaired,
}

/// How a ledgered consumer bounds one step, mirroring `Follow::step`'s shapes (NS-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepBound {
    /// No timeout — process every update to completion.
    None,
    /// Bound only the WAIT for the next update; once one arrives, process it to completion.
    /// The fixed shape ("bound the wait, not the processing").
    BoundedWait(Duration),
    /// KNOWN-BAD reference (the NS-9 shape): bound the WHOLE step — waiting AND the per-seq
    /// fetch/store/ack loop. When per-seq work is slow, the deadline fires mid-range and drops
    /// the step's events: seqs already handled are stored + acked (the two-phase ack keeps the
    /// poison line), but the caller never learns the store moved.
    WholeStep(Duration),
}

/// Options for [`ledgered_catchup`].
#[derive(Clone, Copy, Debug)]
pub struct CatchupOpts {
    pub fetch: FetchMode,
    pub step: StepBound,
    /// Simulated per-Block processing cost (e.g. a persistent store commit — the FS-5 ~15 ms
    /// that made NS-9 fire in the field). Virtual time; free under the kernel.
    pub per_seq_delay: Duration,
    /// KNOWN-BAD reference (the NS-4 shape): EXTRA per-Block cost proportional to how many
    /// Blocks this replica already holds — an O(history) walk per event (the `chain_head`
    /// trait-default re-walking every ancestry, the resolve re-verifying every packet). The
    /// ceiling-finder's red gate: with this on, the "per-event cost is flat vs history" bound
    /// must trip.
    pub per_stored_delay: Duration,
    /// `Some(n)` = a deliberately WEDGED consumer: after storing `n` Blocks it parks forever
    /// mid-stream — the faithful model of the field deadlock (a consumer frozen in a full ack
    /// channel: progress made, then nothing, no error). The watchdog's own red-capability
    /// probe: backlog stays nonzero, acks freeze, the stall MUST fire.
    pub wedge_after: Option<u64>,
    /// Max in-flight fetch Interests per catch-up chunk (`1` = the serial one-per-RTT loop).
    /// `> 1` pipelines the FETCH only ([`TwoPhaseReplica::fetch_window`], name-correlated so N
    /// outstanding can never mispair) while store/ack still run strictly in seq order,
    /// holding at the first miss — the ceiling-finder's serial-vs-windowed knob. Applies to
    /// [`FetchMode::Stock`]; the known-bad [`FetchMode::ArrivalPaired`] stays serial (its
    /// point is the pairing bug, not throughput).
    pub window: usize,
}

impl Default for CatchupOpts {
    fn default() -> Self {
        Self {
            fetch: FetchMode::Stock,
            step: StepBound::None,
            per_seq_delay: Duration::ZERO,
            per_stored_delay: Duration::ZERO,
            wedge_after: None,
            window: 1,
        }
    }
}

/// The instrumented consumer loop for matrix cells: a [`TwoPhaseReplica`] catch-up that
/// records every store/ack/report into the [`Ledger`], with pluggable known-bad shapes
/// ([`FetchMode::ArrivalPaired`], [`StepBound::WholeStep`], `ack: false`) so the matrix's
/// historical-bug rows can prove their own red-capability against the identical scenario.
pub async fn ledgered_catchup(
    replica: TwoPhaseReplica,
    ledger: std::sync::Arc<Ledger>,
    replica_name: String,
    opts: CatchupOpts,
) {
    let mut replica = replica;
    loop {
        // One step: obtain the next update (and, depending on the bound, process it inside or
        // outside the deadline), yielding the step's *reported events* — newly stored seqs the
        // caller learns about. `None` from the channel = group closed.
        let events: Option<Vec<(String, u64)>> = match opts.step {
            StepBound::None => match replica.handle.recv().await {
                Some(u) => Some(process_update(&replica, &ledger, &replica_name, u, &opts).await),
                None => None,
            },
            StepBound::BoundedWait(d) => {
                // The fixed shape: the deadline covers only the wait.
                match tokio::time::timeout(d, replica.handle.recv()).await {
                    Ok(Some(u)) => {
                        Some(process_update(&replica, &ledger, &replica_name, u, &opts).await)
                    }
                    Ok(None) => None,
                    Err(_) => Some(Vec::new()), // silence is not an error; try again
                }
            }
            StepBound::WholeStep(d) => {
                // KNOWN-BAD: the deadline covers processing too. A mid-range cancellation
                // drops the events vec — stores/acks already made stay made.
                match tokio::time::timeout(d, async {
                    match replica.handle.recv().await {
                        Some(u) => {
                            Some(process_update(&replica, &ledger, &replica_name, u, &opts).await)
                        }
                        None => None,
                    }
                })
                .await
                {
                    Ok(step) => step,
                    Err(_) => Some(Vec::new()), // the step was cancelled: EVENTS LOST
                }
            }
        };
        match events {
            Some(evs) => {
                for _ in evs {
                    ledger.record_reported(&replica_name);
                }
            }
            None => break,
        }
    }
}

/// Process one advertised update: per seq — fetch (stock serial, stock windowed, or
/// arrival-paired), simulate the per-Block cost, record the store, ack, and collect the
/// newly-stored seqs as the step's events. Windowed fetches (`opts.window > 1`) pipeline the
/// FETCH only: store/ack still run strictly in seq order over the buffered chunk, holding at
/// the first miss exactly like the serial loop.
async fn process_update(
    replica: &TwoPhaseReplica,
    ledger: &Ledger,
    replica_name: &str,
    update: ndn_sync::SyncUpdate,
    opts: &CatchupOpts,
) -> Vec<(String, u64)> {
    let mut events = Vec::new();
    if opts.window > 1 && opts.fetch == FetchMode::Stock {
        let mut next = update.low_seq;
        while next <= update.high_seq {
            let hi = (next + opts.window as u64 - 1).min(update.high_seq);
            let chunk = replica.fetch_window(&update.name, next, hi, opts.window).await;
            let requested = (hi - next + 1) as usize;
            for (i, slot) in chunk.into_iter().take(requested).enumerate() {
                let seq = next + i as u64;
                let Some(bytes) = slot else {
                    return events; // hold at the gap; the buffered tail is discarded
                };
                ingest_one(replica, ledger, replica_name, &update, seq, bytes, opts, &mut events)
                    .await;
            }
            next = hi + 1;
        }
        return events;
    }
    for seq in update.low_seq..=update.high_seq {
        let bytes = match opts.fetch {
            FetchMode::Stock => replica.fetch(&update.name, seq).await,
            FetchMode::ArrivalPaired => replica.fetch_arrival_paired(&update.name, seq).await,
        };
        let Some(bytes) = bytes else {
            match opts.fetch {
                // Hold at the gap; the next advertisement retries from here.
                FetchMode::Stock => break,
                // The field consumer's shape: on a client-side timeout it MOVED ON to the
                // next seq while the timed-out Interest stayed pending in the PIT — which is
                // exactly what lets the held reply land mid-way through a later exchange.
                FetchMode::ArrivalPaired => continue,
            }
        };
        ingest_one(replica, ledger, replica_name, &update, seq, bytes, opts, &mut events).await;
    }
    events
}

/// Ingest ONE fetched publication: the per-seq store/cost/wedge/ack body, identical for the
/// serial and windowed paths (windowing changes arrival, never this).
#[allow(clippy::too_many_arguments)]
async fn ingest_one(
    replica: &TwoPhaseReplica,
    ledger: &Ledger,
    replica_name: &str,
    update: &ndn_sync::SyncUpdate,
    seq: u64,
    bytes: bytes::Bytes,
    opts: &CatchupOpts,
    events: &mut Vec<(String, u64)>,
) {
    let newly = ledger.record_stored(replica_name, &update.publisher, seq, &bytes);
    if newly {
        // The per-event cost model applies to NEW Blocks only — it models the commit
        // (store write, verify, projection), not a re-advertised range's idempotent
        // re-walk (which the sync layer produces freely and must stay cheap).
        if !opts.per_seq_delay.is_zero() {
            tokio::time::sleep(opts.per_seq_delay).await;
        }
        if !opts.per_stored_delay.is_zero() {
            // O(history) per event — cost grows with what is already held (NS-4).
            let held = ledger.stored_count(replica_name);
            tokio::time::sleep(opts.per_stored_delay * held as u32).await;
        }
    }
    if let Some(cap) = opts.wedge_after {
        let held = {
            let stored = ledger.stored.lock().unwrap();
            stored.keys().filter(|(r, _, _)| r == replica_name).count() as u64
        };
        if held >= cap {
            // The field deadlock, modeled faithfully: mid-stream, mid-update, the
            // consumer freezes (as if parked in a full ack channel). No error, no ack,
            // no return — the watchdog is the only thing that can see this.
            std::future::pending::<()>().await;
        }
    }
    let _ = replica.handle.ack(&update.publisher, seq).await;
    ledger.record_ack();
    if newly {
        events.push((update.publisher.clone(), seq));
    }
}

/// One matrix cell's verdicts, serialized into the scoreboard.
#[derive(Debug, Clone, Serialize)]
pub struct CellReport {
    /// Cell id, `scenario/topology`.
    pub cell: String,
    /// The seed that reproduces this exact run (kernel + fabric + jitter RNG).
    pub seed: u64,
    /// The liveness half.
    pub liveness: LivenessVerdict,
    /// The safety half.
    pub invariants: Invariants,
    /// Publications authored / total acks, for the human reading the board.
    pub published: u64,
    pub acks: u64,
    /// The cell's overall verdict: converged AND both invariants hold.
    pub pass: bool,
}

impl CellReport {
    /// The NORMATIVE projection of this report — the fields the CI tripwire keys on and the
    /// fields that are same-seed deterministic: cell, seed, liveness *verdict class*,
    /// invariant verdicts, published count, and pass. Raw progress counters (`acks`, a stall's
    /// snapshot numbers) are diagnostic, not normative: they ride scheduling that tokio's
    /// `select!` randomizes from an unseeded RNG (`Builder::rng_seed` is `tokio_unstable` —
    /// full bit-determinism of the counters is a named residue until the kernel can seed it).
    pub fn normative(&self) -> String {
        let verdict = match self.liveness {
            LivenessVerdict::Converged => "converged",
            LivenessVerdict::Stalled { .. } => "stalled",
            LivenessVerdict::Budget { .. } => "budget",
        };
        format!(
            "{}|seed={}|{}|poison_free={}|event_integrity={}|published={}|pass={}",
            self.cell,
            self.seed,
            verdict,
            self.invariants.poison_free,
            self.invariants.event_integrity,
            self.published,
            self.pass
        )
    }

    /// Assemble a report from a finished cell.
    pub fn evaluate(
        cell: impl Into<String>,
        seed: u64,
        ledger: &Ledger,
        replicas: &[String],
        liveness: LivenessVerdict,
    ) -> Self {
        let invariants = ledger.invariants(replicas);
        let published = ledger.published.lock().unwrap().len() as u64;
        let acks = ledger.acks_total();
        let pass = liveness == LivenessVerdict::Converged
            && invariants.poison_free
            && invariants.event_integrity;
        Self {
            cell: cell.into(),
            seed,
            liveness,
            invariants,
            published,
            acks,
            pass,
        }
    }
}

/// The scoreboard: every cell's report, JSON-serializable for the CI tripwire.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Scoreboard {
    pub cells: Vec<CellReport>,
}

impl Scoreboard {
    pub fn push(&mut self, report: CellReport) {
        self.cells.push(report);
    }

    /// All cells passed.
    pub fn all_pass(&self) -> bool {
        self.cells.iter().all(|c| c.pass)
    }

    /// Pretty JSON for artifacts / diffing (deterministic given deterministic cells).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("scoreboard serializes")
    }
}
