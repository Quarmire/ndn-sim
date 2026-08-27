//! The **stall matrix** — instrument (c) of the field bench suite (skyfall FIELD-REPORT-2
//! §7(c)): scenario × topology cells on the deterministic `VirtualKernel`, each judged by the
//! DUAL assertion from `ndn_sim::liveness` — the end-state-agnostic **progress watchdog**
//! (backlog > 0 somewhere + zero acks anywhere over a window ⇒ stall) and the **convergence
//! invariants** (no-poison/byte-identity, event integrity). Every field bug shared one
//! signature — progress stops, nothing errors — and this suite makes that signature a
//! first-class CI failure.
//!
//! ## The historical-bug rows (red-capable by construction)
//!
//! Each NS row runs the CURRENT stack (green) and has a red-capability gate that swaps in the
//! documented known-bad shape and asserts the cell REDDENS — a row that can't turn a known-bad
//! stack red is a shell:
//!
//! - **NS-6 reorder→mispair**: row = the hold fault (delay-without-drop) under the stock
//!   name-paired fetch → green. Red gate: `FetchMode::ArrivalPaired` (the pre-`fe36e7be`
//!   pairing, preserved in the fieldkit) → a held stale reply is stored under the wrong seq →
//!   the **byte-identity invariant** reddens. (Liveness alone can't see a mispair — it
//!   converges to wrong bytes. That is why the assertion is dual.)
//! - **NS-7 burst deadlock**: row = a 400-Block catch-up through the stock two-phase channels
//!   → green since N-11 (`169f9a58`; the true pre-fix red-proof is in git history — ndn-sim
//!   `dbe14fd` pinned `Stalled{at:11}/400` against ndn-rs `2472b6d9`). Red gate: a consumer
//!   that freezes mid-stream (`wedge_after` — progress made, then nothing, no error, the
//!   deadlock's exact signature) → the **watchdog** fires.
//! - **NS-8 restart starvation**: row = a publisher restart with the persistent store
//!   (N-13/N-15) → green. Red gate: `RestartablePublisher::new_ephemeral` (the stock per-boot
//!   data plane) → the lagging peer starves → the **watchdog** fires.
//! - **NS-9 step-timeout event loss**: row = slow per-Block processing under
//!   `StepBound::BoundedWait` (bound the wait, not the processing) → green. Red gate:
//!   `StepBound::WholeStep` (the `Follow::step` shape from the field) → the deadline fires
//!   mid-range, stores/acks survive but the step's events are dropped → the **event-integrity
//!   invariant** reddens while liveness converges (the field symptom: a view sitting stale on
//!   a store that had moved).
//!
//! ## The scoreboard
//!
//! `stall_matrix_scoreboard` runs every green cell, asserts all pass, and writes the JSON
//! scoreboard (seed per cell — every failure is a seed you hand a debugger) to
//! `$CARGO_TARGET_TMPDIR/stall-scoreboard.json` + stdout. CI tracks it as a qualitative
//! tripwire (pass/stalled per cell), not a perf number — that's instrument (a)'s job.
//! `scoreboard_is_deterministic` pins same-seed → identical report.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_sim::fieldkit::{RestartablePublisher, TwoPhaseReplica, settle};
use ndn_sim::liveness::{
    CatchupOpts, CellReport, Ledger, LivenessVerdict, Scoreboard, StepBound,
    ledgered_catchup, watch,
};
use ndn_sim::{FrameMatcher, HoldRule, LinkConfig, NodeId, RunningSimulation, Simulation,
    VirtualKernel};
use tokio_util::sync::CancellationToken;

const GROUP: &str = "/grp";
const PUBLISHER: &str = "/nodes/A";
const STALL_WINDOW: Duration = Duration::from_secs(20);
const BUDGET: Duration = Duration::from_secs(600);

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Topo {
    /// A(publisher) — B(replica).
    Pair,
    /// A(publisher) — B(replica) — C(replica): C's fetches cross a real relay hop.
    Line3,
}

impl Topo {
    fn replica_names(self) -> Vec<String> {
        match self {
            Topo::Pair => vec!["B".into()],
            Topo::Line3 => vec!["B".into(), "C".into()],
        }
    }
}

/// Build a fabric for `topo` with `link` on every edge. Returns the fabric, the publisher
/// node, and the replica nodes in `replica_names` order.
async fn build_topology(
    k: std::sync::Arc<dyn ndn_sim::SimKernel>,
    seed: u64,
    topo: Topo,
    link: LinkConfig,
) -> (RunningSimulation, NodeId, Vec<NodeId>) {
    let mut sim = Simulation::new().without_radio_interference().kernel(k).seed(seed);
    let a = sim.add_node(EngineConfig::default());
    match topo {
        Topo::Pair => {
            let b = sim.add_node(EngineConfig::default());
            sim.link(a, b, link);
            sim.add_route(a, GROUP, b);
            sim.add_route(b, GROUP, a);
            sim.add_route(b, PUBLISHER, a);
            sim.add_strategy(a, GROUP, "multicast");
            sim.add_strategy(b, GROUP, "multicast");
            // A publisher restart serves the same prefixes from NEW app faces; multicast so
            // the live instance always hears (best-route can pin the dead boot's face).
            sim.add_strategy(a, PUBLISHER, "multicast");
            let fabric = sim.start().await.unwrap();
            (fabric, a, vec![b])
        }
        Topo::Line3 => {
            let b = sim.add_node(EngineConfig::default());
            let c = sim.add_node(EngineConfig::default());
            sim.link(a, b, link.clone());
            sim.link(b, c, link);
            for (from, to) in [(a, b), (b, a), (b, c), (c, b)] {
                sim.add_route(from, GROUP, to);
            }
            sim.add_route(b, PUBLISHER, a);
            sim.add_route(c, PUBLISHER, b);
            for n in [a, b, c] {
                sim.add_strategy(n, GROUP, "multicast");
            }
            sim.add_strategy(a, PUBLISHER, "multicast");
            let fabric = sim.start().await.unwrap();
            (fabric, a, vec![b, c])
        }
    }
}

/// Attach a ledgered replica (sync plane + instrumented catch-up loop) on each replica node.
async fn attach_replicas(
    fabric: &RunningSimulation,
    nodes: &[NodeId],
    names: &[String],
    ledger: &Arc<Ledger>,
    opts: CatchupOpts,
    cancel: &CancellationToken,
) {
    for (node, rname) in nodes.iter().zip(names) {
        let replica = TwoPhaseReplica::attach(
            fabric,
            *node,
            &name(GROUP),
            &name(&format!("/nodes/{rname}")),
            Duration::from_millis(500),
            cancel,
        )
        .await
        .expect("replica attaches");
        tokio::spawn(ledgered_catchup(
            replica,
            Arc::clone(ledger),
            rname.clone(),
            opts,
        ));
    }
}

/// Publish `count` Blocks through `publisher`, recording each authored payload in the ledger
/// under its assigned SVS seq (live — this is what makes backlog end-state-agnostic).
async fn publish_ledgered(
    publisher: &ndn_app::Publisher,
    ledger: &Ledger,
    count: usize,
    tag: &str,
) {
    for i in 0..count {
        let payload = format!("blk-{tag}-{i}");
        let seq = publisher.put(payload.as_bytes()).await.expect("put");
        ledger.record_published(PUBLISHER, seq, payload.as_bytes());
    }
}

/// One single-phase cell: build the topology, attach replicas, optionally install a hold
/// fault, publish `blocks`, and watch. Covers the clean / drop / reorder / burst / slow-store
/// scenarios; restart and lag have their own multi-phase runners.
fn run_simple_cell(
    cell: &str,
    seed: u64,
    topo: Topo,
    link: LinkConfig,
    hold: Option<HoldRule>,
    blocks: usize,
    opts: CatchupOpts,
) -> CellReport {
    fastrand::seed(seed);
    let kernel = VirtualKernel::new();
    let cell = cell.to_string();
    kernel.run(move |k| async move {
        let (fabric, a, replicas) = build_topology(k, seed, topo, link).await;
        let cancel = CancellationToken::new();
        let ledger = Arc::new(Ledger::new());
        let rnames = topo.replica_names();

        attach_replicas(&fabric, &replicas, &rnames, &ledger, opts, &cancel).await;
        let publisher = fabric
            .engine_of(a)
            .unwrap()
            .app_node(cancel.child_token())
            .publish(name(GROUP), name(PUBLISHER))
            .await
            .expect("publisher");
        settle(Duration::from_millis(300)).await;

        if let Some(rule) = hold {
            // The reorder fault: delay matching Data on the publisher's egress WITHOUT
            // dropping them (Topo::Pair edge a→b; line topologies would install per-edge).
            fabric.hold_link(a, replicas[0], rule).unwrap();
        }

        publish_ledgered(&publisher, &ledger, blocks, "w").await;
        let liveness = watch(&ledger, &rnames, STALL_WINDOW, BUDGET).await;
        let report = CellReport::evaluate(cell, seed, &ledger, &rnames, liveness);

        cancel.cancel();
        fabric.shutdown().await;
        report
    })
}

/// The NS-8 row runner: converge a baseline, partition, publish into the void, restart the
/// publisher, heal, and watch. `persistent` selects the fixed regime (store retained across
/// the boot) vs the stock ephemeral one (the starvation the red gate pins).
fn run_restart_cell(cell: &str, seed: u64, persistent: bool) -> CellReport {
    fastrand::seed(seed);
    let kernel = VirtualKernel::new();
    let cell = cell.to_string();
    kernel.run(move |k| async move {
        let (fabric, a, replicas) = build_topology(k, seed, Topo::Pair, LinkConfig::lan()).await;
        let cancel = CancellationToken::new();
        let ledger = Arc::new(Ledger::new());
        let rnames = Topo::Pair.replica_names();

        attach_replicas(
            &fabric,
            &replicas,
            &rnames,
            &ledger,
            CatchupOpts::default(),
            &cancel,
        )
        .await;

        let group = name(GROUP);
        let local = name(PUBLISHER);
        let mut publisher = if persistent {
            RestartablePublisher::new(&fabric, a, &group, &local, &cancel).unwrap()
        } else {
            RestartablePublisher::new_ephemeral(&fabric, a, &group, &local, &cancel).unwrap()
        };
        publisher.start().await.unwrap();
        settle(Duration::from_millis(300)).await;

        // Phase 1: a baseline replicates.
        publish_ledgered(publisher.publisher().unwrap(), &ledger, 2, "pre").await;
        let baseline = watch(&ledger, &rnames, STALL_WINDOW, BUDGET).await;
        assert_eq!(
            baseline,
            LivenessVerdict::Converged,
            "restart cell precondition: the pre-partition baseline converges"
        );

        // Phase 2 (no watchdog — the fault window is intentional): partition, publish into
        // the void, restart the publisher, heal.
        fabric.set_link_up(a, replicas[0], false).unwrap();
        publish_ledgered(publisher.publisher().unwrap(), &ledger, 1, "split").await;
        publisher.stop();
        publisher.start().await.unwrap();
        fabric.set_link_up(a, replicas[0], true).unwrap();

        // Phase 3: the peer is one Block behind a restarted publisher — the NS-8 moment.
        let liveness = watch(&ledger, &rnames, STALL_WINDOW, BUDGET).await;
        let report = CellReport::evaluate(cell, seed, &ledger, &rnames, liveness);

        cancel.cancel();
        fabric.shutdown().await;
        report
    })
}

/// The lag row: a late joiner attaches only after the publisher built history, and must
/// converge from the publisher's (same-boot) store with no re-announce.
fn run_lag_cell(cell: &str, seed: u64) -> CellReport {
    fastrand::seed(seed);
    let kernel = VirtualKernel::new();
    let cell = cell.to_string();
    kernel.run(move |k| async move {
        let (fabric, a, replicas) = build_topology(k, seed, Topo::Line3, LinkConfig::lan()).await;
        let cancel = CancellationToken::new();
        let ledger = Arc::new(Ledger::new());
        let rnames = Topo::Line3.replica_names();

        // Only B attaches up front.
        attach_replicas(
            &fabric,
            &replicas[..1],
            &rnames[..1],
            &ledger,
            CatchupOpts::default(),
            &cancel,
        )
        .await;
        let publisher = fabric
            .engine_of(a)
            .unwrap()
            .app_node(cancel.child_token())
            .publish(name(GROUP), name(PUBLISHER))
            .await
            .expect("publisher");
        settle(Duration::from_millis(300)).await;

        publish_ledgered(&publisher, &ledger, 20, "w").await;
        let head_start = watch(&ledger, &rnames[..1], STALL_WINDOW, BUDGET).await;
        assert_eq!(
            head_start,
            LivenessVerdict::Converged,
            "lag cell precondition: the on-time replica converges first"
        );

        // C joins late, 20 Blocks behind.
        attach_replicas(
            &fabric,
            &replicas[1..],
            &rnames[1..],
            &ledger,
            CatchupOpts::default(),
            &cancel,
        )
        .await;
        let liveness = watch(&ledger, &rnames, STALL_WINDOW, BUDGET).await;
        let report = CellReport::evaluate(cell, seed, &ledger, &rnames, liveness);

        cancel.cancel();
        fabric.shutdown().await;
        report
    })
}

fn lossy() -> LinkConfig {
    LinkConfig {
        delay: Duration::from_millis(20),
        jitter: Duration::from_millis(5),
        loss_rate: 0.25,
        bandwidth_bps: 0,
    }
}

/// The hold fault used by the reorder row: delay two mid-stream Data replies by 2 s — past
/// nothing on the stock consumer (absorbed as late replies) but exactly the straggler window
/// the arrival-paired red gate mispairs on.
fn reorder_hold() -> HoldRule {
    HoldRule {
        matcher: FrameMatcher::Data,
        skip: 1,
        count: 2,
        delay: Duration::from_secs(2),
    }
}

/// The NS-9 row's per-Block cost (the FS-5 persistent-store commit that made the field bug
/// fire) and the step bounds under test.
const SLOW_STORE: Duration = Duration::from_millis(15);

// ────────────────────────────────────────────────────────────────────────────────────────────
// The scoreboard: every green cell of the v1 matrix. All must pass; the JSON is the artifact.
// ────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn stall_matrix_scoreboard() {
    let mut board = Scoreboard::default();

    // Baselines: clean and lossy, pair and relay line.
    board.push(run_simple_cell(
        "clean/pair", 0xC701, Topo::Pair, LinkConfig::lan(), None, 30,
        CatchupOpts::default(),
    ));
    board.push(run_simple_cell(
        "clean/line3", 0xC702, Topo::Line3, LinkConfig::lan(), None, 30,
        CatchupOpts::default(),
    ));
    board.push(run_simple_cell(
        "drop/pair", 0xC703, Topo::Pair, lossy(), None, 30,
        CatchupOpts::default(),
    ));
    board.push(run_simple_cell(
        "drop/line3", 0xC704, Topo::Line3, lossy(), None, 20,
        CatchupOpts::default(),
    ));

    // NS-6 row — reorder (delay-without-drop) under the stock name-paired fetch.
    board.push(run_simple_cell(
        "reorder-ns6/pair", 0xC706, Topo::Pair,
        LinkConfig { delay: Duration::from_millis(30), ..LinkConfig::default() },
        Some(reorder_hold()), 12, CatchupOpts::default(),
    ));

    // NS-6 row, WINDOWED (skyfall §6.1): the same reorder fault with 16 fetches in flight.
    // Out-of-order arrival is exactly where a held stale reply could mispair — the
    // name-correlated window must keep the byte-identity invariant green.
    board.push(run_simple_cell(
        "reorder-ns6-windowed/pair", 0xC716, Topo::Pair,
        LinkConfig { delay: Duration::from_millis(30), ..LinkConfig::default() },
        Some(reorder_hold()), 12, CatchupOpts { window: 16, ..CatchupOpts::default() },
    ));

    // NS-7 row — a 400-Block catch-up through the stock two-phase channels.
    board.push(run_simple_cell(
        "burst-ns7/pair", 0xC707, Topo::Pair, LinkConfig::lan(), None, 400,
        CatchupOpts::default(),
    ));

    // NS-7 row, WINDOWED: the same 400-Block burst with the windowed catch-up ON — the
    // channel-geometry deadlock must stay unreachable when acks arrive in chunk-sized runs.
    board.push(run_simple_cell(
        "burst-ns7-windowed/pair", 0xC717, Topo::Pair, LinkConfig::lan(), None, 400,
        CatchupOpts { window: 16, ..CatchupOpts::default() },
    ));

    // NS-8 row — publisher restart with the persistent store (the N-13/N-15 regime).
    board.push(run_restart_cell("restart-ns8/pair", 0xC708, true));

    // NS-9 row — slow per-Block processing under the FIXED step shape (bound the wait).
    board.push(run_simple_cell(
        "slowstore-ns9/pair", 0xC709, Topo::Pair, LinkConfig::lan(), None, 30,
        CatchupOpts {
            per_seq_delay: SLOW_STORE,
            step: StepBound::BoundedWait(Duration::from_millis(200)),
            ..CatchupOpts::default()
        },
    ));

    // Lag row — a late joiner 20 Blocks behind converges off the publisher's store.
    board.push(run_lag_cell("lag/line3", 0xC70A));

    let json = board.to_json();
    println!("{json}");
    if let Some(dir) = option_env!("CARGO_TARGET_TMPDIR") {
        let path = std::path::Path::new(dir).join("stall-scoreboard.json");
        std::fs::write(&path, &json).expect("write scoreboard");
        println!("scoreboard written to {}", path.display());
    }
    assert!(
        board.all_pass(),
        "stall matrix has failing cells — the scoreboard above names them (each failure is a \
         seed you can hand a debugger)"
    );
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// Red-capability gates: a watchdog that never fires — or a row that can't redden a known-bad
// stack — is a shell. Each gate swaps in the documented known-bad shape and asserts red.
// ────────────────────────────────────────────────────────────────────────────────────────────

/// The watchdog fires on a deliberately wedged stack (a consumer that stores but never acks —
/// the frozen-acks signature every field stall shared) and stays silent on the healthy twin.
#[test]
fn watchdog_fires_on_a_wedged_stack_and_stays_silent_on_a_healthy_one() {
    // Healthy twin first: identical cell, stock consumer → converges, invariants hold.
    let healthy = run_simple_cell(
        "gate-healthy/pair", 0xC7A0, Topo::Pair, LinkConfig::lan(), None, 10,
        CatchupOpts::default(),
    );
    assert!(
        healthy.pass,
        "the watchdog must stay SILENT on a healthy stack: {healthy:?}"
    );

    // The wedge: a consumer that freezes mid-stream after 4 Blocks — the field deadlock's
    // signature (progress made, then frozen, no error). The watchdog MUST fire.
    let wedged = run_simple_cell(
        "gate-wedged/pair", 0xC7A1, Topo::Pair, LinkConfig::lan(), None, 10,
        CatchupOpts { wedge_after: Some(4), ..CatchupOpts::default() },
    );
    let LivenessVerdict::Stalled { backlog, acks } = wedged.liveness else {
        panic!(
            "the watchdog must FIRE on a wedged stack (this is the NS-7 signature — the true \
             pre-N-11 red-proof is pinned in git history at ndn-sim dbe14fd): {wedged:?}"
        );
    };
    assert!(backlog > 0 && acks > 0, "wedged MID-stream: progress made, then frozen");
    assert!(!wedged.pass);
}

/// NS-6 red gate: the arrival-paired fetch (the pre-`fe36e7be` pairing, preserved in the
/// fieldkit) under the hold fault stores a held stale reply under the wrong seq — the
/// byte-identity invariant reddens. Liveness alone would call this converged to wrong bytes:
/// that is exactly why the assertion is dual.
///
/// The drive is a SINGLE sequential pass over the advertised seqs (fetch each name once, move
/// on after a client-side timeout — the field consumer's shape). Deliberately not routed
/// through the SVS catch-up loop: in-order range retries + the Content Store self-align an
/// arrival-paired consumer (a held reply gets popped by its own name's retry, accidentally
/// correct), and the range shapes vary with sync-round interleaving. The single pass IS the
/// deterministic mispair geometry — a held mid-stream reply lands inside the NEXT fetch's
/// (timeout, timeout+RTT) window, ahead of that fetch's own reply, and every later pairing
/// shifts by one (the pinned-red original is `field_faults.rs` at ndn-sim `dbe14fd`).
#[test]
fn ns6_row_reddens_with_arrival_paired_pairing() {
    fastrand::seed(0xC7A6);
    let kernel = VirtualKernel::new();
    let invariants = kernel.run(|k| async move {
        // 200 ms one-way (400 ms RTT); hold the 3rd Data by +800 ms → it lands ~200 ms after
        // the 1 s client wait expires, inside the next fetch's own-reply window.
        let (fabric, a, replicas) = build_topology(
            k,
            0xC7A6,
            Topo::Pair,
            LinkConfig { delay: Duration::from_millis(200), ..LinkConfig::default() },
        )
        .await;
        let cancel = CancellationToken::new();
        let ledger = Arc::new(Ledger::new());

        let publisher = fabric
            .engine_of(a)
            .unwrap()
            .app_node(cancel.child_token())
            .publish(name(GROUP), name(PUBLISHER))
            .await
            .expect("publisher");
        settle(Duration::from_millis(300)).await;
        publish_ledgered(&publisher, &ledger, 12, "w").await;

        fabric
            .hold_link(
                a,
                replicas[0],
                HoldRule {
                    matcher: FrameMatcher::Data,
                    skip: 2,
                    count: 1,
                    delay: Duration::from_millis(800),
                },
            )
            .unwrap();

        // The known-bad consumer, one sequential pass: fetch each advertised seq by arrival
        // pairing; on timeout move on (the timed-out Interest stays pending in the PIT).
        let replica = TwoPhaseReplica::attach(
            &fabric,
            replicas[0],
            &name(GROUP),
            &name("/nodes/B"),
            Duration::from_millis(500),
            &cancel,
        )
        .await
        .unwrap();
        for seq in 1..=12u64 {
            if let Some(bytes) = replica.fetch_arrival_paired(&name(PUBLISHER), seq).await
                && ledger.record_stored("B", PUBLISHER, seq, &bytes)
            {
                ledger.record_reported("B");
            }
        }

        let invariants = ledger.invariants(&["B".to_string()]);
        cancel.cancel();
        fabric.shutdown().await;
        invariants
    });

    assert!(
        !invariants.poison_free,
        "the NS-6 row must redden a known-bad (arrival-paired) consumer via byte-identity — \
         got {invariants:?}"
    );
    println!("NS-6 mispair caught: {:?}", invariants.violations);
}

/// NS-8 red gate: the stock per-boot (ephemeral) data plane starves the lagging peer after a
/// publisher restart — the watchdog fires on the healed, silent fabric.
#[test]
fn ns8_row_reddens_with_the_ephemeral_data_plane() {
    let red = run_restart_cell("gate-ns8-ephemeral/pair", 0xC7A8, false);
    assert!(
        matches!(red.liveness, LivenessVerdict::Stalled { .. }),
        "the NS-8 row must redden the stock per-boot data plane (peer one Block behind, \
         nothing errors): {red:?}"
    );
    assert!(!red.pass);
}

/// NS-9 red gate: bounding the WHOLE step (the `Follow::step` field shape) instead of just
/// the wait drops in-flight events when per-Block processing is slow — the store converges
/// but the caller never learns: event integrity reddens while liveness is green.
#[test]
fn ns9_row_reddens_with_a_whole_step_bound() {
    let red = run_simple_cell(
        "gate-ns9-wholestep/pair", 0xC7A9, Topo::Pair, LinkConfig::lan(), None, 30,
        CatchupOpts {
            per_seq_delay: SLOW_STORE,
            step: StepBound::WholeStep(Duration::from_millis(50)),
            ..CatchupOpts::default()
        },
    );
    assert_eq!(
        red.liveness,
        LivenessVerdict::Converged,
        "NS-9 is NOT a liveness failure — the store moves; that is what made it invisible"
    );
    assert!(
        !red.invariants.event_integrity,
        "the NS-9 row must redden the whole-step bound via event integrity: {red:?}"
    );
    assert!(!red.pass);
}

/// Same seed ⇒ identical NORMATIVE report (cell, seed, verdict class, invariants, published,
/// pass) — every red cell is a seed you can hand a debugger. Raw progress counters are
/// diagnostic, not compared: tokio's `select!` polls branches in an order drawn from an
/// unseeded RNG (`Builder::rng_seed` is `tokio_unstable`), so schedule-sensitive counts
/// wiggle between runs while every verdict stays fixed — the named determinism residue.
#[test]
fn scoreboard_is_deterministic() {
    let run = || {
        run_simple_cell(
            "determinism/drop-pair", 0xC7D0, Topo::Pair, lossy(), None, 20,
            CatchupOpts::default(),
        )
        .normative()
    };
    let first = run();
    let second = run();
    assert_eq!(
        first, second,
        "same seed must reproduce the identical normative cell report"
    );
}
