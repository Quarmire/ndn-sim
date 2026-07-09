//! The **ceiling-finder**, macro tier — instrument (a) of the field bench suite (skyfall
//! FIELD-REPORT-2 §7(a)). Deterministic, seeded, bisectable perf cells over real
//! `ForwarderEngine`s on the `VirtualKernel`, riding instrument (c)'s framework (`Ledger`,
//! fieldkit consumers, seed-per-cell, normative projections) instead of forking it.
//!
//! THE RULE (the design crux): the scoreboard **records** absolute numbers — virtual-time
//! durations, rates, percentiles, curve points — for humans and bisection; CI **asserts**
//! only SHAPES: growth bounds ("per-event cost flat vs history", "catch-up linear-ish in
//! backlog, not quadratic"), catastrophic-superlinearity guards, and knees that are FOUND,
//! not assumed. Absolute p99s are never CI-asserted.
//!
//! Red-capability (same discipline as the watchdog): `flat_bound_reddens_on_a_quadratic_path`
//! swaps in a consumer whose per-event cost grows with history — `CatchupOpts::
//! per_stored_delay`, the NS-4 field shape (`chain_head` re-walking every ancestry per query)
//! — and the flat-vs-history bound MUST trip. A bound that can't go red is a shell.
//!
//! Durations are VIRTUAL time: protocol shape (round trips, cadence, modeled per-event
//! costs), not host CPU — that is what makes them deterministic. Host-CPU per-op numbers live
//! in the micro tier (criterion benches in ndf-core / ndf-policy, where the code lives).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_sim::ceiling::{
    BoundCheck, PerfBoard, PerfCell, find_knee, growth_bound, latency_catchup, percentile,
    time_to_drain,
};
use ndn_sim::fieldkit::{TwoPhaseReplica, settle};
use ndn_sim::liveness::{CatchupOpts, Ledger, ledgered_catchup};
use ndn_sim::{LinkConfig, NodeId, RunningSimulation, Simulation, VirtualKernel};
use tokio_util::sync::CancellationToken;

const PUBLISHER: &str = "/nodes/A";
const DRAIN_BUDGET: Duration = Duration::from_secs(1200);

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

/// A—B pair on a LAN link, routes + multicast for `groups` sync prefixes.
async fn build_pair(
    k: std::sync::Arc<dyn ndn_sim::SimKernel>,
    seed: u64,
    groups: &[String],
) -> (RunningSimulation, NodeId, NodeId) {
    let mut sim = Simulation::new().kernel(k).seed(seed);
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    sim.link(a, b, LinkConfig::lan());
    for g in groups {
        sim.add_route(a, g, b);
        sim.add_route(b, g, a);
        sim.add_strategy(a, g, "multicast");
        sim.add_strategy(b, g, "multicast");
    }
    sim.add_route(b, PUBLISHER, a);
    let fabric = sim.start().await.unwrap();
    (fabric, a, b)
}

/// A star: publisher hub A with `peers` spokes, one sync group.
async fn build_star(
    k: std::sync::Arc<dyn ndn_sim::SimKernel>,
    seed: u64,
    peers: usize,
) -> (RunningSimulation, NodeId, Vec<NodeId>) {
    let mut sim = Simulation::new().kernel(k).seed(seed);
    let a = sim.add_node(EngineConfig::default());
    let spokes: Vec<NodeId> = (0..peers).map(|_| sim.add_node(EngineConfig::default())).collect();
    for &s in &spokes {
        sim.link(a, s, LinkConfig::lan());
        sim.add_route(a, "/grp", s);
        sim.add_route(s, "/grp", a);
        sim.add_route(s, PUBLISHER, a);
        sim.add_strategy(s, "/grp", "multicast");
    }
    sim.add_strategy(a, "/grp", "multicast");
    sim.add_strategy(a, PUBLISHER, "multicast");
    let fabric = sim.start().await.unwrap();
    (fabric, a, spokes)
}

#[allow(clippy::too_many_arguments)]
async fn attach_ledgered(
    fabric: &RunningSimulation,
    node: NodeId,
    group: &str,
    local: &str,
    ledger: &Arc<Ledger>,
    rname: &str,
    opts: CatchupOpts,
    cancel: &CancellationToken,
) {
    attach_ledgered_at(
        fabric,
        node,
        group,
        local,
        ledger,
        rname,
        opts,
        Duration::from_millis(500),
        cancel,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn attach_ledgered_at(
    fabric: &RunningSimulation,
    node: NodeId,
    group: &str,
    local: &str,
    ledger: &Arc<Ledger>,
    rname: &str,
    opts: CatchupOpts,
    sync_interval: Duration,
    cancel: &CancellationToken,
) {
    let replica = TwoPhaseReplica::attach(
        fabric,
        node,
        &name(group),
        &name(local),
        sync_interval,
        cancel,
    )
    .await
    .expect("replica attaches");
    tokio::spawn(ledgered_catchup(
        replica,
        Arc::clone(ledger),
        rname.to_string(),
        opts,
    ));
}

async fn publish_n(publisher: &ndn_app::Publisher, ledger: &Ledger, pub_name: &str, n: usize) {
    for i in 0..n {
        let payload = format!("blk-{pub_name}-{i}");
        let seq = publisher.put(payload.as_bytes()).await.expect("put");
        ledger.record_published(pub_name, seq, payload.as_bytes());
    }
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// Cell: streaming ingest, per-event cost vs history — quartile durations of a 400-Block
// stream. The FLAT bound: the 4th hundred may cost at most 2.5× the 1st hundred per Block.
// `per_stored_delay` (the NS-4 O(history)-per-event shape) is the red-gate knob.
// ────────────────────────────────────────────────────────────────────────────────────────────

fn run_ingest_cell(cell: &str, seed: u64, per_stored: Duration) -> PerfCell {
    fastrand::seed(seed);
    let kernel = VirtualKernel::new();
    let cell = cell.to_string();
    kernel.run(move |k| async move {
        let (fabric, a, b) = build_pair(k, seed, &["/grp".into()]).await;
        let cancel = CancellationToken::new();
        let ledger = Arc::new(Ledger::new());

        attach_ledgered(
            &fabric, b, "/grp", "/nodes/B", &ledger, "B",
            CatchupOpts {
                // A constant per-Block cost dominates round-trip noise so the quartile shape
                // measures the CONSUMER's cost model, which is what the bound is about.
                per_seq_delay: Duration::from_millis(10),
                per_stored_delay: per_stored,
                ..CatchupOpts::default()
            },
            &cancel,
        )
        .await;
        let publisher = fabric
            .engine_of(a)
            .unwrap()
            .app_node(cancel.child_token())
            .publish(name("/grp"), name(PUBLISHER))
            .await
            .unwrap();
        settle(Duration::from_millis(300)).await;

        const TOTAL: u64 = 400;
        let start = tokio::time::Instant::now();
        publish_n(&publisher, &ledger, PUBLISHER, TOTAL as usize).await;

        // Quartile crossings: the virtual instant the replica's holdings pass 100/200/300/400.
        let mut crossings: Vec<Duration> = Vec::new();
        let mut next = 100u64;
        loop {
            tokio::time::sleep(Duration::from_millis(20)).await;
            let held = ledger.stored_count("B");
            while next <= TOTAL && held >= next {
                crossings.push(start.elapsed());
                next += 100;
            }
            if next > TOTAL {
                break;
            }
            assert!(
                start.elapsed() < DRAIN_BUDGET,
                "ingest cell exceeded budget at {held}/{TOTAL}"
            );
        }

        let q = |i: usize| -> f64 {
            let lo = if i == 0 { Duration::ZERO } else { crossings[i - 1] };
            (crossings[i] - lo).as_secs_f64() * 1e3
        };
        let (q1, q4) = (q(0), q(3));
        let total_ms = crossings[3].as_secs_f64() * 1e3;

        let mut report = PerfCell::new(cell, seed);
        report.metric("q1_ms_per_100", q1);
        report.metric("q2_ms_per_100", q(1));
        report.metric("q3_ms_per_100", q(2));
        report.metric("q4_ms_per_100", q4);
        report.metric("total_ms", total_ms);
        report.metric("blocks_per_vsec", TOTAL as f64 / (total_ms / 1e3));
        report.metric(
            "payload_bytes_per_block",
            ledger.stored_bytes("B") as f64 / TOTAL as f64,
        );
        report.bound(growth_bound(
            "ingest-flat-vs-history",
            "per-event ingest cost is flat as history grows (NOT O(history) per event)",
            (100, q1),
            (400, q4),
            2.5,
        ));

        cancel.cancel();
        fabric.shutdown().await;
        report
    })
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// Cell: the late-join catch-up curve — time-to-converge vs backlog size (skyfall's
// late_join.rs, generalized), swept SERIAL (window=1, one round trip per Block) and WINDOWED
// (window=16, the repl-transport §6.1 pipeline) over the identical scenario. Bounds:
// linear-ish, not quadratic (8× backlog may cost ≤16×; quadratic would be 64×), on both
// curves; and THE BEND — the windowed curve must actually pipeline (≥4× faster at the largest
// backlog; ~window× is the theoretical ceiling, RTT-dominated links sit near it). The
// per-Block knee is FOUND and recorded.
// ────────────────────────────────────────────────────────────────────────────────────────────

/// One late-join catch-up sweep: cold catch-up of each backlog size over an A—B pair,
/// returning `(backlog, total ms)` per point. `window = 1` is the serial one-per-RTT loop.
///
/// A TRUE late join: after the history is published, the fabric settles until the
/// publisher's per-put advert burst has fully drained (each `put` broadcasts a sync
/// Interest; a replica attached mid-burst hears an escalating range one advert at a time
/// and the measurement becomes the BURST's pacing, not the catch-up's). The cold joiner
/// then hears one steady-state advert carrying the whole backlog — the skyfall §6.1 shape
/// where the fetch strategy is what's being measured.
fn late_join_curve(seed: u64, window: usize) -> Vec<(u64, f64)> {
    let backlogs = [50u64, 100, 200, 400];
    let mut curve: Vec<(u64, f64)> = Vec::new(); // (backlog, total ms)
    for (i, &n) in backlogs.iter().enumerate() {
        let point_seed = seed + i as u64;
        fastrand::seed(point_seed);
        let kernel = VirtualKernel::new();
        let ms = kernel.run(move |k| async move {
            let (fabric, a, b) = build_pair(k, point_seed, &["/grp".into()]).await;
            let cancel = CancellationToken::new();
            let ledger = Arc::new(Ledger::new());
            // A tight PERIODIC advert (the stock default is 30 s, which makes a cold
            // joiner's discovery ride the long-tailed suppression-reply path — seed-
            // dependent seconds of noise swamping the phase this sweep measures).
            let pub_cfg = ndn_app::PublisherConfig {
                svs: ndn_sync::SvsConfig {
                    sync_interval: Duration::from_millis(200),
                    jitter_ms: 0,
                    ..ndn_sync::SvsConfig::default()
                },
                ..ndn_app::PublisherConfig::default()
            };
            let publisher = fabric
                .engine_of(a)
                .unwrap()
                .app_node(cancel.child_token())
                .publish_with_config(name("/grp"), name(PUBLISHER), pub_cfg)
                .await
                .unwrap();
            settle(Duration::from_millis(300)).await;
            // History first, replica after: one cold catch-up of exactly `n`.
            publish_n(&publisher, &ledger, PUBLISHER, n as usize).await;
            // Drain the advert burst (≈ a few ms per put, virtual time is free).
            settle(Duration::from_millis(20 * n + 1_000)).await;
            // A tight replica sync interval keeps the DISCOVERY floor (first
            // vector exchange) from swamping the fetch phase the sweep measures.
            attach_ledgered_at(
                &fabric, b, "/grp", "/nodes/B", &ledger, "B",
                CatchupOpts { window, ..CatchupOpts::default() },
                Duration::from_millis(100), &cancel,
            )
            .await;
            let drain =
                time_to_drain(&ledger, &["B".to_string()], DRAIN_BUDGET).await;
            cancel.cancel();
            fabric.shutdown().await;
            drain.as_secs_f64() * 1e3
        });
        curve.push((n, ms));
    }
    curve
}

/// The bend bound: at the largest backlog, the windowed catch-up must be ≥`min_speedup`×
/// faster than the serial one on the identical sweep. This is the §6.1 acceptance shape —
/// red-capable: a window that doesn't pipeline (one fetch per RTT regardless) lands at
/// ratio ≈ 1 and trips it (see `bend_bound_reddens_when_the_window_does_not_pipeline`).
fn bend_bound(serial: &[(u64, f64)], windowed: &[(u64, f64)], min_speedup: f64) -> BoundCheck {
    let (n, serial_ms) = *serial.last().unwrap();
    let (_, windowed_ms) = *windowed.last().unwrap();
    let speedup = if windowed_ms > 0.0 { serial_ms / windowed_ms } else { f64::INFINITY };
    BoundCheck {
        name: "latejoin-window-bends-the-curve".into(),
        claim: format!(
            "the windowed catch-up pipelines: ≥{min_speedup}× faster than serial at backlog \
             {n} (serial ≈ one RTT per Block; windowed ≈ backlog/window RTTs)"
        ),
        detail: format!(
            "serial {serial_ms:.1} ms vs windowed {windowed_ms:.1} ms @ backlog {n} \
             (speedup {speedup:.2}×, bound ≥{min_speedup}×)"
        ),
        pass: speedup >= min_speedup,
    }
}

fn run_late_join_cell(cell: &str, seed: u64) -> PerfCell {
    const WINDOW: usize = 16;
    let serial = late_join_curve(seed, 1);
    let windowed = late_join_curve(seed, WINDOW);

    let mut report = PerfCell::new(cell, seed);
    for (n, ms) in &serial {
        report.metric(format!("catchup_ms_backlog_{n}"), *ms);
    }
    for (n, ms) in &windowed {
        report.metric(format!("catchup_ms_backlog_{n}_w{WINDOW}"), *ms);
    }
    let per_block: Vec<(u64, f64)> = serial.iter().map(|(n, ms)| (*n, ms / *n as f64)).collect();
    let knee = find_knee(&per_block, 3.0);
    report.metric(
        "knee_backlog",
        knee.map(|n| n as f64).unwrap_or(-1.0), // -1 = no knee ≤ 400 (found, not assumed)
    );
    report.bound(growth_bound(
        "latejoin-linearish",
        "catch-up time grows roughly linearly with backlog (8× blocks ≤ 16× time; quadratic \
         would be 64×)",
        (50, serial[0].1),
        (400, serial[3].1),
        16.0,
    ));
    // Small windowed backlogs finish inside one drain-poll tick (50 ms) and read as 0;
    // clamp both points to the measurement resolution so the growth ratio stays meaningful.
    report.bound(growth_bound(
        "latejoin-windowed-linearish",
        "windowed catch-up still grows roughly linearly with backlog (the window divides the \
         RTT count; it must not change the growth ORDER; points clamped to the 50 ms drain-poll \
         resolution)",
        (50, windowed[0].1.max(50.0)),
        (400, windowed[3].1.max(50.0)),
        16.0,
    ));
    report.bound(bend_bound(&serial, &windowed, 4.0));
    report
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// Cell: publish → remote-store latency under sustained load. p50/p99 are RECORDED (never
// CI-asserted); the one bound is tail SHAPE (p99 within 50× p50 — no pathological tail).
// ────────────────────────────────────────────────────────────────────────────────────────────

fn run_latency_cell(cell: &str, seed: u64) -> PerfCell {
    fastrand::seed(seed);
    let kernel = VirtualKernel::new();
    let cell = cell.to_string();
    kernel.run(move |k| async move {
        let (fabric, a, b) = build_pair(k, seed, &["/grp".into()]).await;
        let cancel = CancellationToken::new();
        let ledger = Arc::new(Ledger::new());
        let arrivals: Arc<std::sync::Mutex<BTreeMap<u64, tokio::time::Instant>>> =
            Arc::new(std::sync::Mutex::new(BTreeMap::new()));

        let replica = TwoPhaseReplica::attach(
            &fabric, b, &name("/grp"), &name("/nodes/B"),
            Duration::from_millis(500), &cancel,
        )
        .await
        .unwrap();
        tokio::spawn(latency_catchup(
            replica,
            Arc::clone(&ledger),
            "B".to_string(),
            Arc::clone(&arrivals),
        ));
        let publisher = fabric
            .engine_of(a)
            .unwrap()
            .app_node(cancel.child_token())
            .publish(name("/grp"), name(PUBLISHER))
            .await
            .unwrap();
        settle(Duration::from_millis(300)).await;

        // Sustained load: 150 publications at a 50 ms cadence, publish instant stamped per seq.
        const N: u64 = 150;
        let mut published_at: BTreeMap<u64, tokio::time::Instant> = BTreeMap::new();
        for i in 0..N {
            let payload = format!("blk-{i}");
            let seq = publisher.put(payload.as_bytes()).await.expect("put");
            published_at.insert(seq, tokio::time::Instant::now());
            ledger.record_published(PUBLISHER, seq, payload.as_bytes());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        time_to_drain(&ledger, &["B".to_string()], DRAIN_BUDGET).await;

        let mut lat_ms: Vec<f64> = {
            let arrivals = arrivals.lock().unwrap();
            published_at
                .iter()
                .filter_map(|(seq, pub_t)| {
                    arrivals
                        .get(seq)
                        .map(|arr| arr.duration_since(*pub_t).as_secs_f64() * 1e3)
                })
                .collect()
        };
        assert_eq!(lat_ms.len() as u64, N, "every publication measured");

        let (p50, p99) = (percentile(&mut lat_ms, 0.50), percentile(&mut lat_ms, 0.99));
        let mut report = PerfCell::new(cell, seed);
        report.metric("latency_p50_ms", p50);
        report.metric("latency_p99_ms", p99);
        report.metric(
            "latency_mean_ms",
            lat_ms.iter().sum::<f64>() / lat_ms.len() as f64,
        );
        report.bound(BoundCheck {
            name: "latency-tail-shape".into(),
            claim: "p99 stays within 50× p50 under sustained load (no pathological tail)"
                .into(),
            detail: format!("p50 {p50:.1} ms, p99 {p99:.1} ms"),
            pass: p99 <= p50 * 50.0,
        });

        cancel.cancel();
        fabric.shutdown().await;
        report
    })
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// Cells: THE KNEES — where does it stop being linear? Sweep the dimension, measure total
// drain time, knee = first point costing >3× the 1-unit baseline (parallel-ideal is flat).
// The knee is REPORTED (that's the number nobody has); the only pass/fail is a catastrophic
// superlinearity guard at the sweep max.
// ────────────────────────────────────────────────────────────────────────────────────────────

fn run_chains_knee_cell(cell: &str, seed: u64) -> PerfCell {
    let sweep = [1usize, 2, 4, 8, 16];
    let mut curve: Vec<(u64, f64)> = Vec::new();
    for (i, &chains) in sweep.iter().enumerate() {
        let point_seed = seed + i as u64;
        fastrand::seed(point_seed);
        let kernel = VirtualKernel::new();
        let ms = kernel.run(move |k| async move {
            let groups: Vec<String> = (0..chains).map(|i| format!("/g{i}")).collect();
            let (fabric, a, b) = build_pair(k, point_seed, &groups).await;
            let cancel = CancellationToken::new();
            let ledger = Arc::new(Ledger::new());

            // One sync plane per chain on B; one publisher per chain on A.
            let mut publishers = Vec::new();
            for (gi, g) in groups.iter().enumerate() {
                attach_ledgered(
                    &fabric, b, g, &format!("/nodes/B/c{gi}"), &ledger, "B",
                    CatchupOpts::default(), &cancel,
                )
                .await;
                publishers.push(
                    fabric
                        .engine_of(a)
                        .unwrap()
                        .app_node(cancel.child_token())
                        .publish(name(g), name(&format!("{PUBLISHER}/c{gi}")))
                        .await
                        .unwrap(),
                );
            }
            settle(Duration::from_millis(300)).await;

            let start = tokio::time::Instant::now();
            for (gi, publisher) in publishers.iter().enumerate() {
                publish_n(publisher, &ledger, &format!("{PUBLISHER}/c{gi}"), 20).await;
            }
            time_to_drain(&ledger, &["B".to_string()], DRAIN_BUDGET).await;
            let ms = start.elapsed().as_secs_f64() * 1e3;
            cancel.cancel();
            fabric.shutdown().await;
            ms
        });
        curve.push((chains as u64, ms));
    }

    let mut report = PerfCell::new(cell, seed);
    for (n, ms) in &curve {
        report.metric(format!("drain_ms_chains_{n}"), *ms);
    }
    let knee = find_knee(&curve, 3.0); // total time vs 1-chain baseline; parallel-ideal is flat
    report.metric("knee_chains_per_node", knee.map(|n| n as f64).unwrap_or(-1.0));
    report.bound(growth_bound(
        "chains-superlinearity-guard",
        "16 chains on one node cost ≤10× the 1-chain drain (catastrophic contention guard; \
         the knee itself is reported, not asserted)",
        (1, curve[0].1),
        (16, curve[4].1),
        10.0,
    ));
    report
}

fn run_peers_knee_cell(cell: &str, seed: u64) -> PerfCell {
    let sweep = [1usize, 2, 4, 8];
    let mut curve: Vec<(u64, f64)> = Vec::new();
    for (i, &peers) in sweep.iter().enumerate() {
        let point_seed = seed + i as u64;
        fastrand::seed(point_seed);
        let kernel = VirtualKernel::new();
        let ms = kernel.run(move |k| async move {
            let (fabric, a, spokes) = build_star(k, point_seed, peers).await;
            let cancel = CancellationToken::new();
            let ledger = Arc::new(Ledger::new());
            let rnames: Vec<String> = (0..peers).map(|i| format!("R{i}")).collect();
            for (i, &s) in spokes.iter().enumerate() {
                attach_ledgered(
                    &fabric, s, "/grp", &format!("/nodes/R{i}"), &ledger, &rnames[i],
                    CatchupOpts::default(), &cancel,
                )
                .await;
            }
            let publisher = fabric
                .engine_of(a)
                .unwrap()
                .app_node(cancel.child_token())
                .publish(name("/grp"), name(PUBLISHER))
                .await
                .unwrap();
            settle(Duration::from_millis(300)).await;

            let start = tokio::time::Instant::now();
            publish_n(&publisher, &ledger, PUBLISHER, 20).await;
            time_to_drain(&ledger, &rnames, DRAIN_BUDGET).await;
            let ms = start.elapsed().as_secs_f64() * 1e3;
            cancel.cancel();
            fabric.shutdown().await;
            ms
        });
        curve.push((peers as u64, ms));
    }

    let mut report = PerfCell::new(cell, seed);
    for (n, ms) in &curve {
        report.metric(format!("drain_ms_peers_{n}"), *ms);
    }
    let knee = find_knee(&curve, 3.0);
    report.metric("knee_peers_per_group", knee.map(|n| n as f64).unwrap_or(-1.0));
    report.bound(growth_bound(
        "peers-superlinearity-guard",
        "8 peers in one group cost ≤10× the 1-peer drain (catastrophic guard; the knee is \
         reported, not asserted)",
        (1, curve[0].1),
        (8, curve[3].1),
        10.0,
    ));
    report
}

// ────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn ceiling_scoreboard() {
    let mut board = PerfBoard::default();
    board.push(run_ingest_cell("ingest-flat/pair", 0xA001, Duration::ZERO));
    board.push(run_late_join_cell("latejoin-curve/pair", 0xA010));
    board.push(run_latency_cell("publish-latency/pair", 0xA020));
    board.push(run_chains_knee_cell("chains-knee/pair", 0xA030));
    board.push(run_peers_knee_cell("peers-knee/star", 0xA040));

    let json = board.to_json();
    println!("{json}");
    if let Some(dir) = option_env!("CARGO_TARGET_TMPDIR") {
        let path = std::path::Path::new(dir).join("ceiling-scoreboard.json");
        std::fs::write(&path, &json).expect("write ceiling scoreboard");
        println!("ceiling scoreboard written to {}", path.display());
    }
    assert!(
        board.all_pass(),
        "ceiling-finder has failing shape bounds — the scoreboard above names them (each \
         failure is a seed you can hand a debugger)"
    );
}

/// RED GATE: a deliberately O(history)-per-event consumer (the NS-4 field shape) must trip
/// the flat-vs-history bound. A bound that can't go red is a shell.
#[test]
fn flat_bound_reddens_on_a_quadratic_path() {
    let red = run_ingest_cell(
        "gate-ingest-quadratic/pair",
        0xA0A1,
        Duration::from_micros(200), // +0.2 ms × blocks-already-held, per event
    );
    let flat = red
        .bounds
        .iter()
        .find(|b| b.name == "ingest-flat-vs-history")
        .expect("the flat bound ran");
    assert!(
        !flat.pass,
        "the flat-vs-history bound must trip on an O(history)-per-event consumer: {red:?}"
    );
    assert!(!red.pass);
    println!("quadratic path caught: {}", flat.detail);
}

/// RED GATE: the bend bound must trip when the "windowed" run does not actually pipeline.
/// Two serial sweeps of the same scenario differ only by scheduling noise (speedup ≈ 1×,
/// nowhere near the required 4×) — a bend bound that passed on that would be a shell.
#[test]
fn bend_bound_reddens_when_the_window_does_not_pipeline() {
    let serial = late_join_curve(0xA0B1, 1);
    let not_pipelined = late_join_curve(0xA0B1, 1); // the window knob silently ignored
    let bound = bend_bound(&serial, &not_pipelined, 4.0);
    assert!(
        !bound.pass,
        "the bend bound must trip when windowing yields no pipelining: {}",
        bound.detail
    );
    println!("non-pipelining window caught: {}", bound.detail);
}

/// Same seed ⇒ identical NORMATIVE report (bound verdicts; raw metrics are diagnostic under
/// tokio's unseeded `select!` RNG — the same named residue as instrument (c)).
#[test]
fn ceiling_is_deterministic() {
    let a = run_ingest_cell("determinism/ingest", 0xA0D0, Duration::ZERO).normative();
    let b = run_ingest_cell("determinism/ingest", 0xA0D0, Duration::ZERO).normative();
    assert_eq!(a, b, "same seed must reproduce the identical normative perf report");
}
