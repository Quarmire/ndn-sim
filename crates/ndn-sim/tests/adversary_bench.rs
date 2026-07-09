//! The **adversary bench**, macro tier — instrument (b) of the field bench suite (skyfall
//! FIELD-REPORT-2 §7(b)). The invariants are proven correct; this measures their COST UNDER
//! HOSTILITY. Every cell asserts TWO things (pass = their conjunction):
//!
//! 1. **honest liveness preserved** — the watchdog (`liveness::watch`) runs on the HONEST peer
//!    set *during* the attack; honest peers converge no-poison / byte-identical while the
//!    attacker rages;
//! 2. **attacker cost-to-defender bounded** — `amplification_bound` (O(1) defender work per
//!    hostile action, never amplified) or `cap_bound` (a by-design accumulator stays under its
//!    cap).
//!
//! Real crypto: an honest publisher A signs each SVS publication's payload as an inner `Data`
//! validated against a real `ndn_security::Validator` trusting A alone; an attacker E floods the
//! same group with bad-signature / untrusted-fork / stale-replay publications. The verifying
//! consumer (`adversary::verifying_catchup`) verifies each delivered Block exactly once and
//! stores only what validates — so the flood is O(1)-per-Block work that never advances honest
//! state. Deterministic (`VirtualKernel` + seeded), riding instrument (c)'s Ledger/watch and
//! (a)'s BoundCheck.
//!
//! Red-capable (a bound that can't go red is a shell): `amplification_reddens_on_a_refetch_storm`
//! swaps in a defender that re-fetches the whole held range per hostile Block (the amplified
//! shape) and the amplification bound MUST trip; `honest_liveness_reddens_when_the_attacker_wins`
//! swaps in a credulous consumer that stores unverified attacker bytes and the poison invariant
//! MUST redden.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::encode::DataBuilder;
use ndn_packet::Name;
use ndn_security::{KeyChain, SignWith, TrustSchema, Validator};
use ndn_sim::adversary::{
    AdversaryBoard, AdversaryCell, CostMeter, amplification_bound, cap_bound, verifying_catchup,
};
use ndn_sim::ceiling::BoundCheck;
use ndn_sim::fieldkit::{TwoPhaseReplica, settle};
use ndn_sim::liveness::{Ledger, LivenessVerdict, watch};
use ndn_sim::{LinkConfig, NodeId, RunningSimulation, Simulation, VirtualKernel};
use tokio_util::sync::CancellationToken;

const GROUP: &str = "/grp";
const A_NAME: &str = "/nodes/A";
const E_NAME: &str = "/nodes/E";
const STALL_WINDOW: Duration = Duration::from_secs(20);
const BUDGET: Duration = Duration::from_secs(600);
/// The honest verifying consumer runs with the windowed catch-up ON (skyfall §6.1): the
/// adversary board's liveness/poison/cost verdicts hold under N-outstanding fetches, not just
/// the serial loop.
const VERIFIER_WINDOW: usize = 16;

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

/// A hub topology: honest publisher A, honest replica B, attacker E — all on one multicast
/// group so B hears both A's honest chain and E's flood.
async fn build_hub(
    k: std::sync::Arc<dyn ndn_sim::SimKernel>,
    seed: u64,
    extra_replicas: usize,
) -> (RunningSimulation, NodeId, NodeId, NodeId, Vec<NodeId>) {
    let mut sim = Simulation::new().kernel(k).seed(seed);
    let hub = sim.add_node(EngineConfig::default());
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    let e = sim.add_node(EngineConfig::default());
    let extra: Vec<NodeId> = (0..extra_replicas)
        .map(|_| sim.add_node(EngineConfig::default()))
        .collect();
    let spokes: Vec<NodeId> = [a, b, e].into_iter().chain(extra.iter().copied()).collect();
    for &s in &spokes {
        sim.link(s, hub, LinkConfig::lan());
        sim.add_route(s, GROUP, hub);
        sim.add_route(hub, GROUP, s);
        sim.add_strategy(s, GROUP, "multicast");
        // A's data prefix is reachable from every spoke (fetch A's blocks); E's too (so the
        // flood really crosses the fabric to B).
        sim.add_route(s, A_NAME, hub);
        sim.add_route(s, E_NAME, hub);
    }
    sim.add_strategy(hub, GROUP, "multicast");
    sim.add_route(hub, A_NAME, a);
    sim.add_route(hub, E_NAME, e);
    sim.add_strategy(hub, A_NAME, "multicast");
    sim.add_strategy(hub, E_NAME, "multicast");
    let fabric = sim.start().await.unwrap();
    (fabric, a, b, e, extra)
}

/// A validly-signed inner Data (the block payload an SVS publication carries), signed by
/// `kc` under a hierarchical name so a `Validator` trusting `kc`'s anchor accepts it.
fn signed_block(kc: &KeyChain, base: &str, seq: u64, content: &[u8]) -> Bytes {
    let signer = kc.signer().unwrap();
    let dname: Name = format!("{base}/blk/{seq}").parse().unwrap();
    DataBuilder::new(dname, content).sign_with_sync(&*signer).unwrap()
}

/// A bad-SIGNATURE block: validly assembled, then the trailing signature byte is flipped, so
/// the Ed25519 check fails at crypto (distinct from an untrusted-but-valid signer).
fn bad_sig_block(kc: &KeyChain, base: &str, seq: u64, content: &[u8]) -> Bytes {
    let mut wire = signed_block(kc, base, seq, content).to_vec();
    *wire.last_mut().unwrap() ^= 0xFF;
    Bytes::from(wire)
}

/// Build a validator trusting exactly the given keychains' anchors.
fn validator_trusting(kcs: &[&KeyChain]) -> Arc<Validator> {
    let v = Validator::new(TrustSchema::hierarchical());
    for kc in kcs {
        if let Some(cert) = kc.manager_arc().trust_anchor(kc.key_name()) {
            v.add_trust_anchor(cert);
        }
    }
    Arc::new(v)
}

/// Attach a real SVS publisher on `node` publishing under `local`.
async fn attach_publisher(
    fabric: &RunningSimulation,
    node: NodeId,
    local: &str,
    cancel: &CancellationToken,
) -> ndn_app::Publisher {
    fabric
        .engine_of(node)
        .unwrap()
        .app_node(cancel.child_token())
        .publish(name(GROUP), name(local))
        .await
        .expect("publisher")
}

/// Spawn the verifying honest consumer on `node`.
#[allow(clippy::too_many_arguments)]
async fn attach_verifier(
    fabric: &RunningSimulation,
    node: NodeId,
    local: &str,
    rname: &str,
    ledger: &Arc<Ledger>,
    validator: &Arc<Validator>,
    meter: &Arc<CostMeter>,
    window: usize,
    cancel: &CancellationToken,
) {
    let replica = TwoPhaseReplica::attach(
        fabric, node, &name(GROUP), &name(local),
        Duration::from_millis(500), cancel,
    )
    .await
    .expect("verifier attaches");
    tokio::spawn(verifying_catchup(
        replica,
        Arc::clone(ledger),
        Arc::clone(validator),
        vec![A_NAME.to_string()], // only A's validated content is honest progress
        rname.to_string(),
        Arc::clone(meter),
        window,
    ));
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// Cell: invalid-signature flood — verify-before-ack is the DoS-relevant primitive. E floods
// bad-SIGNATURE blocks while A publishes an honest chain; B verifies each delivered Block once,
// drops every bad one, and converges on A. Bound: induced verify cost is O(1) per bad Block.
// ────────────────────────────────────────────────────────────────────────────────────────────

fn run_invalid_sig_flood(cell: &str, seed: u64) -> AdversaryCell {
    fastrand::seed(seed);
    let kernel = VirtualKernel::new();
    let cell = cell.to_string();
    kernel.run(move |k| async move {
        let (fabric, a, b, e, _) = build_hub(k, seed, 0).await;
        let cancel = CancellationToken::new();
        let ledger = Arc::new(Ledger::new());
        let meter = Arc::new(CostMeter::new());

        let a_kc = KeyChain::ephemeral(A_NAME).unwrap();
        let e_kc = KeyChain::ephemeral(E_NAME).unwrap();
        let validator = validator_trusting(&[&a_kc]); // trusts A only

        attach_verifier(&fabric, b, "/nodes/B", "B", &ledger, &validator, &meter, VERIFIER_WINDOW, &cancel).await;
        let pub_a = attach_publisher(&fabric, a, A_NAME, &cancel).await;
        let pub_e = attach_publisher(&fabric, e, E_NAME, &cancel).await;
        settle(Duration::from_millis(400)).await;

        const HONEST: u64 = 30;
        const FLOOD: u64 = 300;
        // The attacker floods first + throughout; the honest chain must still land.
        for i in 0..FLOOD {
            let blk = bad_sig_block(&e_kc, E_NAME, i, format!("evil-{i}").as_bytes());
            pub_e.put(&blk).await.expect("flood put");
        }
        for i in 0..HONEST {
            let content = format!("honest-{i}");
            let blk = signed_block(&a_kc, A_NAME, i, content.as_bytes());
            let seq = pub_a.put(&blk).await.expect("honest put");
            ledger.record_published(A_NAME, seq, content.as_bytes());
        }

        let liveness = watch(&ledger, &["B".to_string()], STALL_WINDOW, BUDGET).await;

        let cost = vec![amplification_bound(
            "verify-cost-o1-per-badblock",
            "each bad-signature Block costs exactly one verify — no per-Block amplification",
            &meter,
            2.0,
        )];
        let mut report =
            AdversaryCell::evaluate(cell, seed, liveness, &ledger, &["B".to_string()], cost);
        report.metric("honest_blocks", HONEST as f64);
        report.metric("flood_blocks", FLOOD as f64);
        report.metric("hostile_actions", meter.actions_total() as f64);
        report.metric("defender_work", meter.work_total() as f64);
        report.metric("honest_baseline_work", meter.baseline_total() as f64);

        cancel.cancel();
        fabric.shutdown().await;
        report
    })
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// Cell: equivocation / fork storm — E floods validly-self-signed forks of A's chain NAMES
// (untrusted signer). The gate/verifier rejects each; A's honest chain stays unpoisoned. Bound:
// one check per fork, and B holds ONLY A's byte-identical blocks.
// ────────────────────────────────────────────────────────────────────────────────────────────

fn run_fork_storm(cell: &str, seed: u64) -> AdversaryCell {
    fastrand::seed(seed);
    let kernel = VirtualKernel::new();
    let cell = cell.to_string();
    kernel.run(move |k| async move {
        let (fabric, a, b, e, _) = build_hub(k, seed, 0).await;
        let cancel = CancellationToken::new();
        let ledger = Arc::new(Ledger::new());
        let meter = Arc::new(CostMeter::new());

        let a_kc = KeyChain::ephemeral(A_NAME).unwrap();
        let e_kc = KeyChain::ephemeral(E_NAME).unwrap();
        let validator = validator_trusting(&[&a_kc]);

        attach_verifier(&fabric, b, "/nodes/B", "B", &ledger, &validator, &meter, VERIFIER_WINDOW, &cancel).await;
        let pub_a = attach_publisher(&fabric, a, A_NAME, &cancel).await;
        let pub_e = attach_publisher(&fabric, e, E_NAME, &cancel).await;
        settle(Duration::from_millis(400)).await;

        const HONEST: u64 = 30;
        const FORKS: u64 = 200;
        // E's forks: validly signed by E (not corrupt bytes — a real trust-failure), naming A's
        // chain positions with divergent content (the equivocation shape).
        for i in 0..FORKS {
            let forged = signed_block(&e_kc, A_NAME, i % HONEST, format!("fork-{i}").as_bytes());
            pub_e.put(&forged).await.expect("fork put");
        }
        for i in 0..HONEST {
            let content = format!("honest-{i}");
            let blk = signed_block(&a_kc, A_NAME, i, content.as_bytes());
            let seq = pub_a.put(&blk).await.expect("honest put");
            ledger.record_published(A_NAME, seq, content.as_bytes());
        }

        let liveness = watch(&ledger, &["B".to_string()], STALL_WINDOW, BUDGET).await;
        let cost = vec![amplification_bound(
            "fork-check-o1-per-fork",
            "each forged fork costs one trust check — bounded, honest chain unpoisoned",
            &meter,
            2.0,
        )];
        let mut report =
            AdversaryCell::evaluate(cell, seed, liveness, &ledger, &["B".to_string()], cost);
        report.metric("honest_blocks", HONEST as f64);
        report.metric("fork_blocks", FORKS as f64);
        report.metric("hostile_actions", meter.actions_total() as f64);
        report.metric("defender_work", meter.work_total() as f64);
        cancel.cancel();
        fabric.shutdown().await;
        report
    })
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// Cell: ack-withholding peer — a silent non-acker must cost the PUBLISHER nothing unbounded and
// must not starve the OTHER honest peer. B1 acks normally; B2 attaches, fetches, but NEVER acks
// (its two-phase vector never advances, so it re-hears the range every round). Assert B1
// converges and the publisher's serve-work is bounded (linear in delivered, not amplified by
// the withholder's re-advertisement).
// ────────────────────────────────────────────────────────────────────────────────────────────

fn run_ack_withholding(cell: &str, seed: u64) -> AdversaryCell {
    fastrand::seed(seed);
    let kernel = VirtualKernel::new();
    let cell = cell.to_string();
    kernel.run(move |k| async move {
        let (fabric, a, b, e, _) = build_hub(k, seed, 0).await;
        // Reuse E's node as the second honest-but-withholding replica B2.
        let cancel = CancellationToken::new();
        let ledger = Arc::new(Ledger::new());
        let meter = Arc::new(CostMeter::new());
        let a_kc = KeyChain::ephemeral(A_NAME).unwrap();
        let validator = validator_trusting(&[&a_kc]);

        attach_verifier(&fabric, b, "/nodes/B", "B", &ledger, &validator, &meter, VERIFIER_WINDOW, &cancel).await;

        // B2: a withholding replica — fetch + count serve pressure, but never ack. Modeled with
        // the fieldkit's naive fetch loop wired to a SEPARATE ledger so its (non-)progress does
        // not confound the honest watchdog; every fetch it makes is publisher serve-work.
        let withholder = TwoPhaseReplica::attach(
            &fabric, e, &name(GROUP), &name("/nodes/B2"),
            Duration::from_millis(500), &cancel,
        )
        .await
        .unwrap();
        {
            let meter = Arc::clone(&meter);
            tokio::spawn(async move {
                let mut w = withholder;
                while let Some(update) = w.handle.recv().await {
                    for seq in update.low_seq..=update.high_seq {
                        if w.fetch(&update.name, seq).await.is_some() {
                            // Each re-fetch a withholder induces is publisher serve-work.
                            meter.action();
                            meter.work();
                        }
                        // NEVER ack — the two-phase vector never advances.
                    }
                }
            });
        }

        let pub_a = attach_publisher(&fabric, a, A_NAME, &cancel).await;
        settle(Duration::from_millis(400)).await;

        const HONEST: u64 = 20;
        for i in 0..HONEST {
            let content = format!("honest-{i}");
            let blk = signed_block(&a_kc, A_NAME, i, content.as_bytes());
            let seq = pub_a.put(&blk).await.expect("honest put");
            ledger.record_published(A_NAME, seq, content.as_bytes());
        }

        // B1 must converge despite B2 withholding.
        let liveness = watch(&ledger, &["B".to_string()], STALL_WINDOW, BUDGET).await;

        // Let the withholder rage a few more rounds; then check its induced serve-work is
        // bounded (a re-fetch of the range per round, not an unbounded blow-up: the data plane
        // serves from the store / CS, one Data per Interest — O(delivered) per round, capped by
        // the fixed number of rounds the watch ran).
        let cost = vec![amplification_bound(
            "withholder-serve-bounded",
            "a silent non-acker induces bounded publisher serve-work per delivered Block \
             (re-fetch from store, never an unbounded blow-up)",
            &meter,
            // Generous: the range is re-fetched a bounded number of sync rounds during the
            // watch window; each fetch is one served Data. Amplification would be super-linear.
            60.0,
        )];
        let mut report =
            AdversaryCell::evaluate(cell, seed, liveness, &ledger, &["B".to_string()], cost);
        report.metric("honest_blocks", HONEST as f64);
        report.metric("withholder_refetches", meter.actions_total() as f64);
        cancel.cancel();
        fabric.shutdown().await;
        report
    })
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// Cell: storage poisoning — a Content Store accepts unreferenced junk BY DESIGN (cache_packet);
// measure that its accrual is BOUNDED by the byte cap (eviction holds under a flood). This is a
// store-level cost measurement, not a fabric cell: the finding is "bounded, cap holds".
// ────────────────────────────────────────────────────────────────────────────────────────────

fn run_storage_poisoning(cell: &str, seed: u64) -> AdversaryCell {
    use ndn_store::{ContentStore, CsMeta, LruCs};
    // Cap the store at 64 KiB; flood 5000 unreferenced ~200 B junk Data (≈ 1 MB, 15× the cap).
    const CAP: usize = 64 * 1024;
    let kernel = VirtualKernel::new();
    let cell = cell.to_string();
    kernel.run(move |_k| async move {
        let cs = LruCs::new(CAP);
        for i in 0..5000u64 {
            let name: Name = format!("/junk/{i}").parse().unwrap();
            let junk = DataBuilder::new(name.clone(), &[0xAB; 180]).build();
            cs.insert(junk, Arc::new(name), CsMeta { stale_at: u64::MAX }).await;
        }
        let held = cs.current_bytes() as u64;

        // Honest liveness is trivially preserved (no honest peer is touched by a poisoned CS on
        // an isolated node); this cell's substance is the cap bound. Build a converged empty
        // ledger so the composed pass reflects the cost bound.
        let ledger = Ledger::new();
        let cost = vec![cap_bound(
            "cs-junk-accrual-capped",
            "unreferenced junk accrues but the CS byte cap holds under a 15× flood (eviction \
             bounds it — not unbounded growth)",
            held,
            CAP as u64,
        )];
        let mut report =
            AdversaryCell::evaluate(cell, seed, LivenessVerdict::Converged, &ledger, &[], cost);
        report.metric("cap_bytes", CAP as f64);
        report.metric("held_bytes_after_flood", held as f64);
        report.metric("flood_data_packets", 5000.0);
        report
    })
}

// ────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn adversary_scoreboard() {
    let mut board = AdversaryBoard::default();
    board.push(run_invalid_sig_flood("invalid-sig-flood/hub", 0xB001));
    board.push(run_fork_storm("fork-storm/hub", 0xB002));
    board.push(run_ack_withholding("ack-withholding/hub", 0xB003));
    board.push(run_storage_poisoning("storage-poisoning/cs", 0xB004));

    let json = board.to_json();
    println!("{json}");
    if let Some(dir) = option_env!("CARGO_TARGET_TMPDIR") {
        let path = std::path::Path::new(dir).join("adversary-scoreboard.json");
        std::fs::write(&path, &json).expect("write adversary scoreboard");
        println!("adversary scoreboard written to {}", path.display());
    }
    assert!(
        board.all_pass(),
        "adversary bench has failing cells — honest liveness broke or attacker cost was \
         amplified (the scoreboard above names them; each failure is a seed for a debugger)"
    );
}

/// RED GATE (amplification): a defender that re-fetches its whole held range per hostile Block —
/// the amplified shape — must trip the amplification bound. Built directly on the meter so it is
/// hermetic and fast.
#[test]
fn amplification_reddens_on_a_refetch_storm() {
    let meter = CostMeter::new();
    // 50 honest baseline units.
    for _ in 0..50 {
        meter.baseline_work();
    }
    // 100 hostile actions, each fanning out into a growing re-walk (1, 2, 3, … work units) —
    // the O(history)-per-action amplification a naive defender exhibits.
    for i in 0..100u64 {
        meter.action();
        for _ in 0..=i {
            meter.work();
        }
    }
    let bound = amplification_bound(
        "gate-refetch-amplification",
        "re-fetching the held range per hostile Block is amplification and must trip",
        &meter,
        2.0,
    );
    assert!(
        !bound.pass,
        "the amplification bound must go red on a per-action fan-out: {bound:?}"
    );
    println!("amplification caught: {}", bound.detail);
}

/// RED GATE (honest liveness / poison): a credulous consumer that stores UNVERIFIED attacker
/// bytes under an honest seq must redden the byte-identity invariant — the safety half is real,
/// not decorative.
#[test]
fn honest_liveness_reddens_when_the_attacker_wins() {
    let ledger = Ledger::new();
    // The honest publisher authored seq 1 = "honest".
    ledger.record_published(A_NAME, 1, b"honest");
    // A credulous consumer stored the attacker's bytes under that seq (no verify).
    ledger.record_stored("B", A_NAME, 1, &Bytes::from_static(b"POISON"));
    ledger.record_reported("B");

    let cost: Vec<BoundCheck> = vec![];
    let cell = AdversaryCell::evaluate(
        "gate-poison",
        0xB0FF,
        LivenessVerdict::Converged, // liveness "converged" — but to WRONG bytes
        &ledger,
        &["B".to_string()],
        cost,
    );
    assert!(
        !cell.invariants.poison_free,
        "storing unverified attacker bytes must redden the poison invariant: {cell:?}"
    );
    assert!(!cell.pass, "a poisoned cell cannot pass even when liveness reads converged");
    println!("poison caught: {:?}", cell.invariants.violations);
}

/// Same seed ⇒ identical NORMATIVE report (verdicts + bound passes; raw counts diagnostic under
/// tokio's unseeded select! RNG — the named residue shared with (a)/(c)).
#[test]
fn adversary_is_deterministic() {
    let a = run_fork_storm("determinism/fork", 0xB0D0).normative();
    let b = run_fork_storm("determinism/fork", 0xB0D0).normative();
    assert_eq!(a, b, "same seed must reproduce the identical normative adversary report");
    let _ = BTreeMap::<String, f64>::new();
}
