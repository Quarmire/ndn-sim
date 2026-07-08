//! Self-tests for the field-failure primitives (`ndn_sim::fieldkit` + the `hold_link` fault) —
//! each one drives the **stock** stack against its fault/scenario and observes the documented
//! silent-stall bug. Source of truth: skyfall `FIELD-REPORT.md` §3/§6 (NS-6 / NS-7 / NS-8).
//!
//! ## These tests PIN bugs — they are supposed to be red-capable
//!
//! A fault that cannot turn a known-bad implementation red is a shell. So each test here
//! asserts that the *current* upstream behavior exhibits the failure:
//!
//! - **NS-6** (`held_reply_...`): `ndn_app::Consumer::fetch_wire` used to pair
//!   request→response by arrival order (no name match) — this test originally PINNED that
//!   off-by-one (a held /svc/1 reply returned as /svc/2's answer, the stream shifted by one).
//!   **FLIPPED GREEN (NS-6a fixed, 2026-07-08):** `fetch_wire` now pairs by name and discards
//!   stragglers, so the same scenario asserts the fixed contract — the late reply is never
//!   mis-delivered and each fetch returns its own Data. A mispair here means NS-6 is back.
//! - **NS-7** (`burst_catchup_...`): the pre-N-11 `svs_task` (bounded update=256 / ack=64
//!   channels, one select loop, blocking `update_tx.send(...).await` inside an arm) mutually
//!   stalls with a fetch-and-ack-inline consumer under a 400-Block catch-up. The N-11 fix
//!   (buffer + coalesce per publisher, deliver via a `reserve()` arm) landed while this
//!   harness was being built, so the checked-in assertion is the GREEN side of the gate:
//!   convergence at 400. Red-capability was verified against the pre-fix tree — see the
//!   RED-PROOF note on `run_burst` for the observed wedge.
//! - **NS-8** (`lagging_peer_...`): a publisher restart (fresh boot, empty `DataStore`) leaves
//!   a one-Block-behind peer with no fetch path — starvation on the stock data plane. The
//!   test also proves the scenario is *recoverable* (the field workaround — re-publishing
//!   history through the new boot — converges), so the starvation assert isolates the data
//!   plane, not broken wiring. A history-serving fix flips the starvation leg.
//!
//! Deterministic: `VirtualKernel` + seeded fabric + seeded `fastrand` (ndn-sync's suppression
//! jitter is thread-local; the kernel's runtime is single-threaded, so seeding the test thread
//! pins it). All wall-clock cost is virtual.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::error::AppError;
use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::fieldkit::{
    CatchupOutcome, Progress, RestartablePublisher, TwoPhaseReplica, drive_until_or_stall,
    naive_catchup, publish_backlog,
};
use ndn_sim::{FrameMatcher, HoldRule, LinkConfig, Simulation, VirtualKernel};
use tokio_util::sync::CancellationToken;

const GROUP: &str = "/grp";

fn name(s: &str) -> Name {
    s.parse().unwrap()
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// NS-6 — a held (delayed-not-dropped) Data reply arrives after the requester timed out. The
// pre-fix Consumer paired by arrival order and handed every subsequent fetch the previous
// fetch's reply (the off-by-one this test originally pinned red). With NS-6a fixed, the same
// fault must be ABSORBED: the straggler is discarded, every fetch answers with its own name.
// ────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn held_reply_is_discarded_never_mispaired() {
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k).seed(6);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        // A real one-way latency so a reply can be late relative to a client timeout without
        // being later than the NEXT exchange's reply: 60 ms each way, nothing random.
        sim.link(
            a,
            b,
            LinkConfig {
                delay: Duration::from_millis(60),
                jitter: Duration::ZERO,
                loss_rate: 0.0,
                bandwidth_bps: 0,
            },
        );
        sim.add_route(b, "/svc", a);
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        // Producer on A: answers every /svc/<n> Interest with Data named exactly like it.
        let producer = fabric
            .engine_of(a)
            .unwrap()
            .register_producer("/svc", cancel.child_token());
        tokio::spawn(async move {
            let _ = producer
                .serve(|interest, responder| async move {
                    let reply_name = (*interest.name).clone();
                    let _ = responder.respond(reply_name, b"payload".as_slice()).await;
                })
                .await;
        });
        let mut consumer = fabric
            .engine_of(b)
            .unwrap()
            .app_consumer(cancel.child_token());
        ndn_sim::fieldkit::settle(Duration::from_millis(100)).await;

        // THE FAULT: hold the first Data A sends toward B by +60 ms — delayed, NOT dropped.
        // It will land at t≈180 ms: after fetch #1's 150 ms client timeout, but before
        // fetch #2's own reply (~270 ms). A loss knob cannot express this; that is why no
        // existing suite could reach the bug.
        fabric
            .hold_link(a, b, HoldRule::nth(FrameMatcher::Data, 0, Duration::from_millis(60)))
            .unwrap();

        let interest = |n: &str| {
            InterestBuilder::new(name(n))
                .lifetime(Duration::from_secs(4)) // PIT keeps the late reply flowing
                .build()
        };

        // Fetch #1: its reply is held past the client-side wait → Timeout. (The Interest
        // itself stays pending in the PIT — the reply is en route, just late. Exactly the
        // mid-burst RTT spike from the field.)
        let r1 = consumer
            .fetch_wire(interest("/svc/1"), Duration::from_millis(150))
            .await;
        assert!(
            matches!(r1, Err(AppError::Timeout)),
            "fetch #1 must time out client-side (reply held, not dropped): {r1:?}"
        );

        // Fetch #2: the late /svc/1 reply arrives FIRST (t≈180 ms, before /svc/2's own reply
        // at ≈270 ms). NS-6a contract: it is a straggler — discarded, never mis-delivered —
        // and this fetch returns its OWN Data. (Pre-fix, arrival-order pairing returned
        // /svc/1 here and shifted every later fetch by one; the pinned red run is in git
        // history at ndn-sim dbe14fd.)
        let d2 = consumer
            .fetch_wire(interest("/svc/2"), Duration::from_secs(4))
            .await
            .expect("fetch #2 returned a packet");
        assert_eq!(
            d2.name.to_string(),
            "/svc/2",
            "NS-6 regression: a straggler reply was mis-delivered as this fetch's answer"
        );

        // No shift: every later fetch keeps answering with its own name.
        let d3 = consumer
            .fetch_wire(interest("/svc/3"), Duration::from_secs(4))
            .await
            .expect("fetch #3 returned a packet");
        assert_eq!(d3.name.to_string(), "/svc/3", "the stream must not shift");

        // The held reply wasn't wasted — just correctly attributed: it satisfied B's PIT and
        // sits in the CS, so a re-ask for /svc/1 succeeds cleanly.
        let d1 = consumer
            .fetch_wire(interest("/svc/1"), Duration::from_secs(4))
            .await
            .expect("re-fetch of the timed-out name succeeds");
        assert_eq!(d1.name.to_string(), "/svc/1");

        cancel.cancel();
        fabric.shutdown().await;
    });
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// NS-7 — a several-hundred-Block catch-up wedges the stock two-phase sync geometry: the
// svs_task blocks delivering to the full update channel (and stops draining acks); the
// consumer blocks sending to the full ack channel (and stops draining updates). Mutual stall,
// silent, permanent. The 5-Block control leg shows why every ≤5-Block suite is blind to it.
// ────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn burst_catchup_survives_the_two_phase_sync_channels() {
    // Control: the scenario at old suite scale (5 Blocks) — the channels never fill, which is
    // exactly why every pre-existing suite was structurally blind to NS-7.
    let reached = run_burst(5, 42);
    assert_eq!(
        reached,
        CatchupOutcome::Reached(5),
        "the 5-Block control must converge — at suite scale the geometry never bites"
    );

    // The burst: 400 Blocks through ONE catch-up, fetch-and-ack-inline consumer. This is the
    // NS-7 acceptance gate: against the pre-N-11 `svs_task` (blocking
    // `update_tx.send(...).await` inside the select loop) THIS EXACT SCENARIO WEDGES — the
    // red-capability proof is recorded in the module header. With the N-11 buffered/coalesced
    // delivery it must converge; a stall here means the NS-7 deadlock is back.
    let outcome = run_burst(400, 43);
    assert_eq!(
        outcome,
        CatchupOutcome::Reached(400),
        "NS-7 regression: the 400-Block catch-up wedged the sync channels again \
         (svs_task ↔ two-phase consumer mutual stall)"
    );
}

/// One burst-catch-up run: publisher on A, two-phase replica + naive consumer on B, `n` Blocks
/// through one catch-up. Returns what the stall probe saw.
///
/// RED-PROOF (2026-07-08): this exact scenario, built against pre-N-11 ndn-rs `2472b6d9`
/// (blocking `update_tx.send(...).await` in the svs_task select loop), produced
/// `Stalled { at: 11 }` out of 400 — permanent (zero movement for a further 30 virtual
/// seconds), while the 5-Block control leg still converged on the same buggy code. The wedge
/// point differs from the field's ~44 only by consumer shape: this naive consumer re-acks
/// every re-advertised seq, so the 64-deep ack channel fills at triangular speed (≈ update
/// #11); skyfall's coalescing consumer acked distinct seqs and got further before freezing.
/// Same deadlock, same channels.
fn run_burst(n: u64, seed: u64) -> CatchupOutcome {
    fastrand::seed(seed);
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k).seed(seed);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        sim.link(a, b, LinkConfig::lan());
        sim.add_route(a, GROUP, b);
        sim.add_route(b, GROUP, a);
        sim.add_route(b, "/nodes/A", a);
        sim.add_strategy(a, GROUP, "multicast");
        sim.add_strategy(b, GROUP, "multicast");
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        let group = name(GROUP);

        // The replica attaches FIRST so the publish burst floods it with per-publish sync
        // rounds — the field shape ("a publish burst re-advertises the whole unacked range
        // every sync round").
        let replica = TwoPhaseReplica::attach(
            &fabric,
            b,
            &group,
            &name("/nodes/B"),
            Duration::from_millis(500),
            &cancel,
        )
        .await
        .unwrap();
        let progress = Progress::new();
        tokio::spawn(naive_catchup(replica, progress.clone()));

        let publisher = fabric
            .engine_of(a)
            .unwrap()
            .app_node(cancel.child_token())
            .publish(group.clone(), name("/nodes/A"))
            .await
            .unwrap();
        ndn_sim::fieldkit::settle(Duration::from_millis(200)).await;

        publish_backlog(&publisher, n as usize, |i| {
            format!("block-{i}").into_bytes()
        })
        .await
        .unwrap();

        let outcome = drive_until_or_stall(&progress, n, Duration::from_secs(15)).await;
        // A stall verdict must mean WEDGED, not slow: nothing may move for another window.
        if let CatchupOutcome::Stalled { at } = outcome {
            tokio::time::sleep(Duration::from_secs(30)).await;
            assert_eq!(
                progress.get(),
                at,
                "the stall is permanent — any movement means the probe misfired"
            );
        }
        cancel.cancel();
        fabric.shutdown().await;
        outcome
    })
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// NS-8 — a peer that fell one Block behind while the publisher's process restarted starves
// forever on the stock data plane: the missing Block exists in the application's history, but
// the new boot's SVS instance neither advertises nor serves it. The workaround leg (re-publish
// history through the new boot) converges — proving the starvation assert isolates the data
// plane, not broken test wiring.
// ────────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn lagging_peer_starves_after_publisher_restart() {
    fastrand::seed(8);
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k).seed(8);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        sim.link(a, b, LinkConfig::lan());
        sim.add_route(a, GROUP, b);
        sim.add_route(b, GROUP, a);
        sim.add_route(b, "/nodes/A", a);
        // Multicast on A's prefixes: after a restart the engine holds the dead boot's faces
        // alongside the fresh ones — fan out so the live instance always hears.
        sim.add_strategy(a, GROUP, "multicast");
        sim.add_strategy(a, "/nodes/A", "multicast");
        sim.add_strategy(b, GROUP, "multicast");
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        let group = name(GROUP);
        let history = ["history-1", "history-2", "history-3"];

        // B: a two-phase replica recording every publication it fetched+acked, by seq.
        let replica = TwoPhaseReplica::attach(
            &fabric,
            b,
            &group,
            &name("/nodes/B"),
            Duration::from_millis(500),
            &cancel,
        )
        .await
        .unwrap();
        let progress = Progress::new();
        let received: Arc<StdMutex<BTreeMap<u64, Bytes>>> = Arc::new(StdMutex::new(BTreeMap::new()));
        {
            let progress = progress.clone();
            let received = Arc::clone(&received);
            let mut replica = replica;
            tokio::spawn(async move {
                while let Some(update) = replica.handle.recv().await {
                    for seq in update.low_seq..=update.high_seq {
                        if let Some(bytes) = replica.fetch(&update.name, seq).await {
                            let _ = replica.handle.ack(&update.publisher, seq).await;
                            if received.lock().unwrap().insert(seq, bytes).is_none() {
                                progress.incr();
                            }
                        }
                    }
                }
            });
        }

        // Boot 1: A publishes two Blocks; B replicates them.
        let mut publisher = RestartablePublisher::new(&fabric, a, &group, &name("/nodes/A"), &cancel)
            .unwrap();
        publisher.start().await.unwrap();
        ndn_sim::fieldkit::settle(Duration::from_millis(200)).await;
        publisher.publisher().unwrap().put(history[0]).await.unwrap();
        publisher.publisher().unwrap().put(history[1]).await.unwrap();
        assert_eq!(
            drive_until_or_stall(&progress, 2, Duration::from_secs(15)).await,
            CatchupOutcome::Reached(2),
            "pre-restart baseline: both Blocks replicate"
        );

        // B goes dark; A publishes one more Block (B never hears the announcement), then A's
        // process restarts: fresh boot, EMPTY DataStore, seq space reset. The third Block now
        // exists only in the application's history — nothing on the wire serves it.
        fabric.set_link_up(a, b, false).unwrap();
        publisher.publisher().unwrap().put(history[2]).await.unwrap();
        publisher.stop();
        publisher.start().await.unwrap();
        fabric.set_link_up(a, b, true).unwrap();

        // THE STARVATION: B is one Block behind, the link is healthy, both sides sync — and
        // nothing ever converges. Silent, permanent.
        let starved = drive_until_or_stall(&progress, 3, Duration::from_secs(20)).await;
        assert_eq!(
            starved,
            CatchupOutcome::Stalled { at: 2 },
            "PINNED BUG (NS-8): the stock per-boot data plane must starve the lagging peer. \
             If B converged, a history-serving story landed — flip this leg into its gate."
        );
        // And it stays starved — this is not slow convergence.
        tokio::time::sleep(Duration::from_secs(30)).await;
        assert_eq!(progress.get(), 2, "still exactly one Block behind, forever");

        // The field workaround (skyfall `announce_history`): re-publish the WHOLE history
        // through the new boot. Convergence here proves the starvation above was the data
        // plane's doing — same fabric, same replica, only the serving story changed. (It
        // works because the authoritative-for-self guard keeps the restarted publisher from
        // adopting its own old seqs, so the re-publish realigns the seq space 1..=3 and B's
        // acked vector leaves exactly the gap at 3 — the O(history)-per-boot cost and the
        // alignment luck are both named in the field report as the reason a real fix is
        // needed.)
        publish_backlog(publisher.publisher().unwrap(), history.len(), |i| {
            history[i].as_bytes().to_vec()
        })
        .await
        .unwrap();
        assert_eq!(
            drive_until_or_stall(&progress, 3, Duration::from_secs(20)).await,
            CatchupOutcome::Reached(3),
            "re-announced history un-starves the peer (the workaround shape)"
        );
        assert_eq!(
            received.lock().unwrap().get(&3).map(|b| b.as_ref().to_vec()),
            Some(history[2].as_bytes().to_vec()),
            "the missing Block itself crossed — byte-identical"
        );

        cancel.cancel();
        fabric.shutdown().await;
    });
}
