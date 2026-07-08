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
//! - **NS-8** (`lagging_peer_...`): a publisher restart with a fresh empty `DataStore` per boot
//!   leaves a one-Block-behind peer with no fetch path — starvation on the stock data plane
//!   (`lagging_peer_starves_after_publisher_restart`, still red-capable). **FLIPPED GREEN
//!   (N-13, 2026-07-08):** with a persistent store carried across the boot
//!   (`BackendStore`/retained `DataStore` + `SvSync::join` seq recovery + serve-from-store), the
//!   restarted boot recovers its seq and answers the gap fetch from its store — the peer
//!   converges with NO O(history) re-announce (`lagging_peer_converges_after_restart_via_persistent_store`).
//!   The retired workaround was skyfall's `announce_history` genesis-first re-publish.
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
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_packet::Name;
use ndn_security::{KeyChain, SignWith, TrustSchema, ValidationResult, Validator};
use ndn_sim::fieldkit::{
    CatchupOutcome, HistoryServerNode, Progress, RestartablePublisher, TwoPhaseReplica,
    drive_until_or_stall, naive_catchup, publish_backlog,
};
use ndn_sim::{FrameMatcher, HoldRule, LinkConfig, Simulation, VirtualKernel};
use ndn_sync::{DataStore, MemoryStore, svs_data_name};
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
// NS-8 — a peer one Block behind while the publisher's process restarts. On the STOCK per-boot
// data plane (fresh empty `DataStore`, seq reset) the missing Block lives only in the
// application's history — the new boot neither advertises nor serves it — so the peer starves
// forever (`lagging_peer_starves_after_publisher_restart`, ephemeral). With a PERSISTENT store
// carried across the boot (N-13/N-15: `BackendStore`/retained `DataStore` +
// `SvSync::join` seq recovery + serve-from-store), the restarted boot recovers its seq and
// answers the gap fetch straight from the store — the peer converges with NO O(history)
// re-announce (`lagging_peer_converges_after_restart_via_persistent_store`, the green gate).
// ────────────────────────────────────────────────────────────────────────────────────────────

/// Run the NS-8 restart scenario and return the post-restart catch-up outcome plus the bytes
/// B ended up holding for seq 3. `persistent` selects the served-history store discipline:
/// `true` = one store retained across boots (the N-13 fix), `false` = a fresh empty store per
/// boot (the stock starvation). A publishes exactly three Blocks total and — critically —
/// **never re-publishes after the restart**, so any convergence is a served-from-store fetch of
/// the single missing Block (announce cost O(gap)=1, not O(history)=3).
fn run_lagging_peer(persistent: bool) -> (CatchupOutcome, Option<Vec<u8>>) {
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
        let mut publisher = if persistent {
            RestartablePublisher::new(&fabric, a, &group, &name("/nodes/A"), &cancel).unwrap()
        } else {
            RestartablePublisher::new_ephemeral(&fabric, a, &group, &name("/nodes/A"), &cancel)
                .unwrap()
        };
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
        // process restarts. Persistent: the store survives the boot. Ephemeral: fresh empty
        // store, seq reset. Either way the third Block now lives only in A's store — nothing was
        // re-published on the wire.
        fabric.set_link_up(a, b, false).unwrap();
        publisher.publisher().unwrap().put(history[2]).await.unwrap();
        publisher.stop();
        publisher.start().await.unwrap();
        fabric.set_link_up(a, b, true).unwrap();

        // Drive the catch-up. Persistent: B fetches the ONE missing Block, served from A's
        // recovered store, and converges. Ephemeral: nothing serves seq 3 — permanent starvation.
        let outcome = drive_until_or_stall(&progress, 3, Duration::from_secs(20)).await;
        if let CatchupOutcome::Stalled { at } = outcome {
            // A stall verdict must mean WEDGED, not slow: nothing may move for another window.
            tokio::time::sleep(Duration::from_secs(30)).await;
            assert_eq!(progress.get(), at, "the starvation is permanent, not slow convergence");
        }
        let seq3 = received.lock().unwrap().get(&3).map(|b| b.as_ref().to_vec());

        cancel.cancel();
        fabric.shutdown().await;
        (outcome, seq3)
    })
}

/// Stock per-boot data plane (fresh empty store per boot): the lagging peer starves forever —
/// the pinned NS-8 bug. Red-capable characterization that the persistent gate below must beat.
#[test]
fn lagging_peer_starves_after_publisher_restart() {
    let (outcome, seq3) = run_lagging_peer(false);
    assert_eq!(
        outcome,
        CatchupOutcome::Stalled { at: 2 },
        "PINNED BUG (NS-8): a fresh empty store per boot leaves the lagging peer no fetch path"
    );
    assert_eq!(seq3, None, "the missing Block never crossed on the stock data plane");
}

/// THE GATE (NS-8 / N-13). A persistent store carried across the restart lets the new boot
/// recover its seq and SERVE its history: B fetches the single missing Block straight from A's
/// store and converges — no `O(history)` genesis-first re-announce (A re-published nothing after
/// the restart, so the announce cost is O(gap)=1). Flipped GREEN from the starvation leg above.
#[test]
fn lagging_peer_converges_after_restart_via_persistent_store() {
    let (outcome, seq3) = run_lagging_peer(true);
    assert_eq!(
        outcome,
        CatchupOutcome::Reached(3),
        "persistent-backed publisher serves its history across the boot — the peer converges"
    );
    assert_eq!(
        seq3,
        Some(b"history-3".to_vec()),
        "the missing Block crossed, byte-identical, served from the restarted publisher's store"
    );
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// D-42 — the OFFLINE-writer regime the online-restart fix does NOT cover: a peer needs a chain's
// history while the writer is simply DOWN. A cooperative HistoryServer (durable replica: ingest
// everything advertised, serve from store) closes it. Topology W—H—R (writer and reader never
// directly linked), so a converged reader can ONLY have been served by H. RED without the
// server is exactly `lagging_peer_starves_after_publisher_restart` on the stock path.
// ────────────────────────────────────────────────────────────────────────────────────────────

/// THE OFFLINE GATE (D-42). A HistoryServer on H ingests W's chain while W is up; W then goes
/// offline and STAYS down; the lagging reader R fetches the history FROM H and converges,
/// byte-identical. Served by H, provably — the W↔H link is down and W and R share no link.
#[test]
fn offline_writer_history_served_by_history_server() {
    fastrand::seed(8);
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k).seed(8);
        let w = sim.add_node(EngineConfig::default());
        let h = sim.add_node(EngineConfig::default());
        let r = sim.add_node(EngineConfig::default());
        // W — H — R. No W↔R link: R can only be served by H.
        sim.link(w, h, LinkConfig::lan());
        sim.link(h, r, LinkConfig::lan());
        // Sync group across both hops.
        sim.add_route(w, GROUP, h);
        sim.add_route(h, GROUP, w);
        sim.add_route(h, GROUP, r);
        sim.add_route(r, GROUP, h);
        // Data plane: H ingests W's data from W; R fetches W's data from H.
        sim.add_route(h, "/nodes/W", w);
        sim.add_route(r, "/nodes/W", h);
        // H holds two group faces and both fetches-and-serves /nodes/W → multicast.
        sim.add_strategy(h, GROUP, "multicast");
        sim.add_strategy(h, "/nodes/W", "multicast");
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        let group = name(GROUP);
        let w_base = name("/nodes/W");
        let history = ["hist-1", "hist-2", "hist-3"];

        // The durable HistoryServer on H (ingests everything advertised, serves from store).
        // Serve /nodes/W at the SAME prefix H routes to W, so under multicast the FIB entry has
        // both nexthops (H-app + the W link): H's own ingest fetch reaches W (its app face is the
        // excluded originator), and R's fetch reaches H's store (the W link being down).
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let server = HistoryServerNode::attach(
            &fabric,
            h,
            &group,
            &name("/nodes/H"),
            std::slice::from_ref(&w_base),
            Arc::clone(&store),
            Duration::from_millis(50),
            &cancel,
        )
        .await
        .unwrap();

        // W publishes three Blocks while up.
        let publisher = fabric
            .engine_of(w)
            .unwrap()
            .app_node(cancel.child_token())
            .publish(group.clone(), w_base.clone())
            .await
            .unwrap();
        ndn_sim::fieldkit::settle(Duration::from_millis(200)).await;
        for blk in history {
            publisher.put(blk).await.unwrap();
        }

        // Wait until H has durably ingested W's full history.
        let mut ingested = false;
        for _ in 0..600 {
            if (1..=3).all(|s| server.store().find_under(&svs_data_name(&w_base, &group, s)).is_some())
            {
                ingested = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ingested, "HistoryServer must ingest W's full history while W is up");

        // W goes offline and STAYS down — the writer process is gone.
        fabric.set_link_up(w, h, false).unwrap();
        drop(publisher);

        // R (lagging peer) discovers via H's advertisement and fetches the history from H.
        let replica = TwoPhaseReplica::attach(
            &fabric,
            r,
            &group,
            &name("/nodes/R"),
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

        let outcome = drive_until_or_stall(&progress, 3, Duration::from_secs(20)).await;
        assert_eq!(
            outcome,
            CatchupOutcome::Reached(3),
            "R converges — served by the HistoryServer with the writer offline (D-42 offline tier)"
        );
        assert_eq!(
            received.lock().unwrap().get(&3).map(|b| b.as_ref().to_vec()),
            Some(b"hist-3".to_vec()),
            "the missing Block crossed byte-identical, served by H (writer's link down)"
        );

        cancel.cancel();
        drop(server);
        fabric.shutdown().await;
    });
}

/// C1 (D-42) — a serving member is UNTRUSTED: the fetcher RE-VERIFIES. A byzantine
/// HistoryServer that serves tampered bytes under a valid name is rejected by the fetcher's
/// signature validation, never accepted "because it's the repo." Proves no trusted-server
/// short-circuit on the fetch side: the server serves BOTH a genuine and a tampered Block; the
/// verifying fetcher accepts the genuine and rejects the tampered — purely on the crypto.
#[test]
fn history_server_served_bytes_are_re_verified_not_trusted() {
    fastrand::seed(8);
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k).seed(8);
        let h = sim.add_node(EngineConfig::default());
        let r = sim.add_node(EngineConfig::default());
        sim.link(h, r, LinkConfig::lan());
        sim.add_route(r, "/nodes/W", h); // R fetches W's data from the server H
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        let group = name(GROUP);
        let w_base = name("/nodes/W");
        let good_name = svs_data_name(&w_base, &group, 1);
        let bad_name = svs_data_name(&w_base, &group, 2);

        // W's key + a validator that trusts W's anchor (the fetcher's trust).
        let kc = KeyChain::ephemeral("/nodes/W").unwrap();
        let validator = Validator::new(TrustSchema::hierarchical());
        if let Some(cert) = kc.manager_arc().trust_anchor(kc.key_name()) {
            validator.add_trust_anchor(cert);
        }
        let signer = kc.signer().unwrap();

        // A genuine W-signed Block, and a tampered one (a content byte flipped after signing, so
        // the signature no longer matches — the wire still decodes, verification is what fails).
        let good_content = b"genuine-history-block".to_vec();
        let good_wire = DataBuilder::new(good_name.clone(), &good_content)
            .sign_with_sync(&*signer)
            .expect("sign good");
        let bad_content = b"about-to-be-tampered!".to_vec();
        let signed_bad = DataBuilder::new(bad_name.clone(), &bad_content)
            .sign_with_sync(&*signer)
            .expect("sign bad");
        let tampered_wire = {
            let mut t = signed_bad.to_vec();
            let pos = t
                .windows(bad_content.len())
                .position(|w| w == bad_content.as_slice())
                .expect("content in wire");
            t[pos] ^= 0x01;
            Bytes::from(t)
        };

        // A byzantine HistoryServer: it holds (and will serve) BOTH the genuine and the tampered
        // wire under valid names. (No writer needed — we poison the store directly.)
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let server = HistoryServerNode::attach(
            &fabric,
            h,
            &group,
            &name("/nodes/H"),
            std::slice::from_ref(&w_base),
            Arc::clone(&store),
            Duration::from_millis(50),
            &cancel,
        )
        .await
        .unwrap();
        store.insert(good_name.clone(), good_wire);
        store.insert(bad_name.clone(), tampered_wire);

        let mut consumer = fabric.engine_of(r).unwrap().app_consumer(cancel.child_token());

        // Genuine Block: served by H and it VERIFIES → accepted.
        let good = tokio::time::timeout(Duration::from_secs(5), consumer.fetch(good_name.clone()))
            .await
            .expect("fetch good timed out")
            .expect("H serves the genuine wire");
        assert!(
            matches!(validator.validate(&good).await, ValidationResult::Valid(_)),
            "a genuine, correctly-signed Block served by H validates"
        );

        // Tampered Block: also served by H, but the fetcher's verification REJECTS it — not
        // accepted because the repo served it.
        let bad = tokio::time::timeout(Duration::from_secs(5), consumer.fetch(bad_name.clone()))
            .await
            .expect("fetch bad timed out")
            .expect("H serves the tampered wire too");
        assert_eq!(*bad.name, bad_name, "same valid name — only the bytes are tampered");
        assert!(
            !matches!(validator.validate(&bad).await, ValidationResult::Valid(_)),
            "tampered bytes served by the repo MUST be rejected by the fetcher (untrusted serving)"
        );

        cancel.cancel();
        drop(server);
        fabric.shutdown().await;
    });
}
