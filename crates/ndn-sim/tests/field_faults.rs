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
    CatchupOutcome, Progress, RestartablePublisher, TwoPhaseReplica, drive_until_or_stall,
    naive_catchup, publish_backlog,
};
use ndn_sim::{FrameMatcher, HoldRule, LinkConfig, Simulation, VirtualKernel};
use ndn_app::Consumer;
use ndn_repo::{
    BlobFetch, Repo, RepoCmd, RepoCmdRes, RepoService, RepoServiceConfig, SyncJoin,
    sync_protocol_svs_v3,
};
use ndn_sync::{DataStore, MemoryStore, SvSyncConfig, SvsConfig, svs_data_name};
use tokio::sync::mpsc;
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
// history while the writer is simply DOWN. The durable serving member is a REAL `ndn-repo` in
// two-phase (reject-without-poison) mode — the ndn-sync `HistoryServer` fork was retired in favor
// of ndn-repo (regaining ndnd RepoCmd interop). Topology W—hub—REPO—hub—R: with the writer's link
// down and the reader served only through the repo, a converged reader can ONLY have been served
// by the repo. RED without a server is `lagging_peer_starves_after_publisher_restart`.
// ────────────────────────────────────────────────────────────────────────────────────────────

/// A real `ndn-repo` `RepoService` in two-phase mode, attached to a node's engine over an app
/// face — the D-42 durable serving member. It auto-joins `group` (operator config), ingests the
/// chain reject-without-poison, and serves it from `store`. The publication namespace lives under
/// the group (ndnd/`svs_data_name` convention), so one `group` prefix routes sync + data alike.
struct RepoNode {
    store: Arc<dyn DataStore>,
}

impl RepoNode {
    async fn attach(
        fabric: &ndn_sim::RunningSimulation,
        node: ndn_sim::NodeId,
        group: &Name,
        node_id: &str,
        store: Arc<dyn DataStore>,
        sync_interval: Duration,
        cancel: &CancellationToken,
    ) -> Self {
        let engine = fabric.engine_of(node).expect("engine for repo node");
        let app = engine.app_node(cancel.child_token());
        let conn = app.connection();

        let repo = Repo::new(Arc::clone(&store));
        let config = RepoServiceConfig {
            node_id: node_id.to_string(),
            two_phase_ingest: true,
            initial_groups: vec![group.clone()],
            svs: SvSyncConfig {
                svs: SvsConfig { sync_interval, jitter_ms: 0, ..Default::default() },
                fetch_timeout: Duration::from_secs(2),
                ..Default::default()
            },
            ..Default::default()
        };
        let (send_tx, mut send_rx) = mpsc::channel::<Bytes>(256);
        let (recv_tx, recv_rx) = mpsc::channel::<Bytes>(256);
        let (reg_tx, mut reg_rx) = mpsc::channel::<Name>(64);
        let svc = RepoService::new(repo, name("/repo-svc"), send_tx, config).with_registration(reg_tx);

        // Register every prefix the service asks for (its command prefix + each joined group) on
        // the face, so the forwarder delivers commands, sync Interests, and publication Interests.
        {
            let conn = Arc::clone(&conn);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        p = reg_rx.recv() => match p {
                            Some(p) => { let _ = conn.register_prefix(&p).await; }
                            None => break,
                        },
                    }
                }
            });
        }
        // Outbound: everything the service emits → the face.
        {
            let conn = Arc::clone(&conn);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        pkt = send_rx.recv() => match pkt {
                            Some(p) => { let _ = conn.send(p).await; }
                            None => break,
                        },
                    }
                }
            });
        }
        // Inbound: everything off the face → the service demux.
        {
            let conn = Arc::clone(&conn);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    let wire = tokio::select! {
                        _ = cancel.cancelled() => break,
                        w = conn.recv() => match w { Some(w) => w, None => break },
                    };
                    if recv_tx.send(wire).await.is_err() {
                        break;
                    }
                }
            });
        }
        tokio::spawn(svc.run(recv_rx));
        Self { store }
    }

    fn store(&self) -> &Arc<dyn DataStore> {
        &self.store
    }
}

/// THE OFFLINE GATE (D-42), now via **ndn-repo**. A repo ingests W's chain while W is up; W goes
/// offline and STAYS down; the lagging reader fetches the history from the repo and converges,
/// byte-identical. Served by the repo, provably — the writer's link is down and CS is off, so a
/// server store is the only possible source.
#[test]
fn offline_writer_history_served_via_ndn_repo() {
    fastrand::seed(8);
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let no_cs = || EngineConfig { cs_capacity_bytes: 0, ..EngineConfig::default() };
        let mut sim = Simulation::new().kernel(k).seed(8);
        let sw = sim.add_node(no_cs());
        let w = sim.add_node(no_cs());
        let repo = sim.add_node(no_cs());
        let r = sim.add_node(no_cs());
        for member in [w, repo, r] {
            sim.link(sw, member, LinkConfig::lan());
        }
        // One prefix routes sync AND data (publications live under the group). The hub multicasts
        // to the writer + repo + reader; whichever is live and holds a Block answers.
        for member in [w, repo, r] {
            sim.add_route(member, GROUP, sw);
            sim.add_route(sw, GROUP, member);
        }
        sim.add_strategy(sw, GROUP, "multicast");
        // The reader registers the group for sync AND fetches data under it (ndnd naming). Those
        // two FIB nexthops (its own sync face + the hub) must both be tried, or a data fetch can
        // be delivered only to the reader's own face and never reach the repo — so multicast.
        sim.add_strategy(r, GROUP, "multicast");
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        let group = name(GROUP);
        let w_base = name("/grp/w"); // publisher under the group (ndnd naming)
        let history = ["hist-1", "hist-2", "hist-3"];

        // The durable serving member: a real ndn-repo in two-phase mode.
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let server =
            RepoNode::attach(&fabric, repo, &group, "repo", Arc::clone(&store), Duration::from_millis(50), &cancel).await;

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

        // Wait until the repo has durably ingested W's full history.
        let mut ingested = false;
        for _ in 0..600 {
            if (1..=3).all(|s| server.store().find_under(&svs_data_name(&w_base, &group, s)).is_some())
            {
                ingested = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ingested, "the ndn-repo must ingest W's full history while W is up");

        // W goes offline and STAYS down.
        fabric.set_link_up(sw, w, false).unwrap();
        drop(publisher);

        // The reader fetches the history — served by the repo, writer gone.
        let (outcome, seq3) =
            drive_reader(&fabric, r, &group, &name("/grp/r"), &cancel, 3, Duration::from_secs(20)).await;
        assert_eq!(
            outcome,
            CatchupOutcome::Reached(3),
            "reader converges — served by the ndn-repo with the writer offline (D-42 offline tier)"
        );
        assert_eq!(
            seq3,
            Some(b"hist-3".to_vec()),
            "the missing Block crossed byte-identical, served by the repo (writer's link down)"
        );

        cancel.cancel();
        drop(server);
        fabric.shutdown().await;
    });
}

// ────────────────────────────────────────────────────────────────────────────────────────────
// D-42 cooperative HA (mediator-federation-policy §Redistribution) — the mesh keeps serving
// through member churn. Invariant: "≥1 live member ⇒ K restorable" — a new member back-fills the
// chain from a SURVIVING SERVER (never the offline writer), so history stays reachable as members
// come and go. This gate proves the SUBSTRATE MECHANISM composes for that continuity; the churn is
// triggered manually (drop/add a member), NOT by an auto-orchestrator — presence-triggered
// auto-redistribution (D-46) is the policy-layer binding, a separate ndf-policy follow-on.
// ────────────────────────────────────────────────────────────────────────────────────────────

/// Attach a fresh two-phase reader on `node`, drive it toward `target`, and return the outcome
/// plus the bytes it ended up holding for seq 3.
async fn drive_reader(
    fabric: &ndn_sim::RunningSimulation,
    node: ndn_sim::NodeId,
    group: &Name,
    local: &Name,
    cancel: &CancellationToken,
    target: u64,
    timeout: Duration,
) -> (CatchupOutcome, Option<Vec<u8>>) {
    let replica =
        TwoPhaseReplica::attach(fabric, node, group, local, Duration::from_millis(500), cancel)
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
    let outcome = drive_until_or_stall(&progress, target, timeout).await;
    let seq3 = received.lock().unwrap().get(&3).map(|b| b.as_ref().to_vec());
    (outcome, seq3)
}

/// Run the churn scenario over real **ndn-repo** members. `backfill_from_peer` is the single knob
/// under test: when `true` a joining repo's chain fetches reach the cooperative (a surviving
/// repo); when `false` they reach ONLY the (offline) writer — the mutation that must make HA
/// fail. Returns the baseline reader outcome, the post-churn fresh-reader outcome, and that
/// reader's seq-3 bytes.
///
/// Topology: an undropped hub `SW` carries everything under `/grp` (sync + data, since ndnd names
/// publications under the group), so connectivity survives any member dropping. Members drop by
/// downing their hub link (a presence-absence). The mutation is separated from sync by prefix
/// specificity: repo3's `/grp/w` (data) route is overridden to the writer in RED, while its `/grp`
/// (sync) route always reaches the hub — so it still HEARS the survivor but cannot FETCH from it.
#[allow(clippy::too_many_lines)]
fn run_cooperative_ha(
    backfill_from_peer: bool,
) -> (CatchupOutcome, CatchupOutcome, Option<Vec<u8>>) {
    fastrand::seed(8);
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k).seed(8);
        // No forwarder content store anywhere: a cached copy at the hub would mask the RED
        // starvation (and inflate GREEN), but caching is best-effort availability, not the HA
        // guarantee under test. With CS off, the ONLY source of a Block is a repo's store.
        let no_cs = || EngineConfig {
            cs_capacity_bytes: 0,
            ..EngineConfig::default()
        };
        let sw = sim.add_node(no_cs());
        let w = sim.add_node(no_cs());
        let repo1 = sim.add_node(no_cs());
        let repo2 = sim.add_node(no_cs());
        let repo3 = sim.add_node(no_cs());
        let r = sim.add_node(no_cs());
        let r2 = sim.add_node(no_cs());
        for member in [w, repo1, repo2, repo3, r, r2] {
            sim.link(sw, member, LinkConfig::lan());
        }
        sim.link(repo3, w, LinkConfig::lan()); // the RED "back-fill only from the writer" path

        // Everything under /grp fans out through the hub (sync AND data — ndnd naming).
        for member in [w, repo1, repo2, repo3, r, r2] {
            sim.add_route(member, GROUP, sw);
            sim.add_route(sw, GROUP, member);
        }
        sim.add_strategy(sw, GROUP, "multicast");
        // Readers register the group for sync yet fetch data under it — both nexthops (own sync
        // face + hub) must be tried, or a data fetch never leaves for the cooperative.
        sim.add_strategy(r, GROUP, "multicast");
        sim.add_strategy(r2, GROUP, "multicast");
        // THE MUTATION: repo3's DATA route for the writer's namespace `/grp/w` (a longer prefix
        // than `/grp`, so it governs data fetches while `/grp` still governs sync). GREEN leaves
        // it unset → data rides `/grp` to the hub (a surviving repo). RED points it at the writer
        // (direct link, and the writer is offline) → repo3 can only "catch up from the writer".
        if !backfill_from_peer {
            sim.add_route(repo3, "/grp/w", w);
        }

        let fabric = sim.start().await.unwrap();
        let cancel = CancellationToken::new();
        let group = name(GROUP);
        let w_base = name("/grp/w"); // publisher under the group (ndnd naming)
        let history = ["hist-1", "hist-2", "hist-3"];

        // K=2: repo1 and repo2 serve, ingesting W's chain while the writer is up.
        let store1: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let s1 = RepoNode::attach(&fabric, repo1, &group, "repo1", Arc::clone(&store1), Duration::from_millis(50), &cancel).await;
        let store2: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let s2 = RepoNode::attach(&fabric, repo2, &group, "repo2", Arc::clone(&store2), Duration::from_millis(50), &cancel).await;

        // Writer publishes, then leaves for good.
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
        let mut ingested = false;
        for _ in 0..600 {
            if [&store1, &store2].iter().all(|st| {
                (1..=3).all(|s| st.find_under(&svs_data_name(&w_base, &group, s)).is_some())
            }) {
                ingested = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ingested, "the K=2 repos must ingest the chain while the writer is up");
        // Writer OFFLINE for the rest of the scenario (both its links down + process gone).
        fabric.set_link_up(sw, w, false).unwrap();
        fabric.set_link_up(repo3, w, false).unwrap();
        drop(publisher);

        // Baseline: a reader converges, served by the live cooperative (writer offline).
        let (baseline, _) =
            drive_reader(&fabric, r, &group, &name("/grp/r"), &cancel, 3, Duration::from_secs(15)).await;

        // CHURN. Drop repo1 (K → 1), then a NEW repo3 joins and must back-fill the full chain from
        // the surviving repo2 (GREEN) — or reach only the offline writer (RED).
        fabric.set_link_up(sw, repo1, false).unwrap();
        let store3: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let s3 = RepoNode::attach(&fabric, repo3, &group, "repo3", Arc::clone(&store3), Duration::from_millis(50), &cancel).await;
        for _ in 0..300 {
            if (1..=3).all(|s| store3.find_under(&svs_data_name(&w_base, &group, s)).is_some()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Drop repo2 — the last member that ingested directly from the writer. Only repo3 remains:
        // it holds the chain iff it back-filled.
        fabric.set_link_up(sw, repo2, false).unwrap();

        // Continuity: a FRESH reader that joins after the full churn converges iff ≥1 live member
        // holds the chain — i.e. iff redistribution restored K by peer back-fill.
        let (after, seq3) =
            drive_reader(&fabric, r2, &group, &name("/grp/r2"), &cancel, 3, Duration::from_secs(20)).await;

        cancel.cancel();
        drop((s1, s2, s3));
        fabric.shutdown().await;
        (baseline, after, seq3)
    })
}

/// THE HA GATE (D-42 redistribution). Through a full member turnover — drop H1, a new H3 joins
/// and back-fills from surviving H2, drop H2 — a fresh reader still converges byte-identical,
/// served by the back-filled member with the writer offline the whole time. "≥1 live member ⇒
/// K restorable" holds as a substrate mechanism.
#[test]
fn cooperative_ha_survives_member_churn_via_peer_backfill() {
    let (baseline, after, seq3) = run_cooperative_ha(true);
    assert_eq!(
        baseline,
        CatchupOutcome::Reached(3),
        "baseline: the live cooperative serves the reader with the writer offline"
    );
    assert_eq!(
        after,
        CatchupOutcome::Reached(3),
        "≥1 live member ⇒ K restorable: the fresh reader converges after full churn, served by \
         the back-filled member"
    );
    assert_eq!(
        seq3,
        Some(b"hist-3".to_vec()),
        "the chain crossed byte-identical through redistribution (peer back-fill)"
    );
}

/// THE RED HALF (mutation-check). Disable peer back-fill — a joining member's chain fetches reach
/// ONLY the offline writer ("never by assuming the writer is online", inverted). Now
/// redistribution cannot restore K: the new member stays empty, and once the members that
/// ingested directly from the writer drop, the reader starves. This is what makes the gate
/// load-bearing: back-fill from a surviving server is THE mechanism that enables cooperative HA.
#[test]
fn cooperative_ha_starves_when_backfill_reaches_only_the_writer() {
    let (baseline, after, _) = run_cooperative_ha(false);
    assert_eq!(
        baseline,
        CatchupOutcome::Reached(3),
        "baseline is identical: original members serve the reader before churn"
    );
    assert!(
        matches!(after, CatchupOutcome::Stalled { .. }),
        "without peer back-fill (a joiner reaching only the offline writer) redistribution cannot \
         restore K; once the original holders drop, the fresh reader starves — got {after:?}"
    );
}

/// C1 (D-42) — a serving member is UNTRUSTED: the fetcher RE-VERIFIES, and this composes over
/// ndn-repo unchanged (nothing repo-side is in the trust path). A byzantine ndn-repo that serves
/// tampered bytes under a valid name is rejected by the fetcher's signature validation, never
/// accepted "because it's the repo." The repo serves BOTH a genuine and a tampered Block; the
/// verifying fetcher accepts the genuine and rejects the tampered — purely on the crypto.
#[test]
fn history_served_bytes_are_re_verified_not_trusted_via_ndn_repo() {
    fastrand::seed(8);
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let no_cs = || EngineConfig { cs_capacity_bytes: 0, ..EngineConfig::default() };
        let mut sim = Simulation::new().kernel(k).seed(8);
        let sw = sim.add_node(no_cs());
        let repo = sim.add_node(no_cs());
        let r = sim.add_node(no_cs());
        for member in [repo, r] {
            sim.link(sw, member, LinkConfig::lan());
            sim.add_route(member, GROUP, sw);
            sim.add_route(sw, GROUP, member);
        }
        sim.add_strategy(sw, GROUP, "multicast");
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        let group = name(GROUP);
        let w_base = name("/grp/w"); // publisher under the group (ndnd naming)
        let good_name = svs_data_name(&w_base, &group, 1);
        let bad_name = svs_data_name(&w_base, &group, 2);

        // W's key + a validator that trusts W's anchor (the fetcher's trust).
        let kc = KeyChain::ephemeral("/grp/w").unwrap();
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

        // A byzantine ndn-repo: it holds (and will serve) BOTH the genuine and the tampered wire
        // under valid names. (No writer needed — we poison the store directly.)
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let server =
            RepoNode::attach(&fabric, repo, &group, "repo", Arc::clone(&store), Duration::from_millis(50), &cancel).await;
        store.insert(good_name.clone(), good_wire);
        store.insert(bad_name.clone(), tampered_wire);

        let mut consumer = fabric.engine_of(r).unwrap().app_consumer(cancel.child_token());

        // Genuine Block: served by the repo and it VERIFIES → accepted.
        let good = tokio::time::timeout(Duration::from_secs(5), consumer.fetch(good_name.clone()))
            .await
            .expect("fetch good timed out")
            .expect("repo serves the genuine wire");
        assert!(
            matches!(validator.validate(&good).await, ValidationResult::Valid(_)),
            "a genuine, correctly-signed Block served by the repo validates"
        );

        // Tampered Block: also served by the repo, but the fetcher's verification REJECTS it — not
        // accepted because the repo served it.
        let bad = tokio::time::timeout(Duration::from_secs(5), consumer.fetch(bad_name.clone()))
            .await
            .expect("fetch bad timed out")
            .expect("repo serves the tampered wire too");
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

/// The PAYOFF of riding ndn-repo instead of the retired fork: the ndnd `RepoCmd` interop is back.
/// An ndnd-shaped client drives the repo over the wire — a `SyncJoin` makes it start holding a
/// group, a `BlobFetch` queues a by-name ingest — each answered with a `RepoCmdRes` 200. (The
/// HistoryServer fork had no command interface; this is what the fork forfeited.)
#[test]
fn ndnd_repo_cmd_interop_drives_the_repo() {
    fastrand::seed(8);
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let no_cs = || EngineConfig { cs_capacity_bytes: 0, ..EngineConfig::default() };
        let mut sim = Simulation::new().kernel(k).seed(8);
        let sw = sim.add_node(no_cs());
        let repo = sim.add_node(no_cs());
        let c = sim.add_node(no_cs());
        sim.link(sw, repo, LinkConfig::lan());
        sim.link(sw, c, LinkConfig::lan());
        // Route the repo command prefix (client → repo) and the repo's group (both via the hub).
        sim.add_route(c, "/repo-svc", sw);
        sim.add_route(sw, "/repo-svc", repo);
        sim.add_route(repo, GROUP, sw);
        sim.add_route(sw, GROUP, repo);
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        let group = name(GROUP);
        let store: Arc<dyn DataStore> = Arc::new(MemoryStore::new());
        let _repo =
            RepoNode::attach(&fabric, repo, &group, "repo", Arc::clone(&store), Duration::from_millis(50), &cancel).await;

        let mut consumer = fabric.engine_of(c).unwrap().app_consumer(cancel.child_token());

        // ndnd-shaped SyncJoin: tell the repo to start holding a NEW group over the wire.
        let join = RepoCmd::SyncJoin(SyncJoin {
            protocol: Some(sync_protocol_svs_v3()),
            group: Some(name("/grp2")),
            ..Default::default()
        });
        let res = drive_repo_cmd(&mut consumer, &name("/repo-svc/join"), join.encode()).await;
        assert_eq!(res.status, 200, "SyncJoin accepted over the wire (ndnd RepoCmd interop)");

        // ndnd-shaped BlobFetch: queue a by-name ingest.
        let blob = RepoCmd::BlobFetch(BlobFetch {
            name: Some(name("/grp/w/grp/%01")),
            ..Default::default()
        });
        let res2 = drive_repo_cmd(&mut consumer, &name("/repo-svc/blob"), blob.encode()).await;
        assert_eq!(res2.status, 200, "BlobFetch accepted over the wire (ndnd RepoCmd interop)");

        cancel.cancel();
        fabric.shutdown().await;
    });
}

/// Send an ndnd-shaped `RepoCmd` as a signed command Interest and decode the `RepoCmdRes` reply.
async fn drive_repo_cmd(consumer: &mut Consumer, name: &Name, cmd: Bytes) -> RepoCmdRes {
    let builder = InterestBuilder::new(name.clone())
        .must_be_fresh()
        .app_parameters(cmd.to_vec());
    let data = tokio::time::timeout(Duration::from_secs(5), consumer.fetch_with(builder))
        .await
        .expect("repo command timed out")
        .expect("no RepoCmdRes reply");
    RepoCmdRes::decode(data.content().unwrap().clone()).expect("decode RepoCmdRes")
}
