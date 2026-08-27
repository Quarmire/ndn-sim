//! Full-stack named-time carriage over real ndn-sim engines (design §12).
//!
//! Beacons ride **real SVS** (ndn-app `Publisher`/`Subscriber`) as **node-signed
//! Data**, forwarded through real `ForwarderEngine`s across real links, decoded
//! and **validated with real crypto** against per-node trust anchors, then fed
//! to real `Timekeeper`s — the ensemble converges to the reference.
//!
//! Three tests: two connectivity probes (an SVS publication crosses a real link,
//! and a dual-role exchange crosses a hub), then the convergence demo — a GNSS
//! reference disciplining four oscillators over a shared radio medium.
//!
//! The named-time stack was already proven convergent against a modeled medium
//! (see `named_time_convergence.rs`); this replaces that medium with the actual
//! NDN forwarding plane — engines, faces, FIB/PIT/CS, a shared radio segment,
//! SVS state vectors, Ed25519 signatures, and trust-anchor validation — end to
//! end.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_security::{KeyChain, SignWith, TrustSchema, ValidationResult, Validator};
use ndn_sim::{LinkConfig, Simulation, VirtualKernel};
use ndn_time::provenance::{Authenticity, KeyId, MeasurementProvenance, PathId};
use ndn_time::{ClockCapability, Discipline, TimeInterval, TimePolicy};
use ndn_time_sources::Reading;
use ndn_timekeeper::{Timekeeper, beacon_wire};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

/// Probe: an SVS publication crosses a real ndn-sim link from A to B.
#[test]
fn svs_publication_crosses_a_real_link() {
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        sim.link(a, b, LinkConfig::lan());
        sim.add_route(a, "/time", b);
        sim.add_route(b, "/time", a);
        sim.add_route(b, "/n", a);
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        let a_node = fabric.engine_of(a).unwrap().app_node(cancel.child_token());
        let b_node = fabric.engine_of(b).unwrap().app_node(cancel.child_token());

        let publisher = a_node.publish("/time", "/n/0").await.expect("publish");
        let mut sub = b_node.subscribe("/time", "/n/1").await.expect("subscribe");

        ndn_app::rt::sleep(Duration::from_millis(200)).await;
        publisher.put(b"beacon-payload").await.expect("put");

        let sample = tokio::time::timeout(Duration::from_secs(10), sub.recv())
            .await
            .expect("subscriber timed out — SVS did not cross the link")
            .expect("sample");
        assert_eq!(sample.payload.as_deref(), Some(&b"beacon-payload"[..]));

        fabric.shutdown().await;
    });
}

/// Probe: dual-role (each node both publishes and subscribes on the same group)
/// over a hub — isolates whether the carriage itself works before the demo.
#[test]
fn svs_dual_role_crosses_a_hub() {
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k);
        let hub = sim.add_node(EngineConfig::default());
        let spokes: Vec<_> = (0..2)
            .map(|_| sim.add_node(EngineConfig::default()))
            .collect();
        for (i, &s) in spokes.iter().enumerate() {
            sim.link(s, hub, LinkConfig::default());
            sim.add_route(s, "/time", hub);
            sim.add_route(s, "/n", hub);
            sim.add_strategy(s, "/time", "multicast");
            sim.add_route(hub, "/time", s);
            sim.add_route(hub, &format!("/n/{i}"), s);
        }
        sim.add_strategy(hub, "/time", "multicast");
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        let mut pubs = Vec::new();
        let mut subs = Vec::new();
        for (i, &s) in spokes.iter().enumerate() {
            let node = fabric.engine_of(s).unwrap().app_node(cancel.child_token());
            pubs.push(node.publish("/time", format!("/n/{i}")).await.unwrap());
            subs.push(node.subscribe("/time", format!("/sub/{i}")).await.unwrap());
        }
        ndn_app::rt::sleep(Duration::from_millis(500)).await;
        pubs[0].put(b"hi-from-0").await.unwrap();

        let sample = tokio::time::timeout(Duration::from_secs(15), subs[1].recv())
            .await
            .expect("node 1 timed out receiving node 0's publication over the hub")
            .expect("sample");
        assert_eq!(sample.publisher, "/n/0");
        assert_eq!(sample.payload.as_deref(), Some(&b"hi-from-0"[..]));
        fabric.shutdown().await;
    });
}

/// A node's simulated physical clock plus its Timekeeper. The sim has one true
/// (virtual) clock; disparate clocks are modeled as `offset_ns` (steered by the
/// discipline loop) + `drift_ppb` (the intrinsic error it must track out).
struct NodeState {
    tk: Timekeeper,
    offset_ns: i64,
    drift_ppb: i64,
    beacon_seq: u64,
}

impl NodeState {
    /// Wall reading at absolute virtual time `now` (`elapsed` since t0 keeps
    /// `drift·t` within i64).
    fn wall(&self, now: i64, elapsed: i64) -> i64 {
        now + self.offset_ns + self.drift_ppb * elapsed / 1_000_000_000
    }

    fn steer(&mut self, d: Discipline, dt_ns: i64) {
        match d {
            Discipline::Step { correction_ns } => self.offset_ns += correction_ns,
            Discipline::Slew { rate_ppb } => self.offset_ns += rate_ppb * dt_ns / 1_000_000_000,
            Discipline::Track { .. } | Discipline::Withhold { .. } => {}
        }
    }
}

/// Full-stack convergence: a GNSS reference and four free-running oscillators on
/// a shared radio medium. The reference publishes node-signed beacons over real
/// SVS; each oscillator subscribes, validates the Ed25519 signature against the
/// reference's trust anchor, feeds its `Timekeeper`, and steers its clock — the
/// ensemble converges to sub-microsecond.
///
/// Single-role by design (reference publishes, oscillators subscribe): SVS's
/// all-hear-all model wants one publisher per identity on the segment, so this
/// is the clean shape for disciplining a group to a reference. A full mesh where
/// every node both publishes and subscribes needs one bidirectional SvSync per
/// node rather than the two-handle facade.
#[test]
fn nodes_converge_over_real_svs_beacon_carriage() {
    const SPOKES: usize = 5; // node 0 = GNSS reference, 1..4 = oscillators
    const CADENCE: Duration = Duration::from_secs(1);
    const THRESHOLD_NS: u64 = 500_000; // 0.5 ms convergence bar
    let osc_offsets = [8_000_000i64, -6_000_000, 4_000_000, -9_000_000];
    let osc_drifts = [300i64, -250, 350, -200];
    let initial_spread = osc_offsets.iter().map(|o| o.unsigned_abs()).max().unwrap();

    let kernel = VirtualKernel::new();
    let final_max = kernel.run(|k| async move {
        // ---- fabric: all nodes on one shared radio medium --------------------
        // SVS wants an all-hear-all broadcast segment (a routed hub aggregates
        // concurrent sync Interests in the PIT; a mesh floods). A shared radio
        // medium is exactly that segment — every node's beacon broadcasts to all.
        let mut sim = Simulation::new().without_radio_interference()
            .kernel(k.clone())
            .with_radio_medium(Arc::new(ndn_sim::FreeSpacePathLoss::default()), 7);
        let spokes: Vec<_> = (0..SPOKES)
            .map(|i| {
                sim.add_radio_node(
                    EngineConfig::default(),
                    ndn_sim::Position::xy(i as f64, 0.0),
                )
            })
            .collect();
        // Each node has two local /time app faces (its publisher + subscriber)
        // plus its radio face; multicast so an incoming sync Interest fans out to
        // both local SVS instances (and its own out to the air).
        for &s in &spokes {
            sim.add_strategy(s, "/time", "multicast");
            sim.add_strategy(s, "/n", "multicast");
        }
        let fabric = sim.start().await.unwrap();
        for &s in &spokes {
            fabric
                .route_over_radio(s, &"/time".parse().unwrap())
                .unwrap();
            fabric.route_over_radio(s, &"/n".parse().unwrap()).unwrap();
        }

        // ---- one trust anchor per node, one shared validator -----------------
        let keychains: Vec<KeyChain> = (0..SPOKES)
            .map(|i| KeyChain::ephemeral(format!("/n/{i}")).unwrap())
            .collect();
        let validator = Validator::new(TrustSchema::hierarchical());
        for kc in &keychains {
            if let Some(cert) = kc.manager_arc().trust_anchor(kc.key_name()) {
                validator.add_trust_anchor(cert);
            }
        }
        let validator = Arc::new(validator);

        // ---- per-node Timekeeper + publisher/subscriber loops ----------------
        let policy = TimePolicy::default();
        let cancel = CancellationToken::new();
        let t0 = k.runtime().unix_nanos() as i64;
        let mut states: Vec<Arc<Mutex<NodeState>>> = Vec::new();
        // Evidence that beacons really crossed the fabric (not just local math).
        let puts = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let ingests = Arc::new(std::sync::atomic::AtomicU64::new(0));

        for i in 0..SPOKES {
            let (offset, drift, cap, self_unc) = if i == 0 {
                (0i64, 0i64, ClockCapability::gnss_disciplined(), 50u64)
            } else {
                (
                    osc_offsets[i - 1],
                    osc_drifts[i - 1],
                    ClockCapability::oscillator_tcxo(),
                    20_000_000u64,
                )
            };
            let st = Arc::new(Mutex::new(NodeState {
                tk: Timekeeper::new(i as u64, KeyId(i as u64), cap, policy),
                offset_ns: offset,
                drift_ppb: drift,
                beacon_seq: 0,
            }));
            states.push(st.clone());

            let node = fabric
                .engine_of(spokes[i])
                .unwrap()
                .app_node(cancel.child_token());

            if i == 0 {
                // The GNSS reference: publishes its signed beacon; never steers.
                // Single-role (publish only) so there is no same-node SvSync pair.
                let publisher = node.publish("/time", "/n/0").await.unwrap();
                let signer = keychains[0].signer().unwrap();
                let st_pub = st.clone();
                let k_pub = k.clone();
                let puts_pub = puts.clone();
                tokio::spawn(async move {
                    loop {
                        ndn_app::rt::sleep(CADENCE).await;
                        let wire = {
                            let mut s = st_pub.lock().await;
                            let now = k_pub.runtime().unix_nanos() as i64;
                            let elapsed = now - t0;
                            let local_wall = s.wall(now, elapsed);
                            s.tk.ingest_local_reading(&Reading {
                                wall: TimeInterval::new(local_wall, self_unc),
                                cap,
                                captured_mono_ns: elapsed as u64,
                            });
                            let out = s.tk.tick(elapsed as u64, local_wall);
                            s.beacon_seq += 1;
                            let corrected = local_wall + out.correction.offset_ns;
                            // Content = beacon_wire ++ send-time (monotonic). The
                            // receiver uses the send-time as captured_mono so the
                            // discipline advances out the full in-flight delay
                            // (both share the sim's monotonic clock; a real link
                            // would recover it via the measurement layer).
                            let mut content = beacon_wire::encode(
                                s.beacon_seq,
                                corrected,
                                out.correction.uncertainty_ns,
                                &cap,
                            )
                            .to_vec();
                            content.extend_from_slice(&elapsed.to_be_bytes());
                            let dname: ndn_packet::Name =
                                format!("/n/0/time/beacon/{}", s.beacon_seq)
                                    .parse()
                                    .unwrap();
                            DataBuilder::new(dname, &content)
                                .sign_with_sync(&*signer)
                                .unwrap()
                        };
                        if publisher.put(&wire).await.is_ok() {
                            puts_pub.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                });
            } else {
                // An oscillator: subscribes to the reference's beacons (single
                // role, subscribe only) and disciplines its clock toward them.
                let mut subscriber = node.subscribe("/time", format!("/sub/{i}")).await.unwrap();
                let st_sub = st.clone();
                let val = validator.clone();
                let ingests_sub = ingests.clone();
                tokio::spawn(async move {
                    while let Some(sample) = subscriber.recv().await {
                        let Some(payload) = sample.payload else {
                            continue;
                        };
                        let Some(peer) = sample
                            .publisher
                            .rsplit('/')
                            .next()
                            .and_then(|s| s.parse::<usize>().ok())
                        else {
                            continue;
                        };
                        let Ok(data) = Data::decode(payload) else {
                            continue;
                        };
                        let ValidationResult::Valid(safe) = val.validate(&data).await else {
                            continue; // failed crypto / trust — drop it
                        };
                        let Some(content) = safe.data().content() else {
                            continue;
                        };
                        if content.len() < 8 {
                            continue;
                        }
                        let Some(dec) = beacon_wire::decode(content) else {
                            continue;
                        };
                        // Recover the sender's send-time (trailing 8 bytes) as the
                        // sample's captured_mono — the moment its wall was valid.
                        let send_mono =
                            i64::from_be_bytes(content[content.len() - 8..].try_into().unwrap());
                        let beacon = dec.into_beacon(
                            send_mono as u64,
                            MeasurementProvenance {
                                distance_bounded: false,
                                replay_protected: true,
                                authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(
                                    peer as u64,
                                )),
                                path: PathId(peer as u32 + 1),
                            },
                        );
                        st_sub.lock().await.tk.ingest_beacon(peer as u64, &beacon);
                        ingests_sub.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                });

                // discipline task: on cadence, fold in the local clock + peers,
                // tick, and steer.
                let st_disc = st.clone();
                let k_disc = k.clone();
                tokio::spawn(async move {
                    loop {
                        ndn_app::rt::sleep(CADENCE).await;
                        let mut s = st_disc.lock().await;
                        let now = k_disc.runtime().unix_nanos() as i64;
                        let elapsed = now - t0;
                        let local_wall = s.wall(now, elapsed);
                        s.tk.ingest_local_reading(&Reading {
                            wall: TimeInterval::new(local_wall, self_unc),
                            cap,
                            captured_mono_ns: elapsed as u64,
                        });
                        let out = s.tk.tick(elapsed as u64, local_wall);
                        s.steer(out.discipline, CADENCE.as_nanos() as i64);
                    }
                });
            }
        }

        // ---- drive virtual time until the oscillators converge ---------------
        println!(
            "\nfull-stack SVS convergence: 1 GNSS reference + {} oscillators on a \
             shared radio medium, initial spread {:.3} ms\n",
            SPOKES - 1,
            initial_spread as f64 / 1e6
        );
        let mut final_max = u64::MAX;
        let mut streak = 0;
        for round in 0..60 {
            ndn_app::rt::sleep(CADENCE).await;
            let now = k.runtime().unix_nanos() as i64;
            let elapsed = now - t0;
            let mut max_err = 0u64;
            for st in states.iter().take(SPOKES).skip(1) {
                let s = st.lock().await;
                max_err = max_err.max((s.wall(now, elapsed) - now).unsigned_abs());
            }
            final_max = max_err;
            if round < 8 || round % 5 == 0 {
                println!(
                    "  round {round:>2}: max err {:>8.1} µs",
                    max_err as f64 / 1e3
                );
            }
            if max_err < THRESHOLD_NS {
                streak += 1;
                if streak >= 3 {
                    println!("  converged at round {round}");
                    break;
                }
            } else {
                streak = 0;
            }
        }

        use std::sync::atomic::Ordering::Relaxed;
        let carriage = (puts.load(Relaxed), ingests.load(Relaxed));
        cancel.cancel();
        fabric.shutdown().await;
        (final_max, carriage)
    });

    let (final_max, (beacons_published, beacons_ingested)) = final_max;
    println!(
        "final max error {:.1} µs  ({beacons_published} beacons published, \
         {beacons_ingested} validated + ingested by peers)\n",
        final_max as f64 / 1e3
    );
    assert!(
        initial_spread > 1_000_000,
        "the oscillators started >1 ms apart"
    );
    assert!(
        beacons_ingested > 0,
        "no beacon crossed the fabric — the carriage did not work"
    );
    assert!(
        final_max < THRESHOLD_NS,
        "ensemble should converge to <{THRESHOLD_NS} ns over real SVS, got {final_max} ns"
    );
}
