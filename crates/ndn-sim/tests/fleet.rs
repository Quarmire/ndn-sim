//! Fleet regression suite: the miniMUAS fabric exactly as deployed — a GCS and three airframes,
//! each booted from its own ndn-fwd TOML (`tests/fixtures/fleet/`) through ndn-fwd's boot code,
//! UDP peer faces with NDNLPv2 fragmentation + reliability, all sharing one lossy managed Wi-Fi
//! cell — running the fleet's three workloads at once:
//!
//! - **telemetry**: each airframe's LatestPublisher mints a version every 300 ms (~3.3/s); the
//!   GCS polls each with CanBePrefix+MustBeFresh at the same rate, and each airframe polls one
//!   peer the same way (the swarm);
//! - **video-sized Data**: iuas-01 publishes ~8 KB samples at 10/s (every one LP-fragmented);
//! - **an NDNSF-style service call**: the GCS publishes a ~1 KB request on SVS pub/sub that every
//!   airframe must receive.
//!
//! Each assertion is something an operator reads off the fleet (sample rate, stale samples,
//! longest telemetry gap, service-call reach, `cs/info` hits, `faces/list` LP counters), and each
//! maps to a bug the fleet actually shipped: strategy choices silently not applied (sync reached
//! one peer, every service call timed out), CanBePrefix+MustBeFresh answered from one arbitrary
//! cached version (caches stopped answering), and LP retransmissions re-condemned until they were
//! given up on (see `ndn-rs/docs/nfd-divergence-findings.md`). Deterministic: one seed, virtual
//! time.
//!
//! Replaces the hand-wired `muas_mesh_svs` reproduction, which linked the nodes with in-process
//! faces, bare FIB routes, and directly-inserted strategies — the three substitutions the fleet
//! bugs hid behind.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::Bytes;

use ndn_app::EngineAppExt;
use ndn_sim::{
    AppSpec, FaceKind, FaceProfile, FlowStats, NodeId, RunningSimulation, Scenario, SimKernel,
    VirtualKernel,
};
use tokio_util::sync::CancellationToken;

const SEED: u64 = 7;
const TELEMETRY_MS: u64 = 300;
const VIDEO_MS: u64 = 100;
const VIDEO_BYTES: usize = 8000;
/// Measurement window after the consumers start.
const RUN: Duration = Duration::from_secs(20);
const AIRFRAMES: [&str; 3] = ["iuas-01", "iuas-02", "wuas-01"];

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fleet")
}

/// Fleet-wide NDNLPv2 counters, summed over every peer face (what `faces/list` shows per face).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct LpTotals {
    retransmitted: u64,
    duplicates: u64,
    gave_up: u64,
    evicted: u64,
    acks_sent: u64,
}

impl LpTotals {
    /// Share of retransmissions the receiver already had — pure wasted airtime. The fleet
    /// measured 46% (6795 duplicates / 14850 retransmits in 120 s) while Acks were being batched.
    fn spurious_ratio(&self) -> f64 {
        self.duplicates as f64 / self.retransmitted.max(1) as f64
    }
}

#[derive(Debug, Clone, PartialEq)]
struct FleetRun {
    telemetry: Vec<(&'static str, FlowStats)>,
    video: FlowStats,
    /// Airframes whose service-request subscriber received the GCS's request.
    svs_reached: Vec<&'static str>,
    /// `(poller, publisher, stats)` for each airframe's poll of a peer's telemetry.
    swarm: Vec<(&'static str, &'static str, FlowStats)>,
    /// Content Store hits summed over every node during the measurement window (`cs/info`).
    cs_hits: u64,
    lp: LpTotals,
}

fn node(fabric: &RunningSimulation, label: &str) -> NodeId {
    fabric
        .topology()
        .nodes
        .iter()
        .find(|n| n.label == label)
        .map(|n| n.id)
        .unwrap_or_else(|| panic!("fleet node {label} missing"))
}

fn lp_totals(fabric: &RunningSimulation, nodes: &[NodeId]) -> LpTotals {
    let mut t = LpTotals::default();
    for &n in nodes {
        for face in fabric.face_stats(n).unwrap() {
            if let (FaceKind::Link { .. }, Some(lp)) = (&face.kind, face.lp) {
                t.retransmitted += lp.resent + lp.fast_retx;
                t.duplicates += lp.duplicate_frames;
                t.gave_up += lp.gave_up;
                t.evicted += lp.unacked_evictions;
                t.acks_sent += lp.acks_sent;
            }
        }
    }
    t
}

fn cs_hits(fabric: &RunningSimulation) -> u64 {
    fabric.snapshot_metrics().iter().map(|m| m.cs_hits).sum()
}

fn run_fleet() -> FleetRun {
    // ndn-sync's suppression jitter draws from the thread-local fastrand.
    fastrand::seed(SEED);
    let scenario = Scenario::from_toml_file(&fixtures().join("scenario.toml")).unwrap();
    VirtualKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
        let fabric = scenario.build(k).unwrap().start().await.unwrap();
        let gcs = node(&fabric, "gcs");
        let airframes: Vec<NodeId> = AIRFRAMES.iter().map(|a| node(&fabric, a)).collect();

        // Publishers first; consumers half a period later so each poll lands mid-period.
        for (&name, &n) in AIRFRAMES.iter().zip(&airframes) {
            fabric
                .spawn_app(
                    n,
                    AppSpec::LatestPublisher {
                        prefix: format!("/muas/v2/{name}/telemetry/live"),
                        interval_ms: TELEMETRY_MS,
                        size: Some(200),
                        freshness_ms: None,
                    },
                )
                .unwrap();
        }
        fabric
            .spawn_app(
                airframes[0],
                AppSpec::LatestPublisher {
                    prefix: "/muas/v2/iuas-01/video/live".into(),
                    interval_ms: VIDEO_MS,
                    size: Some(VIDEO_BYTES),
                    freshness_ms: None,
                },
            )
            .unwrap();

        // The service call rides SVS pub/sub on the /muas group, like NDNSF.
        let cancel = CancellationToken::new();
        let mut subscribers = Vec::new();
        for (&name, &n) in AIRFRAMES.iter().zip(&airframes) {
            let app = fabric.engine_of(n).unwrap().app_node(cancel.child_token());
            let sub = app
                .subscribe("/muas", format!("/muas/v2/{name}").as_str())
                .await
                .expect("subscribe");
            subscribers.push((name, sub, app));
        }
        let gcs_app = fabric
            .engine_of(gcs)
            .unwrap()
            .app_node(cancel.child_token());
        let requester = gcs_app
            .publish("/muas", "/muas/v2/gcs")
            .await
            .expect("publish");

        ndn_app::rt::sleep(Duration::from_millis(TELEMETRY_MS / 2)).await;
        let telemetry_apps: Vec<_> = AIRFRAMES
            .iter()
            .map(|name| {
                let id = fabric
                    .spawn_app(
                        gcs,
                        AppSpec::LatestConsumer {
                            prefix: format!("/muas/v2/{name}/telemetry/live"),
                            interval_ms: TELEMETRY_MS,
                            count: 0,
                            lifetime_ms: None,
                            stale_slack_ms: None,
                        },
                    )
                    .unwrap();
                (*name, id)
            })
            .collect();
        let video_app = fabric
            .spawn_app(
                gcs,
                AppSpec::LatestConsumer {
                    prefix: "/muas/v2/iuas-01/video/live".into(),
                    interval_ms: VIDEO_MS,
                    count: 0,
                    lifetime_ms: None,
                    stale_slack_ms: None,
                },
            )
            .unwrap();
        let measure_from = fabric.clock().now();
        let hits_before = cs_hits(&fabric);

        // Each airframe also polls a peer's telemetry, as the fleet does (its capture:
        // `.13 > .11/.12/.14 INTEREST /muas/v2/wuas-01/telemetry/live?CanBePrefix&MustBeFresh`,
        // answered by the GCS from cache). Offset from the GCS's polls so a copy fetched for
        // the GCS is still fresh on the path when the airframe asks.
        ndn_app::rt::sleep(Duration::from_millis(TELEMETRY_MS / 6)).await;
        let swarm_apps: Vec<_> = AIRFRAMES
            .iter()
            .zip(&airframes)
            .enumerate()
            .map(|(i, (&poller, &n))| {
                let target = AIRFRAMES[(i + 1) % AIRFRAMES.len()];
                let id = fabric
                    .spawn_app(
                        n,
                        AppSpec::LatestConsumer {
                            prefix: format!("/muas/v2/{target}/telemetry/live"),
                            interval_ms: TELEMETRY_MS,
                            count: 0,
                            lifetime_ms: None,
                            stale_slack_ms: None,
                        },
                    )
                    .unwrap();
                (poller, target, id)
            })
            .collect();

        // NDNSF service requests are always > 800 B (wrapped CP-ABE key + ciphertext + names).
        ndn_app::rt::sleep(Duration::from_secs(1) - Duration::from_millis(TELEMETRY_MS / 6)).await;
        requester.put(vec![0x5a; 1024]).await.expect("put");
        let mut svs_reached = Vec::new();
        for (name, sub, _app) in &mut subscribers {
            if let Ok(Some(_)) = tokio::time::timeout(Duration::from_secs(10), sub.recv()).await {
                svs_reached.push(*name);
            }
        }

        ndn_app::rt::sleep((measure_from + RUN).saturating_duration_since(fabric.clock().now()))
            .await;

        let run = FleetRun {
            telemetry: telemetry_apps
                .iter()
                .map(|(name, id)| (*name, fabric.flow_stats(*id).unwrap()))
                .collect(),
            video: fabric.flow_stats(video_app).unwrap(),
            svs_reached,
            swarm: swarm_apps
                .iter()
                .map(|(poller, target, id)| (*poller, *target, fabric.flow_stats(*id).unwrap()))
                .collect(),
            cs_hits: cs_hits(&fabric) - hits_before,
            lp: lp_totals(&fabric, &[&[gcs][..], &airframes].concat()),
        };
        cancel.cancel();
        fabric.shutdown().await;
        run
    })
}

/// One fleet run shared by every assertion below (they read different gauges of the same run).
static FLEET: LazyLock<FleetRun> = LazyLock::new(run_fleet);

fn expected_samples(interval_ms: u64) -> f64 {
    RUN.as_millis() as f64 / interval_ms as f64
}

/// Telemetry keeps the publish rate at every poller — the GCS and each airframe polling a peer —
/// every sample is fresh, and no stream stalls for more than 2 s: the fleet's flight-readiness
/// bar (Round 14: 3.25-3.33/s, zero gaps > 2 s, after the stale-cache fix; 1.18-2.87/s with
/// 5-10 s gaps before it).
#[test]
fn telemetry_keeps_the_publish_rate_fresh_and_gap_free() {
    let run = &*FLEET;
    let expected = expected_samples(TELEMETRY_MS);
    let gcs = run
        .telemetry
        .iter()
        .map(|(publisher, s)| (format!("gcs <- {publisher}"), s));
    let swarm = run
        .swarm
        .iter()
        .map(|(poller, publisher, s)| (format!("{poller} <- {publisher}"), s));
    for (name, s) in gcs.chain(swarm) {
        let rate = s.new_versions() as f64 / RUN.as_secs_f64();
        assert!(
            s.new_versions() as f64 >= 0.9 * expected,
            "{name} telemetry: {rate:.2} new samples/s, publish rate {:.2}/s ({s:?})",
            1000.0 / TELEMETRY_MS as f64
        );
        assert_eq!(
            s.stale, 0,
            "{name} telemetry: MustBeFresh answered with stale samples ({s:?})"
        );
        assert!(
            s.max_gap_ms() <= 2000.0,
            "{name} telemetry: {:.0} ms without a new sample ({s:?})",
            s.max_gap_ms()
        );
    }
}

/// A ~1 KB SVS service request from the GCS reaches every airframe. Fails if `/muas` is not
/// multicast on every node (sync then reaches one peer: every NDNSF call timed out on the fleet).
#[test]
fn svs_service_request_reaches_every_peer() {
    assert_eq!(FLEET.svs_reached, AIRFRAMES.to_vec());
}

/// Caches answer the swarm's telemetry polls. When an airframe polls a peer, that peer's latest
/// sample crossed the poller moments earlier on the GCS's multicast poll and is still fresh, so
/// the poll is a Content Store hit: the fleet's `cs/info` hits (summed) cover every swarm poll.
/// Round 14's stale-cache bug (CanBePrefix answered from ONE arbitrary descendant, which
/// MustBeFresh then rejected) left caches answering ~1/N of such polls — the fleet counted 87
/// hits, 1015 after the fix — and every miss is an Interest re-flooded across the cell.
#[test]
fn caches_answer_the_swarms_telemetry_polls() {
    let polls: u64 = FLEET.swarm.iter().map(|(_, _, s)| s.sent).sum();
    assert!(
        FLEET.cs_hits >= polls,
        "{} Content Store hits fleet-wide against {polls} swarm telemetry polls",
        FLEET.cs_hits
    );
}

/// ~8 KB Data (6 LP fragments each) keeps flowing across the lossy cell: LP reliability repairs
/// lost fragments instead of the whole sample dying (the fleet's 76% IP-reassembly failure mode).
#[test]
fn video_sized_data_survives_the_lossy_cell() {
    let s = &FLEET.video;
    assert!(
        s.new_versions() as f64 >= 0.8 * expected_samples(VIDEO_MS),
        "video: {} of ~{:.0} samples ({s:?})",
        s.new_versions(),
        expected_samples(VIDEO_MS)
    );
    assert_eq!(s.stale, 0, "video: stale samples ({s:?})");
}

/// NDNLPv2 recovery stays efficient: few retransmissions are spurious (the receiver already had
/// the frame) and almost nothing is given up on.
#[test]
fn lp_recovery_is_not_spurious() {
    let lp = FLEET.lp;
    assert!(
        lp.retransmitted > 0,
        "a 5%-loss cell must exercise LP recovery ({lp:?})"
    );
    assert!(
        lp.spurious_ratio() <= 0.25,
        "{:.0}% of LP retransmissions were duplicates at the receiver ({lp:?})",
        lp.spurious_ratio() * 100.0
    );
    assert!(
        lp.gave_up * 100 <= lp.retransmitted,
        "LP gave up on {} frames against {} retransmissions ({lp:?})",
        lp.gave_up,
        lp.retransmitted
    );
}

/// The same seed replays the same fleet run, counter for counter.
#[test]
fn the_fleet_run_is_deterministic() {
    assert_eq!(run_fleet(), *FLEET);
}

/// The Interest nonce a UDP payload carries, if it is (the first fragment of) an Interest. A
/// Nack carries its Interest too, but is not a forwarded copy of it.
fn interest_nonce(payload: &Bytes) -> Option<u32> {
    let packet = if ndn_packet::lp::is_lp_packet(payload) {
        let lp = ndn_packet::lp::LpPacket::decode(payload.clone()).ok()?;
        if lp.nack.is_some() || lp.frag_index.unwrap_or(0) != 0 {
            return None;
        }
        lp.fragment?
    } else {
        payload.clone()
    };
    ndn_packet::Interest::decode(packet).ok()?.nonce()
}

/// Round 15 (`nfd-divergence-findings.md`): each configured peer face bound an ephemeral port, so
/// its datagrams reached the neighbour from a source no face there matched, and the neighbour's
/// listener minted a second face for it. A neighbour split across two faces survives
/// `nexthops_excluding(in_face)`: every node sent each `/muas` Interest back to the node it came
/// from, 12 wire copies per Interest on this 4-node mesh against NFD's 9. Checked the way it was
/// found, following each nonce through a packet capture: Interests no one answers, so every node
/// floods each one (as the fleet's `/muas` sync Interests do), on a quiet lossless LAN where
/// arrival order is the order each forwarder handles a nonce in. And checked the way Round 16
/// verified the fix, on the face table: one UDP face per peer.
#[test]
fn interests_never_return_to_the_node_they_came_from() {
    const PROBES: u64 = 20;
    let scenario = Scenario::from_toml_file(&fixtures().join("scenario.toml")).unwrap();
    let (hops, faces) = VirtualKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
        let fabric = scenario
            .build(k)
            .unwrap()
            .with_peer_link(FaceProfile::udp())
            .start()
            .await
            .unwrap();
        fabric.start_udp_capture();
        // iuas-02 (.13) originated the Interests Round 15's capture followed.
        fabric
            .spawn_app(
                node(&fabric, "iuas-02"),
                AppSpec::Consumer {
                    prefix: "/muas/v2/probe".into(),
                    count: PROBES,
                    interval_ms: 50,
                    lifetime_ms: Some(100),
                },
            )
            .unwrap();
        ndn_app::rt::sleep(Duration::from_secs(4)).await;
        let capture = fabric.take_udp_capture();

        // Every nonce's hops `(from, to)`, in arrival order.
        let mut hops: BTreeMap<u32, Vec<(IpAddr, IpAddr)>> = BTreeMap::new();
        for d in &capture {
            if let Some(nonce) = interest_nonce(&d.payload) {
                hops.entry(nonce)
                    .or_default()
                    .push((d.src.ip(), d.dst.ip()));
            }
        }
        // Each node's UDP faces per peer address, read off the engine's face table.
        let mut faces: BTreeMap<String, BTreeMap<IpAddr, usize>> = BTreeMap::new();
        for n in fabric.topology().nodes {
            let per_peer = faces.entry(n.label).or_default();
            for f in fabric.engine_of(n.id).unwrap().faces().face_info() {
                let peer = f
                    .remote_uri
                    .as_deref()
                    .and_then(|u| u.strip_prefix("udp4://"))
                    .and_then(|a| a.parse::<SocketAddr>().ok());
                if let Some(peer) = peer {
                    *per_peer.entry(peer.ip()).or_default() += 1;
                }
            }
        }
        fabric.shutdown().await;
        (hops, faces)
    });

    let copies: Vec<usize> = hops.values().map(Vec::len).collect();
    let copies = format!(
        "{} Interests, wire copies each: mean {:.2}, max {}",
        copies.len(),
        copies.iter().sum::<usize>() as f64 / copies.len().max(1) as f64,
        copies.iter().max().unwrap_or(&0)
    );
    assert_eq!(
        hops.len() as u64,
        PROBES,
        "every probe must cross the mesh ({copies})"
    );
    for (nonce, hops) in &hops {
        // Where each node first received this nonce from.
        let mut came_from: HashMap<IpAddr, IpAddr> = HashMap::new();
        for &(from, to) in hops {
            assert_ne!(
                came_from.get(&from),
                Some(&to),
                "{from} sent Interest {nonce:08x} back to {to}, the node it came from \
                 ({copies}; this one: {hops:?})"
            );
            came_from.entry(to).or_insert(from);
        }
    }
    for (label, per_peer) in &faces {
        assert!(
            per_peer.len() == 3 && per_peer.values().all(|&n| n == 1),
            "{label}: UDP faces per peer {per_peer:?}, want exactly one for each of 3 peers ({copies})"
        );
    }
}
