//! Cognitive-radio scenario in the sim: cognitive NDN nodes over a shared `RadioBus`, with an
//! optional co-band interferer and a listen-before-talk toggle — the sim reproduction of the
//! hardware N=3 LBT / co-band experiment the blocked radios owe us (task #57 increments 2-3).
//!
//! Each node runs the REAL `RadioPolicy` via `SimCognition`: it hears RSSI off the bus, decides its
//! transmit MCS per named object, and takes turns (half-duplex offset) sending Interest→Data. We
//! measure per-node Data delivered + PER across three conditions:
//!   1. baseline (no interferer)
//!   2. co-band interferer, LBT off
//!   3. co-band interferer, LBT on
//! and expect LBT to help ONLY when the channel is genuinely collision-limited (the on-air lesson).
//!
//! Run: `cargo run -p ndn-sim --example cognitive_radio_sim`

use std::sync::Arc;

use bytes::Bytes;
use ndn_radio_cognition::{Priority, RadioCapability, RadioId};
use ndn_sim::cognition::SimCognition;
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::CarrierSenseInterference;
use ndn_sim::radio::RadioBus;
use ndn_sim::{FreeSpacePathLoss, NodeId, Position, World};

/// Airtime (ns) the bus will charge for a frame of `bytes` at `mcs` — the SAME formula RadioBus uses,
/// so our sensing window and the bus's collision window agree.
fn bus_airtime_ns(mcs: u8, bytes: usize) -> u64 {
    (bytes as u64) * 8 * 1_000_000_000 / (mcs_phy_rate_bps(mcs).max(1) as u64)
}

const MAX_MCS: u8 = 7;
const PAYLOAD: usize = 40;
const TICK_NS: u64 = 200_000_000; // 200 ms per round
const ROUNDS: u64 = 60;

fn fnv1a64(s: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in s {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// One traffic class → (name, priority).
const CLASSES: &[(&str, Priority)] = &[
    ("alarm", Priority::Urgent),
    ("telemetry", Priority::Normal),
    ("bulk", Priority::Bulk),
];

struct Node {
    id: NodeId,
    cog: SimCognition,
    name: &'static str,
    /// pairwise half-duplex offset (in ticks) so the two ends take turns.
    offset: u64,
    delivered: u32,
    sent: u32,
}

fn airtime_ms(mcs: u8, bytes: usize) -> f32 {
    // crude: higher mcs = faster; enough to drive the duty budget + contention window.
    let rate_kbps = 5.0 * (mcs as f32 + 1.0);
    (bytes as f32 * 8.0) / rate_kbps
}

/// Per-round telemetry sample (the observability time-series the dashboard renders).
struct Rec {
    round: u64,
    a_deliv: u32,
    b_deliv: u32,
    a_mcs: i16, // -1 = LBT-deferred this round
    b_mcs: i16,
    deferrals: u32, // cumulative LBT backoff deferrals this condition
}

fn main() {
    // The RadioBus delivery timing rides ndn_runtime (tokio), so run inside a runtime context.
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async { real_main() });
}

fn real_main() {
    println!("=== cognitive-radio sim: N=2 nodes + co-band interferer, LBT off vs on ===\n");
    let conditions = [
        ("baseline (clean channel)", false, false),
        ("co-band interferer, LBT off", true, false),
        ("co-band interferer, LBT on", true, true),
    ];
    let mut json = String::from("{\"rounds\":");
    json.push_str(&ROUNDS.to_string());
    json.push_str(",\"conditions\":[");
    for (ci, (label, interferer, lbt)) in conditions.iter().enumerate() {
        let (a_del, a_sent, b_del, b_sent, recs) = run(*interferer, *lbt);
        let per = |d: u32, s: u32| if s == 0 { 1.0 } else { 1.0 - d as f32 / s as f32 };
        println!(
            "{}. {label}\n   A: {a_del}/{a_sent} delivered (PER {:.2})   B: {b_del}/{b_sent} delivered (PER {:.2})\n",
            ci + 1,
            per(a_del, a_sent),
            per(b_del, b_sent),
        );
        if ci > 0 {
            json.push(',');
        }
        json.push_str(&format!(
            "{{\"label\":\"{label}\",\"interferer\":{interferer},\"lbt\":{lbt},\"a_total\":{a_del},\"b_total\":{b_del},\"samples\":["
        ));
        for (ri, r) in recs.iter().enumerate() {
            if ri > 0 {
                json.push(',');
            }
            json.push_str(&format!(
                "{{\"r\":{},\"ad\":{},\"bd\":{},\"am\":{},\"bm\":{},\"def\":{}}}",
                r.round, r.a_deliv, r.b_deliv, r.a_mcs, r.b_mcs, r.deferrals
            ));
        }
        json.push_str("]}");
    }
    json.push_str("]}");
    // Telemetry time-series for the dashboard (examples/cognitive_radio_dashboard.html renders it).
    let path = std::env::temp_dir().join("cognitive_radio_telemetry.json");
    if std::fs::write(&path, &json).is_ok() {
        println!("telemetry → {} ({} bytes)", path.display(), json.len());
    }
}

/// Returns (A delivered, A sent, B delivered, B sent, per-round telemetry).
fn run(interferer: bool, lbt: bool) -> (u32, u32, u32, u32, Vec<Rec>) {
    // Static positions — track locally so we don't need a WorldView snapshot for LBT sensing.
    let posof = |id: NodeId| -> Position {
        match id.0 {
            0 => Position::xy(0.0, 0.0),  // A
            1 => Position::xy(5.0, 0.0),  // B
            _ => Position::xy(2.5, 2.0),  // co-band interferer, between them
        }
    };
    let world = Arc::new(World::new());
    world.place(NodeId(0), posof(NodeId(0)));
    world.place(NodeId(1), posof(NodeId(1)));
    if interferer {
        world.place(NodeId(9), posof(NodeId(9)));
    }
    // Collision model ON: concurrent in-range transmitters collide (hidden-terminal), so an
    // overlapping interferer actually costs delivery.
    let bus = RadioBus::with_interference(
        world.clone(),
        Arc::new(FreeSpacePathLoss::default()),
        0,
        7,
        Arc::new(CarrierSenseInterference),
    );
    // Attach nodes so the bus delivers to them (hold the RX handles alive for the run).
    let _rx = [bus.attach(NodeId(0)), bus.attach(NodeId(1))];

    let cap = || RadioCapability::lora(vec![65]);
    let mut nodes = [
        Node { id: NodeId(0), cog: SimCognition::new(RadioId(0), cap(), MAX_MCS), name: "A", offset: 0, delivered: 0, sent: 0 },
        Node { id: NodeId(1), cog: SimCognition::new(RadioId(0), cap(), MAX_MCS), name: "B", offset: 1, delivered: 0, sent: 0 },
    ];

    // Channel occupancy windows (start_ns, end_ns, who) for the carrier-sense decision.
    let mut in_air: Vec<(u64, u64, NodeId)> = Vec::new();

    // Is the channel sensed busy at `t` from `my_pos` (any OTHER in-range transmitter mid-frame)?
    let busy_at = |t: u64, me: NodeId, in_air: &[(u64, u64, NodeId)]| -> bool {
        let my_pos = posof(me);
        in_air.iter().any(|(s, e, who)| {
            *who != me
                && *s <= t
                && t < *e
                && bus.link_rssi(posof(*who), my_pos).map(|r| r > -108.0).unwrap_or(false)
        })
    };

    let mut recs: Vec<Rec> = Vec::with_capacity(ROUNDS as usize);
    let mut deferrals = 0u32;
    for round in 0..ROUNDS {
        let rstart = round * TICK_NS;
        let mut mcs_used = [-1i16, -1i16]; // per-node this round; -1 = LBT-deferred
        in_air.retain(|(_, e, _)| *e > rstart); // prune finished
        // Co-band interferer: a burst covering [+20ms, +80ms] of the round — overlaps A's slot,
        // leaves a clear gap after 80ms that a listening node can find.
        if interferer {
            // Size the jam frame so its REAL bus airtime spans ~60ms — long enough to overlap A's
            // 40ms slot (collision) yet leave a clear gap after ~80ms for a listener to find.
            let jam_bytes = (60_000_000u64 * mcs_phy_rate_bps(0).max(1) as u64 / (8 * 1_000_000_000))
                .max(16) as usize;
            let ist = rstart + 20_000_000;
            let iend = ist + bus_airtime_ns(0, jam_bytes);
            in_air.push((ist, iend, NodeId(9)));
            let _ = bus.transmit(NodeId(9), 0, Bytes::from(vec![0u8; jam_bytes]), ist);
        }

        for i in 0..nodes.len() {
            let peer_idx = 1 - i;
            // A's intended slot sits inside the interferer burst (40ms); B's is later (130ms, clear).
            let intended = rstart + if nodes[i].offset == 0 { 40_000_000 } else { 130_000_000 };
            let (class, prio) = CLASSES[(round as usize) % CLASSES.len()];
            let peer_name = nodes[peer_idx].name;
            let obj = format!("ndn/sim/{peer_name}/{class}/{round}");
            let pfx = fnv1a64(obj.as_bytes());
            nodes[i].sent += 1;

            // Listen-before-talk: if the intended instant is busy, back off in 15ms steps to find a
            // clear slot within the round. LBT off → transmit at the intended instant regardless.
            let round_end = rstart + TICK_NS;
            let mut tx_ns = intended;
            if lbt {
                let mut t = intended;
                let mut found = false;
                while t + 10_000_000 < round_end {
                    if !busy_at(t, nodes[i].id, &in_air) {
                        found = true;
                        break;
                    }
                    t += 15_000_000;
                }
                if !found {
                    deferrals += 1;
                    continue; // deferred, no clear slot this round → a failed attempt
                }
                tx_ns = t;
            }

            let mcs = nodes[i].cog.decide_mcs(pfx, prio, tx_ns / 1_000_000).unwrap_or(0);
            mcs_used[i] = mcs as i16;
            let end = tx_ns + (airtime_ms(mcs, PAYLOAD) as u64) * 1_000_000;
            in_air.push((tx_ns, end, nodes[i].id));
            nodes[i].cog.record_tx(airtime_ms(mcs, PAYLOAD), tx_ns / 1_000_000);

            let rx = bus.transmit(nodes[i].id, mcs, Bytes::from(obj.into_bytes()), tx_ns);
            for (to, rssi, ok) in rx {
                if to == nodes[peer_idx].id {
                    nodes[peer_idx].cog.observe(nodes[i].id.0 as u64, rssi, tx_ns / 1_000_000);
                    if ok {
                        nodes[peer_idx].delivered += 1;
                    }
                }
            }
        }
        recs.push(Rec {
            round,
            a_deliv: nodes[0].delivered,
            b_deliv: nodes[1].delivered,
            a_mcs: mcs_used[0],
            b_mcs: mcs_used[1],
            deferrals,
        });
    }
    (nodes[0].delivered, nodes[0].sent, nodes[1].delivered, nodes[1].sent, recs)
}
