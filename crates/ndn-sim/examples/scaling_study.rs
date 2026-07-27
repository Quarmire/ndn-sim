//! Network-size scaling — how the named-data broadcast radio behaves from 3 to ~90 nodes. Engineered
//! so the interesting things MOVE: nodes packed in range (collision-limited, not SNR-limited) doing
//! uncoordinated (Aloha-style) random access, so offered load rises with N and contention bites.
//!
//! Per node count (seed-averaged over the real RadioBus + collision model + energy model):
//!   • offered load G — total airtime demanded ÷ window (rises with N).
//!   • channel throughput S — successful (uncollided) airtime ÷ window: the classic rise-then-collapse.
//!   • delivery fraction — of frame×receiver pairs (falls as collisions grow).
//!   • collision fraction — transmits lost to a concurrent in-range sender.
//!   • host energy, promiscuous vs name-filtered — the §3.1 story as a CURVE: a promiscuous host
//!     processes every neighbour's frames (∝ N), a name-filtered host wakes only for its one
//!     subscription (~flat). The gap is the whole argument for the hardware filter, and it widens with N.
//!   • energy per delivered bit — rises as contention wastes transmissions.
//!
//! Run: `cargo run -p ndn-sim --example scaling_study > /tmp/scaling.json`

use std::sync::Arc;

use bytes::Bytes;
use ndn_sim::energy::RadioEnergyModel;
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::CarrierSenseInterference;
use ndn_sim::radio::RadioBus;
use ndn_sim::{
    EnergyModel, FreeSpacePathLoss, ImmediateRuntime, NodeId, Position, World,
};

const SIZES: [u64; 10] = [3, 5, 8, 12, 18, 27, 40, 60, 80, 100];
const MCS: u8 = 5;
const PAYLOAD: usize = 200;
const FRAMES_PER_NODE: u64 = 24;
const WINDOW_NS: u64 = 4_000_000; // 4 ms access window (fixed → offered load rises with N)
const SEEDS: u64 = 8;
const RADIUS_M: f64 = 40.0; // tight disc: all mutually in range, high SNR → loss is COLLISIONS

fn xs(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}

fn airtime_ns() -> u64 {
    (PAYLOAD as u64) * 8 * 1_000_000_000 / (mcs_phy_rate_bps(MCS).max(1) as u64)
}

struct Row {
    n: u64,
    offered: f64,
    throughput: f64,
    delivery: f64,
    collision: f64,
    host_promisc_mj: f64,
    host_filtered_mj: f64,
    uj_per_bit: f64,
}

fn run_size(n: u64) -> Row {
    let air = airtime_ns();
    let model = RadioEnergyModel::default();
    let host_cost = model.host_process_energy_j(PAYLOAD);

    let (mut deliv, mut att, mut succ_tx, mut coll_tx, mut tx_total) = (0u64, 0u64, 0u64, 0u64, 0u64);
    let mut host_promisc_sum = 0.0;
    let mut delivered_bits = 0.0;
    let mut active_energy = 0.0;

    for seed in 0..SEEDS {
        let mut rng = (seed << 1) | 1;
        let world = Arc::new(World::new());
        // Deterministic pseudo-random placement in a disc of radius RADIUS_M (all mutually in range).
        for i in 0..n {
            let ang = (xs(&mut rng) as f64 / u64::MAX as f64) * std::f64::consts::TAU;
            let r = RADIUS_M * (xs(&mut rng) as f64 / u64::MAX as f64).sqrt();
            world.place(NodeId(i as usize), Position::xy(r * ang.cos(), r * ang.sin()));
        }
        let bus = RadioBus::with_interference_on(
            world.clone(),
            Arc::new(FreeSpacePathLoss::default()),
            0,
            seed | 1,
            Arc::new(CarrierSenseInterference),
            Arc::new(ImmediateRuntime),
        );
        bus.set_energy_model(Arc::new(model));
        for i in 0..n {
            let _ = bus.attach(NodeId(i as usize));
        }

        // Every node schedules FRAMES_PER_NODE transmits at uniformly random instants (Aloha).
        let mut sends: Vec<(u64, u64)> = Vec::new(); // (time, node)
        for i in 0..n {
            for _ in 0..FRAMES_PER_NODE {
                sends.push((xs(&mut rng) % WINDOW_NS, i));
            }
        }
        sends.sort_by_key(|(t, _)| *t);

        for (t, node) in sends {
            tx_total += 1;
            let rx = bus.transmit(NodeId(node as usize), MCS, Bytes::from(vec![0u8; PAYLOAD]), t);
            let mut any_ok = false;
            for (_, _, ok) in &rx {
                att += 1;
                if *ok {
                    deliv += 1;
                    any_ok = true;
                    delivered_bits += PAYLOAD as f64 * 8.0;
                }
            }
            if any_ok {
                succ_tx += 1;
            } else if !rx.is_empty() {
                coll_tx += 1;
            }
        }

        // Promiscuous host energy per node (frames each node processed × host cost) — from the model.
        let acct = bus.energy_accounts();
        for i in 0..n {
            let a = acct.get(&NodeId(i as usize)).copied().unwrap_or_default();
            host_promisc_sum += a.host_j;
            active_energy += a.tx_j + a.rx_j + a.host_j;
        }
    }

    let seeds = SEEDS as f64;
    let nodes = n as f64;
    let window_s = WINDOW_NS as f64 / 1e9;
    // Offered load G = total airtime demanded ÷ window (per seed).
    let offered = (nodes * FRAMES_PER_NODE as f64 * air as f64) / WINDOW_NS as f64;
    // Throughput S = successful airtime ÷ window.
    let throughput = (succ_tx as f64 / seeds) * air as f64 / WINDOW_NS as f64;
    let delivery = if att > 0 { deliv as f64 / att as f64 } else { 0.0 };
    let collision = if tx_total > 0 { coll_tx as f64 / tx_total as f64 } else { 0.0 };
    // Host energy per node (mJ): promiscuous from the run; filtered = one subscription's frames.
    let host_promisc_mj = host_promisc_sum / (seeds * nodes) * 1e3;
    let host_filtered_mj = FRAMES_PER_NODE as f64 * host_cost * 1e3; // wakes only for its 1 producer
    let uj_per_bit = if delivered_bits > 0.0 { active_energy / delivered_bits * 1e6 } else { 0.0 };
    let _ = window_s;

    Row { n, offered, throughput, delivery, collision, host_promisc_mj, host_filtered_mj, uj_per_bit }
}

fn main() {
    let rows: Vec<Row> = SIZES.iter().map(|&n| run_size(n)).collect();

    // Human-readable table to stderr; JSON to stdout.
    eprintln!("N     G(offer)  S(thru)  delivery  collision  host∅(mJ)  hostF(mJ)  µJ/bit");
    for r in &rows {
        eprintln!(
            "{:>3}   {:7.2}  {:6.3}   {:5.0}%    {:5.0}%    {:7.2}   {:7.2}   {:6.2}",
            r.n, r.offered, r.throughput, r.delivery * 100.0, r.collision * 100.0,
            r.host_promisc_mj, r.host_filtered_mj, r.uj_per_bit
        );
    }

    let mut j = String::from("{\"sizes\":[");
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            j.push(',');
        }
        j.push_str(&format!(
            "{{\"n\":{},\"offered\":{:.3},\"throughput\":{:.4},\"delivery\":{:.4},\"collision\":{:.4},\"host_promisc\":{:.4},\"host_filtered\":{:.4},\"uj_per_bit\":{:.3}}}",
            r.n, r.offered, r.throughput, r.delivery, r.collision, r.host_promisc_mj, r.host_filtered_mj, r.uj_per_bit
        ));
    }
    j.push_str("]}");
    println!("{j}");
}
