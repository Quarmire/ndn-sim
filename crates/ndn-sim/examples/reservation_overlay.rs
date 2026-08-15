//! **The reservation overlay** — the temporal-access controller, validated over the real `RadioBus`.
//!
//! Not a binary engage/disengage switch (the wrong structure); a per-name choice of RESERVE vs
//! CONTEND, running simultaneously — a named PRMA / Reservation-ALOHA. Latency-class content reserves
//! its slot (protected); bulk content contends for idle/unreserved slots (immediate at low load).
//! Three disciplines compared across offered load, then the coexistence gradient (foreign nodes that
//! ignore the schedule):
//!
//!   • contention — every node fires immediately when its own carrier-sense says clear (CSMA).
//!   • tdma       — every node waits for its owned slot (collision-free, wastes idle slots, high latency).
//!   • overlay    — latency reserves; bulk contends for idle unreserved slots. The proposed design.
//!
//! Hidden terminals are real: the receiver hears all, but transmitters only carrier-sense neighbours
//! within `HEAR_R`, so out-of-range pairs collide (the case slotting exists to fix). Metrics are
//! per-class delivery and p99 access latency, over the real PHY + collision model.
//!
//! `cargo run --example reservation_overlay --release -p ndn-sim`. Writes CSV + JSON.

use std::sync::Arc;

use bytes::Bytes;
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::CarrierSenseInterference;
use ndn_sim::radio::RadioBus;
use ndn_sim::{FreeSpacePathLoss, ImmediateRuntime, NodeId, Position, World};

const N: usize = 12; // transmitters (nodes 1..=N); receiver is node 0
const SUPERFRAMES: u64 = 400;
const SEEDS: u64 = 24;
const MCS: u8 = 5;
const PAYLOAD: usize = 60;
const RESIDUAL_NS: i64 = 7_000; // the shared-reference clock we validated
const GUARD_NS: u64 = 10_000;
const HEAR_R: f64 = 34.0; // transmitter mutual carrier-sense range (< field ⇒ hidden terminals)
const FIELD: f64 = 45.0;

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

#[derive(Clone, Copy, PartialEq)]
enum Arm {
    Contention,
    Tdma,
    Overlay,
}

/// Per-class (latency, bulk) results.
struct Res {
    off: [u64; 2],
    del: [u64; 2],
    lat: [Vec<u64>; 2], // access latency of delivered packets, ns
}

fn run(arm: Arm, load: f64, frac_lat: f64, frac_foreign: f64, seed: u64) -> Res {
    let mut rng = seed | 1;
    let world = Arc::new(World::new());
    world.place(NodeId(0), Position::xy(0.0, 0.0));
    // transmitters scattered in a disc → some mutually hidden.
    let mut pos = vec![(0.0f64, 0.0f64); N + 1];
    for i in 1..=N {
        let (mut x, mut y);
        loop {
            x = (xs(&mut rng) as f64 / u64::MAX as f64 - 0.5) * 2.0 * FIELD;
            y = (xs(&mut rng) as f64 / u64::MAX as f64 - 0.5) * 2.0 * FIELD;
            if x * x + y * y <= FIELD * FIELD {
                break;
            }
        }
        pos[i] = (x, y);
        world.place(NodeId(i), Position::xy(x, y));
    }
    let hears = |a: usize, b: usize| ((pos[a].0 - pos[b].0).hypot(pos[a].1 - pos[b].1)) <= HEAR_R;

    let bus = RadioBus::with_interference_on(
        world.clone(),
        Arc::new(FreeSpacePathLoss::default()),
        0,
        seed,
        Arc::new(CarrierSenseInterference),
        Arc::new(ImmediateRuntime),
    );
    let _rx = bus.attach(NodeId(0));

    let air = airtime_ns();
    let slot = air + GUARD_NS;
    let sf = N as u64 * slot; // superframe

    // node classes/roles: first frac_lat are latency; a frac_foreign share ignore the schedule.
    let is_lat: Vec<bool> = (1..=N).map(|i| (i as f64) <= frac_lat * N as f64).collect();
    let is_foreign: Vec<bool> = (1..=N).map(|_| (xs(&mut rng) as f64 / u64::MAX as f64) < frac_foreign).collect();

    let mut backlog: Vec<Option<u64>> = vec![None; N + 1]; // arrival SUPERFRAME index of the queued packet
    let mut r = Res { off: [0; 2], del: [0; 2], lat: [Vec::new(), Vec::new()] };

    for f in 0..SUPERFRAMES {
        let base = f * sf;
        // arrivals (one-deep queue; new arrivals while backlogged are dropped).
        for i in 1..=N {
            if (xs(&mut rng) as f64 / u64::MAX as f64) < load && backlog[i].is_none() {
                let cls = if is_lat[i - 1] { 0 } else { 1 };
                r.off[cls] += 1;
                backlog[i] = Some(f);
            }
        }
        // reserved slots this superframe = latency nodes with a packet, in their owned slot.
        let mut reserved = vec![false; N];
        if arm == Arm::Overlay {
            for i in 1..=N {
                if backlog[i].is_some() && is_lat[i - 1] && !is_foreign[i - 1] {
                    reserved[(i - 1) % N] = true;
                }
            }
        }
        // overlay: CCLF distributes cooperative bulk across DISTINCT earliest idle unreserved slots
        // (the claimable-slot mechanism working) — low latency without bulk-bulk collisions.
        let mut bulk_slot: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
        if arm == Arm::Overlay {
            let mut assigned = reserved.clone();
            let mut cand: Vec<usize> =
                (1..=N).filter(|&i| backlog[i].is_some() && !is_lat[i - 1] && !is_foreign[i - 1]).collect();
            cand.sort_by_key(|&i| std::cmp::Reverse(f - backlog[i].unwrap())); // oldest packet first
            for i in cand {
                for s in 0..N {
                    if !assigned[s] {
                        assigned[s] = true;
                        bulk_slot.insert(i, s as u64);
                        break;
                    }
                }
            }
        }
        // choose a send time for each node with a packet.
        let mut sends: Vec<(usize, u64)> = Vec::new();
        for i in 1..=N {
            let Some(arr) = backlog[i] else { continue };
            let owned = ((i - 1) % N) as u64;
            let age = (f - arr).min(6);
            let t = if is_foreign[i - 1] {
                // foreign: immediate CSMA with backoff, ignores the schedule entirely.
                let cw = (air * (1u64 << age)).min(sf);
                base + xs(&mut rng) % cw.max(1)
            } else {
                match arm {
                    // CSMA/CA: transmit ASAP within a contention window that grows with retries.
                    Arm::Contention => {
                        let cw = (air * (1u64 << age)).min(sf);
                        base + xs(&mut rng) % cw.max(1)
                    }
                    Arm::Tdma => (base as i64 + (owned * slot) as i64 + RESIDUAL_NS).max(0) as u64,
                    Arm::Overlay => {
                        if is_lat[i - 1] {
                            // reserve the owned slot — protected, bounded latency.
                            (base as i64 + (owned * slot) as i64 + RESIDUAL_NS).max(0) as u64
                        } else {
                            // bulk: the CCLF-assigned distinct idle slot (low latency at low load).
                            let s = *bulk_slot.get(&i).unwrap_or(&owned);
                            let jit = (xs(&mut rng) % (GUARD_NS / 2 + 1)) as i64;
                            (base as i64 + (s * slot) as i64 + RESIDUAL_NS + jit).max(0) as u64
                        }
                    }
                }
            };
            let _ = arr;
            sends.push((i, t));
        }
        // carrier sense: a cooperative node defers (skips) if it HEARS an earlier overlapping tx.
        sends.sort_by_key(|&(_, t)| t);
        let mut kept: Vec<(usize, u64)> = Vec::new();
        for &(i, t) in &sends {
            let defer = !is_foreign[i - 1]
                && arm != Arm::Tdma
                && kept.iter().any(|&(j, tj)| hears(i, j) && tj <= t && t < tj + air);
            if !defer {
                kept.push((i, t));
            }
        }
        // transmit over the real bus.
        for &(i, t) in &kept {
            let rx = bus.transmit(NodeId(i), MCS, Bytes::from(vec![0u8; PAYLOAD]), t);
            if rx.iter().any(|(to, _, ok)| *to == NodeId(0) && *ok) {
                if let Some(arr) = backlog[i].take() {
                    let cls = if is_lat[i - 1] { 0 } else { 1 };
                    r.del[cls] += 1;
                    r.lat[cls].push((t + air).saturating_sub(arr * sf)); // arr is a superframe index
                }
            }
        }
    }
    r
}

fn agg(arm: Arm, load: f64, frac_lat: f64, frac_foreign: f64) -> (f64, f64, f64, f64) {
    // returns (lat_delivery, lat_p99_us, bulk_delivery, bulk_p99_us)
    let (mut o, mut d) = ([0u64; 2], [0u64; 2]);
    let mut lat: [Vec<u64>; 2] = [Vec::new(), Vec::new()];
    for s in 0..SEEDS {
        let r = run(arm, load, frac_lat, frac_foreign, (s << 3) | 1);
        for c in 0..2 {
            o[c] += r.off[c];
            d[c] += r.del[c];
            lat[c].extend(&r.lat[c]);
        }
    }
    let p99 = |v: &mut Vec<u64>| {
        v.sort_unstable();
        if v.is_empty() { 0.0 } else { v[(v.len() * 99 / 100).min(v.len() - 1)] as f64 / 1e3 }
    };
    (
        d[0] as f64 / o[0].max(1) as f64,
        p99(&mut lat[0]),
        d[1] as f64 / o[1].max(1) as f64,
        p99(&mut lat[1]),
    )
}

fn main() {
    use std::io::Write;
    let dir = "docs/data/reservation-overlay";
    let _ = std::fs::create_dir_all(dir);
    let mut csv = std::fs::File::create(format!("{dir}/overlay.csv")).unwrap();
    writeln!(csv, "sweep,arm,x,lat_delivery,lat_p99_us,bulk_delivery,bulk_p99_us").unwrap();

    println!("Reservation overlay over the real RadioBus ({N} tx, hidden terminals, tight clock 7µs).\n");

    // Sweep 1: offered load, 50/50 class mix, no foreign.
    println!("SWEEP 1 — offered load (50% latency / 50% bulk, all cooperative)");
    println!("{:<24}{:>26}{:>26}", "", "LATENCY class", "BULK class");
    println!("{:<12}{:>12}{:>13}{:>13}{:>13}{:>13}", "load", "arm", "delivery", "p99 µs", "delivery", "p99 µs");
    for &load in &[0.1f64, 0.3, 0.6, 0.9] {
        for (nm, arm) in [("contention", Arm::Contention), ("tdma", Arm::Tdma), ("overlay", Arm::Overlay)] {
            let (ld, lp, bd, bp) = agg(arm, load, 0.5, 0.0);
            println!("{:<12}{:>12}{:>12.0}%{:>12.0}{:>12.0}%{:>12.0}", format!("{load:.1}"), nm, ld * 100.0, lp, bd * 100.0, bp);
            writeln!(csv, "load,{nm},{load},{ld:.4},{lp:.0},{bd:.4},{bp:.0}").ok();
        }
        println!("  ─");
    }

    // Sweep 2: coexistence — fraction of foreign nodes (ignore the schedule), at load 0.6.
    println!("\nSWEEP 2 — coexistence: fraction FOREIGN (ignore the schedule), overlay, load 0.6, 50% latency");
    println!("{:<14}{:>14}{:>14}{:>16}{:>14}", "foreign %", "lat delivery", "lat p99 µs", "bulk delivery", "bulk p99 µs");
    for &ff in &[0.0f64, 0.1, 0.25, 0.5] {
        let (ld, lp, bd, bp) = agg(Arm::Overlay, 0.6, 0.5, ff);
        println!("{:<14}{:>13.0}%{:>14.0}{:>15.0}%{:>14.0}", format!("{:.0}", ff * 100.0), ld * 100.0, lp, bd * 100.0, bp);
        writeln!(csv, "foreign,overlay,{ff},{ld:.4},{lp:.0},{bd:.4},{bp:.0}").ok();
    }

    println!("\nSWEEP 1: overlay should track contention's low latency at low load AND protect the latency");
    println!("  class like tdma at high load — dominating both. SWEEP 2: latency degradation vs foreign share");
    println!("  is the honest coexistence cost (self-announcing reservations + CCA bound it, SIC would too).");
    eprintln!("{{\"experiment\":\"reservation_overlay\"}}");
    println!("wrote {dir}/overlay.csv");
}
