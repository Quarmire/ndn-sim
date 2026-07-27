//! Time-slice MAC over a common-view clock — the low-latency, collision-free access that named-time
//! unlocks (the offset-free scalable replacement for carrier-sense / the LoRa pairwise offset).
//!
//! N nodes share one broadcast channel and each sends one frame per TDMA superframe to a common
//! receiver. The whole point turns on ONE physical ratio: **slot width is set by the frame's
//! airtime, and the clock only helps if its residual error fits inside the guard.** On the Wi-Fi
//! named-data radio a short frame is on air for only microseconds, so the slots are microseconds and
//! the guard is a fraction of that — which a *software* clock (millisecond residual) cannot hold, but
//! a hardware TSF common-view clock (sub-microsecond, task #41) can. Everything below is scaled to
//! the medium's own measured airtime, not to invented millisecond constants.
//!
//! Metrics per discipline (seed-averaged over the REAL RadioBus PHY + collision model):
//!   • delivery   — fraction of the N per-superframe frames that arrive uncollided.
//!   • goodput    — delivered payload bits per second of channel time (aggregate).
//!   • access latency — superframe-start → successful transmission, mean and p99. The TDMA payoff
//!     is a BOUNDED tail; contention and a coarse clock have long p99 tails.
//!
//! Four disciplines:
//!   • contention             — each node fires at an uncoordinated random instant → collisions.
//!   • slotted · software clock — slots, residual ≈ 100× airtime (ms, NTP/software) → spills.
//!   • slotted · hardware TSF   — slots, residual = guard/4 (sub-µs) → collision-free.
//!   • slotted · perfect clock  — zero residual, the ceiling for comparison.
//!
//! Takeaway: on a µs-airtime radio, time-slotting is only collision-free with a µs-class clock. That
//! is why the named-radio doctrine wants hardware TSF common-view (task #41), not a software TSF, and
//! why the ms-scale named-time `Timekeeper` (tests/named_time_convergence.rs) suffices for LoRa/HaLow
//! (ms airtime) but not the Wi-Fi face. Clock precision sets the floor on how tightly you can pack
//! the channel.
//!
//! Run: `cargo run -p ndn-sim --example time_slice_mac`

use std::sync::Arc;

use bytes::Bytes;
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::CarrierSenseInterference;
use ndn_sim::radio::RadioBus;
use ndn_sim::{FreeSpacePathLoss, ImmediateRuntime, NodeId, Position, World};

const N: u64 = 6; // contending transmitters (nodes 1..=N); receiver is node 0
const FRAMES: u64 = 40;
const SEEDS: u64 = 40;
const MCS: u8 = 5;
const PAYLOAD: usize = 60;

fn xs(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}

/// The frame's on-air window on this PHY — the physical width every slot must contain.
fn airtime_ns() -> u64 {
    (PAYLOAD as u64) * 8 * 1_000_000_000 / (mcs_phy_rate_bps(MCS).max(1) as u64)
}

enum Mode {
    Contention,
    /// Slotted; `residual_ns` = the clock's ± error vs the common view (its precision).
    Slotted { residual_ns: u64 },
}

struct Trial {
    delivered: u32,
    attempted: u32,
    /// Access latency (superframe-start → successful TX) of each DELIVERED frame, ns.
    latencies: Vec<u64>,
}

fn trial(mode: &Mode, seed: u64) -> Trial {
    // Star: receiver at origin, N transmitters on a 30 m ring — all mutually in range, all heard by
    // the receiver at high SNR, so PHY erasure is ~0 and COLLISIONS are what move the number. Default
    // grid cell + realistic distances (the O(min(box, occupied)) range query scales fine now), and an
    // ImmediateRuntime so the bus's delayed delivery is a synchronous inline send — a batch
    // Monte-Carlo over the real PHY + collision model, with no per-frame timer and no geometry hack.
    let world = Arc::new(World::new());
    world.place(NodeId(0), Position::xy(0.0, 0.0));
    for i in 1..=N {
        let ang = i as f64 * std::f64::consts::TAU / N as f64;
        world.place(NodeId(i as usize), Position::xy(30.0 * ang.cos(), 30.0 * ang.sin()));
    }
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
    let guard = air; // a full-airtime guard between slots
    let slot = air + guard; // one slot holds one frame + its guard
    let frame_ns = N * slot; // the TDMA superframe

    let mut rng = seed | 1;
    // Each node's fixed clock residual (drawn once — its standing offset from the common view).
    let clocks: Vec<i64> = (0..=N)
        .map(|_| match mode {
            Mode::Contention => 0,
            Mode::Slotted { residual_ns } if *residual_ns == 0 => 0,
            Mode::Slotted { residual_ns } => {
                (xs(&mut rng) % (2 * *residual_ns + 1)) as i64 - *residual_ns as i64
            }
        })
        .collect();

    let mut out = Trial { delivered: 0, attempted: 0, latencies: Vec::new() };
    for f in 0..FRAMES {
        let base = f * frame_ns;
        let mut sends: Vec<(NodeId, u64)> = (1..=N)
            .map(|i| {
                let t = match mode {
                    Mode::Contention => base + (xs(&mut rng) % frame_ns),
                    Mode::Slotted { .. } => {
                        (base as i64 + ((i - 1) * slot) as i64 + clocks[i as usize]).max(0) as u64
                    }
                };
                (NodeId(i as usize), t)
            })
            .collect();
        // Transmit in time order so the collision model sees concurrency correctly.
        sends.sort_by_key(|(_, t)| *t);
        for (node, t) in sends {
            out.attempted += 1;
            let rx = bus.transmit(node, MCS, Bytes::from(vec![0u8; PAYLOAD]), t);
            if rx.iter().any(|(to, _, ok)| *to == NodeId(0) && *ok) {
                out.delivered += 1;
                out.latencies.push(t.saturating_sub(base) + air); // access delay + own airtime
            }
        }
    }
    out
}

/// (delivery, goodput_bps, mean_latency_ns, p99_latency_ns)
fn run(mode: &Mode) -> (f64, f64, f64, u64) {
    let frame_ns = N * (2 * airtime_ns());
    let (mut d, mut a) = (0u64, 0u64);
    let mut lat: Vec<u64> = Vec::new();
    for s in 0..SEEDS {
        let t = trial(mode, (s << 1) | 1);
        d += t.delivered as u64;
        a += t.attempted as u64;
        lat.extend(t.latencies);
    }
    let delivery = d as f64 / a as f64;
    // Aggregate goodput: delivered payload bits over the total channel time simulated per seed-avg.
    let bits = d as f64 * PAYLOAD as f64 * 8.0;
    let secs = SEEDS as f64 * FRAMES as f64 * frame_ns as f64 / 1e9;
    let goodput = bits / secs;
    lat.sort_unstable();
    let mean = if lat.is_empty() { 0.0 } else { lat.iter().sum::<u64>() as f64 / lat.len() as f64 };
    let p99 = if lat.is_empty() { 0 } else { lat[(lat.len() * 99 / 100).min(lat.len() - 1)] };
    (delivery, goodput, mean, p99)
}

fn main() {
    let air = airtime_ns();
    let guard = air;
    println!("time-slice MAC over a common-view clock — {N} transmitters → 1 receiver, {SEEDS} seeds");
    println!(
        "frame airtime = {:.1} µs (MCS{MCS}, {PAYLOAD} B)  →  slot = {:.1} µs, guard = {:.1} µs\n",
        air as f64 / 1e3,
        (air + guard) as f64 / 1e3,
        guard as f64 / 1e3
    );

    let modes: [(&str, &str, Mode); 4] = [
        ("contention (uncoordinated)", "     —      ", Mode::Contention),
        ("slotted · software clock", "±923 µs (ms)", Mode::Slotted { residual_ns: air * 100 }),
        ("slotted · hardware TSF", "±2.3 µs(sub)", Mode::Slotted { residual_ns: guard / 4 }),
        ("slotted · perfect clock", "  0.0 µs    ", Mode::Slotted { residual_ns: 0 }),
    ];

    println!("discipline                    clock resid   delivery   goodput    lat mean   lat p99");
    for (label, resid, mode) in &modes {
        let (delivery, goodput, mean, p99) = run(mode);
        println!(
            "  {label:<27} {resid}   {:5.0}%   {:6.1} Mb/s   {:6.1} µs   {:6.1} µs",
            delivery * 100.0,
            goodput / 1e6,
            mean / 1e3,
            p99 as f64 / 1e3
        );
    }
    println!(
        "\ntakeaway: on a {:.0}-µs-airtime radio, slotting is collision-free + bounded-latency ONLY",
        air as f64 / 1e3
    );
    println!("with a µs-class clock — hardware TSF common-view (task #41), not a software TSF.");
    println!("a coarse (ms) clock makes slotting WORSE than uncoordinated contention.");
}
