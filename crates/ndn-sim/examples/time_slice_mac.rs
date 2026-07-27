//! Time-slice MAC over a common-view clock — the low-latency, collision-free access that named-time
//! unlocks (the offset-free scalable replacement for carrier-sense / the LoRa pairwise offset).
//!
//! N nodes share one broadcast channel and each sends one frame per TDMA frame to a common receiver.
//! The whole point turns on ONE physical ratio: **slot width is set by the frame's airtime, and the
//! clock only helps if its residual error fits inside the guard.** On the Wi-Fi named-data radio a
//! short frame is on air for only microseconds, so the slots are microseconds and the guard is a
//! fraction of that — which a *software* clock (millisecond residual) cannot hold, but a hardware
//! TSF common-view clock (sub-microsecond, task #41) can. Everything below is scaled to the medium's
//! own measured airtime, not to invented millisecond constants.
//!
//! Four disciplines, delivery = fraction of the N per-frame frames that arrive uncollided (seed-avg):
//!   • contention             — each node fires at an uncoordinated random instant → collisions.
//!   • slotted · TSF clock     — node i in slot i, residual = guard/4 (sub-µs, hardware TSF) → clean.
//!   • slotted · software clock — same slots, residual ≈ 100× airtime (ms, NTP/software) → spills.
//!   • slotted · perfect clock — zero residual, the collision-free ceiling for comparison.
//!
//! Takeaway: on a µs-airtime radio, time-slotting is only collision-free with a µs-class clock. This
//! is precisely why the named-radio doctrine wants hardware TSF common-view, not a software TSF —
//! and why the ms-scale named-time `Timekeeper` (tests/named_time_convergence.rs) is enough for
//! LoRa/HaLow (ms airtime) but not for the Wi-Fi face. The clock's *precision* sets the floor on
//! how tightly you can pack the channel.
//!
//! Run: `cargo run -p ndn-sim --example time_slice_mac`

use std::sync::Arc;

use bytes::Bytes;
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::CarrierSenseInterference;
use ndn_sim::radio::RadioBus;
use ndn_sim::{FreeSpacePathLoss, NodeId, Position, World};

const N: u64 = 6; // contending transmitters (nodes 1..=N); receiver is node 0
const FRAMES: u64 = 25;
const SEEDS: u64 = 24;
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

/// Returns (delivered, attempted) summed over all frames of one trial.
fn trial(mode: &Mode, seed: u64) -> (u32, u32) {
    // Star: receiver at origin, N transmitters on a tight ring — all mutually in range, all heard by
    // the receiver at high SNR, so PHY erasure is ~0 and COLLISIONS are what move the number. The
    // ring is sub-metre so the tx→rx propagation delay rounds to zero, keeping the bus's delivery
    // path fully synchronous (no per-frame timer spawn) — this is a batch Monte-Carlo over the real
    // PHY + collision model, not an event-driven run, so the medium's timing is not what we measure.
    // Coarse grid cell: all nodes cluster in <1 m, so one big cell keeps the bus's range query at
    // O(27 cells) instead of scanning ~(max_range/100 m)³ ≈ 59k empty cells per transmit.
    let world = Arc::new(World::new().with_grid_cell(5000.0));
    world.place(NodeId(0), Position::xy(0.0, 0.0));
    for i in 1..=N {
        let ang = i as f64 * std::f64::consts::TAU / N as f64;
        world.place(NodeId(i as usize), Position::xy(0.05 * ang.cos(), 0.05 * ang.sin()));
    }
    let bus = RadioBus::with_interference(
        world.clone(),
        Arc::new(FreeSpacePathLoss::default()),
        0,
        seed,
        Arc::new(CarrierSenseInterference),
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

    let (mut delivered, mut attempted) = (0u32, 0u32);
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
            attempted += 1;
            let rx = bus.transmit(node, MCS, Bytes::from(vec![0u8; PAYLOAD]), t);
            if rx.iter().any(|(to, _, ok)| *to == NodeId(0) && *ok) {
                delivered += 1;
            }
        }
    }
    (delivered, attempted)
}

fn run(mode: &Mode) -> f64 {
    let (mut d, mut a) = (0u64, 0u64);
    for s in 0..SEEDS {
        let (dd, aa) = trial(mode, (s << 1) | 1);
        d += dd as u64;
        a += aa as u64;
    }
    d as f64 / a as f64
}

fn main() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let air = airtime_ns();
        let guard = air;
        println!("time-slice MAC over a common-view clock — {N} transmitters → 1 receiver, {SEEDS} seeds");
        println!(
            "frame airtime = {:.1} µs (MCS{MCS}, {PAYLOAD} B)  →  slot = {:.1} µs, guard = {:.1} µs\n",
            air as f64 / 1e3,
            (air + guard) as f64 / 1e3,
            guard as f64 / 1e3
        );

        let contention = run(&Mode::Contention);
        let tsf = run(&Mode::Slotted { residual_ns: guard / 4 }); // sub-µs hardware TSF
        let software = run(&Mode::Slotted { residual_ns: air * 100 }); // ms-class software clock
        let perfect = run(&Mode::Slotted { residual_ns: 0 });

        println!("discipline                          clock residual      delivery");
        println!("  contention (uncoordinated)              —              {:5.0}%", contention * 100.0);
        println!("  slotted · software clock          ±{:>6.1} µs   (ms)    {:5.0}%   ← residual ≫ slot → collisions", (air * 100) as f64 / 1e3, software * 100.0);
        println!("  slotted · hardware TSF            ±{:>6.2} µs (sub-µs)   {:5.0}%   ← residual < guard → clean", (guard / 4) as f64 / 1e3, tsf * 100.0);
        println!("  slotted · perfect clock            0.00 µs             {:5.0}%   ← collision-free ceiling", perfect * 100.0);
        println!(
            "\ntakeaway: on a {:.0}-µs-airtime radio, slotting only pays off with a µs-class clock.",
            air as f64 / 1e3
        );
        println!("that is the case for hardware TSF common-view (task #41), not a software TSF.");
    });
}
