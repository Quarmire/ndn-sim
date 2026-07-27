//! Energy consumption over the named-data radio — the pluggable [`EnergyModel`] in action.
//!
//! A shared broadcast channel with mixed roles, all in range: 3 producers each emit their prefix's
//! frames, 1 relay retransmits all of them (its "declared contribution"), and a sink + a leaf
//! consumer only listen. The bus charges TX energy to each sender and RX energy to *every in-range
//! radio* per frame — the "listen to everything" cost. We report per-node joules (TX / RX / idle /
//! total) and system energy-per-delivered-bit, and two doctrine numbers fall straight out:
//!
//!   • §4 — the cooperation-vs-power dial: the relay (which forwards for others) burns the most; a
//!     leaf that relays nothing is cheapest on the active axis. Contribution IS power.
//!   • §3.1 — the monitor-mode listen tax: every node pays RX energy for *every* frame on the
//!     channel, even ones for names it does not want. We compute the counterfactual a hardware
//!     name-group filter buys the leaf — it only wakes for its one wanted prefix — as the RX-energy
//!     saving, quantifying "the tax is a monitor-mode artifact, not the architecture."
//!
//! The model is pluggable ([`RadioEnergyModel`] here); swap it for a LoRa/HaLow front-end's numbers
//! without touching the bus.
//!
//! Run: `cargo run -p ndn-sim --example energy_sim`

use std::sync::Arc;

use bytes::Bytes;
use ndn_sim::energy::RadioEnergyModel;
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::CarrierSenseInterference;
use ndn_sim::radio::RadioBus;
use ndn_sim::{EnergyModel, FreeSpacePathLoss, ImmediateRuntime, NodeId, Position, World};

const PRODUCERS: u64 = 3;
const RELAY: u64 = 4;
const SINK: u64 = 0;
const LEAF: u64 = 5;
const N: u64 = 6; // nodes 0..=5
const ROUNDS: u64 = 200;
const MCS: u8 = 5;
const PAYLOAD: usize = 200;
const SEEDS: u64 = 12;
const UTILIZATION: f64 = 0.5; // channel duty cycle → frame spacing

fn airtime_ns() -> u64 {
    (PAYLOAD as u64) * 8 * 1_000_000_000 / (mcs_phy_rate_bps(MCS).max(1) as u64)
}

fn main() {
    let air = airtime_ns();
    let spacing = (air as f64 / UTILIZATION) as u64; // non-overlapping → no collisions confound energy
    let model = RadioEnergyModel::default();
    let idle_w = model.idle_power_w();

    // Frames per round: each producer once + the relay retransmits all producers.
    let frames_per_round = PRODUCERS + PRODUCERS; // producers + relay's retransmissions
    let total_frames = ROUNDS * frames_per_round;
    let duration_s = (total_frames * spacing) as f64 / 1e9;

    // Energy is deterministic (airtime-based, independent of the erasure draw); delivered bits are
    // not, so we seed-average the delivery to get energy-per-DELIVERED-bit honestly.
    let mut acct = ndn_sim::EnergyAccounts::new();
    let mut delivered_frames = 0u64;
    for s in 0..SEEDS {
        let world = Arc::new(World::new());
        world.place(NodeId(SINK as usize), Position::xy(0.0, 0.0));
        for i in 1..N {
            let ang = i as f64 * std::f64::consts::TAU / (N - 1) as f64;
            world.place(NodeId(i as usize), Position::xy(30.0 * ang.cos(), 30.0 * ang.sin()));
        }
        let bus = RadioBus::with_interference_on(
            world.clone(),
            Arc::new(FreeSpacePathLoss::default()),
            0,
            (s << 1) | 1,
            Arc::new(CarrierSenseInterference),
            Arc::new(ImmediateRuntime),
        );
        bus.set_energy_model(Arc::new(model));
        let _rx = bus.attach(NodeId(SINK as usize)); // count deliveries at the sink

        let mut t = 0u64;
        let send = |bus: &RadioBus, node: u64, t: u64| -> bool {
            let rx = bus.transmit(NodeId(node as usize), MCS, Bytes::from(vec![0u8; PAYLOAD]), t);
            rx.iter().any(|(to, _, ok)| *to == NodeId(SINK as usize) && *ok)
        };
        for _ in 0..ROUNDS {
            for p in 1..=PRODUCERS {
                if send(&bus, p, t) {
                    delivered_frames += 1;
                }
                t += spacing;
            }
            // The relay retransmits each producer's frame — its cooperative contribution.
            for _ in 1..=PRODUCERS {
                send(&bus, RELAY, t);
                t += spacing;
            }
        }
        // Energy is identical every seed; capture it once.
        if s == 0 {
            acct = bus.energy_accounts();
        }
    }

    let role = |n: u64| match n {
        SINK => "sink   (listen only)",
        RELAY => "relay  (forwards all)",
        LEAF => "leaf   (listen only)",
        _ => "producer",
    };
    let idle_j = idle_w * duration_s;

    println!("energy over the named-data radio — {N} nodes, {ROUNDS} rounds, {PAYLOAD} B @ MCS{MCS}");
    println!(
        "  duration {:.1} ms, channel ~{:.0}% utilized, idle {:.2} W → {:.1} mJ/node of listen\n",
        duration_s * 1e3,
        UTILIZATION * 100.0,
        idle_w,
        idle_j * 1e3
    );
    println!("node  role                    TX mJ    RX mJ   idle mJ   total mJ");
    let mut totals = (0.0, 0.0);
    for n in 0..N {
        let a = acct.get(&NodeId(n as usize)).copied().unwrap_or_default();
        let total = a.total_j(idle_w, duration_s);
        println!(
            "  {n}   {:<22}  {:6.2}   {:6.2}   {:6.2}    {:6.2}",
            role(n),
            a.tx_j * 1e3,
            a.rx_j * 1e3,
            idle_j * 1e3,
            total * 1e3
        );
        totals.0 += a.active_j();
        totals.1 += total;
    }

    // System energy-per-delivered-bit (active energy; idle is a standing cost, not per-bit).
    let delivered_bits = (delivered_frames / SEEDS.max(1)) as f64 * PAYLOAD as f64 * 8.0;
    let sys_total = totals.1;
    println!(
        "\nsystem: {:.1} mJ total ({:.1} mJ active), {:.0} delivered bits/seed → {:.2} µJ per delivered bit",
        sys_total * 1e3,
        totals.0 * 1e3,
        delivered_bits,
        if delivered_bits > 0.0 { sys_total / delivered_bits * 1e6 } else { 0.0 }
    );

    // §4 power dial: the relay's active energy vs a pure listener's.
    let relay_active = acct.get(&NodeId(RELAY as usize)).map(|a| a.active_j()).unwrap_or(0.0);
    let leaf_active = acct.get(&NodeId(LEAF as usize)).map(|a| a.active_j()).unwrap_or(0.0);
    println!(
        "\n§4 cooperation-vs-power: the relay burns {:.1}× the active energy of a pure-listen leaf\n         ({:.2} mJ vs {:.2} mJ) — forwarding for others IS the power cost.",
        if leaf_active > 0.0 { relay_active / leaf_active } else { f64::INFINITY },
        relay_active * 1e3,
        leaf_active * 1e3
    );

    // §3.1 listen tax: the leaf pays RX for every frame; a hardware name-group filter wakes it only
    // for its one wanted prefix (say producer 1 of the 4 senders → 1/4 of the traffic it processes).
    let leaf = acct.get(&NodeId(LEAF as usize)).copied().unwrap_or_default();
    let wanted_fraction = 1.0 / (PRODUCERS + 1) as f64; // 1 wanted sender out of 3 producers + relay
    let filtered_rx = leaf.rx_j * wanted_fraction;
    println!(
        "§3.1 listen tax: leaf RX {:.2} mJ processing EVERY frame; a hardware name-filter (wants 1 of\n         {} senders) would wake it for {:.0}% → {:.2} mJ, a {:.0}% RX-energy cut. The tax is a\n         monitor-mode artifact, not the architecture.",
        leaf.rx_j * 1e3,
        PRODUCERS + 1,
        wanted_fraction * 100.0,
        filtered_rx * 1e3,
        (1.0 - wanted_fraction) * 100.0
    );
}
