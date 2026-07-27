//! Energy consumption over the named-data radio — the pluggable [`EnergyModel`] in action, including
//! the **host** CPU cost and the **MAC-offload** validation the doctrine (§3.1) turns on.
//!
//! A shared broadcast channel, all in range: `producers` each emit their prefix's frames, a relay
//! retransmits all of them (its "declared contribution"), and a sink + leaf only listen. The bus
//! charges TX energy to the sender, RX radio energy to every in-range radio, and **host CPU energy**
//! to every host the frame *reaches* — every host under monitor mode, or only name-group matches when
//! a hardware filter is installed. Three results:
//!
//!   Part 1 — per-node joules (TX / RX / host / idle): the §4 cooperation-vs-power dial (the relay
//!            burns most; a pure listener least on the active axis).
//!   Part 2 — MAC offload A/B: the leaf's host energy, promiscuous vs a hardware name-filter that
//!            wakes it only for its one wanted prefix. Host CPU is the dominant, offloadable cost.
//!   Part 3 — the crux of §3.1: as ambient traffic the leaf does NOT want grows, promiscuous host
//!            energy scales with it while filtered host energy stays ~flat — "the tax is a
//!            monitor-mode artifact, not the architecture."
//!
//! Run: `cargo run -p ndn-sim --example energy_sim`

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use ndn_sim::energy::RadioEnergyModel;
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::CarrierSenseInterference;
use ndn_sim::radio::RadioBus;
use ndn_sim::{
    EnergyAccount, EnergyAccounts, EnergyModel, FreeSpacePathLoss, ImmediateRuntime, NodeId,
    Position, World,
};

const SINK: u64 = 0;
const RELAY: u64 = 1;
const LEAF: u64 = 2;
const FIRST_PRODUCER: u64 = 3; // producers are nodes 3..3+P
const WANTED_GROUP: u64 = FIRST_PRODUCER; // the leaf wants producer 3's prefix
const ROUNDS: u64 = 200;
const MCS: u8 = 5;
const PAYLOAD: usize = 200;
const UTILIZATION: f64 = 0.5;

fn airtime_ns() -> u64 {
    (PAYLOAD as u64) * 8 * 1_000_000_000 / (mcs_phy_rate_bps(MCS).max(1) as u64)
}

/// Run the scenario with `producers` senders. `filtered` installs a hardware name-filter so the leaf
/// wakes only for `WANTED_GROUP`. Returns (accounts, run duration seconds).
fn scenario(filtered: bool, producers: u64) -> (EnergyAccounts, f64) {
    let air = airtime_ns();
    let spacing = (air as f64 / UTILIZATION) as u64;
    let n = FIRST_PRODUCER + producers; // 0..n

    let world = Arc::new(World::new());
    world.place(NodeId(SINK as usize), Position::xy(0.0, 0.0));
    for i in 1..n {
        let ang = i as f64 * std::f64::consts::TAU / (n - 1) as f64;
        world.place(NodeId(i as usize), Position::xy(30.0 * ang.cos(), 30.0 * ang.sin()));
    }
    let bus = RadioBus::with_interference_on(
        world.clone(),
        Arc::new(FreeSpacePathLoss::default()),
        0,
        1,
        Arc::new(CarrierSenseInterference),
        Arc::new(ImmediateRuntime),
    );
    bus.set_energy_model(Arc::new(RadioEnergyModel::default()));
    if filtered {
        // The leaf's radio hardware-filters to its one wanted group; everyone else stays promiscuous.
        let mut f = HashMap::new();
        f.insert(NodeId(LEAF as usize), WANTED_GROUP);
        bus.set_host_filter(f);
    }

    let mut t = 0u64;
    let mut frames = 0u64;
    for _ in 0..ROUNDS {
        for p in FIRST_PRODUCER..FIRST_PRODUCER + producers {
            // Each producer's frame carries its own name-group (= its node id).
            bus.transmit_named(NodeId(p as usize), MCS, p, Bytes::from(vec![0u8; PAYLOAD]), t);
            t += spacing;
            frames += 1;
            // The relay retransmits it under the same group (its cooperative contribution).
            bus.transmit_named(NodeId(RELAY as usize), MCS, p, Bytes::from(vec![0u8; PAYLOAD]), t);
            t += spacing;
            frames += 1;
        }
    }
    (bus.energy_accounts(), (frames * spacing) as f64 / 1e9)
}

fn leaf(acct: &EnergyAccounts) -> EnergyAccount {
    acct.get(&NodeId(LEAF as usize)).copied().unwrap_or_default()
}

fn main() {
    let model = RadioEnergyModel::default();
    let idle_w = model.idle_power_w();
    let producers = 3;

    // ---- Part 1: per-node breakdown (promiscuous) ------------------------------------------------
    let (acct, dur) = scenario(false, producers);
    let idle_j = idle_w * dur;
    println!("energy over the named-data radio — {} senders + relay, {ROUNDS} rounds, {PAYLOAD} B @ MCS{MCS}", producers);
    println!("  duration {:.1} ms, idle {:.2} W → {:.1} mJ/node\n", dur * 1e3, idle_w, idle_j * 1e3);
    let role = |n: u64| match n {
        SINK => "sink   (listen only)",
        RELAY => "relay  (forwards all)",
        LEAF => "leaf   (listen only)",
        _ => "producer",
    };
    println!("node  role                    TX mJ    RX mJ   host mJ   idle mJ   total mJ");
    for n in 0..FIRST_PRODUCER + producers {
        let a = acct.get(&NodeId(n as usize)).copied().unwrap_or_default();
        println!(
            "  {n}   {:<22} {:6.2}   {:6.2}   {:7.2}   {:6.2}   {:7.2}",
            role(n),
            a.tx_j * 1e3,
            a.rx_j * 1e3,
            a.host_j * 1e3,
            idle_j * 1e3,
            a.total_j(idle_w, dur) * 1e3
        );
    }
    let relay_tx = acct.get(&NodeId(RELAY as usize)).map(|a| a.tx_j).unwrap_or(0.0);
    println!(
        "\n§4 cooperation-vs-power: the relay spends {:.2} mJ TRANSMITTING (forwarding for others);",
        relay_tx * 1e3
    );
    println!("   a leaf transmits nothing. And host-processing cost is set by filter WIDTH — a relay");
    println!("   that carries many groups pays host energy for each; a narrow leaf pays for one (Parts 2–3).");

    // ---- Part 2: MAC offload A/B on the leaf's host ---------------------------------------------
    let (acct_f, _) = scenario(true, producers);
    let host_promisc = leaf(&acct).host_j;
    let host_filtered = leaf(&acct_f).host_j;
    println!(
        "\n§3.1 MAC offload — leaf host CPU energy over {} senders:",
        producers
    );
    println!(
        "   monitor (process every frame):   {:.2} mJ  ({} frames to host)",
        host_promisc * 1e3,
        leaf(&acct).frames_to_host
    );
    println!(
        "   hardware name-filter (1 wanted): {:.2} mJ  ({} frames to host)  → {:.0}% cut",
        host_filtered * 1e3,
        leaf(&acct_f).frames_to_host,
        (1.0 - host_filtered / host_promisc.max(1e-12)) * 100.0
    );

    // ---- Part 3: ambient-invariance (the crux) --------------------------------------------------
    println!("\n§3.1 the crux — leaf host energy vs AMBIENT traffic it does not want:");
    println!("   senders   monitor host mJ   filtered host mJ");
    for p in [3u64, 6, 12] {
        let (a_prom, _) = scenario(false, p);
        let (a_filt, _) = scenario(true, p);
        println!(
            "   {p:>5}      {:>10.2}       {:>10.2}",
            leaf(&a_prom).host_j * 1e3,
            leaf(&a_filt).host_j * 1e3
        );
    }
    println!("   monitor scales with ambient; the name-filter stays flat — the tax is a monitor-mode");
    println!("   artifact (the radio drops non-matching frames before the CPU wakes), not the architecture.");
}
