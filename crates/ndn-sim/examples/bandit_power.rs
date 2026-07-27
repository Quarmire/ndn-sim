//! Can a learning policy beat a fixed one by turning the TX-power dial? — the contextual bandit
//! (`ndn_radio_cognition::ContextualBandit`, real code) against a fixed-max-power baseline, over the
//! now-live power dial (`RadioBus::set_tx_power` feeds both propagation *and* energy).
//!
//! Each round the bandit picks an arm (rate × power × FEC) for the link's context, applies it with
//! the real `apply_arm`, transmits at the resulting power, and learns from the real `reward` — which
//! penalizes airtime + a **power footprint**, so trimming power is rewarded *only when it still
//! delivers*. The baseline always transmits at max power and the baseline rate.
//!
//! Expected, and the point: on a STRONG link the bandit learns to back power off (arm 3, −6 dB) —
//! same delivery, less TX energy; on a MARGINAL link, backing off misses, the miss penalty teaches
//! it to keep power, matching the baseline. A fixed policy cannot make that call. The tail prints the
//! bandit's learned per-arm UCB scores (`select_traced`) — the decision-observability surface.
//!
//! Run: `cargo run -p ndn-sim --example bandit_power`

use std::sync::Arc;

use bytes::Bytes;
use ndn_radio_cognition::{ARMS, Context, ContextualBandit, TxParams, WifiRate, apply_arm, reward};
use ndn_sim::energy::RadioEnergyModel;
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::CarrierSenseInterference;
use ndn_sim::radio::RadioBus;
use ndn_sim::{FreeSpacePathLoss, ImmediateRuntime, NodeId, Position, World};

const SINK: usize = 0;
const TX: usize = 1;
const BASE_MCS: u8 = 5;
const MAX_MCS: u8 = 7;
const MAX_POWER_IDX: u8 = 63; // the bandit's power axis: 63 = full power, 0.5 dB/index
const MAX_DBM: f64 = 20.0;
const PAYLOAD: usize = 200;
const ROUNDS: u64 = 2000;

fn dbm_of(power_idx: u8) -> f64 {
    MAX_DBM - (MAX_POWER_IDX as i32 - power_idx as i32) as f64 * 0.5 // DB_PER_POWER_IDX = 0.5
}

fn base_params() -> TxParams {
    let mut p = TxParams::wifi(WifiRate { mcs: Some(BASE_MCS), bw: Some(2), nss: Some(1), ..Default::default() });
    p.tx_power = Some(MAX_POWER_IDX);
    p
}

fn airtime_ns() -> u64 {
    (PAYLOAD as u64) * 8 * 1_000_000_000 / (mcs_phy_rate_bps(BASE_MCS).max(1) as u64)
}

fn new_bus(dist: f64, seed: u64) -> (Arc<RadioBus>, u64) {
    let world = Arc::new(World::new());
    world.place(NodeId(SINK), Position::xy(0.0, 0.0));
    world.place(NodeId(TX), Position::xy(dist, 0.0));
    let bus = RadioBus::with_interference_on(
        world.clone(),
        Arc::new(FreeSpacePathLoss::default()),
        0,
        seed,
        Arc::new(CarrierSenseInterference),
        Arc::new(ImmediateRuntime),
    );
    bus.set_energy_model(Arc::new(RadioEnergyModel::default()));
    // Register the sink so it appears in transmit's return (the map owns the sender; the receiver
    // half can drop — we read the synchronous verdict, not the channel).
    let _ = bus.attach(NodeId(SINK));
    (bus, airtime_ns())
}

/// Returns (delivery_fraction, tx_energy_j, mean_dbm, delivered_bits).
struct Run {
    delivery: f64,
    tx_j: f64,
    mean_dbm: f64,
    delivered_bits: f64,
}

fn run_baseline(dist: f64) -> Run {
    let (bus, air) = new_bus(dist, 1);
    let (mut delivered, mut dbm_sum) = (0u64, 0.0);
    for r in 0..ROUNDS {
        bus.set_tx_power(NodeId(TX), MAX_DBM);
        dbm_sum += MAX_DBM;
        let rx = bus.transmit(NodeId(TX), BASE_MCS, Bytes::from(vec![0u8; PAYLOAD]), r * air * 2);
        if rx.iter().any(|(to, _, ok)| *to == NodeId(SINK) && *ok) {
            delivered += 1;
        }
    }
    let tx_j = bus.energy_accounts().get(&NodeId(TX)).map(|a| a.tx_j).unwrap_or(0.0);
    Run {
        delivery: delivered as f64 / ROUNDS as f64,
        tx_j,
        mean_dbm: dbm_sum / ROUNDS as f64,
        delivered_bits: delivered as f64 * PAYLOAD as f64 * 8.0,
    }
}

fn run_bandit(dist: f64) -> (Run, ContextualBandit, Context) {
    let (bus, air) = new_bus(dist, 1);
    let mut bandit = ContextualBandit::new(1.0);

    // Probe the link once (max power) to fix the context the bandit keys on.
    bus.set_tx_power(NodeId(TX), MAX_DBM);
    let probe = bus.transmit(NodeId(TX), BASE_MCS, Bytes::from(vec![0u8; PAYLOAD]), 0);
    let rssi = probe.iter().find(|(to, _, _)| *to == NodeId(SINK)).map(|(_, r, _)| *r).unwrap_or(-95.0);
    let ctx = Context::new(rssi.round() as i8, 0, 1, 1);

    let (mut delivered, mut dbm_sum) = (0u64, 0.0);
    for r in 1..=ROUNDS {
        let arm = bandit.select(&ctx);
        let mut p = base_params();
        apply_arm(&ARMS[arm], &mut p, MAX_MCS, MAX_POWER_IDX);
        let mcs = p.mcs().unwrap_or(BASE_MCS);
        let dbm = dbm_of(p.tx_power.unwrap_or(MAX_POWER_IDX));
        dbm_sum += dbm;
        bus.set_tx_power(NodeId(TX), dbm);
        let rx = bus.transmit(NodeId(TX), mcs, Bytes::from(vec![0u8; PAYLOAD]), r * air * 2);
        let ok = rx.iter().any(|(to, _, d)| *to == NodeId(SINK) && *d);
        if ok {
            delivered += 1;
        }
        bandit.update(&ctx, arm, reward(ok, &p, MAX_POWER_IDX));
    }
    let tx_j = bus.energy_accounts().get(&NodeId(TX)).map(|a| a.tx_j).unwrap_or(0.0);
    let run = Run {
        delivery: delivered as f64 / ROUNDS as f64,
        tx_j,
        mean_dbm: dbm_sum / ROUNDS as f64,
        delivered_bits: delivered as f64 * PAYLOAD as f64 * 8.0,
    };
    (run, bandit, ctx)
}

fn main() {
    println!("contextual bandit vs fixed-max-power baseline — the TX-power dial, {ROUNDS} rounds/link");
    println!("(reward = airtime + power footprint, miss heavily penalized; power feeds RSSI AND energy)\n");
    println!("link       policy      delivery   mean TX   TX energy   TX µJ/bit");
    for (label, dist) in [("strong (40 m)", 40.0), ("mid (400 m)", 400.0), ("weak (700 m)", 700.0)] {
        let b = run_baseline(dist);
        let (g, bandit, ctx) = run_bandit(dist);
        let ppb = |run: &Run| if run.delivered_bits > 0.0 { run.tx_j / run.delivered_bits * 1e6 } else { f64::NAN };
        println!(
            "{label:<14} baseline    {:5.0}%    {:5.1} dBm   {:6.2} mJ   {:6.3}",
            b.delivery * 100.0, b.mean_dbm, b.tx_j * 1e3, ppb(&b)
        );
        println!(
            "{:<14} bandit      {:5.0}%    {:5.1} dBm   {:6.2} mJ   {:6.3}   learned best arm {}",
            "", g.delivery * 100.0, g.mean_dbm, g.tx_j * 1e3, ppb(&g),
            bandit.best(&ctx).unwrap_or(0)
        );
        // Decision observability: the learned per-arm UCB scores for this link's context.
        let choice = bandit.select_traced(&ctx);
        let scores: Vec<String> = choice.scores.iter().map(|s| {
            if s.is_infinite() { "  ∞  ".into() } else { format!("{s:5.2}") }
        }).collect();
        println!("               ↳ arm UCB [base,rate−,rate+,pwr−6dB,fec+]: [{}]\n", scores.join(", "));
    }
    println!("arms: 0 baseline · 1 lower rate · 2 higher rate · 3 trim power −6 dB · 4 FEC not rate");
}
