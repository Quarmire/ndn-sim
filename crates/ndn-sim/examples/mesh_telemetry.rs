//! Multi-node mesh telemetry generator — produces the JSON the named-data-radio dashboard renders.
//!
//! A 7-node broadcast mesh (producer → 2 relays → 4 consumers at varied distances) runs over the real
//! RadioBus with the RadioLog, energy model, and a live ContextualBandit on the producer. Every
//! transmission is heard by every in-range node with its own outcome (delivered / erased / collided) —
//! the fan-out the dashboard visualizes. We aggregate the raw log into compact JSON: node positions +
//! roles, per-edge reception stats (the fan-out DAG), a time-binned per-link delivery heatmap, per-node
//! energy, and the bandit's per-round decisions (arm + UCB scores) — decision observability.
//!
//! Run: `cargo run -p ndn-sim --example mesh_telemetry > /tmp/mesh_telemetry.json`

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use ndn_radio_cognition::{ARMS, Context, ContextualBandit, TxParams, WifiRate, apply_arm, reward};
use ndn_sim::energy::RadioEnergyModel;
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::{CarrierSenseInterference, DeliveryReason};
use ndn_sim::radio::RadioBus;
use ndn_sim::{
    EnergyModel, FreeSpacePathLoss, ImmediateRuntime, NodeId, Position, RadioLog, World,
};

const BASE_MCS: u8 = 5;
const MAX_MCS: u8 = 7;
const MAX_POWER_IDX: u8 = 63;
const MAX_DBM: f64 = 20.0;
const PAYLOAD: usize = 220;
const ROUNDS: u64 = 400;
const BINS: usize = 24;
const TARGET: usize = 6; // the far consumer the producer's bandit optimizes for

struct Node {
    id: usize,
    role: &'static str,
    x: f64,
    y: f64,
}

fn nodes() -> Vec<Node> {
    vec![
        Node { id: 0, role: "producer", x: 0.0, y: 0.0 },
        Node { id: 1, role: "relay", x: 200.0, y: 90.0 },
        Node { id: 2, role: "relay", x: 200.0, y: -90.0 },
        Node { id: 3, role: "consumer", x: 380.0, y: 150.0 },
        Node { id: 4, role: "consumer", x: 380.0, y: -150.0 },
        Node { id: 5, role: "consumer", x: 300.0, y: 0.0 },
        Node { id: 6, role: "consumer", x: 560.0, y: 20.0 }, // far — marginal link
    ]
}

fn dbm_of(power_idx: u8) -> f64 {
    MAX_DBM - (MAX_POWER_IDX as i32 - power_idx as i32) as f64 * 0.5
}

fn base_params() -> TxParams {
    let mut p = TxParams::wifi(WifiRate { mcs: Some(BASE_MCS), bw: Some(2), nss: Some(1), ..Default::default() });
    p.tx_power = Some(MAX_POWER_IDX);
    p
}

fn airtime_ns() -> u64 {
    (PAYLOAD as u64) * 8 * 1_000_000_000 / (mcs_phy_rate_bps(BASE_MCS).max(1) as u64)
}

fn main() {
    let ns = nodes();
    let world = Arc::new(World::new());
    for n in &ns {
        world.place(NodeId(n.id), Position::xy(n.x, n.y));
    }
    let bus = RadioBus::with_interference_on(
        world.clone(),
        Arc::new(FreeSpacePathLoss::default()),
        0,
        7,
        Arc::new(CarrierSenseInterference),
        Arc::new(ImmediateRuntime),
    );
    let log = RadioLog::new();
    bus.set_radio_log(log.clone());
    bus.set_energy_model(Arc::new(RadioEnergyModel::default()));
    for n in &ns {
        let _ = bus.attach(NodeId(n.id));
    }

    let air = airtime_ns();
    let mut bandit = ContextualBandit::new(1.0);

    // Probe producer→target to fix the bandit's context.
    bus.set_tx_power(NodeId(0), MAX_DBM);
    let probe = bus.transmit(NodeId(0), BASE_MCS, Bytes::from(vec![0u8; PAYLOAD]), 0);
    let rssi = probe.iter().find(|(to, _, _)| *to == NodeId(TARGET)).map(|(_, r, _)| *r).unwrap_or(-90.0);
    let ctx = Context::new(rssi.round() as i8, 20, 4, 1);

    // Per-round decisions: (arm, delivered_to_target).
    let mut decisions: Vec<(usize, [f32; ARMS.len()], bool)> = Vec::new();
    let mut t = air; // start after the probe

    for _ in 0..ROUNDS {
        // Producer transmits under the bandit's arm.
        let choice = bandit.select_traced(&ctx);
        let arm = choice.arm;
        let mut p = base_params();
        apply_arm(&ARMS[arm], &mut p, MAX_MCS, MAX_POWER_IDX);
        let mcs = p.mcs().unwrap_or(BASE_MCS);
        bus.set_tx_power(NodeId(0), dbm_of(p.tx_power.unwrap_or(MAX_POWER_IDX)));
        let rx = bus.transmit(NodeId(0), mcs, Bytes::from(vec![0u8; PAYLOAD]), t);
        let heard_target = rx.iter().any(|(to, _, ok)| *to == NodeId(TARGET) && *ok);
        bandit.update(&ctx, arm, reward(heard_target, &p, MAX_POWER_IDX));
        decisions.push((arm, choice.scores, heard_target));
        t += air * 2;

        // The two relays rebroadcast at full power/base rate (their cooperative contribution).
        for r in [1u64, 2] {
            bus.set_tx_power(NodeId(r as usize), MAX_DBM);
            bus.transmit(NodeId(r as usize), BASE_MCS, Bytes::from(vec![0u8; PAYLOAD]), t);
            t += air * 2;
        }
    }

    // ---- Aggregate the RadioLog -----------------------------------------------------------------
    let records = log.records();
    let t_min = records.iter().map(|r| r.t_ns).min().unwrap_or(0);
    let t_max = records.iter().map(|r| r.t_ns).max().unwrap_or(1);
    let span = (t_max - t_min).max(1);

    // Per-edge totals + a per-edge time-binned delivery series.
    struct Edge {
        total: u64,
        delivered: u64,
        collided: u64,
        rssi_sum: f64,
        dist: f64,
        bins: [(u32, u32); BINS], // (total, delivered) per bin
    }
    let mut edges: BTreeMap<(usize, usize), Edge> = BTreeMap::new();
    for r in &records {
        let e = edges.entry((r.from.0, r.to.0)).or_insert(Edge {
            total: 0,
            delivered: 0,
            collided: 0,
            rssi_sum: 0.0,
            dist: r.distance_m,
            bins: [(0, 0); BINS],
        });
        e.total += 1;
        e.rssi_sum += r.rssi_dbm;
        if r.delivered {
            e.delivered += 1;
        }
        if matches!(r.reason, DeliveryReason::Collision) {
            e.collided += 1;
        }
        let bin = (((r.t_ns - t_min) as u128 * BINS as u128) / span as u128).min(BINS as u128 - 1) as usize;
        e.bins[bin].0 += 1;
        if r.delivered {
            e.bins[bin].1 += 1;
        }
    }

    // ---- Emit JSON --------------------------------------------------------------------------------
    let mut s = String::from("{\n");
    // nodes
    s.push_str("\"nodes\":[");
    for (i, n) in ns.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!("{{\"id\":{},\"role\":\"{}\",\"x\":{},\"y\":{}}}", n.id, n.role, n.x, n.y));
    }
    s.push_str("],\n");
    // edges (fan-out DAG + heatmap)
    s.push_str("\"edges\":[");
    for (i, ((from, to), e)) in edges.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let bins: Vec<String> = e
            .bins
            .iter()
            .map(|(t, d)| if *t == 0 { "null".into() } else { format!("{:.3}", *d as f64 / *t as f64) })
            .collect();
        s.push_str(&format!(
            "{{\"from\":{from},\"to\":{to},\"total\":{},\"delivered\":{},\"collided\":{},\"rssi\":{:.1},\"dist\":{:.0},\"bins\":[{}]}}",
            e.total,
            e.delivered,
            e.collided,
            e.rssi_sum / e.total as f64,
            e.dist,
            bins.join(",")
        ));
    }
    s.push_str("],\n");
    // energy
    let acct = bus.energy_accounts();
    let model = RadioEnergyModel::default();
    let dur_s = span as f64 / 1e9;
    s.push_str("\"energy\":[");
    for (i, n) in ns.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let a = acct.get(&NodeId(n.id)).copied().unwrap_or_default();
        s.push_str(&format!(
            "{{\"id\":{},\"tx\":{:.4},\"rx\":{:.4},\"host\":{:.4},\"idle\":{:.4}}}",
            n.id,
            a.tx_j,
            a.rx_j,
            a.host_j,
            model.idle_power_w() * dur_s
        ));
    }
    s.push_str("],\n");
    // decisions (bandit)
    s.push_str("\"decisions\":[");
    for (i, (arm, scores, ok)) in decisions.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let sc: Vec<String> = scores
            .iter()
            .map(|v| if v.is_finite() { format!("{v:.3}") } else { "null".into() })
            .collect();
        s.push_str(&format!("{{\"arm\":{arm},\"scores\":[{}],\"ok\":{}}}", sc.join(","), ok));
    }
    s.push_str("],\n");
    s.push_str(&format!("\"target\":{TARGET},\"rounds\":{ROUNDS},\"bins\":{BINS}\n}}"));
    println!("{s}");
}
