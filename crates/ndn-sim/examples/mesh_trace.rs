//! Multi-node distributed trace — the telemetry, reconstructed and node-attributed, with the radio
//! DECISION woven into the spans.
//!
//! ASSESSMENT (why this shape). The sim already captures the engine's in-node causal span tree
//! (`SpanLog`, span_id/parent_span_id off `tracing`) and exports OTLP (`otel_export.rs`). But two
//! honest gaps stop that being a MULTI-NODE trace:
//!   1. `CapturedSpan` has no node id, and every node's `ForwarderEngine` shares ONE in-process
//!      `tracing` dispatcher — so engine spans can't be attributed to a node, nor stitched across
//!      nodes (span ids are per-registry). The REAL deployment avoids this: each node is its own
//!      process, and ndn-observability ships spans as OTLP-in-Data carrying trace context, so a
//!      consumer's fetch and the producer's serve stitch into one trace on the wire ([[observability]]).
//!   2. The bandit decision (`select_traced` → per-arm UCB scores) is captured as DATA but was never
//!      woven into a request span — "why did this node pick this rate" sat beside the trace, not in it.
//!
//! What IS node-attributed in the sim: the `RadioLog` (every frame: from, to, t, delivered/collided)
//! and the decision stream. So this reconstructs the distributed trace the real OTLP-in-Data stitch
//! would show — a request's causal path Interest→relay→producer→Data-back across node lanes — and
//! stamps each forwarding hop with the arm/rate/power its bandit chose. That is the visualization
//! target: a swimlane trace with decision observability INLINE, not beside.
//!
//! Run: `cargo run -p ndn-sim --example mesh_trace`

use std::sync::Arc;

use bytes::Bytes;
use ndn_radio_cognition::{apply_arm, reward, WifiRate, ARMS, Context, ContextualBandit, TxParams};
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::CarrierSenseInterference;
use ndn_sim::radio::RadioBus;
use ndn_sim::{FreeSpacePathLoss, ImmediateRuntime, NodeId, Position, World};

const REQUESTS: u64 = 14;
const PAYLOAD: usize = 256;
const BASE_MCS: u8 = 5;
const MAX_MCS: u8 = 7;
const MAX_PIDX: u8 = 63;
const MAX_DBM: f64 = 20.0;

// Line topology: consumer → relay1 → relay2 → producer. Interest walks up, Data walks back.
const PATH: [(usize, &str, f64); 4] =
    [(0, "consumer", 0.0), (1, "relay-1", 160.0), (2, "relay-2", 320.0), (3, "producer", 480.0)];

fn air_ns(mcs: u8) -> u64 {
    (PAYLOAD as u64) * 8 * 1_000_000_000 / (mcs_phy_rate_bps(mcs).max(1) as u64)
}
fn dbm_of(pidx: u8) -> f64 {
    MAX_DBM - (MAX_PIDX as i32 - pidx as i32) as f64 * 0.5
}

#[derive(Clone)]
struct Span {
    id: u64,
    parent: Option<u64>,
    node: usize,
    lane: &'static str,
    kind: &'static str, // interest | data | retry | decision
    name: String,
    t0: u64,
    dur: u64,
    ok: bool,
    arm: Option<usize>,
    mcs: Option<u8>,
    dbm: Option<f64>,
}

fn main() {
    let world = Arc::new(World::new());
    for (id, _, x) in PATH {
        world.place(NodeId(id), Position::xy(x, 0.0));
    }
    // Generous sensitivity so 160 m links deliver reliably — then retries in the trace come from
    // COLLISIONS (overlapping requests), the interesting failure mode, not from range.
    let prop = Arc::new(FreeSpacePathLoss { tx_power_dbm: 20.0, freq_hz: 2.4e9, rx_sensitivity_dbm: -85.0 });
    let bus = RadioBus::with_interference_on(
        world.clone(),
        prop,
        0,
        7,
        Arc::new(CarrierSenseInterference),
        Arc::new(ImmediateRuntime),
    );
    for (id, _, _) in PATH {
        let _ = bus.attach(NodeId(id));
        bus.set_tx_power(NodeId(id), MAX_DBM);
    }
    // one bandit per forwarding node (each learns its own downstream link)
    let mut bandits: Vec<ContextualBandit> = (0..PATH.len()).map(|_| ContextualBandit::new(1.0)).collect();

    let mut spans: Vec<Span> = Vec::new();
    let mut next_id = 0u64;
    let mut id = || {
        next_id += 1;
        next_id
    };

    // Transmit one hop from `tx`→`rx`; returns (delivered, rssi). Bandit at `tx` picks rate/power.
    let base_air = air_ns(BASE_MCS);
    let mut latencies = Vec::new();

    for r in 0..REQUESTS {
        let name = format!("/clip/seg{r}");
        // Requests are launched every ~7 hops of airtime — mostly clean, with enough overlap that a
        // request's Interest sometimes collides with the previous request's returning Data at the
        // consumer↔relay-1 link (the retries clustered on the consumer lane).
        let mut t = r * base_air * 6;
        let mut parent: Option<u64> = None;
        let t_start = t;

        // --- Interest walks UP the path: consumer→relay1→relay2→producer (basic rate, no decision) ---
        for hop in 0..PATH.len() - 1 {
            let (from, to) = (PATH[hop].0, PATH[hop + 1].0);
            let rx = bus.transmit(NodeId(from), BASE_MCS, Bytes::from(vec![0u8; PAYLOAD]), t);
            let ok = rx.iter().any(|(n, _, d)| *n == NodeId(to) && *d);
            let sid = id();
            spans.push(Span {
                id: sid, parent, node: from, lane: PATH[hop].1, kind: "interest",
                name: name.clone(), t0: t, dur: base_air, ok,
                arm: None, mcs: Some(BASE_MCS), dbm: None,
            });
            parent = Some(sid);
            t += base_air;
            if !ok {
                // one retry (visible in the trace as a red span on the same lane)
                let rx2 = bus.transmit(NodeId(from), BASE_MCS, Bytes::from(vec![0u8; PAYLOAD]), t);
                let ok2 = rx2.iter().any(|(n, _, d)| *n == NodeId(to) && *d);
                let rid = id();
                spans.push(Span {
                    id: rid, parent, node: from, lane: PATH[hop].1, kind: "retry",
                    name: name.clone(), t0: t, dur: base_air, ok: ok2,
                    arm: None, mcs: Some(BASE_MCS), dbm: None,
                });
                parent = Some(rid);
                t += base_air;
            }
        }

        // --- Data walks BACK: producer→relay2→relay1→consumer, each sender's BANDIT picks rate/power ---
        for hop in (0..PATH.len() - 1).rev() {
            let (from, to) = (PATH[hop + 1].0, PATH[hop].0);
            // measure the downstream link RSSI WITHOUT emitting a frame (no probe → no extra collisions)
            let (fx, tx_x) = (PATH[hop + 1].2, PATH[hop].2);
            let rssi = bus.link_rssi(Position::xy(fx, 0.0), Position::xy(tx_x, 0.0)).unwrap_or(-90.0);
            let ctx = Context::new(rssi.round() as i8, 20, 4, 1);
            let choice = bandits[from].select_traced(&ctx);
            let arm = choice.arm;
            let mut p: TxParams = TxParams::wifi(WifiRate { mcs: Some(BASE_MCS), bw: Some(2), nss: Some(1), ..Default::default() });
            p.tx_power = Some(MAX_PIDX);
            apply_arm(&ARMS[arm], &mut p, MAX_MCS, MAX_PIDX);
            let mcs = p.mcs().unwrap_or(BASE_MCS);
            let pidx = p.tx_power.unwrap_or(MAX_PIDX);
            bus.set_tx_power(NodeId(from), dbm_of(pidx));
            let dur = air_ns(mcs);
            let rx = bus.transmit(NodeId(from), mcs, Bytes::from(vec![0u8; PAYLOAD]), t);
            let ok = rx.iter().any(|(n, _, d)| *n == NodeId(to) && *d);
            bandits[from].update(&ctx, arm, reward(ok, &p, MAX_PIDX));
            bus.set_tx_power(NodeId(from), MAX_DBM);
            let sid = id();
            spans.push(Span {
                id: sid, parent, node: from, lane: PATH[hop + 1].1, kind: "data",
                name: name.clone(), t0: t, dur, ok,
                arm: Some(arm), mcs: Some(mcs), dbm: Some(dbm_of(pidx)),
            });
            parent = Some(sid);
            t += dur;
        }
        latencies.push((t - t_start) as f64 / 1000.0); // µs
    }

    // ---- report ----
    let n = spans.len();
    let ok = spans.iter().filter(|s| s.ok).count();
    let retries = spans.iter().filter(|s| s.kind == "retry").count();
    let mean_lat = latencies.iter().sum::<f64>() / latencies.len() as f64;
    println!("Multi-node distributed trace — {REQUESTS} requests, {} spans across {} node lanes\n", n, PATH.len());
    println!("  spans           {n}  ({} delivered, {retries} retries)", ok);
    println!("  mean end-to-end {:.0} µs (Interest up 3 hops + Data back 3 hops)", mean_lat);
    println!("  decision spans  {} Data hops, each stamped with the bandit's arm/MCS/power\n", spans.iter().filter(|s| s.kind == "data").count());
    println!("  the trace stitches on the wire the way the real OTLP-in-Data path does — every span");
    println!("  carries its node, its causal parent, and (on Data hops) WHY that rate was chosen.\n");

    // per-node span counts
    println!("  node        interest  data  retry");
    for (id_, label, _) in PATH {
        let c = |k: &str| spans.iter().filter(|s| s.node == id_ && s.kind == k).count();
        println!("  {:<10}    {:>5}  {:>4}  {:>5}", label, c("interest"), c("data"), c("retry"));
    }

    // JSON for the trace dashboard
    let js: Vec<String> = spans.iter().map(|s| format!(
        "{{\"id\":{},\"parent\":{},\"node\":{},\"lane\":\"{}\",\"kind\":\"{}\",\"name\":\"{}\",\"t0\":{},\"dur\":{},\"ok\":{},\"arm\":{},\"mcs\":{},\"dbm\":{}}}",
        s.id,
        s.parent.map(|p| p.to_string()).unwrap_or("null".into()),
        s.node, s.lane, s.kind, s.name, s.t0, s.dur, s.ok,
        s.arm.map(|a| a.to_string()).unwrap_or("null".into()),
        s.mcs.map(|m| m.to_string()).unwrap_or("null".into()),
        s.dbm.map(|d| format!("{:.1}", d)).unwrap_or("null".into()),
    )).collect();
    let lanes: Vec<String> = PATH.iter().map(|(id_, l, _)| format!("{{\"node\":{id_},\"label\":\"{l}\"}}")).collect();
    eprintln!("{{\"lanes\":[{}],\"spans\":[{}],\"arms\":{}}}", lanes.join(","), js.join(","), ARMS.len());
}
