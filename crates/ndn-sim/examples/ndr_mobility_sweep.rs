//! **NDR mobility sweep harness** — the measurement scaffold for `wireless-forwarding-under-flux.md`.
//!
//! `N` nodes roam a disc under `RandomWaypoint` at a swept speed; node 0 produces `/svc`, the rest each
//! fetch a *unique* name every round while everyone moves. Multi-hop forwarding is the **`broadcast`**
//! strategy — a relay re-broadcasts on the incoming radio face, i.e. **flooding**: the honest baseline the
//! soft-prefix-reach strategy (the reachability-prior design) must beat. Emits, per speed: delivery ratio,
//! total airtime, and **airtime per satisfied Interest** — the metric a good prior should drive down.
//!
//! Deterministic (`DesKernel` event queue + seeded mobility), so runs replay bit-for-bit at
//! event granularity. Swap `STRATEGY` (env `NDR_STRATEGY`) to A/B one axis at a time, per the doc's §7
//! protocol.
//!
//! Run: `cargo run -p ndn-sim --example ndr_mobility_sweep`
use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{AppSpec, DesKernel, Position, RandomWaypointMobility, RangeThreshold, SimKernel, Simulation};
use ndn_strategy_reach as _; // force-link so `soft-prefix-reach` is in the strategy registry (linkme)
use tokio_util::sync::CancellationToken;

const N: usize = 12; // nodes (1 producer + 11 consumers)
const REGION_R: f64 = 60.0; // roam-disc radius (m)
const COMM_R: f64 = 30.0; // radio range (m) — sub-diameter, so multi-hop matters
const ROUNDS: usize = 40; // fetch rounds per run
const ROUND_DT_MS: u64 = 500; // virtual time between rounds (nodes move)
const FETCH_LIFETIME_MS: u64 = 400; // Interest lifetime (< ROUND_DT so a miss resolves before the move)
// A/B: `NDR_STRATEGY=broadcast` (flood baseline) vs `NDR_STRATEGY=soft-prefix-reach` (the reachability prior).
fn strategy() -> String {
    std::env::var("NDR_STRATEGY").unwrap_or_else(|_| "broadcast".into())
}

struct Row {
    speed: f64,
    attempts: u32,
    delivered: u32,
    airtime_ms: f64,
}

fn run(speed: f64) -> Row {
    DesKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
        // `broadcast` (flood) self-registers via linkme at link time — `set_strategy("broadcast")` resolves.
        let strat = strategy();
        let mut sim = Simulation::new()
            .kernel(k.clone())
            .with_radio_medium(Arc::new(RangeThreshold { range_m: COMM_R, tx_power_dbm: 20.0 }), 7);

        let nodes: Vec<_> =
            (0..N).map(|_| sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0))).collect();
        sim.add_app(
            nodes[0],
            AppSpec::Producer { prefix: "/svc".into(), content: Some("air".into()), freshness_ms: None },
        );

        let svc: Name = "/svc".parse().unwrap();
        let fabric = sim.start().await.unwrap();
        // Named-data radio = Monitor (broadcast injection); the default Managed mode needs association.
        fabric.radio_bus().unwrap().set_mac_mode(ndn_sim::WifiMode::Monitor);

        // Every node roams the disc (seeded per-node). Consumers/relays route `/svc` over the radio and
        // flood; the PRODUCER gets NO radio route — that would compete with its local app face and, under
        // best-route, make it re-broadcast the Interest instead of serving it.
        for (i, &node) in nodes.iter().enumerate() {
            let seed = 0x1234_5678u64 ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            fabric.set_mobility(node, Arc::new(RandomWaypointMobility { radius: REGION_R, speed_mps: speed, seed }));
            if i != 0 {
                fabric.route_over_radio(node, &svc).unwrap();
                fabric.set_strategy(node, &svc, &strat).unwrap();
            }
        }

        // One reusable consumer per non-producer node.
        let mut consumers: Vec<_> =
            nodes[1..].iter().map(|&c| fabric.engine_of(c).unwrap().app_consumer(CancellationToken::new())).collect();

        let mut attempts = 0u32;
        let mut delivered = 0u32;
        for r in 0..ROUNDS {
            // All consumers express concurrently in one time window (unique names → no cross-consumer cache
            // sharing, so each fetch tests that node's own reachability *now*).
            let futs = consumers.iter_mut().enumerate().map(|(i, consumer)| {
                let name: Name = format!("/svc/{r}/{i}").parse().unwrap();
                async move {
                    consumer
                        .fetch_with(InterestBuilder::new(name).lifetime(Duration::from_millis(FETCH_LIFETIME_MS)))
                        .await
                        .is_ok()
                }
            });
            let results = futures::future::join_all(futs).await;
            attempts += results.len() as u32;
            delivered += results.iter().filter(|&&ok| ok).count() as u32;
            k.runtime().sleep(Duration::from_millis(ROUND_DT_MS)).await; // advance virtual time — nodes move
        }

        let airtime = fabric.radio_bus().unwrap().total_airtime();
        fabric.shutdown().await;
        Row { speed, attempts, delivered, airtime_ms: airtime.as_secs_f64() * 1000.0 }
    })
}

fn main() {
    println!(
        "NDR mobility sweep — N={N}, disc r={REGION_R}m, comm r={COMM_R}m, strategy={}, {ROUNDS} rounds\n",
        strategy()
    );
    println!("{:>8}  {:>9}  {:>9}  {:>11}  {:>16}", "speed", "delivered", "attempts", "deliv-ratio", "airtime/deliv(ms)");
    for &speed in &[0.0, 1.0, 5.0, 15.0, 30.0] {
        let row = run(speed);
        let ratio = row.delivered as f64 / row.attempts.max(1) as f64;
        let apd = if row.delivered > 0 { row.airtime_ms / row.delivered as f64 } else { f64::NAN };
        println!("{:>8.1}  {:>9}  {:>9}  {:>11.3}  {:>16.3}", row.speed, row.delivered, row.attempts, ratio, apd);
    }
    println!("\nBaseline = flooding. The reachability-prior strategy should hold delivery-ratio while cutting");
    println!("airtime/deliv (it scopes the flood). A/B by swapping STRATEGY once that strategy is registered.");
}
