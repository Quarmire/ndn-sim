//! **Multi-producer scenario** — exhibits the *memory axis* the single-prefix sweep can't
//! (`wireless-forwarding-under-flux.md` §10): scalar-map vs counting-Bloom reach memory across many prefixes.
//!
//! `N` nodes roam a disc; each produces its own prefix `/p/{k}` and relays every *other* prefix (all nodes
//! route the `/p` catch-all over the radio + run one soft-prefix-reach instance, which keys the reach prior at
//! depth 2 so `/p/{k}` are distinct). Every node fetches a rotating non-self prefix each round.
//!
//! The point: a **scalar map** grows O(K) entries; a **counting Bloom** is FIXED width. Shrinking the Bloom
//! (`NDR_BLOOM_CELLS`) at fixed K forces saturation — and the failure mode is **fail-safe** (a false positive
//! makes a cold prefix inherit reach → an *extra* re-broadcast → more airtime, but never a blackhole; §7). So
//! delivery holds while airtime/deliv rises, which is exactly the bounded-memory tradeoff.
//!
//! ```sh
//! NDR_PREFIX_DEPTH=2 NDR_STRATEGY=soft-prefix-reach-defer cargo run --example ndr_multiproducer -p ndn-sim
//! NDR_PREFIX_DEPTH=2 NDR_STRATEGY=soft-prefix-reach-bloom NDR_BLOOM_CELLS=256 cargo run --example ndr_multiproducer -p ndn-sim
//! NDR_PREFIX_DEPTH=2 NDR_STRATEGY=soft-prefix-reach-bloom NDR_BLOOM_CELLS=8   cargo run --example ndr_multiproducer -p ndn-sim
//! ```
use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{AppSpec, DesKernel, Position, RandomWaypointMobility, RangeThreshold, SimKernel, Simulation};
use ndn_strategy_reach as _; // force-link the strategy registry (linkme)
use tokio_util::sync::CancellationToken;

const N: usize = 12;
const REGION_R: f64 = 60.0;
const COMM_R: f64 = 30.0;
const ROUNDS: usize = 40;
const ROUND_DT_MS: u64 = 500;
const FETCH_LIFETIME_MS: u64 = 400;

fn env_usize(k: &str, d: usize) -> usize {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn env_f64(k: &str, d: f64) -> f64 {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
}
fn strategy() -> String {
    std::env::var("NDR_STRATEGY").unwrap_or_else(|_| "soft-prefix-reach-defer".into())
}

fn run(k_prefixes: usize, speed: f64) -> (u32, u32, f64) {
    DesKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
        let strat = strategy();
        let mut sim = Simulation::new()
            .kernel(k.clone())
            .with_radio_medium(Arc::new(RangeThreshold { range_m: COMM_R, tx_power_dbm: 20.0 }), 7);
        let nodes: Vec<_> =
            (0..N).map(|_| sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0))).collect();
        // K producers of `/p/{j}`, assigned round-robin to nodes.
        for j in 0..k_prefixes {
            sim.add_app(
                nodes[j % N],
                AppSpec::Producer { prefix: format!("/p/{j}"), content: Some("air".into()), freshness_ms: None },
            );
        }
        let root: Name = "/p".parse().unwrap();
        let fabric = sim.start().await.unwrap();
        fabric.radio_bus().unwrap().set_mac_mode(ndn_sim::WifiMode::Monitor);
        // Every node roams, relays the `/p` catch-all over the radio, and runs the reach strategy on it.
        for (i, &node) in nodes.iter().enumerate() {
            let seed = 0x1234_5678u64 ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
            fabric.set_mobility(node, Arc::new(RandomWaypointMobility { radius: REGION_R, speed_mps: speed, seed }));
            fabric.route_over_radio(node, &root).unwrap();
            fabric.set_strategy(node, &root, &strat).unwrap();
        }
        let mut consumers: Vec<_> =
            nodes.iter().map(|&c| fabric.engine_of(c).unwrap().app_consumer(CancellationToken::new())).collect();

        let mut attempts = 0u32;
        let mut delivered = 0u32;
        for r in 0..ROUNDS {
            let futs = consumers.iter_mut().enumerate().map(|(ci, consumer)| {
                // A rotating target prefix, skipping the one THIS node produces (so the fetch tests the radio).
                let mut j = (ci + 1 + r) % k_prefixes;
                if j % N == ci {
                    j = (j + 1) % k_prefixes;
                }
                let name: Name = format!("/p/{j}/{r}/{ci}").parse().unwrap();
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
            k.runtime().sleep(Duration::from_millis(ROUND_DT_MS)).await;
        }
        let airtime = fabric.radio_bus().unwrap().total_airtime();
        fabric.shutdown().await;
        (delivered, attempts, airtime.as_secs_f64() * 1000.0)
    })
}

fn main() {
    let k = env_usize("NDR_PREFIXES", 12);
    let speed = env_f64("NDR_SPEED", 5.0);
    let cells = env_usize("NDR_BLOOM_CELLS", 256);
    let (d, a, air) = run(k, speed);
    let ratio = d as f64 / a.max(1) as f64;
    let apd = if d > 0 { air / d as f64 } else { f64::NAN };
    println!(
        "multiproducer  strat={:<26} K={k:<3} speed={speed} bloom_cells={cells:<4}  ->  deliv {d}/{a} ({ratio:.3})   airtime/deliv {apd:.3} ms",
        strategy()
    );
    println!("(memory footprint: scalar map = O(K) entries; counting Bloom = fixed {cells} cells regardless of K)");
}
