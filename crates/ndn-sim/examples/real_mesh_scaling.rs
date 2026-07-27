//! Real-forwarder multi-hop scaling — a chain of N real ForwarderEngines over the RadioBus, each relay
//! running `BroadcastStrategy`, a consumer at one end fetching from a producer at the other. Unlike the
//! link-level scaling study, every hop is genuine PIT→FIB→radio→PIT forwarding. As the chain grows we
//! measure what actually changes with hop count:
//!   • delivery ratio (did the multi-hop fetch complete);
//!   • end-to-end RTT (grows ~linearly with hops);
//!   • radio transmissions per delivered fetch (the flood's overhead — grows with the relay count).
//!
//! This is the credible base the coding × CCLF × scale / vs-MANET / mobility comparisons build on.
//!
//! Run: `cargo run -p ndn-sim --example real_mesh_scaling`

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{FreeSpacePathLoss, Position, Simulation};
use ndn_strategy::{BroadcastStrategy, ErasedStrategy};
use tokio_util::sync::CancellationToken;

const SPACING_M: f64 = 130.0; // neighbours in range (~200 m), next-neighbours out ⇒ a true chain
const SENSITIVITY_DBM: f64 = -66.0;
const FETCHES: usize = 8;

const BATCH: usize = 24; // concurrent fetches for the saturated-throughput measurement

struct Row {
    n: usize,
    hops: usize,
    delivery: f64,
    rtt_ms: f64,
    tx_per_fetch: f64,
    warm_tx: f64,
    tput: f64, // saturated fetches/sec through the chain (half-duplex + interference throttle it)
}

async fn run_chain(n: usize) -> Row {
    let prop = Arc::new(FreeSpacePathLoss {
        tx_power_dbm: 20.0,
        freq_hz: 2.4e9,
        rx_sensitivity_dbm: SENSITIVITY_DBM,
    });
    let mut sim = Simulation::new().with_radio_medium(prop, 7);
    let nodes: Vec<_> = (0..n)
        .map(|i| sim.add_radio_node(EngineConfig::default(), Position::xy(i as f64 * SPACING_M, 0.0)))
        .collect();
    let fabric = sim.start().await.unwrap();
    // Realistic physics: half-duplex is on by default (a relay can't RX while it TXes); widen the
    // interference range past the decode range so concurrent hops beyond the next neighbour still
    // clash (why a single-radio chain falls below 1/hop).
    if let Some(bus) = fabric.radio_bus() {
        bus.set_interference_range_factor(1.8);
    }
    let log = fabric.capture_radio();

    let prefix: Name = "/mesh".parse().unwrap();
    // Consumer (0) + every relay route the prefix at the air; relays re-broadcast (BroadcastStrategy).
    for &node in &nodes[..n - 1] {
        fabric.route_over_radio(node, &prefix).unwrap();
    }
    for &node in &nodes[1..n - 1] {
        fabric.engine_of(node).unwrap().strategy_table().insert(
            &prefix,
            Arc::new(BroadcastStrategy::new()) as Arc<dyn ErasedStrategy>,
        );
    }
    // Producer at the far end.
    let prod = fabric.engine_of(nodes[n - 1]).unwrap().register_producer("/mesh", CancellationToken::new());
    let serve = tokio::spawn(async move {
        let _ = prod
            .serve(|i, r| async move {
                // Stamp a FreshnessPeriod so intermediate Content Stores actually admit + cache it
                // (the DefaultAdmissionPolicy treats freshness=0 as non-cacheable) — the caching axis.
                let content = bytes::Bytes::from_static(b"payload");
                let wire = ndn_packet::encode::DataBuilder::new((*i.name).clone(), &content)
                    .freshness(Duration::from_secs(30))
                    .build();
                let _ = r.respond_bytes(wire).await;
            })
            .await;
    });
    tokio::time::sleep(Duration::from_millis(30)).await; // let the producer's serve loop arm

    let eng_c = fabric.engine_of(nodes[0]).unwrap();
    let (mut ok, mut rtt_sum) = (0usize, 0.0f64);
    for k in 0..FETCHES {
        let mut consumer = eng_c.app_consumer(CancellationToken::new());
        let b = InterestBuilder::new(format!("/mesh/seg{k}").parse::<Name>().unwrap())
            .lifetime(Duration::from_secs(2));
        let t = Instant::now();
        let got = tokio::time::timeout(Duration::from_millis(1500), consumer.fetch_with(b)).await;
        if matches!(got, Ok(Ok(_))) {
            ok += 1;
            rtt_sum += t.elapsed().as_secs_f64() * 1e3;
        }
    }

    // Cold overhead so far: distinct (transmitter, instant) pairs on the medium = radio transmissions.
    let tx_set = |l: &Arc<ndn_sim::RadioLog>| -> HashSet<(usize, u64)> {
        l.records().iter().map(|r| (r.from.0, r.t_ns)).collect()
    };
    let cold_set = log.as_ref().map(tx_set).unwrap_or_default();

    // CACHING axis: re-fetch an already-delivered name. Now that the Data carries freshness, an
    // in-network Content Store serves it — a full N-hop fetch collapses to a near-local cache hit, so
    // the warm cost is ~0 regardless of chain length. The saving IS the cold multi-hop overhead.
    let mut warm = eng_c.app_consumer(CancellationToken::new());
    let wb = InterestBuilder::new("/mesh/seg0".parse::<Name>().unwrap()).lifetime(Duration::from_secs(2));
    let _ = tokio::time::timeout(Duration::from_millis(1500), warm.fetch_with(wb)).await;
    let warm_tx = log.as_ref().map(|l| tx_set(l).difference(&cold_set).count()).unwrap_or(0);

    // SATURATED throughput: fire BATCH fetches concurrently so consecutive packets' hops overlap in
    // the chain. Half-duplex (a relay can't RX packet k+1 while TXing packet k) + the wide
    // interference range then throttle the pipeline — the reason a single-radio chain's throughput
    // falls off *faster* than 1/hop.
    let t0 = Instant::now();
    let mut handles = Vec::new();
    for k in 0..BATCH {
        let eng = eng_c.clone();
        handles.push(tokio::spawn(async move {
            let mut c = eng.app_consumer(CancellationToken::new());
            let b = InterestBuilder::new(format!("/mesh/tput{k}").parse::<Name>().unwrap())
                .lifetime(Duration::from_secs(3));
            matches!(tokio::time::timeout(Duration::from_millis(3000), c.fetch_with(b)).await, Ok(Ok(_)))
        }));
    }
    let mut done = 0usize;
    for h in handles {
        if h.await.unwrap_or(false) {
            done += 1;
        }
    }
    let tput = done as f64 / t0.elapsed().as_secs_f64();

    serve.abort();
    fabric.shutdown().await;

    Row {
        n,
        hops: n - 1,
        delivery: ok as f64 / FETCHES as f64,
        rtt_ms: if ok > 0 { rtt_sum / ok as f64 } else { f64::NAN },
        tx_per_fetch: if ok > 0 { cold_set.len() as f64 / ok as f64 } else { f64::NAN },
        warm_tx: warm_tx as f64,
        tput,
    }
}

#[tokio::main]
async fn main() {
    println!("real-forwarder multi-hop scaling — a chain of N engines, BroadcastStrategy relays\n");
    println!("  N   hops   delivery   RTT(ms)   cold-tx/fetch   warm-tx   sat-tput(/s)");
    let mut rows = Vec::new();
    for n in [2usize, 3, 4, 5, 7, 9, 12] {
        let r = run_chain(n).await;
        println!(
            "  {:>2}   {:>3}    {:>5.0}%   {:>6.1}    {:>9.1}    {:>6.0}    {:>9.1}",
            r.n, r.hops, r.delivery * 100.0, r.rtt_ms, r.tx_per_fetch, r.warm_tx, r.tput
        );
        rows.push(r);
    }
    let mut j = String::from("{\"chain\":[");
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            j.push(',');
        }
        j.push_str(&format!(
            "{{\"n\":{},\"hops\":{},\"delivery\":{:.3},\"rtt_ms\":{:.2},\"tx_per_fetch\":{:.2},\"warm_tx\":{:.1},\"tput\":{:.2}}}",
            r.n, r.hops,
            if r.delivery.is_nan() { 0.0 } else { r.delivery },
            if r.rtt_ms.is_nan() { 0.0 } else { r.rtt_ms },
            if r.tx_per_fetch.is_nan() { 0.0 } else { r.tx_per_fetch },
            r.warm_tx, r.tput
        ));
    }
    j.push_str("]}");
    eprintln!("\n{j}");
}
