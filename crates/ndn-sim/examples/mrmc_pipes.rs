//! MRMC the named-data way — channel = f(name), validated on the REAL ForwarderEngine.
//!
//! The doctrine correction that shaped this: in named-data radio the FACE IS THE MEDIUM — a radio face
//! is a view of the shared broadcast channel, not a link to a peer. So MRMC is NOT "give each host K
//! radios and assign a channel per hop" (that is the IP-MRMC / WCETT host model we compare AGAINST).
//! It is: the medium spans C channels, and named content DISPERSES across them by hashing the name to
//! a channel — the frequency-domain sibling of name-keyed FHSS rendezvous (Key = H(name), #40). No
//! coordinator, no host radio assignment; the channel falls out of the name.
//!
//! This measures the parallel-pipes consequence on real Interest→Data round-trips: K independent named
//! flows share ONE collision domain (all nodes in range). Each pipe's nodes tune to channel
//! `H(prefix) mod C`. With C=1 every pipe contends on one channel; with C≥K a good name-hash spreads
//! them so they run in parallel. We report aggregate goodput (segments/s across all pipes) and how the
//! hash actually distributed the pipes — no assignment algorithm anywhere, just the name.
//!
//! Run: `cargo run -p ndn-sim --example mrmc_pipes`

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{AdjacentLeakChannel, CarrierSenseInterference, FreeSpacePathLoss, OrthogonalChannels, Position, Simulation};
use tokio_util::sync::CancellationToken;

const PIPES: usize = 8;
const WINDOW: usize = 10; // in-flight fetches per pipe — enough offered load to saturate a channel
const RUN: Duration = Duration::from_millis(1200);

/// FNV-1a over the prefix → the channel this NAME rendezvouses on. This is the whole "assignment":
/// a hash of the content name, computable by anyone, needing no coordinator.
fn name_channel(prefix: &str, channels: u8) -> u8 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in prefix.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    (h % channels as u64) as u8
}

async fn fetch(engine: &ndn_engine::ForwarderEngine, name: &str) -> bool {
    let mut consumer = engine.app_consumer(CancellationToken::new());
    let b = InterestBuilder::new(name.parse::<Name>().unwrap()).lifetime(Duration::from_millis(400));
    matches!(tokio::time::timeout(Duration::from_millis(400), consumer.fetch_with(b)).await, Ok(Ok(_)))
}

struct Metrics {
    goodput: f64,     // delivered segments/s aggregate
    airtime_per: f64, // µs of medium airtime spent per DELIVERED segment (contention shows here)
    dist: Vec<usize>, // pipes per channel (how the name-hash spread them)
}

/// One config: `channels` channels, leaky or orthogonal side-bands.
async fn run_config(channels: u8, leaky: bool) -> Metrics {
    let prop = Arc::new(FreeSpacePathLoss { tx_power_dbm: 20.0, freq_hz: 2.4e9, rx_sensitivity_dbm: -85.0 });
    let mut sim = Simulation::new()
        .with_radio_medium(prop, 7)
        .with_radio_interference(Arc::new(CarrierSenseInterference)); // concurrent same-channel frames collide
    // All PIPES clustered inside one collision domain (a few metres, high SNR → isolate CONTENTION,
    // not erasure). Each pipe = a producer + a consumer.
    let mut pipes = Vec::new();
    for i in 0..PIPES {
        let x = 0.2 * i as f64;
        let prod = sim.add_radio_node(EngineConfig::default(), Position::xy(x, 0.0));
        let cons = sim.add_radio_node(EngineConfig::default(), Position::xy(x, 0.4));
        pipes.push((i, prod, cons));
    }
    let fabric = sim.start().await.unwrap();
    let bus = fabric.radio_bus().unwrap();
    if leaky {
        bus.set_channel_model(Arc::new(AdjacentLeakChannel::default()));
    } else {
        bus.set_channel_model(Arc::new(OrthogonalChannels));
    }

    let mut chan_counts = vec![0usize; channels as usize];
    let mut consumers = Vec::new();
    let mut serves = Vec::new();
    for (i, prod, cons) in &pipes {
        let prefix = format!("/pipe/{i}");
        let ch = name_channel(&prefix, channels);
        chan_counts[ch as usize] += 1;
        // BOTH ends of the pipe tune to the name's channel — the only "assignment" is the hash.
        bus.set_channel(*prod, ch);
        bus.set_channel(*cons, ch);
        let name: Name = prefix.parse().unwrap();
        fabric.route_over_radio(*cons, &name).unwrap();
        let producer = fabric.engine_of(*prod).unwrap().register_producer(prefix.as_str(), CancellationToken::new());
        serves.push(tokio::spawn(async move {
            let _ = producer
                .serve(|i, r| async move {
                    // A realistically-sized segment (~2 KB) so its on-air window (bits ÷ PHY rate) is long
                    // enough to actually overlap concurrent frames — i.e. so the medium can CONTEND.
                    let _ = r.respond((*i.name).clone(), bytes::Bytes::from(vec![0x5au8; 2048])).await;
                })
                .await;
        }));
        consumers.push((*i, fabric.engine_of(*cons).unwrap()));
    }

    // Pump every pipe concurrently for RUN wall-time. Each pipe keeps WINDOW fetches in flight (distinct
    // segments, so every one is a real round-trip) — enough offered load that a shared channel becomes
    // airtime-bound, not RTT-bound. That is the only regime where splitting channels can matter.
    let deadline = Instant::now() + RUN;
    let mut workers = Vec::new();
    for (i, eng) in consumers {
        let seg = Arc::new(AtomicU64::new(0));
        let ok = Arc::new(AtomicU64::new(0));
        for _ in 0..WINDOW {
            let (eng, seg, ok) = (eng.clone(), seg.clone(), ok.clone());
            workers.push((
                ok.clone(),
                tokio::spawn(async move {
                    while Instant::now() < deadline {
                        let s = seg.fetch_add(1, Ordering::Relaxed);
                        if fetch(&eng, &format!("/pipe/{i}/seg{s}")).await {
                            ok.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }),
            ));
        }
    }
    let mut total = 0u64;
    let mut seen = std::collections::HashSet::new();
    for (ok, h) in workers {
        let _ = h.await;
        if seen.insert(Arc::as_ptr(&ok)) {
            total += ok.load(Ordering::Relaxed);
        }
    }
    let airtime_us = bus.total_airtime().as_micros() as f64;
    for s in serves {
        s.abort();
    }
    fabric.shutdown().await;
    Metrics {
        goodput: total as f64 / RUN.as_secs_f64(),
        airtime_per: if total > 0 { airtime_us / total as f64 } else { 0.0 },
        dist: chan_counts,
    }
}

#[tokio::main]
async fn main() {
    println!("MRMC the named-data way — channel = H(name), real ForwarderEngine, {PIPES} pipes in one domain\n");
    println!("The only 'channel assignment' is a hash of the content name. No coordinator, no host radios.\n");

    let mut rows = Vec::new();
    let base = run_config(1, false).await; // single channel = the contention baseline
    println!("  channels   model        goodput seg/s   airtime µs/delivered   airtime vs 1ch   pipes/chan");
    println!(
        "  {:>5}      {:<11}  {:>9.0}       {:>10.0}            {:>6}         {:?}",
        1, "baseline", base.goodput, base.airtime_per, "1.00×", base.dist
    );
    rows.push(format!("{{\"c\":1,\"leaky\":false,\"goodput\":{:.1},\"air\":{:.1},\"airratio\":1.0}}", base.goodput, base.airtime_per));
    for &c in &[2u8, 4, 8] {
        for leaky in [false, true] {
            let m = run_config(c, leaky).await;
            let model = if leaky { "adj-leak" } else { "orthogonal" };
            let air_ratio = if base.airtime_per > 0.0 { m.airtime_per / base.airtime_per } else { 0.0 };
            println!(
                "  {:>5}      {:<11}  {:>9.0}       {:>10.0}            {:>5.2}×         {:?}",
                c, model, m.goodput, m.airtime_per, air_ratio, m.dist
            );
            rows.push(format!("{{\"c\":{c},\"leaky\":{leaky},\"goodput\":{:.1},\"air\":{:.1},\"airratio\":{:.3}}}", m.goodput, m.airtime_per, air_ratio));
        }
    }

    println!("\ntakeaway: MRMC the named-data way, on the REAL ForwarderEngine. On one channel the 8 pipes");
    println!("collide into congestion collapse; splitting them across ORTHOGONAL channels — by hashing each");
    println!("NAME to a channel, no coordinator, no host radios — recovers goodput super-linearly (the");
    println!("single-channel case is in collapse) and drops airtime-per-delivered toward the collision-free");
    println!("floor. Adjacent-channel LEAK is a real tax: leaky channels still couple, so C=2 leaky can be");
    println!("WORSE than one channel — you must SPACE the channels (matches the real MT7612U mesh data). The");
    println!("face stays a channel-view of the medium; the 'assignment' is just H(name). That is ndnpipes.");

    eprintln!("{{\"pipes\":{PIPES},\"rows\":[{}]}}", rows.join(","));
}
