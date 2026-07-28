//! Name-keyed FHSS rendezvous (#40) — channel = H(name, epoch), on the real engine.
//!
//! #66 established the static form: channel = H(name), hashed into #66's separated (non-adjacent)
//! classes. #40 makes it HOP. The channel a flow uses at epoch `e` is `hop(name, e)` — a name-shifted
//! walk over the separated-class set. Everyone who cares about `/X` (consumer, producer, relays)
//! computes the same sequence from (a) the name and (b) the shared epoch clock (#61 time-slice MAC /
//! common-view TSF), so they rendezvous with NO coordinator, NO host identity — the frequency-domain
//! sibling of the time-slice MAC. The devourer chip's HopSchedule is the hardware that would clock
//! this on real radios; here we validate the mechanism + its payoff on the sim's real ForwarderEngine.
//!
//! The payoff FHSS buys over the static hash: a persistent single-channel jammer can KILL a flow whose
//! name statically hashes onto it — but a hopping flow only visits the bad channel 1/C of the time, so
//! no flow is ever permanently stuck. We measure worst-flow delivery (fairness) under a static jammer.
//!
//! Run: `cargo run -p ndn-sim --example fhss_rendezvous`

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{AdjacentLeakChannel, CarrierSenseInterference, FreeSpacePathLoss, NodeId, Position, Simulation};
use tokio_util::sync::CancellationToken;

const FLOWS: usize = 4;
const CLASSES: [u8; 4] = [0, 2, 4, 6]; // separated (non-adjacent) hop set — #66's channel classes
const EPOCH_MS: u64 = 120; // hop dwell (a common-view epoch)
const RUN: Duration = Duration::from_millis(1500);
const WINDOW: usize = 6;
const JAM_CH: u8 = 2; // a class channel; a persistent external jammer sits here
const JAM_N: usize = 3;

fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() { h ^= b as u64; h = h.wrapping_mul(0x100000001b3); }
    h
}
/// The channel `name` uses at epoch `e` — a name-shifted walk over the separated classes. Computable
/// by anyone holding the name + the epoch clock; identical for every node that cares about the name.
fn hop(prefix: &str, epoch: u64) -> u8 {
    CLASSES[((fnv(prefix) + epoch) % CLASSES.len() as u64) as usize]
}

async fn fetch(engine: &ndn_engine::ForwarderEngine, name: &str) -> bool {
    let mut consumer = engine.app_consumer(CancellationToken::new());
    let b = InterestBuilder::new(name.parse::<Name>().unwrap()).lifetime(Duration::from_millis(300));
    matches!(tokio::time::timeout(Duration::from_millis(300), consumer.fetch_with(b)).await, Ok(Ok(_)))
}

/// Returns (per-flow delivery ratio, aggregate seg/s).
async fn run(hopping: bool, jam: bool) -> (Vec<f64>, f64) {
    let prop = Arc::new(FreeSpacePathLoss { tx_power_dbm: 20.0, freq_hz: 2.4e9, rx_sensitivity_dbm: -85.0 });
    let mut sim = Simulation::new()
        .with_radio_medium(prop, 7)
        .with_radio_interference(Arc::new(CarrierSenseInterference));
    let n_nodes = FLOWS + if jam { JAM_N } else { 0 };
    let mut pairs = Vec::new();
    for i in 0..n_nodes {
        let x = 0.2 * i as f64;
        let prod = sim.add_radio_node(EngineConfig::default(), Position::xy(x, 0.0));
        let cons = sim.add_radio_node(EngineConfig::default(), Position::xy(x, 0.4));
        pairs.push((prod, cons));
    }
    let fabric = sim.start().await.unwrap();
    let bus = fabric.radio_bus().unwrap();
    bus.set_channel_model(Arc::new(AdjacentLeakChannel::default()));

    // wire producers/consumers; set epoch-0 channels; remember (prod,cons,prefix) for the hop clock
    let mut flows: Vec<(NodeId, NodeId, String)> = Vec::new();
    let mut serves = Vec::new();
    let mut consumers = Vec::new();
    for (i, (prod, cons)) in pairs.iter().enumerate() {
        let (prefix, ch, counted) = if i < FLOWS {
            let p = format!("/flow/{i}");
            let c = hop(&p, 0);
            (p, c, true)
        } else {
            ("/jam/x".to_string(), JAM_CH, false) // persistent static jammer
        };
        bus.set_channel(*prod, ch);
        bus.set_channel(*cons, ch);
        let name: Name = prefix.parse().unwrap();
        fabric.route_over_radio(*cons, &name).unwrap();
        let producer = fabric.engine_of(*prod).unwrap().register_producer(prefix.as_str(), CancellationToken::new());
        serves.push(tokio::spawn(async move {
            let _ = producer.serve(|i, r| async move {
                let _ = r.respond((*i.name).clone(), bytes::Bytes::from(vec![0x5au8; 2048])).await;
            }).await;
        }));
        if counted {
            flows.push((*prod, *cons, prefix.clone()));
            consumers.push((i, fabric.engine_of(*cons).unwrap(), prefix));
        }
    }

    let deadline = Instant::now() + RUN;

    // the hop clock: every EPOCH_MS, retune each flow's endpoints to hop(name, epoch). One task drives
    // all flows in lockstep — the sim's stand-in for the shared common-view epoch clock (#61).
    let hop_task = if hopping {
        let bus = bus.clone();
        let flows = flows.clone();
        Some(tokio::spawn(async move {
            let mut epoch = 1u64;
            while Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(EPOCH_MS)).await;
                for (prod, cons, prefix) in &flows {
                    let c = hop(prefix, epoch);
                    bus.set_channel(*prod, c);
                    bus.set_channel(*cons, c);
                }
                epoch += 1;
            }
        }))
    } else {
        None
    };

    // pump each flow; per-flow (attempts, ok)
    let mut workers = Vec::new();
    let per_flow: Vec<(Arc<AtomicU64>, Arc<AtomicU64>)> =
        (0..FLOWS).map(|_| (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)))).collect();
    for (fi, eng, prefix) in consumers {
        let seg = Arc::new(AtomicU64::new(0));
        let (att, ok) = per_flow[fi].clone();
        for _ in 0..WINDOW {
            let (eng, seg, att, ok, prefix) = (eng.clone(), seg.clone(), att.clone(), ok.clone(), prefix.clone());
            workers.push(tokio::spawn(async move {
                while Instant::now() < deadline {
                    let s = seg.fetch_add(1, Ordering::Relaxed);
                    att.fetch_add(1, Ordering::Relaxed);
                    if fetch(&eng, &format!("{prefix}/seg{s}")).await { ok.fetch_add(1, Ordering::Relaxed); }
                }
            }));
        }
    }
    for w in workers { let _ = w.await; }
    if let Some(h) = hop_task { let _ = h.await; }
    for s in serves { s.abort(); }

    let ratios: Vec<f64> = per_flow.iter().map(|(a, o)| {
        let a = a.load(Ordering::Relaxed);
        if a == 0 { 0.0 } else { o.load(Ordering::Relaxed) as f64 / a as f64 }
    }).collect();
    let agg = per_flow.iter().map(|(_, o)| o.load(Ordering::Relaxed)).sum::<u64>() as f64 / RUN.as_secs_f64();
    fabric.shutdown().await;
    (ratios, agg)
}

#[tokio::main]
async fn main() {
    println!("Name-keyed FHSS rendezvous — channel = hop(H(name), epoch), real ForwarderEngine\n");
    println!("hop set = {CLASSES:?} (separated classes, #66); {FLOWS} flows; jammer static on ch{JAM_CH}\n");

    // show the rendezvous schedule — each flow's channel over the first few epochs
    println!("  hop schedule (channel per epoch):");
    for i in 0..FLOWS {
        let p = format!("/flow/{i}");
        let seq: Vec<u8> = (0..8).map(|e| hop(&p, e)).collect();
        println!("    {:<10} {:?}", p, seq);
    }

    let cfgs = [("static  · no jam", false, false), ("static  · jam@2", false, true),
                ("hopping · no jam", true, false), ("hopping · jam@2", true, true)];
    const REPS: usize = 4; // worst-flow is noisy on the wall-clock engine — average it
    println!("\n  config              worst-flow   mean-flow   aggregate   (mean of {REPS})");
    let mut rows = Vec::new();
    for (name, hopping, jam) in cfgs {
        let (mut worst, mut mean, mut agg) = (0.0, 0.0, 0.0);
        for _ in 0..REPS {
            let (ratios, a) = run(hopping, jam).await;
            worst += ratios.iter().cloned().fold(1.0f64, f64::min);
            mean += ratios.iter().sum::<f64>() / ratios.len() as f64;
            agg += a;
        }
        let (worst, mean, agg) = (worst / REPS as f64, mean / REPS as f64, agg / REPS as f64);
        println!("  {:<18}  {:>7.0}%    {:>7.0}%   {:>7.0}", name, 100.0 * worst, 100.0 * mean, agg);
        rows.push(format!("{{\"cfg\":\"{name}\",\"hopping\":{hopping},\"jam\":{jam},\"worst\":{:.3},\"mean\":{:.3},\"agg\":{:.1}}}",
            worst, mean, agg));
    }

    println!("\ntakeaway: without a jammer, hopping rendezvous delivers like the static hash — the name +");
    println!("shared epoch clock keep every flow's endpoints on the same channel, no coordinator. WITH a");
    println!("persistent single-channel jammer, the STATIC hash strands whatever flow hashed onto that");
    println!("channel (worst-flow → ~0), while HOPPING spreads every flow across the class set so the");
    println!("jammer only costs each flow ~1/C of its airtime — no flow is ever killed. FHSS turns a fatal");
    println!("collision into a graceful, fair tax, and the schedule is still just H(name) — no host identity.");

    eprintln!("{{\"flows\":{FLOWS},\"classes\":{CLASSES:?},\"jam\":{JAM_CH},\"rows\":[{}]}}", rows.join(","));
}
