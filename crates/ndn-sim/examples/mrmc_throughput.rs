//! Multi-radio / multi-channel (MRMC) capacity — the ndnpipes payoff, and its honest limits.
//!
//! Two halves, both on the same slotted-CSMA capacity model + the pluggable `ChannelModel` (so
//! adjacent-channel leakage is real, not a free 1/K):
//!
//!   A. **Parallel pipes.** K named flows share one region; assign them to C channels. On perfectly
//!      orthogonal channels aggregate throughput scales ~C×; with adjacent-channel leakage it scales
//!      only ~C/2 (neighbouring channels still collide). "Put the pipes on different channels" helps —
//!      but leakage taxes it, and the tax is measured, not assumed.
//!
//!   B. **Multi-radio chain.** The single-radio chain collapses to ~1/8 at 4 hops (half-duplex +
//!      interference). Give each relay 2 radios and alternate the hop channels: adjacent hops no longer
//!      interfere and the relay can receive on one radio while transmitting on the other — the chain
//!      pipelines and the capacity climbs back up. This is why MRMC matters for multi-hop, and why the
//!      classic IP/802.11s single-radio stacks can't do it natively.
//!
//! Run: `cargo run -p ndn-sim --example mrmc_throughput`

use ndn_sim::{AdjacentLeakChannel, ChannelModel, OrthogonalChannels};

const SLOTS: u64 = 20_000;
const WINDOW: u64 = 64;
const THRESH: f64 = 0.1; // coupling above which two transmissions collide

// ---- A. parallel pipes in one collision domain -------------------------------------------------
/// K single-hop pipes, all mutually in range, pipe i on channel `i % channels`. Returns aggregate
/// delivered objects per slot (the max set of pipes that can transmit at once under the coupling).
fn parallel_pipes(pipes: usize, channels: usize, ch: &dyn ChannelModel) -> f64 {
    let chan: Vec<u8> = (0..pipes).map(|i| (i % channels) as u8).collect();
    let mut total = 0u64;
    let mut rr = 0usize;
    for _ in 0..SLOTS {
        let mut active: Vec<u8> = Vec::new();
        // rotate start for fairness (doesn't change the aggregate, which is the independent-set size)
        for k in 0..pipes {
            let i = (k + rr) % pipes;
            let c = chan[i];
            if !active.iter().any(|&a| ch.coupling(a, c) > THRESH) {
                active.push(c);
                total += 1;
            }
        }
        rr = (rr + 1) % pipes;
    }
    total as f64 / SLOTS as f64
}

// ---- B. multi-radio, multi-channel chain -------------------------------------------------------
#[derive(Clone, Copy)]
struct Tx {
    t: i64,
    r: i64,
    ch: u8,
}

/// Saturated Interest→Data flow through an `h`-hop chain with `radios` per node and `channels`
/// channels; hop i uses channel `i % channels`. Half-duplex is PER RADIO (a 2-radio node can RX+TX
/// at once on different channels); interference is per the channel coupling. Objects/slot.
fn chain_mrmc(hops: i64, channels: usize, radios: usize, cs_range: i64, ch: &dyn ChannelModel) -> f64 {
    let n = (hops + 1) as usize;
    let hop_ch = |i: i64| (i as usize % channels) as u8;
    let mut fwd = vec![0u64; n];
    let mut rev = vec![0u64; n];
    let (mut outstanding, mut done) = (0u64, 0u64);
    let mut rr = 0usize;
    for _ in 0..SLOTS {
        while outstanding < WINDOW {
            fwd[0] += 1;
            outstanding += 1;
        }
        let mut cands: Vec<Tx> = Vec::new();
        for i in 0..hops {
            if fwd[i as usize] > 0 {
                cands.push(Tx { t: i, r: i + 1, ch: hop_ch(i) });
            }
        }
        for i in 1..=hops {
            if rev[i as usize] > 0 {
                cands.push(Tx { t: i, r: i - 1, ch: hop_ch(i - 1) });
            }
        }
        if cands.is_empty() {
            continue;
        }
        let len = cands.len();
        rr = (rr + 1) % len;
        cands.rotate_left(rr);

        let mut active: Vec<Tx> = Vec::new();
        let mut radio_use = vec![0usize; n]; // radios busy per node this slot
        for c in cands {
            if radio_use[c.t as usize] >= radios || radio_use[c.r as usize] >= radios {
                continue; // no free radio at either endpoint (half-duplex per radio)
            }
            let conflict = active.iter().any(|a| {
                let coupled = ch.coupling(a.ch, c.ch) > THRESH;
                coupled
                    && ((a.t - c.r).abs() <= cs_range
                        || (c.t - a.r).abs() <= cs_range
                        || (a.t - c.t).abs() <= cs_range)
            });
            if !conflict {
                radio_use[c.t as usize] += 1;
                radio_use[c.r as usize] += 1;
                active.push(c);
            }
        }
        for a in &active {
            if a.r > a.t {
                fwd[a.t as usize] -= 1;
                if a.r == hops {
                    rev[hops as usize] += 1;
                } else {
                    fwd[a.r as usize] += 1;
                }
            } else {
                rev[a.t as usize] -= 1;
                if a.r == 0 {
                    done += 1;
                    outstanding -= 1;
                } else {
                    rev[a.r as usize] += 1;
                }
            }
        }
    }
    done as f64 / SLOTS as f64
}

fn main() {
    let ortho = OrthogonalChannels;
    let leaky = AdjacentLeakChannel::default(); // adjacent coupling 0.2

    println!("A. parallel pipes — 8 flows in one region, assigned to C channels (aggregate obj/slot)\n");
    println!("  channels   orthogonal   adjacent-leak   leak tax");
    for c in [1usize, 2, 3, 4, 6, 8] {
        let o = parallel_pipes(8, c, &ortho);
        let l = parallel_pipes(8, c, &leaky);
        println!(
            "  {:>5}      {:>8.1}×    {:>9.1}×      {:>4.0}%",
            c, o, l, if o > 0.0 { 100.0 * (1.0 - l / o) } else { 0.0 }
        );
    }
    println!("  → orthogonal channels give ~C× parallelism; adjacent-channel leakage cuts it ~in half");
    println!("    (neighbouring channels still collide) — the honest ndnpipes-on-orthogonal-channels gain.");

    println!("\nB. multi-radio chain — does MRMC break the single-radio multi-hop collapse?\n");
    let base = chain_mrmc(1, 1, 1, 4, &ortho); // single-hop channel capacity (one flow)
    println!("  hops   1r/1ch   2r/2ch(ortho)   2r/2ch(leaky)   3r/3ch(ortho)   (÷ single-hop)");
    for h in [2i64, 3, 4, 6, 8] {
        let a = chain_mrmc(h, 1, 1, 4, &ortho) / base;
        let b = chain_mrmc(h, 2, 2, 4, &ortho) / base;
        let c = chain_mrmc(h, 2, 2, 4, &leaky) / base;
        let d = chain_mrmc(h, 3, 3, 4, &ortho) / base;
        println!("  {:>3}    {:>6.3}   {:>10.3}    {:>10.3}    {:>10.3}", h, a, b, c, d);
    }
    println!("\ntakeaway: 1-radio/1-channel is the ~1/8-at-4-hops collapse. Two radios on two alternating");
    println!("channels let a relay RX+TX at once and stop adjacent hops interfering — the chain pipelines");
    println!("and capacity climbs back toward the single-hop rate. Leakage claws some back (adjacent hops");
    println!("aren't perfectly orthogonal). Stock IP/802.11s can't do this natively — the fair MRMC");
    println!("comparison must be against the research multi-radio routing schemes (#69).");

    // JSON (stderr) for the dashboard.
    let pipes: Vec<String> = [1usize, 2, 3, 4, 6, 8]
        .iter()
        .map(|&c| {
            format!(
                "{{\"c\":{c},\"ortho\":{:.2},\"leaky\":{:.2}}}",
                parallel_pipes(8, c, &ortho),
                parallel_pipes(8, c, &leaky)
            )
        })
        .collect();
    let chain: Vec<String> = [2i64, 3, 4, 6, 8]
        .iter()
        .map(|&h| {
            format!(
                "{{\"hops\":{h},\"r1\":{:.3},\"r2o\":{:.3},\"r2l\":{:.3},\"r3o\":{:.3}}}",
                chain_mrmc(h, 1, 1, 4, &ortho) / base,
                chain_mrmc(h, 2, 2, 4, &ortho) / base,
                chain_mrmc(h, 2, 2, 4, &leaky) / base,
                chain_mrmc(h, 3, 3, 4, &ortho) / base
            )
        })
        .collect();
    eprintln!("{{\"pipes\":[{}],\"chain\":[{}]}}", pipes.join(","), chain.join(","));
}
