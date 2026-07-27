//! Multi-hop chain capacity — the real reason a single-radio chain collapses, modeled honestly.
//!
//! A saturated Interest→Data flow through an `h`-hop chain, scheduled by a slotted CSMA MAC. Three
//! physical facts, all present here, together produce the textbook collapse (worse than 1/(2h)):
//!   • **half-duplex** — a relay cannot receive while it transmits, so each hop uses the channel and
//!     the relay can't pipeline on one radio;
//!   • **interference range > decode range** — a transmission blocks not just the next hop but every
//!     node within `cs_range` hops, so non-adjacent hops still can't run concurrently (limited reuse);
//!   • **the round-trip contends** — the Interest (forward) and the Data (reverse) both traverse the
//!     same single channel, doubling the channel time per delivered object.
//!
//! Everything is a parameter (`cs_range`, `half_duplex`, `round_trip`) so the model stays pluggable
//! and can be tightened against measurements. Throughput is normalized to the one-hop rate.
//!
//! Run: `cargo run -p ndn-sim --example chain_throughput`

const SLOTS: u64 = 20_000;
const WINDOW: u64 = 64; // outstanding Interests (saturating, so the channel is the bottleneck)

/// A pending transmission `t → r` for the greedy CSMA scheduler.
#[derive(Clone, Copy)]
struct Tx {
    t: i64,
    r: i64,
}

/// Slotted CSMA saturated-flow throughput of an `h`-hop chain, in delivered objects per slot.
fn chain_tput(hops: i64, cs_range: i64, half_duplex: bool, round_trip: bool) -> f64 {
    let n = (hops + 1) as usize;
    let mut fwd = vec![0u64; n]; // Interests queued at each node, moving toward the producer (node hops)
    let mut rev = vec![0u64; n]; // Data queued at each node, moving back toward the consumer (node 0)
    let (mut outstanding, mut done) = (0u64, 0u64);
    let mut rr = 0usize; // rotating priority so no link starves

    for slot in 0..SLOTS {
        // Saturate the source: keep WINDOW Interests in flight.
        while outstanding < WINDOW {
            fwd[0] += 1;
            outstanding += 1;
        }

        // Candidate transmissions this slot: a forward hop for any node holding an Interest, and a
        // reverse hop for any node holding Data (skip the reverse flow entirely when round_trip=false).
        let mut cands: Vec<Tx> = Vec::new();
        for i in 0..hops {
            if fwd[i as usize] > 0 {
                cands.push(Tx { t: i, r: i + 1 });
            }
        }
        if round_trip {
            for i in 1..=hops {
                if rev[i as usize] > 0 {
                    cands.push(Tx { t: i, r: i - 1 });
                }
            }
        }
        if cands.is_empty() {
            continue;
        }
        // Rotate the priority order each slot for fairness.
        let len = cands.len();
        rr = (rr + 1) % len;
        cands.rotate_left(rr);

        // Greedy CSMA: activate a transmission only if it neither carrier-senses nor is interfered by
        // an already-active one, and respects half-duplex (a node can't be in two active links).
        let mut active: Vec<Tx> = Vec::new();
        for c in cands {
            let conflict = active.iter().any(|a| {
                // Half-duplex / one-packet-per-node: shared endpoints can't both act.
                let shared = half_duplex
                    && (a.t == c.t || a.t == c.r || a.r == c.t || a.r == c.r);
                // Interference: a's transmitter within cs_range of c's receiver, or c's transmitter
                // within cs_range of a's receiver (each would corrupt the other's reception).
                let interf = (a.t - c.r).abs() <= cs_range || (c.t - a.r).abs() <= cs_range;
                // Carrier sense: c defers if it HEARS an active transmitter within range — even when
                // it wouldn't actually collide (the exposed-terminal waste that makes real CSMA fall
                // below the idealized-TDMA capacity). Transmitter-to-transmitter, symmetric.
                let cs_defer = (a.t - c.t).abs() <= cs_range;
                shared || interf || cs_defer
            });
            if !conflict {
                active.push(c);
            }
        }

        // Execute: move one packet per active link.
        for a in &active {
            if a.r > a.t {
                // forward hop
                fwd[a.t as usize] -= 1;
                if a.r == hops {
                    if round_trip {
                        rev[hops as usize] += 1; // producer turns the Interest into Data
                    } else {
                        done += 1; // forward-only mode: an Interest reaching the producer counts
                        outstanding -= 1;
                    }
                } else {
                    fwd[a.r as usize] += 1;
                }
            } else {
                // reverse hop
                rev[a.t as usize] -= 1;
                if a.r == 0 {
                    done += 1; // a fetch completed at the consumer
                    outstanding -= 1;
                } else {
                    rev[a.r as usize] += 1;
                }
            }
        }
        let _ = slot;
    }
    done as f64 / SLOTS as f64
}

fn main() {
    println!("multi-hop chain capacity — slotted CSMA, saturated Interest→Data flow\n");
    // The carrier-sense span dominates the collapse. Real 802.11 CS range exceeds the interference
    // range (which exceeds the decode range), and CSMA's exposed-terminal deferral wastes more still,
    // so a chain in practice sits well below the idealized-TDMA 1/4. Show the sensitivity, then the
    // realistic curve.
    // Baseline = the single-hop CHANNEL capacity: one saturated one-way link, 1 object/slot. (The
    // round-trip flow already pays half of that at 1 hop, since Interest and Data share the link.)
    println!("  carrier-sense span sensitivity (round-trip throughput ÷ single-hop channel capacity):");
    println!("  cs_range   3 hops    4 hops    8 hops");
    for cs in [2i64, 3, 4] {
        let base = chain_tput(1, cs, true, false); // = 1.0 obj/slot
        println!(
            "  {:>5}      {:>5.3}     {:>5.3}     {:>5.3}",
            cs,
            chain_tput(3, cs, true, true) / base,
            chain_tput(4, cs, true, true) / base,
            chain_tput(8, cs, true, true) / base
        );
    }

    let cs = 4; // realistic single-radio 802.11-class chain (CS range ~2× tx range + exposed-terminal waste)
    let base = chain_tput(1, cs, true, false); // single-hop one-way channel capacity
    println!("\n  realistic curve (cs_range={cs} hops, half-duplex ON, round-trip ON):");
    println!("  hops   obj/slot   ÷ single-hop   note");
    for h in [1i64, 2, 3, 4, 5, 6, 8] {
        let t = chain_tput(h, cs, true, true);
        let note = match h {
            3 => "  ≈ 1/6 (worse than 1/4)",
            4 => "  ≈ 1/8",
            _ => "",
        };
        println!("  {:>3}    {:>8.4}    {:>8.3}    {}", h, t, t / base, note);
    }

    // Ablation: what each physical effect costs at 4 hops (5 nodes), ÷ single-hop channel capacity.
    println!("\n  ablation at 4 hops (÷ single-hop channel capacity):");
    let base = chain_tput(1, cs, true, false); // one-way single-hop = 1.0
    let full = chain_tput(4, cs, true, true) / base;
    let no_rt = chain_tput(4, cs, true, false) / base;
    let cs1 = chain_tput(4, 1, true, true) / base;
    println!("    full physics (interference + carrier-sense + round-trip):  {full:.3}  ← ≈ 1/8");
    println!("    without the reverse (Data) flow contending (one-way):      {no_rt:.3}");
    println!("    interference range = 1 hop (optimistic reuse):             {cs1:.3}");
    println!("\ntakeaway: full single-radio physics puts a 4-hop chain near 1/8 of the single-hop channel");
    println!("throughput and 3 hops near 1/6 — the classic collapse, well below the naive 1/hops. The");
    println!("contending return path costs ~2× (one-way is {:.3}); wide interference + carrier-sense", no_rt);
    println!("defer-waste do the rest. All of it is parameterised (cs_range / half_duplex / round_trip).");

    // JSON (stderr) for the dashboard: normalized capacity vs hops, plus the naive-1/hops reference.
    let cap: Vec<String> = [1i64, 2, 3, 4, 5, 6, 8]
        .iter()
        .map(|&h| {
            format!(
                "{{\"hops\":{h},\"norm\":{:.4},\"naive\":{:.4}}}",
                chain_tput(h, cs, true, true) / base,
                1.0 / h as f64
            )
        })
        .collect();
    eprintln!("{{\"capacity\":[{}]}}", cap.join(","));
}
