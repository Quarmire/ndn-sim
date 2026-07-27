//! Sim vs measurement — calibrate the multi-hop chain model to the real 802.11s mesh data.
//!
//! The reference (examples/data/real_wifi_multihop.json): MT7612U, 802.11s mesh, IP-bridged relays,
//! iperf3 UDP (one-way), 120 m base, single- vs multi-radio, 2/3 hops. Treated as *one* reference,
//! not the sole truth — the model stays general; this anchors its two free parameters.
//!
//! Model: a one-way saturated flow (matching one-way UDP) through the slotted-CSMA scheduler; each
//! hop on channel `i % channels`, `radios` per node (half-duplex per radio). The schedule gives the
//! STRUCTURAL ratio (single-radio serializes → ~1/hops; spaced multi-channel pipelines → ~1×); a
//! per-hop `link_eff` then captures the real MAC overhead beyond the ideal schedule — higher on the
//! clean, low-contention multi-radio channels, lower on the contended single channel. Two numbers,
//! calibrated once to the reference:
//!     single-radio  link_eff ≈ 0.72   (heavy contention → backoff/retry waste)
//!     multi-radio   link_eff ≈ 0.93   (orthogonal channels → little contention)
//!
//! Run: `cargo run -p ndn-sim --example sim_vs_real`

const SLOTS: u64 = 20_000;
const WINDOW: u64 = 64;
const CS: i64 = 2; // interference/carrier-sense span, hops

/// One-way saturated-flow schedule throughput (objects/slot) through an `h`-hop chain, hop i on
/// channel `i % channels`, `radios` per node. Orthogonal channels (co-channel interferes, else not).
fn schedule(hops: i64, channels: i64, radios: usize) -> f64 {
    let n = (hops + 1) as usize;
    let ch = |i: i64| i % channels;
    let mut q = vec![0u64; n];
    let mut done = 0u64;
    for _ in 0..SLOTS {
        q[0] = WINDOW; // saturate the source
        // Candidate forward hops, DOWNSTREAM-FIRST (higher hop first): drain toward the destination so
        // packets don't pile at the far relay and the half-duplex chain flows (the standard chain-MAC
        // fairness fix — else node 0 always claims the relay's one radio and downstream links starve).
        let mut cands: Vec<i64> = (0..hops).filter(|&i| q[i as usize] > 0).collect();
        cands.sort_unstable_by(|a, b| b.cmp(a));
        let mut active: Vec<(i64, i64)> = Vec::new(); // (tx, chan)
        let mut radio_use = vec![0usize; n];
        for t in cands {
            let r = t + 1;
            if radio_use[t as usize] >= radios || radio_use[r as usize] >= radios {
                continue;
            }
            let c = ch(t);
            // co-channel interferer within CS span (or carrier-sensed) blocks it
            let conflict = active.iter().any(|&(at, ac)| ac == c && (at - r).abs() <= CS || ac == c && (at - t).abs() <= CS);
            if !conflict {
                radio_use[t as usize] += 1;
                radio_use[r as usize] += 1;
                active.push((t, c));
            }
        }
        for (t, _) in &active {
            q[*t as usize] -= 1;
            if *t + 1 == hops {
                done += 1;
            } else {
                q[(*t + 1) as usize] += 1;
            }
        }
    }
    done as f64 / SLOTS as f64
}

/// Retention vs the 1-hop link: structural schedule ratio × the per-hop MAC efficiency.
fn retention(hops: i64, channels: i64, radios: usize, link_eff: f64) -> f64 {
    let base = schedule(1, channels, radios);
    schedule(hops, channels, radios) / base * link_eff.powi((hops - 1) as i32)
}

fn main() {
    // Calibrated per-hop efficiencies (to the mt7612u 802.11s reference).
    const SINGLE_EFF: f64 = 0.72;
    const MULTI_EFF: f64 = 0.93;

    // Reference averages (÷ base 120 m link) from real_wifi_multihop.json.
    let real_single = [("2 hop", 0.36), ("3 hop", 0.22)];
    let real_multi = [("2 hop", 0.94), ("3 hop", 0.87)];

    println!("sim vs measured 802.11s mesh (retention ÷ base 120 m link)\n");
    println!("  SINGLE-RADIO (1 channel, 1 radio, link_eff {SINGLE_EFF})");
    println!("    hops    sim     measured");
    for (h, (_, r)) in [2i64, 3].iter().zip(real_single.iter()) {
        let s = retention(*h, 1, 1, SINGLE_EFF);
        println!("    {h:>3}    {:.2}     {:.2}", s, r);
    }
    println!("\n  MULTI-RADIO (3 channels, 2 radios, link_eff {MULTI_EFF})");
    println!("    hops    sim     measured");
    for (h, (_, r)) in [2i64, 3].iter().zip(real_multi.iter()) {
        let s = retention(*h, 3, 2, MULTI_EFF);
        println!("    {h:>3}    {:.2}     {:.2}", s, r);
    }

    println!("\nfit: the schedule captures the STRUCTURE (single-radio serializes to ~1/hops; spaced");
    println!("multi-channel pipelines to ~1×), and one per-hop efficiency per regime lands it on the");
    println!("measured 802.11s mesh — a reference anchor, not a hard fit. The model stays general:");
    println!("change channels/radios/cs/link_eff and it tracks other setups (LoRa, HaLow, other spacing).");

    // JSON (stderr) for the sim-vs-real overlay: retention at 1/2/3 hops.
    let curve = |ch: i64, r: usize, eff: f64| -> String {
        [1i64, 2, 3].iter().map(|&h| format!("{:.3}", if h == 1 { 1.0 } else { retention(h, ch, r, eff) })).collect::<Vec<_>>().join(",")
    };
    eprintln!("{{\"hops\":[1,2,3],\"sim_single\":[{}],\"sim_multi\":[{}]}}", curve(1, 1, SINGLE_EFF), curve(3, 2, MULTI_EFF));
}
