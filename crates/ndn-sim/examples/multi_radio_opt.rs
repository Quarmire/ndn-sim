//! **Multi-radio assignment optimizer + diversity** — for the REAL world (1–3 radios, asymmetric).
//!
//! 4+ radios is rare even in labs; nodes are asymmetric (radio count AND capability); single-radio is
//! the common case and must be first-class; a scarce radio is MULTI-ROLE (time-shares mover + sweeps).
//! The optimizer allocates scarce radio-time across roles to maximize delivered demand — and leans on
//! COOPERATIVE sensing so a poor node free-rides on a rich neighbour's occupancy map.
//!
//! Part A — delivered demand vs radio count, three policies:
//!   • naive       — every radio a mover on a top-demand channel; the map = only the movers' channels
//!                   (blind avoidance elsewhere).
//!   • optimizer   — spends one radio's worth of time SENSING (self) so avoidance is correct, at the
//!                   cost of mover coverage; at R=1 it TIME-SHARES (mover + partial sweep).
//!   • optimizer+coop — consumes a neighbour's SHARED map (no self-sensing) → all radio-time is mover
//!                   AND avoidance is correct. This is what makes single-radio / asymmetric nodes work.
//!
//! Part B — coverage vs diversity: R radios on DIFFERENT channels (coverage) vs the SAME channel
//!   (RX macro-diversity, combine). Diversity wins on a marginal link; coverage on a good link.
//!
//! `cargo run --example multi_radio_opt --release -p ndn-sim`. Writes CSV.

use std::io::Write;

const C: usize = 8;

fn zipf_demand() -> Vec<f64> {
    let mut d: Vec<f64> = (0..C).map(|i| 1.0 / (i as f64 + 1.0)).collect();
    let s: f64 = d.iter().sum();
    for x in &mut d { *x /= s; }
    d // demand[0] most popular … demand[C-1] least
}

/// top-k channels by a weight vector.
fn top(w: &[f64], k: usize) -> Vec<usize> {
    let mut idx: Vec<usize> = (0..C).collect();
    idx.sort_by(|&a, &b| w[b].partial_cmp(&w[a]).unwrap());
    idx.into_iter().take(k).collect()
}

/// Delivered demand fraction, given r_movers radios and a sensed set (map coverage). Movers FOLLOW the
/// effective (post-avoidance) demand; interfered channels' demand SPREADS across believed-clear
/// channels; a redirect to an unsensed-but-actually-bad channel is lost (the §9.2 harm).
fn value(demand: &[f64], r_movers: usize, sensed: &[usize], bad: &[usize]) -> f64 {
    let believed_clear: Vec<usize> =
        (0..C).filter(|c| if sensed.contains(c) { !bad.contains(c) } else { true }).collect();
    let dest = |c: usize| -> usize {
        if believed_clear.is_empty() { c } else { believed_clear[(c.wrapping_mul(2654435761)) % believed_clear.len()] }
    };
    // effective demand per channel after redirect, then place movers on the top of it.
    let mut eff = vec![0.0f64; C];
    for c in 0..C {
        eff[if bad.contains(&c) { dest(c) } else { c }] += demand[c];
    }
    let movers = top(&eff, r_movers);
    let mut del = 0.0;
    for c in 0..C {
        let landing = if bad.contains(&c) { dest(c) } else { c };
        if !bad.contains(&landing) && movers.contains(&landing) {
            del += demand[c]; // delivered iff it landed on a truly-clear channel a mover covers
        }
    }
    del
}

fn main() {
    let dir = "docs/data/spectrum-access";
    let _ = std::fs::create_dir_all(dir);
    let mut csv = std::fs::File::create(format!("{dir}/optimizer.csv")).unwrap();
    writeln!(csv, "part,policy,x,value").unwrap();
    let demand = zipf_demand();
    let bad = vec![0usize, 1, 2]; // a contiguous interfered BLOCK at the popular low channels

    println!("PART A — delivered demand vs radio count ({C} ch, 3 interfered incl. the busiest)\n");
    println!("{:<20}{:>10}{:>10}{:>10}{:>10}", "policy", "R=1", "R=2", "R=3", "R=4");
    for pol in ["naive", "optimizer", "optimizer+coop"] {
        print!("{:<20}", pol);
        for r in 1..=4usize {
            // (r_movers, sensed map) per policy.
            let (rm, sensed): (usize, Vec<usize>) = match pol {
                // naive: all r radios are movers; the map is only the movers' own channels.
                "naive" => (r, top(&demand, r)),
                // optimizer: spend one radio's time SENSING (full map), r-1 movers; at R=1 time-share
                // a partial sweep (misses half the channels).
                "optimizer" => {
                    if r == 1 { (1, (0..C).step_by(2).collect()) } else { (r - 1, (0..C).collect()) }
                }
                // coop: consume a neighbour's SHARED map (full), all r radios are movers.
                _ => (r, (0..C).collect()),
            };
            let v = value(&demand, rm, &sensed, &bad);
            print!("{:>9.0}%", v * 100.0);
            writeln!(csv, "policy,{pol},{r},{v:.4}").ok();
        }
        println!();
    }

    println!("\nPART B — coverage vs diversity: 2 radios, per-radio delivery p (link margin). same-channel");
    println!("diversity = 1-(1-p)^2 on ALL demand; different-channel coverage = p on top-2 channels' demand.");
    println!("{:<10}{:>18}{:>18}", "p (margin)", "coverage (spread)", "diversity (combine)");
    let top2 = top(&demand, 2);
    let cover_frac: f64 = top2.iter().map(|&c| demand[c]).sum(); // two channels' demand
    let div_frac: f64 = demand[top2[0]]; // ONE channel's demand, but received twice
    for p in [0.3f64, 0.5, 0.7, 0.9] {
        let coverage = p * cover_frac; // 2 radios on 2 channels, single reception each
        let diversity = (1.0 - (1.0 - p).powi(2)) * div_frac; // 2 radios on 1 channel, combine
        println!("{:<10}{:>17.0}%{:>17.0}%", format!("{p:.1}"), coverage * 100.0, diversity * 100.0);
        writeln!(csv, "diversity,coverage,{p},{coverage:.4}").ok();
        writeln!(csv, "diversity,diversity,{p},{diversity:.4}").ok();
    }

    println!("\nA: naive loses the interfered busiest channel (blind avoidance); optimizer sacrifices a mover to");
    println!("   sense (correct avoidance) — wins at low R; optimizer+coop (consume a neighbour's map) is best");
    println!("   AND makes R=1 viable. Diminishing returns past R=2-3 — matching '4+ radios is uncommon'.");
    println!("B: on a MARGINAL link (low p) diversity (combine 2 radios on one channel) beats coverage; on a");
    println!("   GOOD link coverage (spread) wins. The optimizer picks per link margin + demand spread.");
    println!("wrote {dir}/optimizer.csv");
}
