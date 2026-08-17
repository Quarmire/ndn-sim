//! **Link adaptation — the worst-receiver penalty, and what actually beats it** (the HOW-WELL facet).
//!
//! A named BROADCAST radio has no PHY ACKs and must serve every receiver in a name-group with ONE
//! transmission. The classic answer is leader-based rate: pick the PHY rate the WORST receiver decodes
//! (built here: `worst_neighbor_rx_mcs` → `mcs_ceiling`). That throttles the strong to the weakest.
//! Two candidates claim to beat it: systematic K-of-N FEC (built) and rateless/RLNC (unwired at the
//! link, #58). This measures whether either is the real lever — or whether the NAME's reliability
//! target is.
//!
//! Model: C heterogeneous receivers (RSSI spread weak→strong), an 11n-like rate→erasure cliff, a
//! generation of K payload units broadcast once. Erasure e_i(r) rises steeply once a receiver falls
//! below a rate's sensitivity threshold (mirrors `mcs_for_rssi`). Analytic expected values + a binomial
//! decode tail for FEC — no RNG (deterministic, reproducible).
//!
//! Part A — the tail problem: pure rate selection (no coding) CANNOT serve a straggler below the
//!   lowest rate's floor. Coding is mandatory for the tail, not optional.
//! Part B — worst-rate+FEC vs rateless-at-rate for an ALARM name (serve EVERYONE incl. the straggler):
//!   does rateless beat the systematic baseline when the straggler gates airtime either way?
//! Part C — the per-NAME reliability target: ALARM (wait for the straggler) vs BULK (drop the straggler,
//!   it re-Interests later) — the airtime/throughput trade the name class picks. THE hypothesis: this
//!   dominates the coding choice.
//!
//! `cargo run --example link_adapt --release -p ndn-sim`. Writes CSV.

use std::io::Write;

// 11n 20 MHz LGI, MCS 0..7: rate (Mbit/s) and approx RX sensitivity (min RSSI dBm to decode cleanly).
const RATE_MBPS: [f64; 8] = [6.5, 13.0, 19.5, 26.0, 39.0, 52.0, 58.5, 65.0];
const RATE_THR_DBM: [f64; 8] = [-82.0, -79.0, -77.0, -74.0, -70.0, -66.0, -65.0, -64.0];

const K: usize = 32; // payload units in a generation

/// Per-receiver erasure at rate r. At/above the rate's threshold: a 3% floor. Below it: climbs ~9%/dB
/// (a rate cliff). A receiver well below even MCS0's threshold has high erasure at EVERY rate — the
/// straggler that rate selection alone cannot save.
fn erasure(rssi: f64, r: usize) -> f64 {
    let thr = RATE_THR_DBM[r];
    if rssi >= thr {
        0.03
    } else {
        (0.03 + 0.09 * (thr - rssi)).min(0.97)
    }
}

/// Highest rate index every receiver in `group` can decode cleanly (rssi ≥ threshold). None if even the
/// weakest can't clear MCS0 — the straggler case (rate selection alone fails).
fn worst_rate(group: &[f64]) -> Option<usize> {
    (0..8).rev().find(|&r| group.iter().all(|&rssi| rssi >= RATE_THR_DBM[r]))
}

/// Binomial P(X ≥ k) for X ~ Binom(n, p) — the systematic K-of-N decode probability (recover K from any
/// K of N received). Direct sum; n stays small here.
fn binom_ge(n: usize, k: usize, p: f64) -> f64 {
    if k == 0 { return 1.0; }
    if p <= 0.0 { return 0.0; }
    let mut prob = 0.0;
    for x in k..=n {
        // C(n,x) p^x (1-p)^(n-x), computed in log space for stability.
        let mut logc = 0.0f64;
        for i in 0..x { logc += ((n - i) as f64).ln() - ((i + 1) as f64).ln(); }
        let logp = logc + x as f64 * p.ln() + (n - x) as f64 * (1.0 - p).ln();
        prob += logp.exp();
    }
    prob.min(1.0)
}

/// Airtime (ms) to transmit `symbols` units at rate index r (one unit ≈ one MCS symbol-block; relative
/// scale, K units of app data). Airtime scales as symbols / rate.
fn airtime_ms(symbols: f64, r: usize) -> f64 {
    // K units of ~1500 B at RATE_MBPS: (symbols * 1500 * 8 bits) / (rate * 1e6) * 1e3 ms.
    symbols * 1500.0 * 8.0 / (RATE_MBPS[r] * 1e6) * 1e3
}

/// Rateless: expected transmitted symbols for receiver i to collect K useful (non-erased) ones at rate
/// r. Any coded symbol is useful (the rateless property), so E[transmissions] = K / (1 - e_i). The
/// SENDER streams until the target percentile of receivers has decoded → its airtime is gated by that
/// receiver's requirement.
fn rateless_symbols_for(rssi: f64, r: usize) -> f64 {
    let e = erasure(rssi, r);
    if e >= 0.999 { f64::INFINITY } else { K as f64 / (1.0 - e) }
}

fn main() {
    let dir = "docs/data/link-adapt";
    let _ = std::fs::create_dir_all(dir);
    let mut csv = std::fs::File::create(format!("{dir}/link_adapt.csv")).unwrap();
    writeln!(csv, "part,arm,x,value,detail").unwrap();

    // A heterogeneous name-group: a very weak straggler below MCS0's floor, up to a strong receiver.
    let group = [-84.0f64, -80.0, -74.0, -68.0, -62.0, -56.0];
    let strong = group[group.len() - 1];
    let straggler = group[0];
    let rest: Vec<f64> = group[1..].to_vec(); // group without the straggler

    println!("Name-group RSSI (dBm): {group:?}   straggler={straggler}  strong={strong}\n");

    // ---- Part A — rate selection alone cannot serve the tail --------------------------------------
    println!("PART A — can pure rate selection (no coding) serve everyone?");
    match worst_rate(&group) {
        Some(r) => println!("  worst-receiver rate = MCS{r} ({} Mbit/s) — all decode cleanly", RATE_MBPS[r]),
        None => {
            let e = erasure(straggler, 0);
            println!("  NONE — the straggler ({straggler} dBm) can't clear even MCS0; erasure {:.0}% at MCS0.", e * 100.0);
            println!("  ⇒ systematic transmission drops {:.0}% of its symbols → NO decode without FEC.", e * 100.0);
            println!("  Rate adaptation alone is INSUFFICIENT for the tail; coding is mandatory, not optional.");
            writeln!(csv, "A,worst_rate_exists,0,0,straggler_below_mcs0_floor").ok();
        }
    }
    // If we drop the straggler, a worst-rate DOES exist for the rest.
    if let Some(r) = worst_rate(&rest) {
        println!("  (drop the straggler → worst-rate for the rest = MCS{r} ({} Mbit/s))", RATE_MBPS[r]);
        writeln!(csv, "A,worst_rate_without_straggler,{r},{:.1},rest_only", RATE_MBPS[r]).ok();
    }

    // ---- Part B — ALARM name (serve everyone): systematic-FEC vs rateless, BOTH rate-swept ---------
    // FAIR comparison: sweep the PHY rate for BOTH schemes (an earlier version pinned FEC to MCS0 while
    // sweeping rateless — a rigged win). Systematic K-of-N is a FIXED block: pre-size N per rate so the
    // straggler decodes K of N with ≥99% probability (the built link-FEC behaviour, link_fec.rs).
    // Rateless is INCREMENTAL: stream until decode. The only honest gap between them is block-vs-
    // incremental redundancy — measure it.
    println!("\nPART B — ALARM name (must serve the straggler). Airtime to deliver to EVERYONE.");
    println!("  systematic FEC (fixed block, 99% straggler decode), swept over PHY rate:");
    let mut fec_best = (f64::INFINITY, 0usize, 0usize);
    for r in 0..8 {
        let e = erasure(straggler, r);
        if e >= 0.97 { continue; } // straggler can't be served at this rate for any finite block
        let mut n = K;
        // cap the block so an un-decodable rate doesn't loop forever.
        while n < 4000 && binom_ge(n, K, 1.0 - e) < 0.99 { n += 1; }
        if binom_ge(n, K, 1.0 - e) < 0.99 { continue; }
        let air = airtime_ms(n as f64, r);
        println!("      MCS{r} ({:>4} Mbit/s): N={:>4} (R={:>4}) → {:.2} ms", RATE_MBPS[r], n, n - K, air);
        writeln!(csv, "B,fec_rate_sweep,{r},{:.3},N={n}", air).ok();
        if air < fec_best.0 { fec_best = (air, r, n); }
    }
    let fec_air = fec_best.0;
    println!("  ⇒ systematic-FEC best = MCS{} (N={}) at {:.2} ms", fec_best.1, fec_best.2, fec_air);

    // Rateless: sweep the PHY rate. Sender streams until the STRAGGLER collects K (alarm ⇒ 100%). Its
    // airtime = rateless_symbols_for(straggler, r) / rate. Find the airtime-optimal rate.
    println!("  rateless (incremental, serve straggler), swept over PHY rate:");
    let mut best = (f64::INFINITY, 0usize);
    for r in 0..8 {
        let sym = rateless_symbols_for(straggler, r);
        if !sym.is_finite() { continue; }
        let air = airtime_ms(sym, r);
        println!("      MCS{r} ({:>4} Mbit/s): straggler needs {:>5.0} symbols → {:.2} ms", RATE_MBPS[r], sym, air);
        writeln!(csv, "B,rateless_rate_sweep,{r},{:.3},sym={sym:.0}", air).ok();
        if air < best.0 { best = (air, r); }
    }
    let coding_gain = (fec_air / best.0 - 1.0) * 100.0;
    println!("  ⇒ rateless best = MCS{} at {:.2} ms  vs  systematic-FEC best {:.2} ms", best.1, best.0, fec_air);
    println!("    rateless's incremental-vs-block advantage: {:.0}% less airtime (both rate-swept — fair).", coding_gain);
    // Strong-receiver decoupling: at the rateless best rate, when does the STRONG receiver finish?
    let strong_sym = rateless_symbols_for(strong, best.1);
    let strong_air = airtime_ms(strong_sym, best.1);
    println!("  strong receiver finishes at {:.2} ms ({:.0}x sooner than the straggler) — the rateless", strong_air, best.0 / strong_air);
    println!("  dividend: strong RX gets its data early even though the SENDER streams until the straggler.");
    writeln!(csv, "B,rateless_strong_finish,{},{:.3},sooner", best.1, strong_air).ok();

    // ---- Part C — the per-NAME reliability target: the dominant lever -----------------------------
    // BULK name: the straggler is tolerable — serve the REST (drop the -84 straggler; it re-Interests).
    // Now the worst receiver is -80 (clears MCS0), and a higher rate is available. Rateless at that rate.
    println!("\nPART C — the per-NAME reliability target (ALARM: wait for straggler | BULK: drop it).");
    let bulk_worst = rest.iter().cloned().fold(f64::INFINITY, f64::min); // -80
    // Rateless best rate serving the bulk-worst receiver.
    let mut bulk_best = (f64::INFINITY, 0usize);
    for r in 0..8 {
        let sym = rateless_symbols_for(bulk_worst, r);
        if !sym.is_finite() { continue; }
        let air = airtime_ms(sym, r);
        if air < bulk_best.0 { bulk_best = (air, r); }
    }
    let alarm_air = best.0; // from Part B: serve everyone
    let bulk_air = bulk_best.0;
    let goodput_alarm = airtime_ms(K as f64, 0) / alarm_air; // relative useful throughput
    let bulk_goodput = airtime_ms(K as f64, 0) / bulk_air;
    println!("  ALARM (serve all): rateless MCS{}  → {:.2} ms", best.1, alarm_air);
    println!("  BULK  (drop straggler, serve ≥{} dBm): rateless MCS{} → {:.2} ms", bulk_worst, bulk_best.1, bulk_air);
    println!("  ⇒ the BULK target is {:.1}x faster than ALARM by dropping ONE straggler.", alarm_air / bulk_air);
    println!("    Compare the levers: name-target = {:.0}% airtime cut; coding (rateless vs FEC) = {:.0}%.", (1.0 - bulk_air / alarm_air) * 100.0, coding_gain);
    writeln!(csv, "C,alarm_serve_all,{},{:.3},goodput={goodput_alarm:.2}", best.1, alarm_air).ok();
    writeln!(csv, "C,bulk_drop_straggler,{},{:.3},goodput={bulk_goodput:.2}", bulk_best.1, bulk_air).ok();

    println!("\nHEADLINE: three levers, ranked by measured airtime impact. (1) The per-NAME reliability target");
    println!("is the DOMINANT lever — ALARM pays full airtime for the tail; BULK drops the straggler (it");
    println!("re-Interests) and runs multiples faster. (2) Coding (rateless's incremental redundancy vs a");
    println!("pre-sized systematic block) is a REAL but smaller lever, both rate-swept. (3) Rate selection");
    println!("stays MANDATORY — the tail needs the floor (Part A). Rateless's non-airtime gift is DECOUPLING:");
    println!("the strong receiver finishes early regardless of when the sender stops for the straggler.");
    println!("wrote {dir}/link_adapt.csv");
}
