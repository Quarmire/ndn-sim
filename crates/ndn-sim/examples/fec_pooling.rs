//! **Ephemeral-count → FEC pooling — the one honest tie of ephemeral ID to link adaptation.**
//!
//! Rate adaptation can't key per-peer state on a per-frame-rotating nonce, so it doesn't (it keys on the
//! durable reception-report id). The nonce's honest contribution is the neighbour COUNT: the §2
//! source-nonce density feeds `receiver_count`, which feeds `fec_redundancy`'s pooling discount
//! (policy.rs:669):
//!     eff = phy^n ;  parity = ceil(k * eff / (1 - eff)).clamp(0, k)
//! `phy^n` is the probability all `n` receivers miss a frame — so redundancy (and airtime) SHRINKS as
//! the ephemeral count grows. This measures the lever AND bounds when it is valid, because `phy^n`
//! silently assumes two things:
//!
//! Part A — the discount: parity + airtime vs n, under ANY-OF pooling + independent loss (the regime the
//!   formula is built for). The benefit of knowing n — redundancy falls, pool-delivery holds.
//! Part B — the semantics gate: applying the any-of discount to an ALL-OF name (every receiver must
//!   decode — the worst-receiver/alarm case) COLLAPSES delivery. `phy^n` shrinks parity toward zero;
//!   all-of needs it to GROW with the worst receiver. The discount is name-semantics-gated, not free.
//! Part C — the independence gate: correlated loss (a shared interferer hitting all receivers at once —
//!   the contention reality) breaks `phy^n`. The all-miss probability rises from phy^n toward phy, the
//!   parity sized for independence under-provisions, and pool-delivery collapses.
//!
//! Faithful to the code formula (mean-loss sizing → ~50-60% generation success, re-Interest recovers the
//! tail). `cargo run --example fec_pooling --release -p ndn-sim`. Writes CSV + OTLP-in-Data spans.

use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;

use ndn_observability::{Attr, SpanKind, SpanPublisher, SpanRetention};
use ndn_packet::Name;
use ndn_sim::telemetry::SimSpanEmitter;
use ndn_sim::ImmediateRuntime;

const K: usize = 32; // generation_k

/// Binomial P(X ≥ k), X ~ Binom(n, p) — the systematic K-of-N decode probability. Log-space terms.
fn binom_ge(n: usize, k: usize, p: f64) -> f64 {
    if k == 0 { return 1.0; }
    if p <= 0.0 { return 0.0; }
    if p >= 1.0 { return 1.0; }
    let mut prob = 0.0;
    for x in k..=n {
        let mut logc = 0.0f64;
        for i in 0..x { logc += ((n - i) as f64).ln() - ((i + 1) as f64).ln(); }
        prob += (logc + x as f64 * p.ln() + (n - x) as f64 * (1.0 - p).ln()).exp();
    }
    prob.min(1.0)
}

/// The EXACT `fec_redundancy` sizing (policy.rs:669): parity for effective loss `eff`, clamped to k.
/// `None` when eff < 1e-3 (the code returns no parity — the pool is deep enough).
fn code_parity(eff: f64) -> Option<usize> {
    if eff < 1e-3 { return None; }
    let eff = eff.min(0.95);
    Some(((K as f64 * eff / (1.0 - eff)).ceil() as usize).min(K))
}

fn main() {
    let dir = "docs/data/link-adapt";
    let _ = std::fs::create_dir_all(dir);
    let mut csv = std::fs::File::create(format!("{dir}/fec_pooling.csv")).unwrap();
    writeln!(csv, "part,arm,x,value,detail").unwrap();

    let publisher = SpanPublisher::new(Name::from_str("/sim/mac/link/pooling/traces").unwrap(), SpanRetention::default());
    let otlp = SimSpanEmitter::new(Arc::clone(&publisher), Arc::new(ImmediateRuntime));
    let mut vclock: u64 = 0;

    let phy = 0.30f64; // per-receiver per-frame loss on a marginal link

    // ---- Part A — the pooling discount (any-of, independent) --------------------------------------
    println!("PART A — the ephemeral COUNT drives the FEC discount (phy={phy}, any-of, independent).");
    println!("{:<6}{:>10}{:>10}{:>10}{:>16}{:>16}", "n", "eff=phy^n", "parity", "N", "airtime (rel)", "pool-delivery");
    let base_n = {
        // reference airtime at n=1 (N = K + parity).
        let p = code_parity(phy).unwrap_or(0);
        (K + p) as f64
    };
    for n in 1..=6usize {
        let eff = phy.powi(n as i32);
        let parity = code_parity(eff).unwrap_or(0);
        let big_n = K + parity;
        let air = big_n as f64 / base_n; // relative airtime (fixed rate ⇒ ∝ N)
        // pool per-frame reception = 1 - phy^n (at least one of n receivers gets the frame); the pool
        // (cooperative relay/recode) decodes iff it collects ≥K of N.
        let p_pool = 1.0 - phy.powi(n as i32);
        let deliver = binom_ge(big_n, K, p_pool);
        println!("{:<6}{:>10.4}{:>10}{:>10}{:>15.0}%{:>15.0}%", n, eff, parity, big_n, air * 100.0, deliver * 100.0);
        writeln!(csv, "A,discount,{n},{:.4},parity={parity};N={big_n};deliver={:.3}", air, deliver).ok();
        let start = vclock; vclock += 1000;
        otlp.span("mac.pooling.discount", SpanKind::Internal, start, vclock,
            vec![Attr::int("n", n as i64), Attr::int("parity", parity as i64), Attr::int("airtime_pct", (air * 100.0) as i64), Attr::int("deliver_pct", (deliver * 100.0) as i64)]);
    }
    println!("  ⇒ redundancy + airtime SHRINK as the ephemeral count grows (46→32, ~30% less), pool-");
    println!("    delivery holds. This is the honest contribution of the §2 nonce: the count, not identity.");

    // ---- Part B — the semantics gate: any-of discount applied to an all-of name -------------------
    println!("\nPART B — the discount is ANY-OF only. Apply it to an ALL-OF name (every RX must decode):");
    println!("{:<6}{:>18}{:>20}{:>18}", "n", "any-of pool-deliver", "all-of w/ discount", "all-of sized right");
    // correct all-of parity: size so ONE receiver decodes ≥99% at raw phy (no n-discount).
    let mut n_allof = K;
    while binom_ge(n_allof, K, 1.0 - phy) < 0.99 { n_allof += 1; }
    for n in 1..=6usize {
        let eff = phy.powi(n as i32);
        let big_n = K + code_parity(eff).unwrap_or(0);
        let p_pool = 1.0 - phy.powi(n as i32);
        let anyof = binom_ge(big_n, K, p_pool);
        // all-of with the (too-small) any-of block: EVERY receiver must independently decode K of big_n.
        let per_rx = binom_ge(big_n, K, 1.0 - phy);
        let allof_discounted = per_rx.powi(n as i32);
        // all-of correctly sized: every receiver decodes K of n_allof at ≥99%.
        let allof_right = binom_ge(n_allof, K, 1.0 - phy).powi(n as i32);
        println!("{:<6}{:>17.0}%{:>19.1}%{:>17.1}%", n, anyof * 100.0, allof_discounted * 100.0, allof_right * 100.0);
        writeln!(csv, "B,semantics,{n},{:.4},anyof={:.3};allof_right={:.3}", allof_discounted, anyof, allof_right).ok();
    }
    println!("  ⇒ any-of holds; the SAME discount on an all-of name collapses toward 0 (parity shrinks when");
    println!("    all-of needs it to GROW). all-of sized right (N={n_allof}, no n-discount) holds ~99%^n.");
    println!("    The name's reliability semantics MUST gate the pooling discount — it is not free.");

    // ---- Part C — the independence gate: correlated loss breaks phy^n -----------------------------
    println!("\nPART C — the discount assumes INDEPENDENT loss. Correlated loss (a shared interferer) breaks");
    println!("it. n=4, parity sized for phy^4 (assumes independence); actual loss has a common component c.");
    let n = 4usize;
    let big_n = K + code_parity(phy.powi(n as i32)).unwrap_or(0);
    println!("  parity sized as if independent: N={big_n}");
    println!("{:<28}{:>18}{:>16}", "loss correlation (common c)", "pool per-frame rx", "pool-delivery");
    for c in [0.0f64, 0.05, 0.15, 0.30] {
        // marginal phy = c + (1-c)*phy_ind  ⇒  phy_ind = (phy - c)/(1 - c) when c ≤ phy.
        let phy_ind = if c >= phy { 0.0 } else { (phy - c) / (1.0 - c) };
        // pool gets a frame iff NOT common-lost AND ≥1 receiver's independent draw succeeds.
        let p_pool = (1.0 - c) * (1.0 - phy_ind.powi(n as i32));
        let deliver = binom_ge(big_n, K, p_pool);
        let tag = if c == 0.0 { " (independent)" } else if c >= phy { " (fully correlated)" } else { "" };
        println!("{:<28}{:>17.1}%{:>15.0}%", format!("c = {c:.2}{tag}"), p_pool * 100.0, deliver * 100.0);
        writeln!(csv, "C,correlation,{c},{:.4},p_pool={:.3}", deliver, p_pool).ok();
        let start = vclock; vclock += 1000;
        otlp.span("mac.pooling.correlation", SpanKind::Internal, start, vclock,
            vec![Attr::str("c", &format!("{c:.2}")), Attr::int("p_pool_pct", (p_pool * 100.0) as i64), Attr::int("deliver_pct", (deliver * 100.0) as i64)]);
    }
    println!("  ⇒ as loss correlates (all receivers behind one interferer), all-miss rises from phy^n toward");
    println!("    phy, the independence-sized parity under-provisions, and pool-delivery collapses. The");
    println!("    discount needs the losses to actually be independent — contention (correlated) voids it.");

    println!("\nOTLP-in-Data: {} spans emitted through ndn-observability.", publisher.len());
    println!("HEADLINE: the ephemeral count is a REAL FEC lever (Part A: ~30% airtime off at n≥3) but a");
    println!("DOUBLY-GATED one — valid only for any-of names (Part B) with independent loss (Part C). Blind");
    println!("application under-provisions an alarm (all-of) name or a contended (correlated) channel. So");
    println!("the pooling discount must read the name's reliability semantics AND a correlation estimate,");
    println!("not just the count. The ephemeral nonce supplies the count honestly; the gates are the design.");
    println!("wrote {dir}/fec_pooling.csv");
}
