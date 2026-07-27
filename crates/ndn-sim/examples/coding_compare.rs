//! Network-coding axes compared — F1 (end-to-end FEC) vs F2 (in-network RLNC recode) vs F3 (COPE
//! inter-flow XOR), each on the metric where its character shows, over a shared erasure axis.
//!
//! The intra-flow comparison is over a **2-hop lossy path** (source → relay → consumer), because that
//! is where F1 and F2 diverge: F1 parity is minted at the SOURCE, so a loss on the second hop forces
//! the source to resend across BOTH hops; F2 lets the RELAY recode locally, repairing the second hop
//! without re-crossing the first. Metric: total transmissions (both hops) to deliver a K-symbol
//! generation. Baseline "forward" is store-and-forward with no coding (coupon-collector on each hop).
//!
//! F3 (COPE) is inter-flow, so it gets its own metric: two flows crossing a relay, which XORs a packet
//! from each into ONE broadcast that both next-hops decode via their overheard native packet. Its gain
//! is transmissions saved, as a function of how balanced the two flows are (coding opportunities).
//!
//! Rank/coupon dynamics are simulated with erasure draws (GF(256) makes coded survivors innovative
//! w.h.p., matching the real ndn-coding recode codec); averaged over many generations.
//!
//! Run: `cargo run -p ndn-sim --example coding_compare > /tmp/coding.json`

const K: u32 = 12; // symbols per generation
const TRIALS: u32 = 4000;
const CAP: u32 = 100_000; // safety cap on transmissions

fn xs(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}
fn lost(rng: &mut u64, e: f64) -> bool {
    (xs(rng) % 10_000) as f64 / 10_000.0 < e
}

/// Store-and-forward, no coding. Coupon-collector to K distinct on hop1, then on hop2.
fn forward(e: f64, rng: &mut u64) -> u32 {
    let mut tx = 0;
    // hop1: relay collects K distinct source symbols (round-robin resend on loss).
    let mut have = vec![false; K as usize];
    let mut got = 0;
    let mut idx = 0;
    while got < K && tx < CAP {
        tx += 1;
        if !lost(rng, e) && !have[idx] {
            have[idx] = true;
            got += 1;
        }
        idx = (idx + 1) % K as usize;
    }
    // hop2: consumer collects K distinct from the relay.
    let mut chave = vec![false; K as usize];
    let mut cgot = 0;
    idx = 0;
    while cgot < K && tx < CAP {
        tx += 1;
        if !lost(rng, e) && !chave[idx] {
            chave[idx] = true;
            cgot += 1;
        }
        idx = (idx + 1) % K as usize;
    }
    tx
}

/// F1 — end-to-end coded (systematic MDS/RLNC minted at the SOURCE). The relay forwards every symbol
/// it receives verbatim (no recoding). A coded symbol is innovative w.h.p., so the consumer needs K
/// that survive BOTH hops; the source keeps minting fresh ones. Total = source TX + relay TX.
fn f1_e2e(e: f64, rng: &mut u64) -> u32 {
    let mut source_tx = 0;
    let mut relay_tx = 0;
    let mut consumer_rank = 0;
    while consumer_rank < K && source_tx < CAP {
        source_tx += 1;
        if lost(rng, e) {
            continue; // lost on hop1 — relay never sees it
        }
        relay_tx += 1; // relay forwards the received symbol verbatim
        if !lost(rng, e) {
            consumer_rank += 1; // survived hop2 and is innovative
        }
    }
    source_tx + relay_tx
}

/// F2 — in-network RLNC recode. The relay accumulates rank from hop1, then mints FRESH combinations
/// on hop2 from its own subspace, so second-hop losses are repaired locally without re-crossing hop1.
/// Total = hop1 TX (relay to rank K) + hop2 TX (consumer to rank K).
fn f2_recode(e: f64, rng: &mut u64) -> u32 {
    let mut tx = 0;
    // hop1: relay accumulates innovative rank up to K.
    let mut relay_rank = 0;
    while relay_rank < K && tx < CAP {
        tx += 1;
        if !lost(rng, e) {
            relay_rank += 1; // coded ⇒ innovative w.h.p.
        }
    }
    // hop2: relay recodes; every survivor is innovative until the consumer reaches relay_rank (=K).
    let mut consumer_rank = 0;
    while consumer_rank < relay_rank && tx < CAP {
        tx += 1;
        if !lost(rng, e) {
            consumer_rank += 1;
        }
    }
    tx
}

fn mean<F: Fn(f64, &mut u64) -> u32>(f: F, e: f64, seed: u64) -> f64 {
    let mut rng = seed | 1;
    let mut sum = 0u64;
    for _ in 0..TRIALS {
        sum += f(e, &mut rng) as u64;
    }
    sum as f64 / TRIALS as f64
}

/// F3 — COPE inter-flow XOR at a relay carrying two flows. Each round the relay has a packet queued
/// for flow A w.p. `sym` (flow balance) and one for flow B w.p. `sym`. If BOTH are present it XORs them
/// into one broadcast (each next-hop already overheard the other's native packet) → 1 TX instead of 2.
/// Returns (transmissions_without_cope, transmissions_with_cope) over many rounds.
fn cope(sym: f64, rng: &mut u64) -> (u64, u64) {
    let rounds = 20_000u64;
    let (mut plain, mut coded) = (0u64, 0u64);
    for _ in 0..rounds {
        let a = (xs(rng) % 1000) as f64 / 1000.0 < sym;
        let b = (xs(rng) % 1000) as f64 / 1000.0 < sym;
        let n = (a as u64) + (b as u64);
        plain += n; // one transmission per queued packet
        coded += if a && b { 1 } else { n }; // XOR the pair into a single broadcast
    }
    (plain, coded)
}

fn main() {
    let es = [0.0f64, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7];

    eprintln!("2-hop transmissions-to-decode (K={K}):");
    eprintln!("  e     forward   F1(e2e)   F2(recode)   F2 speedup vs forward");
    let mut rows = String::from("[");
    for (i, &e) in es.iter().enumerate() {
        let fwd = mean(forward, e, 11 + i as u64);
        let f1 = mean(f1_e2e, e, 101 + i as u64);
        let f2 = mean(f2_recode, e, 201 + i as u64);
        eprintln!("  {e:.1}    {fwd:7.1}   {f1:7.1}   {f2:9.1}     {:.2}x", fwd / f2.max(1.0));
        if i > 0 {
            rows.push(',');
        }
        rows.push_str(&format!("{{\"e\":{e},\"forward\":{fwd:.1},\"f1\":{f1:.1},\"f2\":{f2:.1}}}"));
    }
    rows.push(']');

    // COPE gain vs flow balance.
    eprintln!("\nCOPE inter-flow gain:");
    eprintln!("  balance   plain TX   coded TX   saved");
    let mut crows = String::from("[");
    let syms = [0.1f64, 0.25, 0.4, 0.55, 0.7, 0.85, 1.0];
    for (i, &s) in syms.iter().enumerate() {
        let mut rng = 7 + i as u64;
        let (plain, coded) = cope(s, &mut rng);
        let saved = 100.0 * (1.0 - coded as f64 / plain.max(1) as f64);
        eprintln!("  {s:.2}      {plain:>8}   {coded:>8}   {saved:4.1}%");
        if i > 0 {
            crows.push(',');
        }
        crows.push_str(&format!("{{\"sym\":{s},\"saved\":{:.4}}}", saved / 100.0));
    }
    crows.push(']');

    println!("{{\"k\":{K},\"twohop\":{rows},\"cope\":{crows}}}");
}
