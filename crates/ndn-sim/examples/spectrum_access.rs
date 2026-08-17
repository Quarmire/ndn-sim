//! **Spectrum access — static name→channel + shared avoidance vs FHSS** (the WHERE facet).
//!
//! The survey found two disjoint mechanisms (name→channel FHSS, occupancy→least-busy pick) that never
//! meet, and FHSS is retune-disabled on 16 ms Wi-Fi. This validates the reframe at the channel level:
//!
//! Part A — interference isolation + fairness, under a persistent per-channel interferer (C channels):
//!   • single       — every name on ch0 (no spectrum use): the interferer kills everything on it.
//!   • static-spread— name on H(name)%C: interference is ISOLATED to the 1/C of names on that channel
//!                    (but those names are STARVED — unfair).
//!   • fhss         — name hops (H(name)+epoch)%C: every name loses ~1/C (fair) — but needs fast retune.
//!   • static+avoid — static-spread + SHARED occupancy avoidance: the starved names MOVE to a clear
//!                    channel → recovers them, retune-free. The proposed COTS design.
//!
//! Part B — rendezvous under avoidance: when names flee the interfered channel, does the producer and
//! consumer still MEET? SHARED occupancy → same clear channel (rendezvous holds); DIVERGENT (local-only)
//! occupancy → they may pick different clear channels → rendezvous BREAKS. The tension, measured.
//!
//! `cargo run --example spectrum_access --release -p ndn-sim`. Writes CSV.

use std::io::Write;

const C: usize = 6; // channels
const NAMES: usize = 300;
const EPOCHS: usize = 400;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn f(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 42) as f64
    }
}
fn h(x: u64) -> u64 {
    let mut z = x.wrapping_mul(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z ^ (z >> 27)
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Single,
    Static,
    Fhss,
    StaticAvoid,
}

/// The interfered channels this run (a persistent interferer on `n_bad` channels, busy≈`busy`).
fn bad_set(n_bad: usize) -> Vec<usize> {
    (0..n_bad).collect()
}

/// Part A: returns (aggregate_delivery, worst_name_delivery).
fn run_a(mode: Mode, n_bad: usize, busy: f64, seed: u64) -> (f64, f64) {
    let bad = bad_set(n_bad);
    let mut rng = Rng(seed | 1);
    let mut del = vec![0u64; NAMES];
    let mut off = vec![0u64; NAMES];
    // shared occupancy view (both sides see it): which channels are bad. For avoidance we remap a
    // bad-channel name to the lowest-index GOOD channel (deterministic ⇒ shared).
    let good: Vec<usize> = (0..C).filter(|c| !bad.contains(c)).collect();
    for e in 0..EPOCHS {
        for nm in 0..NAMES {
            off[nm] += 1;
            let ch = match mode {
                Mode::Single => 0,
                Mode::Static => (h(nm as u64) % C as u64) as usize,
                Mode::Fhss => ((h(nm as u64).wrapping_add(e as u64)) % C as u64) as usize,
                Mode::StaticAvoid => {
                    let base = (h(nm as u64) % C as u64) as usize;
                    if bad.contains(&base) && !good.is_empty() {
                        // remap deterministically to a good channel (shared ⇒ both endpoints agree)
                        good[(h(nm as u64) as usize) % good.len()]
                    } else {
                        base
                    }
                }
            };
            // delivered unless the channel is interfered (loss ∝ busy).
            let lost = bad.contains(&ch) && rng.f() < busy;
            if !lost {
                del[nm] += 1;
            }
        }
    }
    let agg = del.iter().sum::<u64>() as f64 / off.iter().sum::<u64>().max(1) as f64;
    let worst = (0..NAMES).map(|n| del[n] as f64 / off[n].max(1) as f64).fold(1.0, f64::min);
    (agg, worst)
}

/// Part B: rendezvous rate under avoidance. Producer and consumer each pick a channel for the name;
/// with SHARED occupancy they use the same map; with DIVERGENT they each avoid by their own noisy
/// local view (so they may disagree on which channels are bad). Returns fraction that RENDEZVOUS.
fn run_b(shared: bool, n_bad: usize, sense_err: f64, seed: u64) -> f64 {
    let bad = bad_set(n_bad);
    let mut rng = Rng(seed | 1);
    let mut met = 0u64;
    let mut tot = 0u64;
    for nm in 0..NAMES {
        // each endpoint's belief of the bad set: shared = the true set; divergent = true set with
        // per-channel sensing errors (independent between the two endpoints).
        let belief = |r: &mut Rng| -> Vec<usize> {
            if shared {
                bad.clone()
            } else {
                (0..C).filter(|c| {
                    let truly_bad = bad.contains(c);
                    if r.f() < sense_err { !truly_bad } else { truly_bad } // flip with prob sense_err
                }).collect()
            }
        };
        let pick = |b: &[usize]| -> usize {
            let base = (h(nm as u64) % C as u64) as usize;
            if b.contains(&base) {
                let good: Vec<usize> = (0..C).filter(|c| !b.contains(c)).collect();
                if good.is_empty() { base } else { good[(h(nm as u64) as usize) % good.len()] }
            } else {
                base
            }
        };
        let bp = belief(&mut rng);
        let bc = belief(&mut rng);
        tot += 1;
        if pick(&bp) == pick(&bc) {
            met += 1;
        }
    }
    met as f64 / tot as f64
}

fn main() {
    let dir = "docs/data/spectrum-access";
    let _ = std::fs::create_dir_all(dir);
    let mut csv = std::fs::File::create(format!("{dir}/spectrum.csv")).unwrap();
    writeln!(csv, "part,arm,x,agg_delivery_or_rdv,worst_name_delivery").unwrap();

    println!("PART A — {C} channels, 1 interfered channel (busy 90%). Aggregate delivery / worst-name delivery.\n");
    println!("{:<16}{:>18}{:>20}", "mode", "aggregate", "worst name (fairness)");
    for (nm, m) in [("single (no spread)", Mode::Single), ("static-spread", Mode::Static), ("fhss (fast retune)", Mode::Fhss), ("static+avoid", Mode::StaticAvoid)] {
        let (mut a, mut w) = (0.0, 0.0);
        for s in 0..24 { let (x, y) = run_a(m, 1, 0.9, s + 1); a += x; w += y; }
        a /= 24.0; w /= 24.0;
        println!("{:<16}{:>17.0}%{:>19.0}%", nm, a * 100.0, w * 100.0);
        writeln!(csv, "isolation,{nm},1,{a:.4},{w:.4}").ok();
    }

    println!("\nPART B — rendezvous under avoidance: does producer meet consumer after fleeing the bad channel?");
    println!("{:<28}{:>16}", "occupancy view", "rendezvous rate");
    for (nm, shared, err) in [("shared (agreed map)", true, 0.0), ("divergent, 5% sense error", false, 0.05), ("divergent, 15% sense error", false, 0.15), ("divergent, 30% sense error", false, 0.30)] {
        let mut r = 0.0;
        for s in 0..24 { r += run_b(shared, 2, err, s + 1); }
        r /= 24.0;
        println!("{:<28}{:>15.1}%", nm, r * 100.0);
        writeln!(csv, "rendezvous,{nm},{err},{r:.4},0").ok();
    }

    println!("\nA: single collapses; static-spread ISOLATES interference to 1/C of names but STARVES them");
    println!("   (worst-name ~0); fhss spreads the loss fairly but needs fast retune; static+avoid RECOVERS");
    println!("   the starved names retune-free — the COTS win. B: SHARED occupancy keeps rendezvous ~100%;");
    println!("   DIVERGENT avoidance breaks it (endpoints flee to different channels) — why the map must be shared.");
    println!("wrote {dir}/spectrum.csv");
}
