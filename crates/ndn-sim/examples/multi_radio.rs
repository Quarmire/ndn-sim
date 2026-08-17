//! **Multi-radio orchestration — the pool that enables spectrum access.**
//!
//! The spectrum-access design needs a SHARED, COMPLETE occupancy map for avoidance (survey §9.2: a
//! single radio senses only its own channel, so avoidance is blind to the rest and can move a name
//! ONTO an interfered channel it can't see). Multi-radio fills the map. Two validations:
//!
//! Part A — avoidance quality vs SENSING COVERAGE. A node avoids interference by moving a name off a
//!   bad channel to one it BELIEVES clear; unsensed channels are assumed clear. Sweep how many of the
//!   C channels the node's radios cover. Blind (1 channel) → avoidance moves names onto unseen bad
//!   channels → fails; full coverage (a sensor radio / the pool) → avoidance works.
//!
//! Part B — interest coverage vs RADIO COUNT. A node cares about names spread (Zipf) across C channels
//!   but a 16 ms-retune radio can only hold one channel. R radios cover the R highest-demand channels.
//!   Sweep R: how much of the node's demanded traffic can it actually be present for?
//!
//! `cargo run --example multi_radio --release -p ndn-sim`. Writes CSV.

use std::io::Write;

const C: usize = 8; // channels
const NAMES: usize = 400;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn f(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 42) as f64
    }
    fn pick(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
fn hh(x: u64) -> u64 {
    let mut z = x.wrapping_mul(0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
    z ^ (z >> 27)
}

/// Part A: delivery after avoidance, given the node senses `sensed` of C channels.
fn run_a(sensed: usize, n_bad: usize, seed: u64) -> f64 {
    let mut rng = Rng(seed | 1);
    // random bad channel set (the truth) and a random sensed set (what the node's radios cover).
    let mut chans: Vec<usize> = (0..C).collect();
    for i in (1..C).rev() { chans.swap(i, rng.pick(i + 1)); }
    let bad: Vec<usize> = chans[..n_bad].to_vec();
    let mut sc: Vec<usize> = (0..C).collect();
    for i in (1..C).rev() { sc.swap(i, rng.pick(i + 1)); }
    let sensed_set: Vec<usize> = sc[..sensed].to_vec();
    // believed-clear = sensed-and-not-bad, PLUS unsensed (assumed clear — the §9.2 bias).
    let believed_clear: Vec<usize> = (0..C)
        .filter(|c| if sensed_set.contains(c) { !bad.contains(c) } else { true })
        .collect();
    let (mut del, mut tot) = (0u64, 0u64);
    for nm in 0..NAMES {
        let base = (hh(nm as u64) % C as u64) as usize;
        let ch = if bad.contains(&base) && sensed_set.contains(&base) {
            // we can SEE our channel is bad, so we move — but only to a believed-clear one.
            if believed_clear.is_empty() { base } else { believed_clear[(hh(nm as u64) as usize) % believed_clear.len()] }
        } else {
            base // either fine, or bad-but-unsensed (we don't know to move)
        };
        tot += 1;
        if !bad.contains(&ch) { del += 1; } // delivered iff the channel we ended on is truly clear
    }
    del as f64 / tot as f64
}

/// Part B: fraction of demanded traffic the node can be present for, with R radios each holding one
/// channel (the R highest-demand channels), demand Zipf-distributed across C channels.
fn run_b(radios: usize, seed: u64) -> f64 {
    let mut rng = Rng(seed | 1);
    let mut demand = vec![0.0f64; C];
    for _ in 0..NAMES {
        // Zipf-ish over channels: popular channels get most names.
        let r = rng.f().powf(2.0); // skew toward 0
        let ch = (r * C as f64) as usize % C;
        demand[ch] += 1.0;
    }
    let total: f64 = demand.iter().sum();
    demand.sort_by(|a, b| b.partial_cmp(a).unwrap());
    let covered: f64 = demand.iter().take(radios.min(C)).sum();
    covered / total.max(1.0)
}

fn main() {
    let dir = "docs/data/spectrum-access";
    let _ = std::fs::create_dir_all(dir);
    let mut csv = std::fs::File::create(format!("{dir}/multiradio.csv")).unwrap();
    writeln!(csv, "part,x,value").unwrap();

    println!("PART A — avoidance delivery vs SENSING COVERAGE ({C} channels, 3 interfered)\n");
    println!("{:<26}{:>16}", "channels sensed", "delivery after avoid");
    for s in [1usize, 2, 4, 6, 8] {
        let mut d = 0.0;
        for seed in 0..40 { d += run_a(s, 3, seed + 1); }
        d /= 40.0;
        let label = if s == 1 { "1  (single radio — blind)" } else if s == C { "8  (full pool coverage)" } else { "" };
        println!("{:<3}{:<23}{:>15.0}%", s, label, d * 100.0);
        writeln!(csv, "sensing,{s},{d:.4}").ok();
    }

    println!("\nPART B — interest coverage vs RADIO COUNT (demand Zipf across {C} channels)");
    println!("{:<12}{:>18}", "radios", "demand covered");
    for r in [1usize, 2, 3, 4, 6] {
        let mut v = 0.0;
        for seed in 0..40 { v += run_b(r, seed + 1); }
        v /= 40.0;
        println!("{:<12}{:>17.0}%", r, v * 100.0);
        writeln!(csv, "coverage,{r},{v:.4}").ok();
    }
    println!("\nA: blind (single-radio) avoidance moves names onto UNSEEN bad channels → barely helps; full");
    println!("   coverage (a sensor radio / the pool) makes avoidance WORK. Multi-radio fills the map §9.2 needs.");
    println!("B: one 16ms-retune radio can hold ONE channel → covers only the top-demand slice; more radios");
    println!("   cover more of the node's interests simultaneously — the retune tax's answer is more radios.");
    println!("wrote {dir}/multiradio.csv");
}
