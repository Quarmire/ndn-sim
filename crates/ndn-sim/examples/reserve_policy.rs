//! **Reserve-vs-contend policy + the CRDSA/diversity tail** — closing out the WHEN facet.
//!
//! Part A — the escalation controller. Bulk contends by default and escalates to a reservation only
//! when contention is measured to hurt. Four policies over a TIME-VARYING contention profile
//! (quiet → burst → quiet):
//!   • always-contend  — never reserves (the #111-safe floor; collapses under the burst)
//!   • always-reserve  — always reserves (protected, but wastes slots + adds latency when quiet)
//!   • reactive        — collision-hysteresis (FLOOR every node can run: no sensing)
//!   • fused           — reactive + occupancy sensing, weighted by the sensor's MEASURED
//!                       predictiveness (so a misleading sensor is auto-discounted)
//! The "fuse only when it helps" test: run `fused` with a MISLEADING (random) occupancy sensor and
//! confirm the meta-weight collapses it back to `reactive` instead of over-reserving.
//!
//! Part B — the CRDSA tail. On the contention path, k-replica diversity (COTS-feasible; RLNC #58)
//! raises the collision ceiling. Sweep k; report delivery under heavy contention. PHY-SIC (custom
//! hardware) would push further — noted, not modelled.
//!
//! `cargo run --example reserve_policy --release -p ndn-sim`. Writes CSV.

use std::io::Write;

const NSLOTS: usize = 16;
const N: usize = 16;
const SUPERFRAMES: usize = 900;
const SEEDS: u64 = 40;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn f(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 42) as f64
    }
    fn u(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Pol {
    Contend,
    Reserve,
    Reactive,
    Fused,
}

struct Node {
    reserved: bool,
    coll: i32,       // collision hysteresis counter
    w_occ: f64,      // learned weight on the occupancy signal (0..1)
    occ_true: u32,   // occupancy-high-then-collision (predictive hits)
    occ_seen: u32,   // occupancy-high events
    backlog: Option<usize>, // arrival superframe
}

// active-node count over time: quiet (light) → burst (heavy) → quiet.
fn active(sf: usize) -> usize {
    let t = SUPERFRAMES / 3;
    if sf < t || sf >= 2 * t { 3 } else { N } // 3 active when quiet, all N in the burst
}

const ESC: i32 = 3; // escalate after ESC net collisions; release at -ESC
const OCC_HI: f64 = 0.5;

/// Returns (burst_p99_latency, quiet_reserved_fraction, quiet_p99_latency).
fn run(pol: Pol, misleading_occ: bool, seed: u64) -> (f64, f64, f64) {
    let mut rng = Rng(seed.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(1));
    let mut nodes: Vec<Node> = (0..N)
        .map(|_| Node { reserved: false, coll: 0, w_occ: 0.5, occ_true: 0, occ_seen: 0, backlog: None })
        .collect();
    let mut burst_lat = Vec::new();
    let mut quiet_lat = Vec::new();
    let mut quiet_res = Vec::new();
    let t3 = SUPERFRAMES / 3;

    for sf in 0..SUPERFRAMES {
        let na = active(sf);
        // arrivals: the first `na` nodes have traffic (bursty set grows in the burst).
        for i in 0..N {
            if i < na && nodes[i].backlog.is_none() {
                nodes[i].backlog = Some(sf);
            }
        }
        // occupancy the nodes sense this superframe (true = proportional to active load; misleading = random).
        let occ = if misleading_occ { rng.f() } else { (na as f64 / N as f64).min(1.0) };

        // reserved slots (nodes currently in reserved state with traffic).
        let mut slot_taken = vec![false; NSLOTS];
        for (i, nd) in nodes.iter().enumerate() {
            if nd.reserved && nd.backlog.is_some() {
                slot_taken[i % NSLOTS] = true;
            }
        }
        // contenders pick a random currently-unreserved slot; ≥2 in one slot collide.
        let mut pick: Vec<Option<usize>> = vec![None; N];
        let mut count = vec![0u32; NSLOTS];
        for i in 0..N {
            if nodes[i].backlog.is_some() && !nodes[i].reserved {
                let free: Vec<usize> = (0..NSLOTS).filter(|&s| !slot_taken[s]).collect();
                if !free.is_empty() {
                    let s = free[rng.u(free.len())];
                    pick[i] = Some(s);
                    count[s] += 1;
                }
            }
        }
        // resolve: reserved nodes deliver; contenders deliver iff alone in their slot.
        for i in 0..N {
            let Some(arr) = nodes[i].backlog else { continue };
            let delivered = if nodes[i].reserved {
                true
            } else if let Some(s) = pick[i] {
                count[s] == 1
            } else {
                false
            };
            let collided = !delivered && !nodes[i].reserved && pick[i].is_some();
            // policy update
            match pol {
                Pol::Reactive | Pol::Fused => {
                    if collided { nodes[i].coll += 1 } else if delivered { nodes[i].coll -= 1 }
                    nodes[i].coll = nodes[i].coll.clamp(-ESC, ESC);
                    // fused: occupancy can pre-trigger escalation, weighted by learned predictiveness.
                    let mut escalate = nodes[i].coll >= ESC;
                    if pol == Pol::Fused && occ > OCC_HI {
                        nodes[i].occ_seen += 1;
                        if collided { nodes[i].occ_true += 1 }
                        nodes[i].w_occ = nodes[i].occ_true as f64 / nodes[i].occ_seen.max(1) as f64;
                        if nodes[i].w_occ > 0.5 && nodes[i].coll >= ESC - 2 {
                            escalate = true; // trust occupancy only once it has proven predictive
                        }
                    }
                    if escalate { nodes[i].reserved = true }
                    if nodes[i].coll <= -ESC { nodes[i].reserved = false }
                }
                Pol::Contend => nodes[i].reserved = false,
                Pol::Reserve => nodes[i].reserved = true,
            }
            if delivered {
                let lat = (sf - arr) as f64;
                if sf >= t3 && sf < 2 * t3 { burst_lat.push(lat) } else { quiet_lat.push(lat) }
                nodes[i].backlog = None;
            }
        }
        if sf < t3 || sf >= 2 * t3 {
            quiet_res.push(nodes.iter().filter(|n| n.reserved).count() as f64 / N as f64);
        }
    }
    let p99 = |v: &mut Vec<f64>| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        if v.is_empty() { 0.0 } else { v[(v.len() * 99 / 100).min(v.len() - 1)] }
    };
    let qr = quiet_res.iter().sum::<f64>() / quiet_res.len().max(1) as f64;
    (p99(&mut burst_lat), qr, p99(&mut quiet_lat))
}

fn avg(pol: Pol, mis: bool) -> (f64, f64, f64) {
    let (mut a, mut b, mut c) = (0.0, 0.0, 0.0);
    for s in 0..SEEDS {
        let (x, y, z) = run(pol, mis, s + 1);
        a += x; b += y; c += z;
    }
    (a / SEEDS as f64, b / SEEDS as f64, c / SEEDS as f64)
}

/// Part B — k-replica diversity delivery under heavy contention (M contenders, NSLOTS slots).
fn diversity(m: usize, k: usize, seed: u64) -> f64 {
    let mut rng = Rng(seed.wrapping_mul(2862933555777941757).wrapping_add(7));
    const TRIALS: usize = 2000;
    let (mut del, mut tot) = (0u64, 0u64);
    for _ in 0..TRIALS {
        // each of m packets picks k distinct random slots; slot collides if >1 replica lands in it.
        let mut count = vec![0u32; NSLOTS];
        let mut reps: Vec<Vec<usize>> = Vec::new();
        for _ in 0..m {
            let mut r = Vec::new();
            while r.len() < k.min(NSLOTS) {
                let s = rng.u(NSLOTS);
                if !r.contains(&s) { r.push(s); count[s] += 1; }
            }
            reps.push(r);
        }
        for r in &reps {
            tot += 1;
            if r.iter().any(|&s| count[s] == 1) { del += 1; } // ≥1 clean replica ⇒ delivered (no SIC)
        }
    }
    del as f64 / tot as f64
}

fn main() {
    let dir = "docs/data/reservation-overlay";
    let _ = std::fs::create_dir_all(dir);
    let mut csv = std::fs::File::create(format!("{dir}/policy.csv")).unwrap();
    writeln!(csv, "part,arm,x,burst_p99,quiet_reserved_frac,quiet_p99").unwrap();

    println!("PART A — reserve-vs-contend policy over quiet→burst→quiet ({N} nodes, {NSLOTS} slots)");
    println!("{:<16}{:>16}{:>20}{:>16}", "policy", "burst p99 (sf)", "quiet reserved %", "quiet p99 (sf)");
    for (nm, pol) in [("always-contend", Pol::Contend), ("always-reserve", Pol::Reserve), ("reactive (floor)", Pol::Reactive), ("fused (+occupancy)", Pol::Fused)] {
        let (b, r, q) = avg(pol, false);
        println!("{:<16}{:>16.0}{:>19.0}%{:>16.1}", nm, b, r * 100.0, q);
        writeln!(csv, "policy,{nm},0,{b:.1},{r:.4},{q:.1}").ok();
    }
    let (b, r, q) = avg(Pol::Fused, true);
    println!("{:<16}{:>16.0}{:>19.0}%{:>16.1}   ← MISLEADING occupancy sensor", "fused (bad occ)", b, r * 100.0, q);
    writeln!(csv, "policy,fused-misleading,0,{b:.1},{r:.4},{q:.1}").ok();

    println!("\nPART B — CRDSA/diversity tail: delivery vs replicas k, {N} contenders / {NSLOTS} slots (heavy)");
    println!("{:<8}{:>14}", "k reps", "delivery");
    for k in [1usize, 2, 3, 4] {
        let mut d = 0.0;
        for s in 0..SEEDS { d += diversity(N, k, s + 1); }
        d /= SEEDS as f64;
        println!("{:<8}{:>13.1}%", k, d * 100.0);
        writeln!(csv, "diversity,replicas,{k},{:.4},0,0", d).ok();
    }
    println!("\nA: the reactive FLOOR already gets near-full burst protection (p99 6 vs contend 9) at ~1/5 the");
    println!("   airtime cost of always-reserve (12% vs 59% reserved); occupancy fusion adds little HERE, and");
    println!("   a MISLEADING sensor is safely discounted (no over-reservation). Floor default; fuse when proven.");
    println!("B: replica diversity WITHOUT SIC does NOT help — it HURTS at saturation (38→5% as k grows: replicas");
    println!("   add load). The CRDSA gain REQUIRES SIC, which commodity 802.11 can't do. So on COTS the answer to");
    println!("   saturation is reservation escalation (A) or load reduction (rate/FEC); SIC-CRDSA is a CUSTOM ceiling.");
    println!("wrote {dir}/policy.csv");
}
