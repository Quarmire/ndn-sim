//! **Closing the cross-node clock-phase gap** — measured over the REAL `ndn_timekeeper::Timekeeper`.
//!
//! `RadioHwClock::common_view()` states its ceiling: "precision is bounded by the master's build→air
//! TX latency." COTS radios give us a µs-precise **RX** timestamp (latched on preamble correlation)
//! but no **TX** timestamp — so the whole game is to build time on RX stamps and cancel the
//! untimestamped TX side. Arms (all drive the production Timekeeper + beacon codec):
//!
//!  - **build**     — stamp at BUILD; asserted time is stale by `txlat` at reception → bias `txlat`.
//!                    Today's common-view residual.
//!  - **build+cal** — COTS exploit: subtract the CALIBRATED mean `txlat` (a per-radio constant),
//!                    leaving only zero-mean jitter the estimator filters as 1/√N. No TX stamp.
//!  - **shared**    — COTS exploit: RX-stamp a common third-party beacon; the common `txlat` cancels
//!                    in the receiver-pair difference (`CommonViewPool`). No TX stamp.
//!  - **air**       — the ideal: stamp at actual radiate time (HW TX counter, #74). Needs the feature.
//!
//! Two sweeps: (1) residual vs build→air latency at single hop; (2) residual vs hop count on a chain
//! (NetworkTime-style stratum composition). The residual is the guard-band floor.
//!
//! `cargo run --example clock_phase_gap --release -p ndn-sim`. Writes CSV + a JSON line.

use ndn_time::provenance::{Authenticity, KeyId, MeasurementProvenance, PathId};
use ndn_time::{ClockCapability, Discipline, NetworkTime, RefBelief, TimeInterval, TimePolicy};
use ndn_time_sources::Reading;
use ndn_timekeeper::{Timekeeper, beacon_wire};

#[derive(Clone, Copy)]
struct PhysClock {
    offset_ns: i64,
    drift_ppb: i64,
}
impl PhysClock {
    fn wall(&self, t_ns: i64) -> i64 {
        t_ns + self.offset_ns + self.drift_ppb * t_ns / 1_000_000_000
    }
    fn steer(&mut self, d: Discipline, dt_ns: i64) {
        match d {
            Discipline::Step { correction_ns } => self.offset_ns += correction_ns,
            Discipline::Slew { rate_ppb } => self.offset_ns += rate_ppb * dt_ns / 1_000_000_000,
            Discipline::Track { .. } | Discipline::Withhold { .. } => {}
        }
    }
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn drops(&mut self, loss_pct: u64) -> bool {
        self.next() % 100 < loss_pct
    }
    fn jitter(&mut self, half_ns: i64) -> i64 {
        if half_ns == 0 { 0 } else { (self.next() as i64 % (2 * half_ns + 1)) - half_ns }
    }
}

fn peer_prov(sender: usize) -> MeasurementProvenance {
    MeasurementProvenance {
        distance_bounded: false,
        replay_protected: true,
        authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(sender as u64)),
        path: PathId(sender as u32 + 1),
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Arm {
    Build,
    BuildCal,
    Shared,
    Air,
}

struct Node {
    phys: PhysClock,
    tk: Timekeeper,
    cap: ClockCapability,
    pub_unc_ns: u64,
    seq: u64,
}

const RX_JITTER_HALF_NS: i64 = 500; // RX-stamp floor (~0.5 µs, #74)
const CADENCE_NS: i64 = 1_000_000_000;
const ROUNDS: usize = 40;

fn mk_nodes(n_osc: usize, seed: u64) -> Vec<Node> {
    let policy = TimePolicy::default();
    let mut nodes = Vec::new();
    nodes.push(Node {
        phys: PhysClock { offset_ns: 0, drift_ppb: 0 },
        tk: Timekeeper::new(0, KeyId(0), ClockCapability::gnss_disciplined(), policy),
        cap: ClockCapability::gnss_disciplined(),
        pub_unc_ns: 50,
        seq: 0,
    });
    let mut rng = Lcg(seed ^ 0x1234_5678_9abc_def0);
    for i in 0..n_osc {
        let id = (i + 1) as u64;
        let off = rng.jitter(9_000_000);
        let drift = rng.jitter(400);
        nodes.push(Node {
            phys: PhysClock { offset_ns: off, drift_ppb: drift },
            tk: Timekeeper::new(id, KeyId(id), ClockCapability::oscillator_tcxo(), policy),
            cap: ClockCapability::oscillator_tcxo(),
            pub_unc_ns: 20_000_000,
            seq: 0,
        });
    }
    nodes
}

/// One arm's asserted-wall error, given the true stamp `wall`, the drawn latency `lat`, the
/// calibrated mean `txlat`, and per-reception jitters.
fn asserted(arm: Arm, wall: i64, lat: i64, txlat: i64, rxj: i64, rxj2: i64) -> i64 {
    match arm {
        Arm::Build => wall - lat + rxj,                 // stale by lat
        Arm::BuildCal => wall - (lat - txlat) + rxj,    // mean removed → only jitter remains
        Arm::Shared => wall + rxj + rxj2,               // txlat cancels; √2 RX jitter
        Arm::Air => wall + rxj,                          // stamped at radiate
    }
}

/// Run the ensemble; `hears(i,j)` gates delivery (mesh = always; chain = |i-j|<=1).
/// Returns per-oscillator (nodes 1..n) tail-max residual, and rounds-to-converge for the worst node.
fn run(arm: Arm, txlat: i64, n_osc: usize, hears: impl Fn(usize, usize) -> bool, seed: u64) -> (Vec<u64>, usize) {
    let mut nodes = mk_nodes(n_osc, seed);
    let n = nodes.len();
    let mut rng = Lcg(seed.wrapping_mul(2862933555777941757).wrapping_add(3037000493));
    let mut tail: Vec<Vec<u64>> = vec![Vec::new(); n];
    let mut converged = usize::MAX;

    for r in 0..ROUNDS {
        let t = r as i64 * CADENCE_NS;
        let published: Vec<(u64, i64, u64, ClockCapability)> =
            nodes.iter_mut().map(|nd| { nd.seq += 1; (nd.seq, nd.phys.wall(t), nd.pub_unc_ns, nd.cap) }).collect();
        for (i, &(seq, wall, unc, cap)) in published.iter().enumerate() {
            for j in 0..n {
                if i == j || !hears(i, j) || rng.drops(20) {
                    continue;
                }
                let lat = txlat + rng.jitter(txlat / 4);
                let a = asserted(arm, wall, lat, txlat, rng.jitter(RX_JITTER_HALF_NS), rng.jitter(RX_JITTER_HALF_NS));
                let bytes = beacon_wire::encode(seq, a, unc, &cap);
                let Some(dec) = beacon_wire::decode(&bytes) else { continue };
                let beacon = dec.into_beacon(t as u64, peer_prov(i));
                nodes[j].tk.ingest_beacon(i as u64, &beacon);
            }
        }
        for nd in nodes.iter_mut() {
            let local_wall = nd.phys.wall(t);
            let reading = Reading {
                wall: TimeInterval::new(local_wall, if nd.phys.drift_ppb == 0 { 50 } else { 20_000_000 }),
                cap: nd.cap,
                captured_mono_ns: t as u64,
            };
            nd.tk.ingest_local_reading(&reading);
            let out = nd.tk.tick(t as u64, local_wall);
            nd.phys.steer(out.discipline, CADENCE_NS);
            if out.correction.admitted {
                nd.pub_unc_ns = out.correction.uncertainty_ns;
            }
        }
        let errs: Vec<u64> = (1..n).map(|i| (nodes[i].phys.wall(t) - t).unsigned_abs()).collect();
        if *errs.iter().max().unwrap() < 100_000 && converged == usize::MAX {
            converged = r;
        }
        if r >= ROUNDS - 10 {
            for (i, e) in errs.iter().enumerate() {
                tail[i + 1].push(*e);
            }
        }
    }
    let per: Vec<u64> = (1..n).map(|i| *tail[i].iter().max().unwrap()).collect();
    (per, converged)
}

/// The SAME chain, but driven by `NetworkTime`'s EXPLICIT stratum composition (offset_to_ref adds
/// along the shortest path to the lowest-id reference) instead of the Timekeeper's uncertainty
/// fusion. Returns residual (µs) at each hop after convergence. Units are µs (NetworkTime's).
fn run_nt_chain(arm: Arm, txlat_us: i64, hops: usize, seed: u64) -> Vec<i64> {
    let mut nts: Vec<NetworkTime> = (0..=hops).map(|i| NetworkTime::new(i as u64)).collect();
    let mut rng = Lcg(seed ^ 0xabcd_1234);
    // true clock offsets (µs): node 0 = reference (0); others scattered ±5 ms.
    let offs: Vec<i64> = std::iter::once(0).chain((1..=hops).map(|_| rng.jitter(5000))).collect();
    for _round in 0..(3 * hops + 12) {
        for j in 1..=hops {
            // measured hardware offset to the downstream neighbour (nbr_tsf − my_rxtsfl), µs, plus
            // the arm's per-hop error. build's is SYSTEMATIC (−txlat every hop); the rest zero-mean.
            let err = match arm {
                Arm::Build => -txlat_us + rng.jitter(1),
                Arm::BuildCal => rng.jitter((txlat_us / 4).max(1)),
                Arm::Shared => rng.jitter(1) + rng.jitter(1),
                Arm::Air => rng.jitter(1),
            };
            let measured = (offs[j - 1] - offs[j]) + err;
            let nbr = nts[j - 1].belief();
            nts[j].observe(measured, nbr);
        }
    }
    // residual = |offs[k] + offset_to_ref|: offset_to_ref should map this clock (true+offs[k]) onto
    // the reference (offset 0), i.e. equal −offs[k]; the leftover is the composition error.
    (1..=hops).map(|k| (offs[k] + nts[k].offset_to_ref()).abs()).collect()
}

fn main() {
    use std::io::Write;
    let _ = RefBelief { ref_id: 0, stratum: 0, offset_to_ref: 0 }; // (type used via NetworkTime)
    const SEEDS: u64 = 12;
    let dir = "docs/data/clock-phase";
    let _ = std::fs::create_dir_all(dir);
    let mut csv = std::fs::File::create(format!("{dir}/residual.csv")).unwrap();
    writeln!(csv, "experiment,arm,x,residual_max_ns,residual_mean_ns,converge_rounds").unwrap();

    let arms = [("build", Arm::Build), ("build+cal", Arm::BuildCal), ("shared", Arm::Shared), ("air", Arm::Air)];

    // ---- Sweep 1: residual vs build→air latency (single-hop mesh) ----
    println!("SWEEP 1 — residual vs build→air TX latency (5 osc + 1 ref, mesh, 20% loss, {ROUNDS} rounds)\n");
    println!("{:<10} {:>9} {:>15} {:>15} {:>10}", "arm", "txlat µs", "residual max", "residual mean", "converge");
    for &tx_us in &[10i64, 50, 200, 1000, 5000] {
        let tx = tx_us * 1000;
        for (name, arm) in arms {
            let (mut mx, mut mn, mut cv) = (0.0, 0.0, 0.0);
            for s in 0..SEEDS {
                let (per, c) = run(arm, tx, 5, |_, _| true, s + 1);
                mx += *per.iter().max().unwrap() as f64;
                mn += per.iter().sum::<u64>() as f64 / per.len() as f64;
                cv += if c == usize::MAX { ROUNDS as f64 } else { c as f64 };
            }
            (mx, mn, cv) = (mx / SEEDS as f64, mn / SEEDS as f64, cv / SEEDS as f64);
            println!("{:<10} {:>9} {:>12.2} µs {:>12.2} µs {:>7.1} r", name, tx_us, mx / 1e3, mn / 1e3, cv);
            writeln!(csv, "latency,{name},{tx_us},{:.0},{:.0},{:.1}", mx, mn, cv).unwrap();
        }
        println!("  ─");
    }

    // ---- Sweep 2: residual vs hop count (chain, NetworkTime stratum composition) ----
    println!("\nSWEEP 2 — residual vs hop distance from the reference (chain, air-stamp, txlat=50µs)");
    println!("{:<8} {}", "arm", "residual (µs) at hop 1,2,…");
    let tx = 50_000;
    for (name, arm) in [("air", Arm::Air), ("build+cal", Arm::BuildCal), ("build", Arm::Build)] {
        for hops in [8usize] {
            // node j hears only j-1 and j+1 (a line rooted at the reference, node 0).
            let mut per_hop = vec![0.0f64; hops];
            for s in 0..SEEDS {
                let (per, _) = run(arm, tx, hops, |i, j| (i as isize - j as isize).abs() <= 1, s + 1);
                for (h, v) in per.iter().enumerate() {
                    per_hop[h] += *v as f64;
                }
            }
            let cells: Vec<String> = per_hop.iter().enumerate().map(|(h, v)| {
                let us = v / SEEDS as f64 / 1e3;
                writeln!(csv, "hops,{name},{},{:.0},0,0", h + 1, v / SEEDS as f64).ok();
                format!("h{}:{:.1}", h + 1, us)
            }).collect();
            println!("{:<8} {}", name, cells.join("  "));
        }
    }
    // ---- Sweep 3: the SAME chain via NetworkTime explicit stratum composition ----
    println!("\nSWEEP 3 — SAME chain via NetworkTime EXPLICIT stratum composition (8 hops, txlat=50µs)");
    println!("{:<10} {}", "arm", "residual (µs) at hop 1..8");
    for (name, arm) in [("air", Arm::Air), ("shared", Arm::Shared), ("build+cal", Arm::BuildCal), ("build", Arm::Build)] {
        let mut per = vec![0.0f64; 8];
        for s in 0..SEEDS {
            let r = run_nt_chain(arm, 50, 8, s + 1);
            for (h, v) in r.iter().enumerate() {
                per[h] += *v as f64;
            }
        }
        let cells: Vec<String> = per.iter().enumerate().map(|(h, v)| {
            writeln!(csv, "nt_hops,{name},{},{:.0},0,0", h + 1, v / SEEDS as f64 * 1000.0).ok();
            format!("h{}:{:.1}", h + 1, v / SEEDS as f64)
        }).collect();
        println!("{:<10} {}", name, cells.join("  "));
    }
    println!("\nSWEEP 1: 'build' ∝ txlat (breaks the schedule); 'build+cal'/'shared' reach the air floor, NO TX stamp.");
    println!("SWEEP 2 (Timekeeper uncertainty-fusion): a propagation HORIZON — far hops never converge.");
    println!("SWEEP 3 (NetworkTime stratum composition): propagates ALL hops. build accumulates k·txlat (linear,");
    println!("  bad at depth); air/shared accumulate only √k·jitter — the exploit matters MORE with hops.");
    println!("wrote {dir}/residual.csv");
}
