//! Named token — is a demand-adaptive slot grant worth it? (token-passing, transformed)
//!
//! The token concept survives named-data radio as a name-keyed, clock-derived transmit grant (#61
//! time-slice MAC in time, #40 FHSS in frequency). But fixed name-TDMA has token-ring's classic flaw:
//! the grant rotates past IDLE names, wasting slots, and caps a name at 1/N of the airtime even when
//! everyone else is silent. Token ring's fix was demand-adaptive passing (skip idle stations). Its
//! doctrine-compliant form: a slot is OWNED by name (t mod N) but CLAIMABLE — if the owner is idle, the
//! slot opens to a CCLF election among the names that DO have data. No passed token, no host state; the
//! owner keeps a deterministic slot, idle slots get reused. Does that hybrid beat BOTH fixed-TDMA
//! (idle waste) and pure CCLF/contention (collision collapse)?
//!
//! Slotted DES with SATURATED sources — the honest instrument for a MAC-scheduling question. The load
//! axis is the number of ACTIVE names (each always has data = the contention level). Metrics:
//! throughput (delivered/slot), airtime waste (idle% for TDMA / collision% for CCLF), and worst-case
//! access gap (slots between a name's turns — the determinism / tail-latency the token cares about).
//!
//! Run: `cargo run -p ndn-sim --example token_schedule`

const N: usize = 16; // name-groups (the schedule length)
const SLOTS: u64 = 100_000;
const GUARD: f64 = 0.12; // CCLF jitter-guard / window — sets collision rate vs contender count

#[derive(Clone, Copy, PartialEq)]
enum Sched { Tdma, Cclf, Demand }

fn xs(s: &mut u64) -> u64 { let mut x = *s; x ^= x << 13; x ^= x >> 7; x ^= x << 17; *s = x; x }
fn unif(s: &mut u64) -> f64 { (xs(s) >> 11) as f64 / (1u64 << 53) as f64 }
/// Collision probability with `k` distributed contenders (a rival's jitter lands within the guard of
/// the winner's). k=1 → 0; climbs toward 1 as contention grows — the CSMA/CCLF ceiling.
fn p_col(k: usize) -> f64 { if k <= 1 { 0.0 } else { 1.0 - (1.0 - GUARD).powi((k - 1) as i32) } }

struct Out { thru: f64, idle: f64, coll: f64, mean_gap: f64, p99_gap: u64 }

fn run(sched: Sched, active: usize, seed: u64) -> Out {
    let mut rng = seed | 1;
    let (mut delivered, mut idle, mut coll) = (0u64, 0u64, 0u64);
    let mut last = vec![u64::MAX; N];      // last slot each active name transmitted
    let mut gaps: Vec<u64> = Vec::new();   // access gaps for active names (determinism)
    // active names 0..active are always saturated (always have data); a "winner" among them is the
    // min-jitter one — modelled as uniform-random (distributed CCLF has no central chooser).
    let winner = |rng: &mut u64| (xs(rng) as usize) % active;

    for t in 0..SLOTS {
        let served: Option<usize> = match sched {
            Sched::Tdma => {
                let o = (t as usize) % N;
                if o < active { Some(o) } else { idle += 1; None } // owner idle → wasted slot
            }
            Sched::Cclf => {
                // every active name contends every slot
                if active == 0 { idle += 1; None }
                else if unif(&mut rng) < p_col(active) { coll += 1; None }
                else { Some(winner(&mut rng)) }
            }
            Sched::Demand => {
                let o = (t as usize) % N;
                if o < active {
                    Some(o) // owner active → its guaranteed, collision-free slot
                } else if active == 0 {
                    idle += 1; None
                } else if unif(&mut rng) < p_col(active) {
                    coll += 1; None // owner idle → reclaim via CCLF among the active names
                } else {
                    Some(winner(&mut rng))
                }
            }
        };
        if let Some(name) = served {
            delivered += 1;
            if last[name] != u64::MAX { gaps.push(t - last[name]); }
            last[name] = t;
        }
    }
    gaps.sort_unstable();
    let p99 = if gaps.is_empty() { 0 } else { gaps[((gaps.len() as f64 * 0.99) as usize).min(gaps.len() - 1)] };
    let mean = if gaps.is_empty() { 0.0 } else { gaps.iter().sum::<u64>() as f64 / gaps.len() as f64 };
    let s = SLOTS as f64;
    Out { thru: delivered as f64 / s, idle: idle as f64 / s, coll: coll as f64 / s, mean_gap: mean, p99_gap: p99 }
}

fn main() {
    println!("Named token — fixed name-TDMA vs pure CCLF vs demand-adaptive claimable slots\n");
    println!("N={N}-name schedule, saturated sources; load = # active names (contention). 'token' = grant.\n");
    let scheds = [("fixed TDMA", Sched::Tdma), ("pure CCLF", Sched::Cclf), ("demand-adaptive", Sched::Demand)];
    let actives = [2usize, 4, 8, 16];

    println!("  active   scheduler         thru    idle%   coll%   mean-gap   p99-gap   (gap = slots between a name's turns)");
    let mut rows = Vec::new();
    for &a in &actives {
        for (name, s) in scheds {
            let o = run(s, a, 0xC0FFEE ^ a as u64);
            println!("  {:>4}     {:<15}  {:>4.2}    {:>4.0}    {:>4.0}    {:>7.0}   {:>7}",
                a, name, o.thru, 100.0 * o.idle, 100.0 * o.coll, o.mean_gap, o.p99_gap);
            rows.push(format!("{{\"active\":{a},\"sched\":\"{name}\",\"thru\":{:.3},\"idle\":{:.3},\"coll\":{:.3},\"mean_gap\":{:.1},\"p99_gap\":{}}}",
                o.thru, o.idle, o.coll, o.mean_gap, o.p99_gap));
        }
        println!();
    }

    println!("takeaway (the token concept, quantified): fixed name-TDMA is deterministic — every name's turn");
    println!("comes exactly every N slots (p99-gap = {N}) — but it WASTES the idle slots of silent names, so");
    println!("with few active names throughput craters (2 active → thru {:.2}). Pure CCLF reuses every slot,", 2.0 / N as f64);
    println!("so it's great with few contenders, but its collision rate climbs with them — at 16 active it");
    println!("COLLAPSES (throughput → the p_col ceiling) and its access gap goes ragged. Demand-adaptive wins");
    println!("BOTH ends: it tracks CCLF's high throughput when names are few, tracks TDMA's collision-free");
    println!("determinism when names are many, and keeps a bounded owner-slot gap throughout. That is the");
    println!("token — a name-keyed, clock-derived, RECLAIMABLE grant — earning its keep with no host identity.");

    eprintln!("{{\"N\":{N},\"rows\":[{}]}}", rows.join(","));
}
