//! **Rate → lease closure — the slot length IS the link decision** (HOW-WELL ↔ WHEN).
//!
//! The temporal facet leases named airtime; the link facet decides a name's rate + FEC + reliability
//! target. Those are the SAME quantity seen twice: a name's lease duration is exactly the airtime its
//! adapted rate needs to move its generation to the reliability target it was assigned. But in the code
//! `slot_us` is a fixed env constant (#85: `SlotSchedule::from_airtime` has ZERO production callers).
//! A fixed slot is wrong two ways at once:
//!   • A_name < slot  → the lease over-reserves; the tail is idle and denied to others (wasted airtime).
//!   • A_name > slot  → the lease under-reserves; the generation spills the slot boundary → with the
//!                      guard band (#84) the overflow is lost, or it lands in the next owner's slot →
//!                      collision. Either way the name is NOT delivered.
//! No single fixed slot fits a mix of names whose airtimes span an order of magnitude (link_adapt.rs:
//! a -88 dBm alarm needs ~130 ms; a -60 dBm bulk name ~6 ms).
//!
//! Part A — delivered names + airtime efficiency: fixed-slot (swept) vs rate-derived (`from_airtime`),
//!   over a name mix whose per-name airtime comes from the link-adaptation decision (reused logic).
//! Part B — the catch: a rate-derived slot is only shared-computable if both endpoints AGREE on the
//!   worst-receiver rate (from reception reports). Divergent link-state → different slot lengths →
//!   schedule desync → collision. The same shared-map constraint spectrum avoidance had, now on time.
//!
//! `cargo run --example slot_closure --release -p ndn-sim`. Writes CSV + OTLP-in-Data spans.

use std::io::Write;
use std::str::FromStr;
use std::sync::Arc;

use ndn_observability::{Attr, SpanKind, SpanPublisher, SpanRetention};
use ndn_packet::Name;
use ndn_sim::telemetry::SimSpanEmitter;
use ndn_sim::ImmediateRuntime;

// 11n 20 MHz LGI, MCS 0..7 (shared with link_adapt.rs): rate (Mbit/s) and RX sensitivity (dBm).
const RATE_MBPS: [f64; 8] = [6.5, 13.0, 19.5, 26.0, 39.0, 52.0, 58.5, 65.0];
const RATE_THR_DBM: [f64; 8] = [-82.0, -79.0, -77.0, -74.0, -70.0, -66.0, -65.0, -64.0];
const K: usize = 32; // payload units per generation
const GUARD_MS: f64 = 0.2; // CommonView guard band (200 µs) between leases

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }
    fn f(&mut self) -> f64 { (self.next() >> 11) as f64 / (1u64 << 42) as f64 }
}

fn erasure(rssi: f64, r: usize) -> f64 {
    let thr = RATE_THR_DBM[r];
    if rssi >= thr { 0.03 } else { (0.03 + 0.09 * (thr - rssi)).min(0.97) }
}
fn airtime_ms(symbols: f64, r: usize) -> f64 { symbols * 1500.0 * 8.0 / (RATE_MBPS[r] * 1e6) * 1e3 }

/// The link decision, reused: minimum airtime to move K units to a worst-receiver at `worst` dBm, via
/// rateless (stream until it collects K), rate chosen to minimize airtime. This IS the lease the WHEN
/// facet should grant — computed from the name's class (which sets `worst`) + shared link-state.
fn lease_ms(worst: f64) -> f64 {
    (0..8)
        .filter_map(|r| {
            let e = erasure(worst, r);
            if e >= 0.999 { None } else { Some(airtime_ms(K as f64 / (1.0 - e), r)) }
        })
        .fold(f64::INFINITY, f64::min)
}

#[derive(Clone, Copy)]
struct NameJob {
    lease: f64,  // airtime this name's generation needs (from its class's reliability target)
    alarm: bool, // the class — alarm names MUST be served; bulk names are best-effort
}

/// A superframe's worth of contending names. Alarm names (serve a weak straggler) need long leases;
/// bulk names (drop the straggler, serve a mid receiver) need short ones. Airtimes span an order of
/// magnitude — the whole reason a fixed slot can't win.
fn name_mix(n: usize, seed: u64) -> Vec<NameJob> {
    let mut rng = Rng(seed | 1);
    (0..n)
        .map(|_| {
            let alarm = rng.f() < 0.30; // 30% alarm, 70% bulk
            // draw the worst receiver the name must serve: alarm serves a weak straggler; bulk serves a
            // stronger receiver (it drops the straggler, which re-Interests later).
            let worst = if alarm { -88.0 + rng.f() * 12.0 } else { -76.0 + rng.f() * 16.0 };
            NameJob { lease: lease_ms(worst), alarm }
        })
        .collect()
}

/// Packing outcome, split by class — because raw name count is a misleading metric: a small fixed slot
/// maximizes count by dropping every (long-lease) alarm name and packing cheap bulk names. What matters
/// is whether the class that MUST be served gets through, at what airtime efficiency.
struct Outcome {
    alarm_del: usize,
    alarm_tot: usize,
    bulk_del: usize,
    efficiency: f64, // delivered airtime / budget
}

/// Pack names into a superframe of `budget` ms. Fixed-slot: a name fits iff lease ≤ slot (else it spills
/// the boundary and is lost, #84); each delivered name consumes the WHOLE slot (the tail is idle).
/// Rate-derived (`slot=None`): each name leases exactly its airtime + guard.
fn pack(names: &[NameJob], budget: f64, slot: Option<f64>) -> Outcome {
    let mut t = 0.0;
    let (mut alarm_del, mut bulk_del, mut used) = (0usize, 0usize, 0.0);
    let alarm_tot = names.iter().filter(|n| n.alarm).count();
    for nm in names {
        let fits = match slot {
            Some(s) => {
                if nm.lease > s { continue; } // spills the fixed slot → lost (guard band forbids crossing)
                if t + s > budget { break; }
                t += s; // consumes the whole slot; (s - lease) is idle
                true
            }
            None => {
                let need = nm.lease + GUARD_MS;
                if t + need > budget { continue; } // try to fit later (smaller) names
                t += need;
                true
            }
        };
        if fits {
            if nm.alarm { alarm_del += 1; } else { bulk_del += 1; }
            used += nm.lease;
        }
    }
    Outcome { alarm_del, alarm_tot, bulk_del, efficiency: used / budget }
}

fn main() {
    let dir = "docs/data/link-adapt";
    let _ = std::fs::create_dir_all(dir);
    let mut csv = std::fs::File::create(format!("{dir}/slot_closure.csv")).unwrap();
    writeln!(csv, "part,arm,x,delivered,efficiency").unwrap();

    let publisher = SpanPublisher::new(Name::from_str("/sim/mac/link/lease/traces").unwrap(), SpanRetention::default());
    let otlp = SimSpanEmitter::new(Arc::clone(&publisher), Arc::new(ImmediateRuntime));
    let mut vclock: u64 = 0;

    const N: usize = 40;
    const BUDGET: f64 = 500.0; // ms superframe
    const SEEDS: u64 = 32;

    println!("PART A — deliver a name mix in a {BUDGET:.0} ms superframe (N={N} names, airtimes from the");
    println!("link-adaptation decision). Delivery split by CLASS (alarm MUST be served) + airtime eff.\n");
    println!("{:<26}{:>16}{:>12}{:>14}", "policy", "alarm served", "bulk served", "airtime eff.");

    // Fixed-slot sweep — no single size wins: small slots serve zero alarms (their leases all exceed the
    // slot → truncated), large slots serve alarms but waste airtime and starve bulk throughput.
    for s in [8.0f64, 16.0, 32.0, 64.0, 128.0] {
        let (mut a_del, mut a_tot, mut b_del, mut eff) = (0.0, 0.0, 0.0, 0.0);
        for seed in 0..SEEDS {
            let names = name_mix(N, seed + 1);
            let o = pack(&names, BUDGET, Some(s));
            a_del += o.alarm_del as f64; a_tot += o.alarm_tot as f64; b_del += o.bulk_del as f64; eff += o.efficiency;
        }
        let (n, af) = (SEEDS as f64, a_del / a_tot.max(1.0));
        println!("{:<26}{:>13.0}% ({:.1}){:>12.1}{:>13.0}%", format!("fixed slot {s:.0} ms"), af * 100.0, a_del / n, b_del / n, eff / n * 100.0);
        writeln!(csv, "A,fixed_{s:.0},{s},{:.4},{:.4}", af, eff / n).ok();
        let start = vclock; vclock += 1000;
        otlp.span("mac.lease.fixed", SpanKind::Internal, start, vclock,
            vec![Attr::str("slot_ms", &format!("{s:.0}")), Attr::int("alarm_served_pct", (af * 100.0) as i64), Attr::int("bulk_served", (b_del / n) as i64), Attr::int("eff_pct", (eff / n * 100.0) as i64)]);
    }

    // Rate-derived lease — serves the alarm class AND stays efficient.
    let (mut a_del, mut a_tot, mut b_del, mut eff) = (0.0, 0.0, 0.0, 0.0);
    for seed in 0..SEEDS {
        let names = name_mix(N, seed + 1);
        let o = pack(&names, BUDGET, None);
        a_del += o.alarm_del as f64; a_tot += o.alarm_tot as f64; b_del += o.bulk_del as f64; eff += o.efficiency;
    }
    let (n, af) = (SEEDS as f64, a_del / a_tot.max(1.0));
    println!("{:<26}{:>13.0}% ({:.1}){:>12.1}{:>13.0}%", "rate-derived (from_airtime)", af * 100.0, a_del / n, b_del / n, eff / n * 100.0);
    writeln!(csv, "A,rate_derived,0,{:.4},{:.4}", af, eff / n).ok();
    let start = vclock; vclock += 1000;
    otlp.span("mac.lease.rate_derived", SpanKind::Internal, start, vclock,
        vec![Attr::int("alarm_served_pct", (af * 100.0) as i64), Attr::int("bulk_served", (b_del / n) as i64), Attr::int("eff_pct", (eff / n * 100.0) as i64)]);

    // ---- Part B — the shared-link-state catch ----------------------------------------------------
    // A rate-derived lease is computed, not announced (beacon-free) — but only if BOTH endpoints derive
    // the SAME airtime. They derive it from the worst-receiver rate, which comes from reception reports.
    // If their link-state disagrees (sensing/report noise), they compute different lease lengths → the
    // cumulative schedule offsets drift apart → a name's window on one side overlaps the next name's on
    // the other → collision. Sweep the disagreement; a name survives iff the two leases match within the
    // guard band.
    println!("\nPART B — rate-derived leases need SHARED link-state (else the schedule desyncs).");
    println!("{:<30}{:>16}", "worst-rate disagreement", "delivered (no desync)");
    for err in [0.0f64, 0.05, 0.15, 0.30] {
        let mut survive = 0.0;
        for seed in 0..SEEDS {
            let mut rng = Rng((seed + 100) | 1);
            let names = name_mix(N, seed + 1);
            let mut ok = 0usize;
            let mut tp = 0.0; // producer clock
            let mut tc = 0.0; // consumer clock
            for nm in &names {
                // consumer's belief of the lease: same name/class, but if it read a different worst-
                // receiver rate (report noise), its airtime is scaled. Model as a multiplicative jitter
                // on the lease when a per-name coin flips under `err`.
                let cons_lease = if rng.f() < err { nm.lease * (0.6 + rng.f() * 0.8) } else { nm.lease };
                let need_p = nm.lease + GUARD_MS;
                let need_c = cons_lease + GUARD_MS;
                if tp + need_p > BUDGET { break; }
                // the windows align iff the two endpoints' cumulative offsets stay within the guard band.
                if (tp - tc).abs() <= GUARD_MS { ok += 1; }
                tp += need_p;
                tc += need_c;
            }
            survive += ok as f64;
        }
        survive /= SEEDS as f64;
        println!("{:<30}{:>16.1}", format!("{:.0}% of names misread", err * 100.0), survive);
        writeln!(csv, "B,desync_{err},{err},{survive:.2},0").ok();
    }

    println!("\nOTLP-in-Data: {} spans emitted through ndn-observability.", publisher.len());
    println!("A: NO fixed slot wins. Small slots (8-16 ms) serve ~0% of ALARM names — their worst-receiver");
    println!("   leases all exceed the slot, so they spill the boundary and are lost — while gaming the raw");
    println!("   name count with cheap bulk. Large slots (64-128 ms) serve alarms but waste airtime (low");
    println!("   efficiency) and starve bulk throughput. Rate-derived leases serve the alarm class AND run");
    println!("   ~98% efficient — because the lease IS the link decision, sized to each name's true need.");
    println!("B: but the lease must be SHARED-computable — divergent worst-rate reads desync the schedule");
    println!("   (the same shared-map constraint spectrum avoidance had, now on the time axis).");
    println!("wrote {dir}/slot_closure.csv");
}
