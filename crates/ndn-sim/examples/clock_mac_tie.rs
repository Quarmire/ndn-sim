//! **Clock precision → guard band → delivery** — the tie-in, over the REAL `RadioBus` PHY+collision.
//!
//! The companion `clock_phase_gap` experiment measured the cross-node clock RESIDUAL each discipline
//! achieves (software ~ms; build-stamp ~txlat; calibrate ~txlat/4; air/shared ~7 µs single-hop,
//! ~3 µs at 8 hops). This experiment asks the MAC question those residuals actually decide:
//!
//!   Two adjacent-slot owners collide iff their residual DIFFERENCE exceeds the guard band.
//!   So the clock residual sets the MINIMUM guard, the guard sets slot width, and slot width sets
//!   slots/superframe = access latency and goodput.
//!
//! We sweep guard × residual (labelled by the clock discipline that produces it) and report delivery
//! + goodput + access latency, all from the real RadioBus collision model. The payoff: which clock
//! tier unlocks which guard, and what that guard costs in latency/goodput.
//!
//! `cargo run --example clock_mac_tie --release -p ndn-sim`. Writes CSV + a JSON line.

use std::str::FromStr;
use std::sync::Arc;

use bytes::Bytes;
use ndn_observability::{Attr, SpanKind, SpanPublisher, SpanRetention};
use ndn_packet::Name;
use ndn_sim::link_model::mcs_phy_rate_bps;
use ndn_sim::medium::CarrierSenseInterference;
use ndn_sim::radio::RadioBus;
use ndn_sim::telemetry::SimSpanEmitter;
use ndn_sim::{FreeSpacePathLoss, ImmediateRuntime, NodeId, Position, World};

const N: u64 = 8;
const FRAMES: u64 = 60;
const SEEDS: u64 = 40;
const MCS: u8 = 5;
const PAYLOAD: usize = 60;

fn xs(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *s = x;
    x
}
fn airtime_ns() -> u64 {
    (PAYLOAD as u64) * 8 * 1_000_000_000 / (mcs_phy_rate_bps(MCS).max(1) as u64)
}

struct Trial {
    delivered: u32,
    attempted: u32,
    lat: Vec<u64>,
}

/// One superframe run: slot = airtime + guard; node i fires at base + (i-1)·slot ± residual.
fn trial(residual_ns: u64, guard_ns: u64, seed: u64) -> Trial {
    let world = Arc::new(World::new());
    world.place(NodeId(0), Position::xy(0.0, 0.0));
    for i in 1..=N {
        let ang = i as f64 * std::f64::consts::TAU / N as f64;
        world.place(NodeId(i as usize), Position::xy(30.0 * ang.cos(), 30.0 * ang.sin()));
    }
    let bus = RadioBus::with_interference_on(
        world.clone(),
        Arc::new(FreeSpacePathLoss::default()),
        0,
        seed,
        Arc::new(CarrierSenseInterference),
        Arc::new(ImmediateRuntime),
    );
    let _rx = bus.attach(NodeId(0));

    let air = airtime_ns();
    let slot = air + guard_ns;
    let frame_ns = N * slot;
    let mut rng = seed | 1;
    let clocks: Vec<i64> = (0..=N)
        .map(|_| if residual_ns == 0 { 0 } else { (xs(&mut rng) % (2 * residual_ns + 1)) as i64 - residual_ns as i64 })
        .collect();

    let mut out = Trial { delivered: 0, attempted: 0, lat: Vec::new() };
    for f in 0..FRAMES {
        let base = f * frame_ns;
        let mut sends: Vec<(NodeId, u64)> = (1..=N)
            .map(|i| (NodeId(i as usize), (base as i64 + ((i - 1) * slot) as i64 + clocks[i as usize]).max(0) as u64))
            .collect();
        sends.sort_by_key(|(_, t)| *t);
        for (node, t) in sends {
            out.attempted += 1;
            let rx = bus.transmit(node, MCS, Bytes::from(vec![0u8; PAYLOAD]), t);
            if rx.iter().any(|(to, _, ok)| *to == NodeId(0) && *ok) {
                out.delivered += 1;
                out.lat.push(t.saturating_sub(base) + air);
            }
        }
    }
    out
}

/// (delivery, goodput_bps, lat_p99_ns)
fn run(residual_ns: u64, guard_ns: u64) -> (f64, f64, u64) {
    let air = airtime_ns();
    let frame_ns = N * (air + guard_ns);
    let (mut d, mut a) = (0u64, 0u64);
    let mut lat = Vec::new();
    for s in 0..SEEDS {
        let t = trial(residual_ns, guard_ns, (s << 1) | 1);
        d += t.delivered as u64;
        a += t.attempted as u64;
        lat.extend(t.lat);
    }
    let delivery = d as f64 / a as f64;
    let secs = SEEDS as f64 * FRAMES as f64 * frame_ns as f64 / 1e9;
    let goodput = d as f64 * PAYLOAD as f64 * 8.0 / secs;
    lat.sort_unstable();
    let p99 = if lat.is_empty() { 0 } else { lat[(lat.len() * 99 / 100).min(lat.len() - 1)] };
    (delivery, goodput, p99)
}

fn main() {
    use std::io::Write;
    let dir = "docs/data/clock-phase";
    let _ = std::fs::create_dir_all(dir);
    let mut csv = std::fs::File::create(format!("{dir}/mac_tie.csv")).unwrap();
    writeln!(csv, "clock,residual_us,guard_us,delivery,goodput_mbps,lat_p99_us").unwrap();

    // Real OTLP-in-Data telemetry: emit one span per measured (clock, guard) cell through the
    // production ndn-observability SpanPublisher (the same wire as a live node).
    let publisher = SpanPublisher::new(
        Name::from_str("/sim/mac/clock-tie/traces").unwrap(),
        SpanRetention::default(),
    );
    let otlp = SimSpanEmitter::new(Arc::clone(&publisher), Arc::new(ImmediateRuntime));
    let mut vclock_ns: u64 = 0;

    let air = airtime_ns();
    println!("Clock → guard → delivery, over the REAL RadioBus ({N} tx → 1 rx, {SEEDS} seeds).");
    println!("frame airtime = {:.1} µs (MCS{MCS}, {PAYLOAD} B); slot = airtime + guard.\n", air as f64 / 1e3);

    // Residuals labelled by the discipline that produces them (from clock_phase_gap).
    let clocks: [(&str, u64); 5] = [
        ("perfect", 0),
        ("air/shared 8-hop", 3_000),
        ("air/shared 1-hop", 7_000),
        ("calibrate", 50_000),
        ("software/build 1ms", 1_000_000),
    ];
    let guards_us = [10u64, 50, 200, 1000, 5000];

    // Delivery matrix.
    print!("{:<20}", "clock \\ guard µs");
    for g in guards_us {
        print!("{:>10}", g);
    }
    println!();
    for (name, res) in clocks {
        print!("{:<20}", name);
        for &g in &guards_us {
            let (del, gp, p99) = run(res, g * 1000);
            print!("{:>9.0}%", del * 100.0);
            writeln!(csv, "{name},{},{g},{:.4},{:.2},{:.1}", res / 1000, del, gp / 1e6, p99 as f64 / 1e3).ok();
            // OTLP span for this measurement cell.
            let start = vclock_ns;
            vclock_ns += p99.max(1);
            otlp.span(
                "mac.clock.slot_delivery",
                SpanKind::Internal,
                start,
                vclock_ns,
                vec![
                    Attr::str("clock", name),
                    Attr::int("residual_us", (res / 1000) as i64),
                    Attr::int("guard_us", g as i64),
                    Attr::int("delivery_pct", (del * 100.0) as i64),
                    Attr::int("goodput_kbps", (gp / 1e3) as i64),
                ],
            );
        }
        println!();
    }

    // The guard's COST: goodput + p99 access latency at a residual small enough to deliver (perfect).
    println!("\nGuard cost (delivery-safe clock): the price of a wider guard —");
    println!("{:<12}{:>14}{:>16}", "guard µs", "goodput Mb/s", "access p99 µs");
    for &g in &guards_us {
        let (_d, gp, p99) = run(0, g * 1000);
        println!("{:<12}{:>13.1}{:>15.1}", g, gp / 1e6, p99 as f64 / 1e3);
    }

    println!("\nRead: a clock's residual must fit inside the guard or delivery collapses (collisions when");
    println!("adjacent residuals differ by > guard). A tight clock (air/shared ~7µs, ~3µs at 8 hops)");
    println!("unlocks a ~10µs guard → dense slots, low latency, high goodput. A software (ms) clock forces");
    println!("a ms guard → few slots → the #111 tax. THIS is why closing the phase gap earns the slots.");
    // Drain the OTLP-in-Data spans (each a Data packet whose content is an OTLP trace.proto Span).
    let total = publisher.len();
    if let Ok(mut tf) = std::fs::File::create(format!("{dir}/traces.ndjson")) {
        for (trace, span) in publisher.recent_span_ids(30) {
            if let Some(wire) = publisher.lookup(&trace, &span) {
                let hx = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
                writeln!(tf, "{{\"trace\":\"{}\",\"span\":\"{}\",\"data_wire_bytes\":{}}}", hx(&trace), hx(&span), wire.len()).ok();
            }
        }
    }
    println!("OTLP-in-Data: {total} spans emitted through ndn-observability → {dir}/traces.ndjson");
    eprintln!("{{\"experiment\":\"clock_mac_tie\"}}");
    println!("wrote {dir}/mac_tie.csv");
}
