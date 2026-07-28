//! Pipe lifecycle cost — creation, teardown, recreation — over mobility × density.
//!
//! The last #66 axis. DCNLA amortizes a HEAVY setup (SEEK flood → JOIN → per-hop CONTEXT/LINK/PIPE →
//! CHECK → one IBSS association) over a long-lived UNICAST pipe. Named-data radio has NO setup: the
//! first Interest broadcasts on the name-group and forwards by breadcrumb; a break is repaired by
//! re-expressing the Interest (the #70 result). So the question is: at what mobility / density does
//! DCNLA's setup stop amortizing?
//!
//! This is a MODEL (the DCNLA handshake can't run end-to-end here), but every constant is sourced:
//!   • break rate λ(v)      — MEASURED in #70 (mobility_study.rs), 0.5→20 m/s
//!   • per-exchange RTT      — real ForwarderEngine ~4.5 ms (forwarder_mesh.rs)
//!   • IBSS association      — ~150 ms (thesis: association dominates setup, "orders of magnitude" > data)
//!   • per-link rate         — MT7612U MCS5 ≈ 49 Mbps (thesis Figs 24/25, #68 anchor)
//! Generous to DCNLA: on a CHAIN its unicast (ACK + per-link rate-adapt) gets a +10% edge over
//! named-data's rate-adapted broadcast — even though #66 showed they tie on a chain (worst-receiver =
//! the one receiver). If DCNLA loses even WITH that edge, it loses honestly.
//!
//! Run: `cargo run -p ndn-sim --example pipe_lifecycle`

const HOPS: f64 = 4.0;
const RTT_MS: f64 = 4.5; // per control exchange, real engine
const IBSS_ASSOC_MS: f64 = 150.0; // Wi-Fi IBSS association (thesis: the dominant setup cost)
const R0_MBPS: f64 = 49.0; // MT7612U MCS5 per-link
const UNICAST_EDGE: f64 = 1.10; // generous ACK/rate-adapt bonus for DCNLA on a chain

/// Break rate (per second) at speed `v` — interpolated from #70's measured points.
fn lambda(v: f64) -> f64 {
    let pts = [(0.5, 0.031), (1.0, 0.067), (2.0, 0.138), (5.0, 0.229), (10.0, 0.299), (20.0, 0.376)];
    if v <= pts[0].0 { return pts[0].1; }
    for w in pts.windows(2) {
        if v <= w[1].0 {
            let (x0, y0) = w[0];
            let (x1, y1) = w[1];
            return y0 + (y1 - y0) * (v - x0) / (x1 - x0);
        }
    }
    pts[pts.len() - 1].1
}

/// DCNLA pipe setup time (ms): one IBSS association + the handshake (SEEK+JOIN+hops·(CONTEXT+LINK+PIPE)
/// +CHECK), + a SEEK-flood contention term that grows with density (the flood reaches N nodes).
fn dcnla_setup_ms(n: f64) -> f64 {
    let handshake = RTT_MS * (1.0 + 1.0 + HOPS * 3.0 + 1.0); // SEEK, JOIN, 3/hop, CHECK
    let flood = 0.6 * n; // SEEK is a multicast flood → airtime/contention ∝ nodes reached
    IBSS_ASSOC_MS + handshake + flood
}
/// Named-data "setup": no handshake, no association — just re-express one Interest along the path.
fn named_setup_ms() -> f64 {
    RTT_MS * HOPS
}

/// DCNLA control messages emitted per pipe (re)build: SEEK flood (≈N) + per-hop handshake + teardown.
fn dcnla_ctrl_msgs(n: f64) -> f64 {
    n + HOPS * 4.0 + 2.0
}
/// Named-data control per repair: the re-expressed Interest floods until it re-finds a breadcrumb
/// path — bounded by the local neighbourhood, not the whole network.
fn named_ctrl_msgs() -> f64 {
    HOPS * 2.0
}

struct Cell { dcnla: f64, named: f64, dcnla_ovh: f64, named_ovh: f64 }

fn eval(v: f64, n: f64) -> Cell {
    let lam = lambda(v);
    // availability = fraction of time NOT dark rebuilding after a break (mean lifetime 1/λ)
    let a_dcnla = (1.0 - dcnla_setup_ms(n) / 1000.0 * lam).max(0.0);
    let a_named = (1.0 - named_setup_ms() / 1000.0 * lam).max(0.0);
    // effective goodput = per-link rate × availability (rates ~equal on a chain; DCNLA +10% edge)
    Cell {
        dcnla: R0_MBPS * UNICAST_EDGE * a_dcnla,
        named: R0_MBPS * a_named,
        dcnla_ovh: lam * dcnla_ctrl_msgs(n), // control msgs/sec to sustain the flow
        named_ovh: lam * named_ctrl_msgs(),
    }
}

fn main() {
    println!("Pipe lifecycle over mobility × density — DCNLA (setup-amortized) vs named-data (setup-free)\n");
    println!("model grounded in: #70 λ(v), real-engine RTT, thesis IBSS-assoc, MT7612U rate. DCNLA gets a");
    println!("generous +10% unicast edge on a chain.\n");

    let vels = [0.5f64, 1.0, 2.0, 5.0, 10.0, 20.0];
    let dens = [10.0f64, 25.0, 50.0, 100.0];

    // Axis 0 — the robust, assumption-free costs, paid on EVERY create AND rebuild:
    println!("0. per-event cost (create OR recover-from-break), N=50:");
    println!("   setup/recovery latency   DCNLA {:>5.0} ms   named {:>4.0} ms   ({:.0}× slower to recover)",
        dcnla_setup_ms(50.0), named_setup_ms(), dcnla_setup_ms(50.0) / named_setup_ms());
    println!("   control messages/rebuild DCNLA {:>5.0}      named {:>4.0}         ({:.0}× more traffic)\n",
        dcnla_ctrl_msgs(50.0), named_ctrl_msgs(), dcnla_ctrl_msgs(50.0) / named_ctrl_msgs());

    // A. effective goodput vs velocity at a mid density
    let n_a = 50.0;
    println!("A. effective goodput (Mbps) vs speed, N={n_a} — where setup stops amortizing\n");
    println!("  v m/s   λ/s     DCNLA    named    winner");
    let mut a_json = Vec::new();
    for &v in &vels {
        let c = eval(v, n_a);
        let win = if c.named > c.dcnla { "named" } else { "DCNLA" };
        println!("  {:>4.1}   {:.3}   {:>6.1}   {:>6.1}    {}", v, lambda(v), c.dcnla, c.named, win);
        a_json.push(format!("{{\"v\":{v},\"lam\":{:.3},\"dcnla\":{:.1},\"named\":{:.1}}}", lambda(v), c.dcnla, c.named));
    }

    // B. control overhead vs density at a mid velocity
    let v_b = 5.0;
    println!("\nB. control overhead (msgs/s to sustain the flow) vs density, v={v_b} m/s\n");
    println!("  nodes   DCNLA    named");
    let mut b_json = Vec::new();
    for &n in &dens {
        let c = eval(v_b, n);
        println!("  {:>4}    {:>6.1}   {:>5.1}", n as u32, c.dcnla_ovh, c.named_ovh);
        b_json.push(format!("{{\"n\":{n},\"dcnla\":{:.1},\"named\":{:.1}}}", c.dcnla_ovh, c.named_ovh));
    }

    // C. winner map over velocity × density (named advantage in Mbps)
    println!("\nC. named − DCNLA effective goodput (Mbps) over speed × density (＋ = named wins)\n");
    print!("      N=   ");
    for &n in &dens { print!("{:>7}", n as u32); }
    println!();
    let mut c_json = Vec::new();
    for &v in &vels {
        print!("  v={:>4.1} ", v);
        for &n in &dens {
            let c = eval(v, n);
            let d = c.named - c.dcnla;
            print!("{:>+7.1}", d);
            c_json.push(format!("{{\"v\":{v},\"n\":{n},\"delta\":{:.2}}}", d));
        }
        println!();
    }

    println!("\ntakeaway (honest, three axes): on THROUGHPUT the thesis's amortization argument HOLDS — at");
    println!("realistic break rates (λ<0.4/s, #70) a 250 ms setup costs only ~9% availability, so DCNLA's");
    println!("+10% unicast edge (if real; #66 showed they tie on a chain) keeps it competitive on Mbps until");
    println!("the extreme mobile+dense corner. Where DCNLA loses is the PER-EVENT costs it can't amortize:");
    println!("  • recovery LATENCY — ~250 ms to rebuild a broken pipe vs ~18 ms to re-express an Interest (14×)");
    println!("  • control OVERHEAD — a SEEK flood + handshake per rebuild, growing with λ×N (6→27 msg/s) vs ~2");
    println!("So named-data doesn't necessarily deliver more bits — it recovers ~14× faster and spends a");
    println!("fraction of the airtime doing it. For a MANET (responsiveness + scarce spectrum), those are the");
    println!("costs that matter, and they're the ones the named-data floor removes without host identity.");

    eprintln!("{{\"A\":[{}],\"B\":[{}],\"C\":[{}],\"vels\":[0.5,1,2,5,10,20],\"dens\":[10,25,50,100]}}",
        a_json.join(","), b_json.join(","), c_json.join(","));
}
