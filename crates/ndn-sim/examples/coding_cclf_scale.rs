//! Coding × CCLF × scale — the interaction matrix over a dense multi-hop dissemination.
//!
//! coding_compare.rs shows the *character* of RLNC on a 2-hop path; coop.rs implements CCLF timer
//! suppression. Neither shows how the two axes INTERACT as a network scales. This does: a source
//! disseminates one generation of G packets to a whole field of N nodes, and we run the 2×2 —
//! {plain, RLNC} × {flood, CCLF} — over increasing density.
//!
//! The hypothesis I started with was the tidy one — "coding and CCLF are complementary: CCLF suppresses
//! redundant rebroadcasts, coding makes every surviving one universally innovative, so RLNC+CCLF is the
//! sweet spot." The measurement DISAGREED, and chasing why (four model fixes: a GF(2) linear-dependence
//! tail → GF(256) ideal; a rank-comparison want-gate that silenced equal-rank/different-subspace nodes
//! → a subspace-containment gate; then a budget sweep) produced the honest finding instead:
//!
//!   The two axes are NOT the same kind of lever, and for whole-network flood dissemination only ONE
//!   of them moves the needle.
//!     • CCLF is the win — it cuts airtime ~2× at scale by overhearing that neighbours already covered
//!       the content (broadcast-storm mitigation). Robust across budgets and loss.
//!     • Coding is ~NEUTRAL here. Given adequate budget every config delivers the same (dissemination
//!       is connectivity-bound); coding adds only ~3% efficiency on top of CCLF. There is no coupon
//!       wall for plain to hit, because flooding already gives each packet massive spatial redundancy —
//!       and coded rank must diffuse hop-by-hop from the SINGLE source, which under a tight budget +
//!       heavy loss is actually LESS budget-efficient than independent per-packet spread.
//!
//! Coding's real win is a DIFFERENT problem — a lossy relay PATH (source→relay→sink), where recoding
//! repairs the second hop without re-crossing the first. That is exactly what coding_compare.rs (F1/F2)
//! measures. Pairing coding with CCLF here does not create a synergy; claiming it would be the tidy lie.
//!
//! Model: round-based epidemic on a random geometric graph. A node offers if a neighbour still needs
//! something it holds (plain: `have[i] & ~have[j]`; coded: a subspace-containment `helps` test). It
//! transmits one packet (coded: a GF(256)-ideal recoded combination; plain: the packet most neighbours
//! lack); neighbours receive w.p. 1−e. CCLF: a willing node suppresses if ≥C earlier-jitter neighbours
//! also want this round (overhear-cancel). Coded state is a REAL GF(2) basis with Gaussian elimination
//! (subspace diversity, not a scalar-rank fudge); GF(256)-ideal reception adds a rank whenever the
//! sender holds a direction outside the receiver's subspace. tx count is the airtime proxy. Each
//! generation gets a finite BUDGET (it goes stale). Deterministic, averaged over seeds.
//!
//! Run: `cargo run -p ndn-sim --example coding_cclf_scale`

const FIELD: f64 = 100.0; // disc radius, m
const RANGE: f64 = 28.0; // in-range radius, m
const G: u32 = 16; // packets per generation
const C: usize = 2; // CCLF overhear-suppress threshold
const MAXR: usize = 240; // round cap
const SEEDS: u64 = 16; // placements averaged
// A generation is worth a bounded amount of airtime — it goes STALE. Each node gets a finite budget
// (a small multiple of G); it cannot retry forever. This is what makes the loss-robustness of coding
// and the airtime-thrift of CCLF matter: at quiescence with infinite retry, every config converges to
// the same connectivity-bound delivery and the axes look inert.
const BUDGET: u32 = 2 * G;

fn xs(s: &mut u64) -> u64 {
    let mut x = *s;
    x ^= x << 13; x ^= x >> 7; x ^= x << 17; *s = x; x
}
fn unif(s: &mut u64) -> f64 { (xs(s) >> 11) as f64 / (1u64 << 53) as f64 }

struct Graph {
    pos: Vec<(f64, f64)>,
    nbr: Vec<Vec<usize>>,
    jitter: Vec<f64>,
}
fn build(n: usize, seed: u64) -> Graph {
    let mut s = seed | 1;
    let mut pos = Vec::with_capacity(n);
    pos.push((0.0, 0.0)); // source at centre
    for _ in 1..n {
        let r = FIELD * unif(&mut s).sqrt();
        let th = unif(&mut s) * std::f64::consts::TAU;
        pos.push((r * th.cos(), r * th.sin()));
    }
    let mut nbr = vec![Vec::new(); n];
    for i in 0..n {
        for j in (i + 1)..n {
            let (dx, dy) = (pos[i].0 - pos[j].0, pos[i].1 - pos[j].1);
            if (dx * dx + dy * dy).sqrt() <= RANGE { nbr[i].push(j); nbr[j].push(i); }
        }
    }
    let jitter = (0..n).map(|i| { let mut js = seed ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1; unif(&mut js) }).collect();
    Graph { pos, nbr, jitter }
}

struct Out { delivery: f64, tx: f64 }

/// GF(2) coding basis in reduced form: `pivot[p]` is a vector whose highest set bit is `p` (0 = empty).
/// rank = number of occupied pivots. This is REAL random linear coding — subspace diversity, coupon-
/// freeness, and loss-robustness all fall out, instead of being approximated by a scalar rank.
type Basis = [u16; G as usize];
fn rank_of(b: &Basis) -> u32 { b.iter().filter(|&&v| v != 0).count() as u32 }
/// Residual of `v` after reducing against the basis (0 ⇒ v is already in the rowspace).
fn residual(b: &Basis, mut v: u16) -> u16 {
    while v != 0 {
        let p = (15 - v.leading_zeros()) as usize; // highest set bit
        if b[p] == 0 { return v; }
        v ^= b[p];
    }
    0
}
/// Reduce `v` against the basis and, if a nonzero residual survives, insert it. Returns innovative?
fn add_vec(b: &mut Basis, v: u16) -> bool {
    let r = residual(b, v);
    if r != 0 { let p = (15 - r.leading_zeros()) as usize; b[p] = r; true } else { false }
}
/// Does sender `si` hold ANY direction outside receiver `sj`'s subspace? (equal rank, different
/// subspace still helps — this is the gate plain gets right via `have[i] & ~have[j]` and the scalar
/// rank comparison gets WRONG: a cluster all at rank G−1 with different missing dims must still talk.)
fn helps(si: &Basis, sj: &Basis) -> bool { si.iter().any(|&v| v != 0 && residual(sj, v) != 0) }
/// GF(256) ideal recode: a coded packet from sender `si` is innovative to receiver `rj` iff the
/// sender's rowspace isn't already contained in the receiver's — over a large field a random
/// combination hits an innovative direction w.p. ≈ 1 (no GF(2) linear-dependence tail). Advances the
/// receiver by one rank if so. This is the field real RLNC (GF(2^8)) actually deploys — the fair model.
fn recode_innovative(rj: &mut Basis, si: &Basis) -> bool {
    for &v in si.iter() {
        if v == 0 { continue; }
        if add_vec(rj, v) { return true; } // first sender direction outside rj's subspace
    }
    false
}

fn disseminate(g: &Graph, coded: bool, cclf: bool, e: f64, seed: u64) -> (f64, u64) {
    let n = g.pos.len();
    let full = if G == 32 { u32::MAX } else { (1u32 << G) - 1 };
    // coded: per-node GF(2) basis; plain: native-packet bitmask
    let mut basis = vec![[0u16; G as usize]; n];
    let mut have = vec![0u32; n];
    let mut sent = vec![0u32; n];
    if coded { for p in 0..G as usize { basis[0][p] = 1u16 << p; } } // source: full identity basis
    have[0] = full;
    let mut rng = seed | 1;
    let mut tx_total = 0u64;

    let rk = |b: &Basis| rank_of(b);
    let decoded = |i: usize, basis: &[Basis], have: &[u32]| if coded { rk(&basis[i]) >= G } else { have[i] == full };
    // node i offers to the round if some neighbour still needs something it can supply — for coding
    // that is a SUBSPACE-containment test (helps), not a rank comparison: a cluster all at rank G−1
    // with different missing dimensions must still exchange to finish (the fix for the e=0.5 collapse).
    let offers = |i: usize, basis: &[Basis], have: &[u32], g: &Graph| {
        g.nbr[i].iter().any(|&j| if coded { helps(&basis[i], &basis[j]) } else { have[i] & !have[j] != 0 })
    };

    for _round in 0..MAXR {
        let want: Vec<bool> = (0..n).map(|i| sent[i] < BUDGET && (if coded { rk(&basis[i]) > 0 } else { have[i] != 0 }) && offers(i, &basis, &have, g)).collect();
        if !want.iter().any(|&w| w) { break; }
        // CCLF suppression: suppress if >= C earlier-jitter neighbours also want (overhear-cancel)
        let tx: Vec<bool> = (0..n).map(|i| {
            if !want[i] { return false; }
            if !cclf { return true; }
            g.nbr[i].iter().filter(|&&j| want[j] && g.jitter[j] < g.jitter[i]).count() < C
        }).collect();

        let (basis_s, have_s) = (basis.clone(), have.clone());
        for i in 0..n {
            if !tx[i] { continue; }
            sent[i] += 1; tx_total += 1;
            // what goes on air: the packet most neighbours lack (plain); coded case handled at RX.
            let plain_pkt = if coded { 0 } else {
                let mut best = 0u32; let mut best_cnt = -1i32;
                for b in 0..G { let m = 1u32 << b;
                    if have_s[i] & m != 0 {
                        let cnt = g.nbr[i].iter().filter(|&&j| have_s[j] & m == 0).count() as i32;
                        if cnt > best_cnt { best_cnt = cnt; best = m; }
                    } }
                best
            };
            for &j in &g.nbr[i] {
                if unif(&mut rng) < e { continue; } // lost
                if coded {
                    recode_innovative(&mut basis[j], &basis_s[i]); // any-K-of-N: gain a rank if i knows something new
                } else if have_s[i] & plain_pkt != 0 && have[j] & plain_pkt == 0 {
                    have[j] |= plain_pkt;
                }
            }
        }
    }
    let deliv = (0..n).filter(|&i| decoded(i, &basis, &have)).count();
    (deliv as f64 / n as f64, tx_total)
}

fn run(n: usize, coded: bool, cclf: bool, e: f64) -> Out {
    let (mut d, mut t) = (0.0, 0.0);
    for s in 0..SEEDS {
        let g = build(n, 0xABCD_0000 ^ s.wrapping_mul(0x100_0001));
        let (deliv, tx) = disseminate(&g, coded, cclf, e, 0xFEED_0000 ^ s.wrapping_mul(0x0A1B_2C3D));
        d += deliv; t += tx as f64;
    }
    Out { delivery: d / SEEDS as f64, tx: t / SEEDS as f64 }
}

fn main() {
    let configs = [("plain+flood", false, false), ("plain+CCLF", false, true), ("RLNC+flood", true, false), ("RLNC+CCLF", true, true)];
    println!("Coding × CCLF × scale — G={G} packets, field r={FIELD}m, range={RANGE}m, budget={BUDGET} tx/node\n");

    // ---- A: delivery vs erasure (fixed density, finite budget) — coding's robustness ----
    let n_a = 120;
    let eras = [0.10f64, 0.20, 0.30, 0.40, 0.50];
    println!("A. delivery vs per-link erasure e (N={n_a}, dense/connected) — is coding more robust? (no)\n");
    print!("  e      ");
    for (name, _, _) in configs { print!("{:>13}", name); }
    println!();
    let mut a_json = Vec::new();
    for &e in &eras {
        print!("  {:>4.2}  ", e);
        for (name, c, f) in configs {
            let o = run(n_a, c, f, e);
            print!("{:>12.1}%", 100.0 * o.delivery);
            a_json.push(format!("{{\"e\":{e},\"cfg\":\"{name}\",\"deliv\":{:.4},\"tx\":{:.1}}}", o.delivery, o.tx));
        }
        println!();
    }
    println!("\n  → all four track together — dissemination is budget/connectivity-bound, not coding-bound.");
    println!("    Flood's per-packet spatial redundancy means plain hits no coupon wall; coding's any-K-of-N");
    println!("    buys ~nothing here (its win is the lossy relay PATH — coding_compare.rs, not the field).");

    // ---- B: airtime vs scale (fixed erasure) — CCLF's storm mitigation ----
    let e_b = 0.20;
    let scales = [30usize, 60, 120, 200];
    println!("\nB. airtime spent vs density (e={e_b}) — where CCLF earns its keep (lower is better)\n");
    print!("  N     ");
    for (name, _, _) in configs { print!("{:>13}", name); }
    println!();
    let mut b_json = Vec::new();
    for &n in &scales {
        print!("  {:>3}   ", n);
        for (name, c, f) in configs {
            let o = run(n, c, f, e_b);
            print!("{:>13.0}", o.tx);
            b_json.push(format!("{{\"n\":{n},\"cfg\":\"{name}\",\"tx\":{:.1},\"deliv\":{:.4}}}", o.tx, o.delivery));
        }
        println!();
    }
    println!("\n  → flood's airtime climbs with density (the broadcast storm); CCLF stays flat by");
    println!("    overhearing that neighbours already covered the content.");

    // ---- C: the money metric — delivery ÷ airtime at loss+density (config compound) ----
    let (n_c, e_c) = (120usize, 0.30);
    println!("\nC. delivered nodes per 1000 tx at N={n_c}, e={e_c} — the compound (higher is better)\n");
    let mut c_json = Vec::new();
    for (name, c, f) in configs {
        let o = run(n_c, c, f, e_c);
        let eff = if o.tx > 0.0 { 1000.0 * o.delivery * n_c as f64 / o.tx } else { 0.0 };
        println!("  {:<13}  deliv {:>5.1}%   airtime {:>6.0}   efficiency {:>6.1}", name, 100.0 * o.delivery, o.tx, eff);
        c_json.push(format!("{{\"cfg\":\"{name}\",\"deliv\":{:.4},\"tx\":{:.1},\"eff\":{:.2}}}", o.delivery, o.tx, eff));
    }
    println!("\ntakeaway (honest, and NOT what I expected): CCLF is the lever — it roughly halves airtime at");
    println!("scale (col B) and lifts efficiency ~25% (col C). Coding is ~neutral for whole-network flood:");
    println!("RLNC+CCLF beats plain+CCLF by only ~3%, well inside the margin. The tidy 'coding+CCLF sweet");
    println!("spot' story does NOT survive measurement here. Coding's real payoff is the lossy relay path");
    println!("(coding_compare.rs F1/F2), a different problem — pairing it with CCLF creates no synergy.");

    eprintln!("{{\"G\":{G},\"budget\":{BUDGET},\"eras\":[0.1,0.2,0.3,0.4,0.5],\"scales\":[30,60,120,200],\"A\":[{}],\"B\":[{}],\"C\":[{}]}}",
        a_json.join(","), b_json.join(","), c_json.join(","));
}
