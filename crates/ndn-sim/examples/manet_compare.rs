//! Named-data radio vs IP MANET protocols — a fair, honest comparison on the CALIBRATED substrate.
//!
//! The substrate (multi-hop throughput retention) is anchored to the real MT7612U 802.11s mesh data
//! (examples/data/real_wifi_multihop.json, calibrated in sim_vs_real.rs). Every protocol here runs on
//! that same PHY/MAC — so throughput-over-hops is NOT where they differ. The honest thesis:
//!
//!   Throughput-over-hops is a SUBSTRATE story (single-radio collapse vs MRMC retention), NOT an
//!   L3-protocol story. AODV/DSR/802.11s-HWMP/batman-adv and single-radio NDN all land on the
//!   measured single-radio curve; research IP-MRMC (WCETT/MIC) and ndnpipes both land on the
//!   multi-radio curve. Where named-data ACTUALLY differs shows up on three other axes:
//!     B. multi-consumer / repeated content  → relay caching; IP re-fetches end-to-end
//!     C. mobility / route churn             → stateless forwarding sheds route-repair overhead
//!     D. MRMC + caching together            → IP-MRMC needs channel-assignment metrics AND still
//!                                             can't cache; ndnpipes gets MRMC from named pipes + caches
//!
//! FAIRNESS (per the user): stock IP/802.11s can't do MRMC natively → they get ONE radio/channel.
//! Only research IP-MRMC (Draves WCETT / Kyasanur-Vaidya MIC) gets multiple radios — compared
//! separately, as its own row, against ndnpipes.
//!
//! This is a first-order MODEL layered on measured PHY numbers — not a packet-level ns-3 sim. Every
//! assumption is named in-line so it can be argued with and improved.
//!
//! Run: `cargo run -p ndn-sim --example manet_compare`

const SLOTS: u64 = 20_000;
const WINDOW: u64 = 64;
const CS: i64 = 2;

// ---- calibrated substrate (same one-way chain scheduler as sim_vs_real.rs) ----------------------
fn schedule(hops: i64, channels: i64, radios: usize) -> f64 {
    let n = (hops + 1) as usize;
    let ch = |i: i64| i % channels;
    let mut q = vec![0u64; n];
    let mut done = 0u64;
    for _ in 0..SLOTS {
        q[0] = WINDOW;
        let mut cands: Vec<i64> = (0..hops).filter(|&i| q[i as usize] > 0).collect();
        cands.sort_unstable_by(|a, b| b.cmp(a)); // downstream-first drain
        let mut active: Vec<(i64, i64)> = Vec::new();
        let mut radio_use = vec![0usize; n];
        for t in cands {
            let r = t + 1;
            if radio_use[t as usize] >= radios || radio_use[r as usize] >= radios {
                continue;
            }
            let c = ch(t);
            let conflict = active.iter().any(|&(at, ac)| ac == c && (at - r).abs() <= CS || ac == c && (at - t).abs() <= CS);
            if !conflict {
                radio_use[t as usize] += 1;
                radio_use[r as usize] += 1;
                active.push((t, c));
            }
        }
        for (t, _) in &active {
            q[*t as usize] -= 1;
            if *t + 1 == hops {
                done += 1;
            } else {
                q[(*t + 1) as usize] += 1;
            }
        }
    }
    done as f64 / SLOTS as f64
}

/// Calibrated retention ÷ the 1-hop link. `mrmc` → 3 orthogonal channels + 2 radios, else 1/1.
/// link_eff: 0.72 contended (single channel) / 0.93 clean (spaced multi-channel).
fn retention(hops: i64, mrmc: bool) -> f64 {
    if hops <= 1 {
        return 1.0;
    }
    let (channels, radios, eff): (i64, usize, f64) = if mrmc { (3, 2, 0.93) } else { (1, 1, 0.72) };
    let r = schedule(hops, channels, radios) / schedule(1, channels, radios) * eff.powi((hops - 1) as i32);
    r
}

// ---- protocols ----------------------------------------------------------------------------------
#[derive(Clone, Copy)]
enum Route {
    Reactive,    // AODV: flood RREQ on demand / on break
    ReactiveSrc, // DSR: reactive + source route in header + route cache
    HybridL2,    // 802.11s HWMP: proactive tree + reactive, airtime metric
    ProactiveL2, // batman-adv: periodic OGM flood, best next-hop
    Stateless,   // NDN: PIT breadcrumbs, no route to repair
}

#[derive(Clone, Copy)]
struct Proto {
    name: &'static str,
    route: Route,
    mrmc: bool,
    caches: bool,
}

const PROTOS: &[Proto] = &[
    Proto { name: "AODV",          route: Route::Reactive,    mrmc: false, caches: false },
    Proto { name: "DSR",           route: Route::ReactiveSrc, mrmc: false, caches: false },
    Proto { name: "802.11s HWMP",  route: Route::HybridL2,    mrmc: false, caches: false },
    Proto { name: "batman-adv",    route: Route::ProactiveL2, mrmc: false, caches: false },
    Proto { name: "NDN (bcast)",   route: Route::Stateless,   mrmc: false, caches: true  },
    Proto { name: "IP-MRMC(WCETT)",route: Route::Reactive,    mrmc: true,  caches: false },
    Proto { name: "ndnpipes",      route: Route::Stateless,   mrmc: true,  caches: true  },
];

fn main() {
    // ---- Panel A: single-flow throughput vs hops (the substrate story) --------------------------
    // Every protocol runs the same PHY. NDN forwards by broadcast, but on a CHAIN each hop has one
    // receiver, so the named-radio face rates for that neighbour (worst-receiver = the only receiver)
    // — no basic-rate multicast tax here. We still charge NDN a small 0.97 for PIT/dedup processing,
    // to lean conservative rather than flatter it.
    let hops = [1i64, 2, 3, 4, 5];
    println!("A. single-flow throughput retention vs hops (÷ 1-hop link) — SUBSTRATE dominates\n");
    print!("  protocol         ");
    for h in hops {
        print!("{:>6}h", h);
    }
    println!("   radios");
    for p in PROTOS {
        print!("  {:<15}", p.name);
        for h in hops {
            let ndn_tax = if matches!(p.route, Route::Stateless) { 0.97 } else { 1.0 };
            print!("  {:>5.2}", retention(h, p.mrmc) * ndn_tax);
        }
        println!("   {}", if p.mrmc { "multi" } else { "1" });
    }
    println!("\n  → the split is single-radio (~0.17 at 3 hops) vs MRMC (~0.86). L3 protocol barely moves");
    println!("    it. NDN-broadcast ≈ 802.11s on a chain (one receiver/hop). This is a PHY result.");

    // ---- Panel B: multi-consumer / repeated content (caching) -----------------------------------
    // K consumers each fetch the SAME named content across an H=4-hop network. Cost = hop-transmissions
    // to satisfy all K (normalized to one fetch). IP has no relay cache: every consumer traverses the
    // full path → cost ≈ K·H. NDN caches at relays: the first fetch seeds the path, and with content
    // present along the network, each later consumer hits a copy ~1 hop away → cost ≈ H + (K−1)·1.
    // (First-order: dense-ish consumers, LRU big enough to hold the object. Sparse consumers weaken it.)
    let h_b = 4.0;
    println!("\nB. multi-consumer: cost (hop-transmissions) to serve K consumers the same content, H=4\n");
    println!("  K consumers   IP (no cache)   NDN (relay cache)   NDN speedup");
    for k in [1usize, 2, 4, 8, 16, 32] {
        let ip = k as f64 * h_b;
        let ndn = h_b + (k as f64 - 1.0); // first fetch seeds path, later ones ~1 hop to cache
        println!("  {:>7}       {:>10.0}      {:>12.0}        {:>6.1}×", k, ip, ndn, ip / ndn);
    }
    println!("  → IP cost is linear in consumers (no in-network reuse); NDN caching makes it ~flat.");
    println!("    This is structural: routing protocols move packets, they don't hold content.");

    // ---- Panel C: mobility / route churn (control overhead) --------------------------------------
    // Control transmissions/sec vs churn λ (route breaks/sec) over an N=20-node network. Reactive
    // protocols pay a flood (~N) per break; proactive pay a constant periodic cost regardless of
    // churn; stateless NDN pays no explicit repair — a broken path is rediscovered by the next
    // Interest re-expression over existing breadcrumbs/broadcast, folded into the data plane.
    let nn = 20.0;
    let ogm = nn / 1.0; // batman OGM: N originators / 1 s interval
    println!("\nC. mobility: control transmissions/sec vs route-break rate λ (N=20 nodes)\n");
    println!("  λ breaks/s   AODV    DSR    802.11s   batman    NDN(stateless)");
    for lam in [0.0f64, 0.5, 1.0, 2.0, 4.0, 8.0] {
        let aodv = lam * nn; // full RREQ flood per break
        let dsr = lam * nn * 0.6; // route cache salvages some rediscoveries
        let hwmp = 0.3 * nn + lam * nn * 0.5; // periodic tree upkeep + reactive repair
        let bat = ogm; // constant periodic OGMs, churn-independent (but stale)
        let ndn = lam * 0.0; // no explicit repair; cost folded into next data Interest
        println!("  {:>7.1}    {:>5.1}  {:>5.1}   {:>6.1}   {:>6.1}   {:>6.1}", lam, aodv, dsr, hwmp, bat, ndn);
    }
    println!("  → reactive overhead climbs with churn; batman is flat-but-stale; NDN sheds route repair");
    println!("    entirely (no route object exists to break). The named-data mobility advantage.");

    // ---- Panel D: MRMC + caching together (the ndnpipes payoff) ----------------------------------
    // The fair MRMC comparison is single-radio-stock vs research-IP-MRMC vs ndnpipes. Throughput they
    // can tie (both MRMC land on the multi-radio curve). The differentiator is what each needs and what
    // else it gets: IP-MRMC needs an explicit channel-assignment metric (WCETT/MIC) and STILL cannot
    // cache; ndnpipes derives channel diversity from named pipes AND caches. Score a 3-hop, 8-consumer
    // repeated-content workload: throughput retention × caching benefit.
    println!("\nD. MRMC + caching: 3-hop, 8-consumer repeated content — throughput AND reuse together\n");
    let h_d = 3i64;
    let k_d = 8.0;
    println!("  protocol          3-hop tput   serve-8 cost   effective (tput / cost, ↑ better)");
    for p in &[PROTOS[2], PROTOS[3], PROTOS[5], PROTOS[6]] {
        // 802.11s, batman (stock single-radio), IP-MRMC, ndnpipes
        let t = retention(h_d, p.mrmc);
        let cost = if p.caches { h_d as f64 + (k_d - 1.0) } else { k_d * h_d as f64 };
        let eff = t / cost;
        println!("  {:<15}   {:>7.2}     {:>10.0}       {:>8.3}", p.name, t, cost, eff);
    }
    println!("  → IP-MRMC wins throughput back but pays full re-fetch cost for every consumer; ndnpipes");
    println!("    matches the throughput AND collapses the cost via caching — MRMC and naming compound.");

    // ---- JSON for the dashboard -----------------------------------------------------------------
    let a: Vec<String> = PROTOS.iter().map(|p| {
        let tax = if matches!(p.route, Route::Stateless) { 0.97 } else { 1.0 };
        let series: Vec<String> = hops.iter().map(|&h| format!("{:.3}", retention(h, p.mrmc) * tax)).collect();
        format!("{{\"name\":\"{}\",\"mrmc\":{},\"caches\":{},\"tput\":[{}]}}", p.name, p.mrmc, p.caches, series.join(","))
    }).collect();
    let b: Vec<String> = [1usize, 2, 4, 8, 16, 32].iter().map(|&k| {
        format!("{{\"k\":{k},\"ip\":{:.0},\"ndn\":{:.0}}}", k as f64 * h_b, h_b + (k as f64 - 1.0))
    }).collect();
    let c: Vec<String> = [0.0f64, 0.5, 1.0, 2.0, 4.0, 8.0].iter().map(|&lam| {
        format!("{{\"lam\":{lam},\"aodv\":{:.1},\"dsr\":{:.1},\"hwmp\":{:.1},\"batman\":{:.1},\"ndn\":{:.1}}}",
            lam * nn, lam * nn * 0.6, 0.3 * nn + lam * nn * 0.5, ogm, 0.0)
    }).collect();
    let d: Vec<String> = [PROTOS[2], PROTOS[3], PROTOS[5], PROTOS[6]].iter().map(|p| {
        let t = retention(h_d, p.mrmc);
        let cost = if p.caches { h_d as f64 + (k_d - 1.0) } else { k_d * h_d as f64 };
        format!("{{\"name\":\"{}\",\"tput\":{:.3},\"cost\":{:.0},\"eff\":{:.4}}}", p.name, t, cost, t / cost)
    }).collect();
    eprintln!("{{\"hops\":[1,2,3,4,5],\"A\":[{}],\"B\":[{}],\"C\":[{}],\"D\":[{}]}}",
        a.join(","), b.join(","), c.join(","), d.join(","));
}
