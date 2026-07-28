//! Mobility study — velocity × scale, MEASURED on the RandomWaypoint mobility model.
//!
//! #69's Panel C *modeled* mobility overhead. This MEASURES the consequence. N nodes roam a disc
//! under RandomWaypoint at speed v; each epoch we build the in-range connectivity graph and run two
//! forwarding disciplines between the same consumer/producer pairs:
//!
//!   NDN (stateless):   delivered whenever SOME multi-hop path exists right now (BFS on the current
//!                      graph). No route is committed — every Interest re-finds a path. Nothing to
//!                      repair; a moved node just changes which breadcrumbs light up.
//!   IP (route-based):  commits to one path. Delivered while that exact path stays connected. When a
//!                      hop on it breaks, the route goes DOWN for `repair_time` (rediscovery latency),
//!                      then a fresh path is committed. This is the AODV/DSR/HWMP failure mode.
//!
//! Both need a path to EXIST — at high speed / low density the graph partitions and BOTH drop (honest:
//! mobility doesn't conjure connectivity). NDN's edge is using whatever path exists NOW instead of
//! sitting in repair on a stale one. We also measure the committed route's break rate → the real λ
//! that Panel C assumed.
//!
//! Run: `cargo run -p ndn-sim --example mobility_study`

use ndn_sim::{MobilityModel, RandomWaypointMobility};

const REGION_R: f64 = 120.0; // disc radius, m
const COMM_R: f64 = 45.0; // in-range radius, m
const T: f64 = 180.0; // seconds
const DT: f64 = 0.5; // epoch, s
const REPAIR: f64 = 1.5; // IP route rediscovery downtime, s

fn positions(nodes: &[RandomWaypointMobility], t: f64) -> Vec<(f64, f64)> {
    nodes.iter().map(|m| { let p = m.position(t); (p.x, p.y) }).collect()
}

/// Adjacency as per-node neighbour lists (within COMM_R).
fn adjacency(pos: &[(f64, f64)]) -> Vec<Vec<usize>> {
    let n = pos.len();
    let mut adj = vec![Vec::new(); n];
    for i in 0..n {
        for j in (i + 1)..n {
            let (dx, dy) = (pos[i].0 - pos[j].0, pos[i].1 - pos[j].1);
            if (dx * dx + dy * dy).sqrt() <= COMM_R {
                adj[i].push(j);
                adj[j].push(i);
            }
        }
    }
    adj
}

/// Shortest path (BFS) src→dst on the current graph; None if disconnected.
fn bfs(src: usize, dst: usize, adj: &[Vec<usize>]) -> Option<Vec<usize>> {
    if src == dst { return Some(vec![src]); }
    let mut prev = vec![usize::MAX; adj.len()];
    prev[src] = src;
    let mut q = std::collections::VecDeque::from([src]);
    while let Some(u) = q.pop_front() {
        for &v in &adj[u] {
            if prev[v] == usize::MAX {
                prev[v] = u;
                if v == dst {
                    let mut path = vec![dst];
                    let mut c = dst;
                    while c != src { c = prev[c]; path.push(c); }
                    path.reverse();
                    return Some(path);
                }
                q.push_back(v);
            }
        }
    }
    None
}

/// Is a committed route still fully connected in the current adjacency?
fn route_up(route: &[usize], adj: &[Vec<usize>]) -> bool {
    route.windows(2).all(|w| adj[w[0]].contains(&w[1]))
}

struct Result {
    ndn: f64,     // delivery ratio
    ip: f64,      // delivery ratio
    lam: f64,     // measured committed-route break rate (breaks/s)
    ndn_hops: f64, // avg NDN path length when delivered
}

fn run(n: usize, speed: f64) -> Result {
    // deterministic independent tracks; distinct seed per node
    let nodes: Vec<RandomWaypointMobility> = (0..n)
        .map(|i| RandomWaypointMobility { radius: REGION_R, speed_mps: speed, seed: 0x1234_5678 ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) })
        .collect();
    // consumer/producer pairs, spread across the id space, averaged for smooth curves
    let pairs: Vec<(usize, usize)> = (0..8).map(|k| (k, n - 1 - k)).filter(|(a, b)| a < b).collect();
    let epochs = (T / DT) as usize;

    let (mut ndn_ok, mut ip_ok, mut breaks, mut hops_sum, mut hops_cnt, mut total) = (0u64, 0u64, 0u64, 0.0f64, 0u64, 0u64);
    for &(c, p) in &pairs {
        let mut committed: Option<Vec<usize>> = None;
        let mut down_until = -1.0f64;
        for e in 0..epochs {
            let t = e as f64 * DT;
            let adj = adjacency(&positions(&nodes, t));
            total += 1;
            // NDN: any path now?
            if let Some(path) = bfs(c, p, &adj) {
                ndn_ok += 1;
                hops_sum += (path.len() - 1) as f64;
                hops_cnt += 1;
            }
            // IP: committed route with repair
            let intact = committed.as_ref().map_or(false, |r| route_up(r, &adj));
            if intact && t >= down_until {
                ip_ok += 1;
            } else {
                if intact { /* unreachable: intact implies up */ }
                if committed.is_some() && !intact {
                    breaks += 1; // the committed path just broke
                    committed = None;
                    down_until = t + REPAIR;
                }
                if t >= down_until {
                    if let Some(path) = bfs(c, p, &adj) {
                        committed = Some(path);
                        ip_ok += 1; // rediscovered and delivered this epoch
                    }
                }
            }
        }
    }
    Result {
        ndn: ndn_ok as f64 / total as f64,
        ip: ip_ok as f64 / total as f64,
        lam: breaks as f64 / (T * pairs.len() as f64),
        ndn_hops: if hops_cnt > 0 { hops_sum / hops_cnt as f64 } else { 0.0 },
    }
}

fn main() {
    println!("Mobility study — RandomWaypoint, disc r={REGION_R}m, comm r={COMM_R}m, repair={REPAIR}s\n");

    // ---- velocity sweep (fixed density) ----
    let n_v = 40;
    println!("A. delivery vs velocity (N={n_v}): pedestrian → vehicular\n");
    println!("  speed m/s   NDN deliv   IP deliv   NDN−IP gap   route-breaks/s (λ)   NDN hops");
    let vel = [0.5f64, 1.0, 2.0, 5.0, 10.0, 20.0];
    let mut a_json = Vec::new();
    for v in vel {
        let r = run(n_v, v);
        println!("  {:>7.1}     {:>6.1}%    {:>6.1}%    {:>+6.1}pp      {:>8.3}            {:>4.1}",
            v, 100.0 * r.ndn, 100.0 * r.ip, 100.0 * (r.ndn - r.ip), r.lam, r.ndn_hops);
        a_json.push(format!("{{\"v\":{v},\"ndn\":{:.4},\"ip\":{:.4},\"lam\":{:.4},\"hops\":{:.2}}}", r.ndn, r.ip, r.lam, r.ndn_hops));
    }
    println!("\n  → NDN tracks connectivity; IP loses every epoch it's stuck in repair on a stale route.");
    println!("    The gap peaks at moderate churn — paths exist but change faster than IP can re-commit.");

    // ---- scale/density sweep (fixed velocity) ----
    let v_s = 5.0;
    println!("\nB. delivery vs scale/density (v={v_s} m/s): more nodes → richer graph, more paths\n");
    println!("  nodes N   NDN deliv   IP deliv   NDN−IP gap   route-breaks/s (λ)");
    let scales = [12usize, 25, 50, 100];
    let mut b_json = Vec::new();
    for n in scales {
        let r = run(n, v_s);
        println!("  {:>5}     {:>6.1}%    {:>6.1}%    {:>+6.1}pp      {:>8.3}",
            n, 100.0 * r.ndn, 100.0 * r.ip, 100.0 * (r.ndn - r.ip), r.lam);
        b_json.push(format!("{{\"n\":{n},\"ndn\":{:.4},\"ip\":{:.4},\"lam\":{:.4}}}", r.ndn, r.ip, r.lam));
    }
    println!("\n  → density helps BOTH (more alternate paths); NDN converts it faster because it can use");
    println!("    a new path the instant it forms, without a rediscovery round-trip.");

    // ---- velocity × scale gap grid ----
    println!("\nC. NDN−IP delivery gap (pp) over velocity × scale — where statelessness pays most\n");
    print!("      N=   ");
    for n in scales { print!("{:>6}", n); }
    println!();
    let mut c_json = Vec::new();
    for v in vel {
        print!("  v={:>4.1}  ", v);
        for &n in &scales {
            let r = run(n, v);
            let gap = 100.0 * (r.ndn - r.ip);
            print!("{:>5.0} ", gap);
            c_json.push(format!("{{\"v\":{v},\"n\":{n},\"gap\":{:.1}}}", gap));
        }
        println!();
    }

    eprintln!("{{\"A\":[{}],\"B\":[{}],\"C\":[{}],\"repair\":{REPAIR}}}", a_json.join(","), b_json.join(","), c_json.join(","));
}
