//! Topology generators — build a [`Scenario`]'s graph (nodes + wired links) without hand-authoring
//! TOML. A sim toolkit's table stakes: `line(20)`, `grid(4, 5)`, `random(30, 0.15, seed)` instead of
//! a hundred lines of `[[nodes]]`/`[[links]]`.
//!
//! Each generator returns a [`Scenario`] with `n` labelled nodes and a set of links, defaulting to
//! the deterministic [`DesKernel`](crate::DesKernel) (`KernelSpec::Des`) so a generated topology is
//! reproducible out of the box. The graph carries no apps or routes; add them yourself, or use
//! [`add_routes_toward`] to install shortest-path FIB routes toward a producer so the topology
//! forwards a prefix immediately.
//!
//! ```rust
//! use ndn_sim::topo;
//!
//! let mut grid = topo::grid(3, 3);          // 9 nodes, 4-neighbour mesh
//! topo::add_routes_toward(&mut grid, "/demo", 0);   // every node routes /demo toward node 0
//! assert_eq!(grid.nodes.len(), 9);
//! assert_eq!(grid.routes.len(), 8);         // every non-destination node gets one next-hop route
//! ```

use std::collections::{HashMap, VecDeque};

use crate::scenario::{KernelSpec, NodeSpec, RouteSpec, Scenario, ScenarioLink};

/// A scenario shell with `n` labelled nodes on the deterministic DES kernel and no links yet.
fn nodes(n: usize) -> Scenario {
    Scenario {
        kernel: KernelSpec::Des { epoch_ns: None },
        nodes: (0..n)
            .map(|i| NodeSpec { label: Some(format!("n{i}")), ..Default::default() })
            .collect(),
        ..Default::default()
    }
}

/// A 1 ms wired link between two node indices.
fn link(a: usize, b: usize) -> ScenarioLink {
    ScenarioLink { a, b, delay_ms: 1, ..Default::default() }
}

/// A chain: `0 — 1 — 2 — … — (n-1)`. The canonical convergence topology.
pub fn line(n: usize) -> Scenario {
    let mut s = nodes(n);
    s.links = (1..n).map(|i| link(i - 1, i)).collect();
    s
}

/// A ring: a [`line`] with the ends joined (`… — (n-1) — 0`). Needs `n >= 3` to add the closing link.
pub fn ring(n: usize) -> Scenario {
    let mut s = line(n);
    if n >= 3 {
        s.links.push(link(n - 1, 0));
    }
    s
}

/// A star: node `0` is the hub, nodes `1..n` are leaves each linked only to the hub.
pub fn star(n: usize) -> Scenario {
    let mut s = nodes(n);
    s.links = (1..n).map(|i| link(0, i)).collect();
    s
}

/// A `rows × cols` grid with 4-neighbour (von Neumann) links. Node `(r, c)` has index `r*cols + c`.
pub fn grid(rows: usize, cols: usize) -> Scenario {
    let mut s = nodes(rows * cols);
    let idx = |r: usize, c: usize| r * cols + c;
    for r in 0..rows {
        for c in 0..cols {
            if c + 1 < cols {
                s.links.push(link(idx(r, c), idx(r, c + 1)));
            }
            if r + 1 < rows {
                s.links.push(link(idx(r, c), idx(r + 1, c)));
            }
        }
    }
    s
}

/// A full mesh: every pair of the `n` nodes is linked (`n·(n-1)/2` links). Dense — keep `n` small.
pub fn full_mesh(n: usize) -> Scenario {
    let mut s = nodes(n);
    for a in 0..n {
        for b in (a + 1)..n {
            s.links.push(link(a, b));
        }
    }
    s
}

/// A complete `branching`-ary tree of the given `depth` (root = node 0, depth 0 = the root alone).
/// Nodes are numbered breadth-first, so a child of node `p` is `p*branching + k`.
pub fn tree(branching: usize, depth: usize) -> Scenario {
    let branching = branching.max(1);
    // Node count of a complete k-ary tree of the given depth.
    let mut count = 0usize;
    let mut level = 1usize;
    for _ in 0..=depth {
        count += level;
        level = level.saturating_mul(branching);
    }
    let mut s = nodes(count);
    // Link each node (past the root) to its parent (child index c → parent (c-1)/branching).
    for c in 1..count {
        let parent = (c - 1) / branching;
        s.links.push(link(parent, c));
    }
    s
}

/// An Erdős–Rényi random graph: each of the `n·(n-1)/2` possible edges is present with probability
/// `edge_prob`, drawn from a `seed`-seeded deterministic PRNG (same seed → same graph). The result is
/// then made **connected** by linking otherwise-isolated components, so every node is reachable.
pub fn random(n: usize, edge_prob: f64, seed: u64) -> Scenario {
    let mut s = nodes(n);
    let mut rng = SplitMix64::new(seed ^ 0x9E37_79B9_7F4A_7C15);
    let mut parent: Vec<usize> = (0..n).collect();
    for a in 0..n {
        for b in (a + 1)..n {
            if rng.next_f64() < edge_prob {
                s.links.push(link(a, b));
                union(&mut parent, a, b);
            }
        }
    }
    // Connect the components: chain one representative per component into node 0's component.
    for v in 1..n {
        if find(&mut parent, v) != find(&mut parent, 0) {
            s.links.push(link(0, v));
            union(&mut parent, 0, v);
        }
    }
    s
}

/// Install shortest-path FIB routes for `prefix` at every node toward `dest`, computed by BFS over
/// the (undirected) link graph. After this, an Interest for `prefix` from any node walks the shortest
/// hop chain to a producer at `dest`. Existing routes for other prefixes are left untouched.
pub fn add_routes_toward(scenario: &mut Scenario, prefix: &str, dest: usize) {
    let n = scenario.nodes.len();
    if dest >= n {
        return;
    }
    // Adjacency from the undirected links.
    let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
    for l in &scenario.links {
        adj.entry(l.a).or_default().push(l.b);
        adj.entry(l.b).or_default().push(l.a);
    }
    // BFS from dest; `next_hop[v]` = the neighbour of v on the shortest path toward dest.
    let mut next_hop: HashMap<usize, usize> = HashMap::new();
    let mut seen = vec![false; n];
    seen[dest] = true;
    let mut q = VecDeque::from([dest]);
    while let Some(u) = q.pop_front() {
        for &w in adj.get(&u).map(Vec::as_slice).unwrap_or(&[]) {
            if !seen[w] {
                seen[w] = true;
                next_hop.insert(w, u); // reached w from u, so u is w's next hop toward dest
                q.push_back(w);
            }
        }
    }
    for (node, nexthop) in next_hop {
        scenario.routes.push(RouteSpec { node, prefix: prefix.to_string(), nexthop });
    }
    scenario.routes.sort_by_key(|r| (r.node, r.nexthop));
}

// --- a tiny deterministic PRNG (splitmix64) so `random` needs no `rand` dependency ---

struct SplitMix64 {
    state: u64,
}
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// A uniform draw in `[0, 1)`.
    fn next_f64(&mut self) -> f64 {
        // 53 bits of mantissa precision.
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

// --- union-find for the connectivity fix-up ---

fn find(parent: &mut [usize], x: usize) -> usize {
    let mut r = x;
    while parent[r] != r {
        r = parent[r];
    }
    // Path-compress.
    let mut c = x;
    while parent[c] != r {
        let next = parent[c];
        parent[c] = r;
        c = next;
    }
    r
}

fn union(parent: &mut [usize], a: usize, b: usize) {
    let ra = find(parent, a);
    let rb = find(parent, b);
    if ra != rb {
        parent[ra] = rb;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_connected(s: &Scenario) -> bool {
        let n = s.nodes.len();
        if n == 0 {
            return true;
        }
        let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
        for l in &s.links {
            adj.entry(l.a).or_default().push(l.b);
            adj.entry(l.b).or_default().push(l.a);
        }
        let mut seen = vec![false; n];
        seen[0] = true;
        let mut q = VecDeque::from([0usize]);
        let mut count = 1;
        while let Some(u) = q.pop_front() {
            for &w in adj.get(&u).map(Vec::as_slice).unwrap_or(&[]) {
                if !seen[w] {
                    seen[w] = true;
                    count += 1;
                    q.push_back(w);
                }
            }
        }
        count == n
    }

    #[test]
    fn line_ring_star_have_the_expected_edge_counts() {
        assert_eq!(line(5).links.len(), 4);
        assert_eq!(ring(5).links.len(), 5); // the closing edge
        assert_eq!(star(5).links.len(), 4); // hub → 4 leaves
        assert!(is_connected(&line(5)) && is_connected(&ring(5)) && is_connected(&star(5)));
    }

    #[test]
    fn grid_and_mesh_and_tree_are_well_formed() {
        let g = grid(3, 4);
        assert_eq!(g.nodes.len(), 12);
        // 3*(4-1) horizontal + 4*(3-1) wait: rows*(cols-1) horizontal + (rows-1)*cols vertical.
        assert_eq!(g.links.len(), 3 * 3 + 2 * 4);
        assert!(is_connected(&g));

        let m = full_mesh(6);
        assert_eq!(m.links.len(), 6 * 5 / 2);

        let t = tree(2, 3); // complete binary tree of depth 3 = 1+2+4+8 = 15 nodes, 14 edges
        assert_eq!(t.nodes.len(), 15);
        assert_eq!(t.links.len(), 14);
        assert!(is_connected(&t));
    }

    #[test]
    fn random_is_connected_and_deterministic() {
        let a = random(30, 0.1, 42);
        let b = random(30, 0.1, 42);
        assert_eq!(a.links.len(), b.links.len(), "same seed → same graph");
        assert!(is_connected(&a), "the connectivity fix-up guarantees reachability");
        // A different seed gives a different graph (overwhelmingly likely at this size).
        let c = random(30, 0.1, 7);
        assert_ne!(a.links.len(), c.links.len());
    }

    #[test]
    fn routes_toward_reach_every_node() {
        let mut s = line(5); // 0-1-2-3-4
        add_routes_toward(&mut s, "/demo", 0);
        // Every node except the destination gets exactly one next-hop route toward 0.
        assert_eq!(s.routes.len(), 4);
        // On a line toward 0, node k's next hop is k-1.
        for r in &s.routes {
            assert_eq!(r.nexthop, r.node - 1, "line routes point one hop toward the destination");
            assert_eq!(r.prefix, "/demo");
        }
    }
}
