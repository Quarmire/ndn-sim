//! Pluggable IP **routing algorithms** for the in-sim IP plane, so an NDN-vs-IP benchmark can run
//! the routing a given deployment would actually use — infrastructure, MANET, VANET, or FANET.
//!
//! A [`RoutingAlgorithm`] computes each node's routing table (next-hop per destination) from a
//! [`TopologyView`] (the graph, link costs, and — for geographic protocols — node positions). The
//! [`IpNetwork`](crate::IpNetwork) installs the result. On a *static* graph the proactive algorithms
//! converge to the same shortest paths; their differences (control overhead, reconvergence latency,
//! behaviour under mobility) are what a benchmark exposes once the topology moves.
//!
//! # Grounding (canonical references)
//!
//! Infrastructure / wired (table-driven, stable topology):
//! - **RIP** — distance-vector, hop-count, Bellman-Ford, "infinity" = 16 (RFC 2453). Modelled by
//!   [`DistanceVector`].
//! - **OSPF** — link-state, Dijkstra SPF (RFC 2328). Modelled (converged state) by [`ShortestPath`].
//!
//! MANET (mobile ad-hoc):
//! - **DSDV** — proactive destination-sequenced distance-vector (Perkins & Bhagwat, SIGCOMM 1994).
//!   A DV with sequence numbers to avoid loops/count-to-infinity; converged routes = [`DistanceVector`].
//! - **AODV** — reactive on-demand DV, RREQ/RREP + sequence numbers (RFC 3561). *Roadmap*
//!   ([`RoutingCategory::Reactive`]).
//! - **OLSR** — proactive link-state with Multipoint Relays to bound flooding (RFC 3626; OLSRv2 RFC
//!   7181). Converged routes = [`ShortestPath`]; the MPR overhead model is *roadmap*.
//! - **DSR** — reactive source routing (RFC 4728). *Roadmap*.
//! - **Babel** — loop-avoiding DV, wired + wireless (RFC 8966).
//!
//! VANET / FANET (high mobility, position-aware):
//! - **GPSR** — Greedy Perimeter Stateless Routing: greedy geographic forwarding to the neighbour
//!   closest to the destination, with perimeter (face) routing around voids (Karp & Kung, MobiCom
//!   2000). The natural fit for ndn-lab because the [`World`](crate::World) already holds positions
//!   and mobility. Greedy mode = [`GreedyGeographic`]; perimeter mode is *roadmap*.
//! - FANETs commonly adapt MANET protocols (OLSR/AODV/DSDV) plus geographic routing with 3-D /
//!   predictive extensions (Bekmezci, Sahingoz & Temel, "Flying Ad-Hoc Networks (FANETs): A survey",
//!   *Ad Hoc Networks* 11(3), 2013; Oubbati et al., UAV-routing surveys).

use crate::world::Position;

/// The topology a [`RoutingAlgorithm`] routes over: `n` nodes, a weighted adjacency list, and
/// (optionally) node positions for geographic protocols.
pub struct TopologyView {
    /// Number of nodes.
    pub n: usize,
    /// `adj[u]` = the `(neighbour, link_cost)` edges out of node `u` (undirected graphs list both).
    pub adj: Vec<Vec<(usize, u32)>>,
    /// Node positions, when known (radio scenarios / geographic routing). `None` = not position-aware.
    pub positions: Option<Vec<Position>>,
}

impl TopologyView {
    /// A view from an undirected, unit-cost link list (hop-count metric).
    pub fn from_links(n: usize, links: &[(usize, usize)]) -> Self {
        let mut adj = vec![Vec::new(); n];
        for &(a, b) in links {
            adj[a].push((b, 1));
            adj[b].push((a, 1));
        }
        TopologyView { n, adj, positions: None }
    }

    /// Attach node positions (enables [`GreedyGeographic`]).
    pub fn with_positions(mut self, positions: Vec<Position>) -> Self {
        self.positions = Some(positions);
        self
    }
}

/// One routing-table row: reach `dest` via neighbour `next_hop` at path cost `metric`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RouteEntry {
    pub dest: usize,
    pub next_hop: usize,
    pub metric: u32,
}

/// The design family a protocol belongs to — its overhead and mobility behaviour follow from this.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingCategory {
    /// Table-driven: every node maintains routes to all destinations (RIP, OSPF, DSDV, OLSR).
    Proactive,
    /// On-demand: routes discovered per destination when first needed (AODV, DSR).
    Reactive,
    /// Position-based: forwarding decided per hop from node coordinates (GPSR).
    Geographic,
}

/// A routing algorithm that computes per-node routing tables from a [`TopologyView`]. `Send + Sync`
/// so it can drive a background re-router ([`IpNetwork::spawn_router`](crate::IpNetwork::spawn_router)).
pub trait RoutingAlgorithm: Send + Sync {
    /// A short name (e.g. `"shortest-path"`, `"distance-vector"`).
    fn name(&self) -> &'static str;
    /// The protocol family it models.
    fn category(&self) -> RoutingCategory;
    /// `tables[u][..]` = node `u`'s routing table (one [`RouteEntry`] per reachable destination).
    fn compute(&self, view: &TopologyView) -> Vec<Vec<RouteEntry>>;
    /// An estimate of the **control traffic** (bytes) this protocol puts on the wire per update
    /// period over `view` with `active_flows` distinct destinations in use — the routing overhead a
    /// benchmark bills against the payload (so OLSR vs DV vs GPSR differ in *cost*, not just routes).
    /// Grounded in each family's mechanism; see the impls. Default `0` (a genie/static baseline).
    fn control_overhead(&self, view: &TopologyView, active_flows: usize) -> u64 {
        let _ = (view, active_flows);
        0
    }
}

/// Approx bytes on the wire for a message flooded once by every node (each node's neighbours receive
/// it): `nodes × avg_degree × msg_bytes`.
fn flood_bytes(view: &TopologyView, msg_bytes: u64) -> u64 {
    let edges: usize = view.adj.iter().map(Vec::len).sum(); // = 2 × undirected edges
    edges as u64 * msg_bytes
}

/// **Link-state / Dijkstra** shortest paths (the converged state of OSPF / OLSR). Each node computes
/// least-cost paths to every destination; the table's `next_hop` is the first hop on that path.
#[derive(Clone, Copy, Debug, Default)]
pub struct ShortestPath;

impl RoutingAlgorithm for ShortestPath {
    fn name(&self) -> &'static str {
        "shortest-path"
    }
    fn category(&self) -> RoutingCategory {
        RoutingCategory::Proactive
    }
    fn compute(&self, view: &TopologyView) -> Vec<Vec<RouteEntry>> {
        (0..view.n).map(|src| dijkstra_table(view, src)).collect()
    }
    /// Link-state: every node floods a link-state advert (its neighbour list) each period.
    fn control_overhead(&self, view: &TopologyView, _active_flows: usize) -> u64 {
        if view.n == 0 {
            return 0;
        }
        let avg_deg = view.adj.iter().map(Vec::len).sum::<usize>() / view.n;
        let lsa_bytes = 24 + avg_deg as u64 * 6; // header + one entry per neighbour
        view.n as u64 * flood_bytes(view, lsa_bytes)
    }
}

/// Dijkstra from `src`, returning its routing table (first-hop toward each reachable destination).
fn dijkstra_table(view: &TopologyView, src: usize) -> Vec<RouteEntry> {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    let n = view.n;
    let mut dist = vec![u32::MAX; n];
    let mut first_hop = vec![usize::MAX; n];
    dist[src] = 0;
    // Min-heap on (cost, node).
    let mut heap = BinaryHeap::new();
    heap.push(Reverse((0u32, src)));
    while let Some(Reverse((d, u))) = heap.pop() {
        if d > dist[u] {
            continue;
        }
        for &(v, w) in &view.adj[u] {
            let nd = d.saturating_add(w);
            if nd < dist[v] {
                dist[v] = nd;
                // The first hop to `v` is `v` itself if `u == src`, else inherited from `u`.
                first_hop[v] = if u == src { v } else { first_hop[u] };
                heap.push(Reverse((nd, v)));
            }
        }
    }
    (0..n)
        .filter(|&d| d != src && dist[d] != u32::MAX)
        .map(|d| RouteEntry { dest: d, next_hop: first_hop[d], metric: dist[d] })
        .collect()
}

/// **Distance-vector / Bellman-Ford** (the converged state of RIP / DSDV). Equivalent least-cost
/// routes to [`ShortestPath`] on a static graph, but modelled the DV way — each node knows only its
/// neighbours' vectors — with a RIP-style `max_metric` "infinity" beyond which a destination is
/// unreachable (RIP uses 16).
#[derive(Clone, Copy, Debug)]
pub struct DistanceVector {
    /// The "infinity" metric — paths costing at least this are treated as unreachable (RIP = 16).
    pub max_metric: u32,
}

impl Default for DistanceVector {
    fn default() -> Self {
        DistanceVector { max_metric: 16 }
    }
}

impl RoutingAlgorithm for DistanceVector {
    fn name(&self) -> &'static str {
        "distance-vector"
    }
    fn category(&self) -> RoutingCategory {
        RoutingCategory::Proactive
    }
    fn compute(&self, view: &TopologyView) -> Vec<Vec<RouteEntry>> {
        let n = view.n;
        // dist[u][d], next[u][d]: node u's distance to d and its chosen next hop.
        let mut dist = vec![vec![u32::MAX; n]; n];
        let mut next = vec![vec![usize::MAX; n]; n];
        for (u, row) in dist.iter_mut().enumerate() {
            row[u] = 0;
        }
        // Relax neighbour vectors until no change (Bellman-Ford; bounded by n rounds).
        for _ in 0..n {
            let mut changed = false;
            for u in 0..n {
                for &(v, w) in &view.adj[u] {
                    for d in 0..n {
                        if dist[v][d] == u32::MAX {
                            continue;
                        }
                        let cand = w.saturating_add(dist[v][d]);
                        if cand < self.max_metric && cand < dist[u][d] {
                            dist[u][d] = cand;
                            next[u][d] = v; // reach d via neighbour v
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        (0..n)
            .map(|u| {
                (0..n)
                    .filter(|&d| d != u && next[u][d] != usize::MAX)
                    .map(|d| RouteEntry { dest: d, next_hop: next[u][d], metric: dist[u][d] })
                    .collect()
            })
            .collect()
    }
    /// Distance-vector: each node sends its FULL table (all n destinations) to every neighbour
    /// each period — an `n`-entry vector across every directed edge (RIP entry ≈ 20 B).
    fn control_overhead(&self, view: &TopologyView, _active_flows: usize) -> u64 {
        let directed_edges = view.adj.iter().map(Vec::len).sum::<usize>() as u64;
        let vector_bytes = view.n as u64 * 20;
        directed_edges * vector_bytes
    }
}

/// **GPSR greedy geographic forwarding** (Karp & Kung, 2000): each node's next hop toward a
/// destination is the *neighbour closest (Euclidean) to the destination's position*, provided it
/// makes progress. Requires [`TopologyView::positions`]. Greedy mode only — perimeter (face) routing
/// around voids is *roadmap*; where greedy reaches a local minimum with no closer neighbour, the
/// destination is left unrouted (a real void).
#[derive(Clone, Copy, Debug, Default)]
pub struct GreedyGeographic;

impl RoutingAlgorithm for GreedyGeographic {
    fn name(&self) -> &'static str {
        "gpsr-greedy"
    }
    fn category(&self) -> RoutingCategory {
        RoutingCategory::Geographic
    }
    fn compute(&self, view: &TopologyView) -> Vec<Vec<RouteEntry>> {
        let Some(pos) = &view.positions else {
            return vec![Vec::new(); view.n]; // no positions ⇒ geographic routing can't run
        };
        (0..view.n)
            .map(|u| {
                (0..view.n)
                    .filter(|&d| d != u)
                    .filter_map(|d| {
                        // Greedy: the neighbour strictly closer to d than u is (progress), nearest wins.
                        let my_dist = pos[u].distance(pos[d]);
                        view.adj[u]
                            .iter()
                            .map(|&(v, _)| (v, pos[v].distance(pos[d])))
                            .filter(|&(_, vd)| vd < my_dist)
                            .min_by(|a, b| a.1.total_cmp(&b.1))
                            .map(|(v, vd)| RouteEntry {
                                dest: d,
                                next_hop: v,
                                metric: vd as u32,
                            })
                    })
                    .collect()
            })
            .collect()
    }
    /// Geographic: just a small position beacon **broadcast** by each node per period (no tables to
    /// flood) — a single transmission per node, hence far cheaper than the table-driven protocols.
    fn control_overhead(&self, view: &TopologyView, _active_flows: usize) -> u64 {
        view.n as u64 * 16 // position beacon (x,y,z + id), broadcast once
    }
}

/// The kind of network being modelled — picks a sensible default routing algorithm per the
/// literature. A benchmark can always override with a specific [`RoutingAlgorithm`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkKind {
    /// Stable wired/backbone (OSPF/RIP territory).
    Infrastructure,
    /// Mobile ad-hoc (AODV/OLSR/DSDV).
    Manet,
    /// Vehicular ad-hoc (position-based / GPSR).
    Vanet,
    /// Flying/UAV ad-hoc (adapted MANET + geographic, often 3-D).
    Fanet,
}

impl NetworkKind {
    /// A recommended default algorithm for this network kind (grounded in the survey literature).
    /// Position-based defaults require a position-aware [`TopologyView`]; without positions they
    /// route nothing, so pass positions for VANET/FANET.
    pub fn default_routing(self) -> Box<dyn RoutingAlgorithm> {
        match self {
            // Link-state SPF is the backbone workhorse (OSPF).
            NetworkKind::Infrastructure => Box::new(ShortestPath),
            // DSDV-style proactive DV is the canonical MANET table-driven baseline (AODV/OLSR next).
            NetworkKind::Manet => Box::new(DistanceVector::default()),
            // Position-based greedy is the robust choice under fast topology change (VANET/FANET).
            NetworkKind::Vanet | NetworkKind::Fanet => Box::new(GreedyGeographic),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::world::Position;

    /// A square with a diagonal: 0-1-2-3-0 plus 0-2. Shortest 0→2 is the diagonal (cost 1), not 2 hops.
    fn square_with_diagonal() -> TopologyView {
        TopologyView::from_links(4, &[(0, 1), (1, 2), (2, 3), (3, 0), (0, 2)])
    }

    #[test]
    fn shortest_path_prefers_the_diagonal() {
        let t = ShortestPath.compute(&square_with_diagonal());
        let to2 = t[0].iter().find(|r| r.dest == 2).unwrap();
        assert_eq!((to2.next_hop, to2.metric), (2, 1), "0→2 takes the 1-hop diagonal");
    }

    #[test]
    fn distance_vector_matches_shortest_path_on_a_static_graph() {
        let view = square_with_diagonal();
        let sp = ShortestPath.compute(&view);
        let dv = DistanceVector::default().compute(&view);
        // Same least-cost metric to every destination from every source (converged DV == SPF).
        for u in 0..view.n {
            for r in &sp[u] {
                let d = dv[u].iter().find(|e| e.dest == r.dest).expect("dv reaches it too");
                assert_eq!(d.metric, r.metric, "node {u} → {}: same cost", r.dest);
            }
        }
    }

    /// Geographic routing's selling point: its control overhead (position beacons) is a fraction of
    /// the table-driven protocols' (link-state floods / full distance-vector exchanges).
    #[test]
    fn geographic_control_overhead_is_far_lower() {
        let view = square_with_diagonal();
        let sp = ShortestPath.control_overhead(&view, 1);
        let dv = DistanceVector::default().control_overhead(&view, 1);
        let gpsr = GreedyGeographic.control_overhead(&view, 1);
        assert!(gpsr * 5 < sp, "GPSR beacons ≪ link-state floods ({gpsr} vs {sp})");
        assert!(gpsr * 5 < dv, "GPSR beacons ≪ distance-vector exchanges ({gpsr} vs {dv})");
    }

    #[test]
    fn greedy_geographic_forwards_toward_the_destination() {
        // A line placed left→right; 0 should hand a packet for 3 to its right neighbour 1.
        let view = TopologyView::from_links(4, &[(0, 1), (1, 2), (2, 3)]).with_positions(vec![
            Position::xy(0.0, 0.0),
            Position::xy(10.0, 0.0),
            Position::xy(20.0, 0.0),
            Position::xy(30.0, 0.0),
        ]);
        let t = GreedyGeographic.compute(&view);
        let to3 = t[0].iter().find(|r| r.dest == 3).unwrap();
        assert_eq!(to3.next_hop, 1, "greedy forwards toward the closer-to-dest neighbour");
    }
}
