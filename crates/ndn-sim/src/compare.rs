//! **NDN vs IP comparison** (Tier-B, IP-4): run the *same* scenario — topology, workload, link
//! characteristics — through both the NDN forwarding plane and the in-sim [`IpNetwork`](crate::IpNetwork),
//! and report both sides with the same protocol-neutral [`FlowStats`](crate::FlowStats). Because the
//! two planes ride the identical deterministic kernel / links, the difference is the *architecture*,
//! not the harness.
//!
//! What the numbers mean (and their caveats):
//! - **delivered / RTT / loss** — directly comparable (same links, same workload).
//! - **wire bytes** — NDN packets carry names + signatures, so per-packet they're larger than a bare
//!   IP datagram; the interesting comparison is *aggregate* bytes under repeated content, where NDN's
//!   in-network caching serves repeats without reaching the producer (see the caching contrast in the
//!   tests). Signature *verification cost* is modelled as real work on the NDN side but not billed in
//!   bytes; a fully fair CPU comparison is out of scope here.

use std::time::Duration;

use crate::app::{AppSpec, FlowStats, TrafficPattern};
use crate::sim_link::{FaceProfile, LinkConfig};

/// One head-to-head comparison: a `source` node runs a `pattern` workload to a `dest` node over a
/// shared topology, on both planes.
#[derive(Clone, Debug)]
pub struct ComparisonSpec {
    pub n: usize,
    pub links: Vec<(usize, usize)>,
    pub source: usize,
    pub dest: usize,
    pub pattern: TrafficPattern,
    pub count: u32,
    pub payload_len: usize,
    /// One-way link delay, shared by both planes for fairness.
    pub link_delay: Duration,
    /// How long to let the run settle before sampling (virtual ms).
    pub duration_ms: u64,
}

/// The result of a [`compare_ndn_vs_ip`] run — both planes' flow metrics + total bytes on the wire.
#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolComparison {
    pub ndn: FlowStats,
    pub ip: FlowStats,
    pub ndn_wire_bytes: u64,
    pub ip_wire_bytes: u64,
}

impl ProtocolComparison {
    /// A one-line human summary.
    pub fn summary(&self) -> String {
        format!(
            "NDN: {}/{} delivered, {:.1} ms RTT, {} wire B | IP: {}/{} delivered, {:.1} ms RTT, {} wire B",
            self.ndn.received,
            self.ndn.sent,
            self.ndn.mean_rtt_ms(),
            self.ndn_wire_bytes,
            self.ip.received,
            self.ip.sent,
            self.ip.mean_rtt_ms(),
            self.ip_wire_bytes,
        )
    }
}

/// Run `spec` through both planes (each on its own deterministic DES kernel) and compare.
#[cfg(not(target_arch = "wasm32"))]
pub fn compare_ndn_vs_ip(spec: &ComparisonSpec) -> ProtocolComparison {
    let (ndn, ndn_wire_bytes) = run_ndn(spec);
    let (ip, ip_wire_bytes) = run_ip(spec);
    ProtocolComparison { ndn, ip, ndn_wire_bytes, ip_wire_bytes }
}

/// The NDN plane: a producer at `dest`, a `TrafficSource` at `source`, shortest-path routes.
#[cfg(not(target_arch = "wasm32"))]
fn run_ndn(spec: &ComparisonSpec) -> (FlowStats, u64) {
    use crate::scenario::{KernelSpec, NodeSpec, Scenario, ScenarioLink};
    use crate::{DesKernel, NodeId, SimKernel};

    let mut scenario = Scenario { kernel: KernelSpec::Des { epoch_ns: None }, ..Default::default() };
    scenario.nodes = (0..spec.n)
        .map(|i| NodeSpec { label: Some(format!("n{i}")), ..Default::default() })
        .collect();
    scenario.links = spec
        .links
        .iter()
        .map(|&(a, b)| ScenarioLink {
            a,
            b,
            delay_ms: spec.link_delay.as_millis() as u64,
            ..Default::default()
        })
        .collect();
    scenario.nodes[spec.dest].apps.push(AppSpec::Producer {
        prefix: "/bench".into(),
        content: Some("x".repeat(spec.payload_len)),
        freshness_ms: Some(spec.duration_ms.max(4000)),
    });
    scenario.nodes[spec.source].apps.push(AppSpec::TrafficSource {
        prefix: "/bench".into(),
        pattern: spec.pattern,
        count: u64::from(spec.count),
        lifetime_ms: Some(2000),
    });
    crate::topo::add_routes_toward(&mut scenario, "/bench", spec.dest);

    let source = spec.source;
    let duration = Duration::from_millis(spec.duration_ms);
    DesKernel::new().run(move |k: std::sync::Arc<dyn SimKernel>| async move {
        let fabric = scenario.build(k).unwrap().start().await.unwrap();
        ndn_app::rt::sleep(duration).await; // ambient-runtime sleep (virtual under DES)
        // The traffic source's flow metrics.
        let app = fabric
            .apps()
            .into_iter()
            .find(|(_, node, kind)| *node == NodeId(source) && *kind == "traffic_source")
            .map(|(id, _, _)| id);
        let flow = app.and_then(|id| fabric.flow_stats(id)).unwrap_or_default();
        let wire: u64 = fabric.snapshot_metrics().iter().map(|m| m.out_bytes).sum();
        fabric.shutdown().await;
        (flow, wire)
    })
}

/// The IP plane: the same graph, shortest-path routed, `run_flow` from `source` to `dest`.
#[cfg(not(target_arch = "wasm32"))]
fn run_ip(spec: &ComparisonSpec) -> (FlowStats, u64) {
    use crate::{DesKernel, IpNetwork, SimKernel};

    let links = spec.links.clone();
    let (n, source, dest, pattern, count, payload_len) =
        (spec.n, spec.source, spec.dest, spec.pattern, spec.count, spec.payload_len);
    let link_delay = spec.link_delay;
    DesKernel::new().run(move |k: std::sync::Arc<dyn SimKernel>| async move {
        let rt = k.runtime();
        let prof =
            FaceProfile::internal().with_link(LinkConfig { delay: link_delay, ..Default::default() });
        let net = IpNetwork::from_links(rt, n, &links, &prof);
        let stats = net
            .node(source)
            .run_flow(net.addr(dest), pattern, count, payload_len, Duration::from_secs(2))
            .await;
        (stats, net.total_tx_bytes())
    })
}
