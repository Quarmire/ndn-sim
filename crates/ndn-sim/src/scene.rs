//! GUI scene projection + reference renderers (ndn-lab slice 8).
//!
//! The GUI is a **client** of the control + telemetry API (§9), never embedded in the fabric —
//! headless-first stays law. The core's job is to emit a renderable [`SceneSnapshot`]
//! (`world_snapshot()`): node positions, links, per-node metric badges, world bounds, virtual
//! time. A 2-D canvas renders it now; a 3-D / terrain view later renders the *same* data (the
//! 2-D→3-D step is purely GUI). RF-affected-by-terrain is an [`Environment`](crate::world::Environment)
//! model in the core — the GUI just visualizes its output.
//!
//! This module is **framework-agnostic and fully testable**: the projection is pure data, and
//! the reference renderers emit **SVG strings** (no browser, no UI toolkit) — usable directly
//! in the dashboard, in docs, or as an MCP "render" result. The Dioxus dashboard mounts the
//! same `SceneSnapshot` with its own canvas + the slice-6 commands for drag/spawn/remove (that
//! client wiring is the deferred follow-on).

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::TopologySnapshot;
use crate::telemetry::MetricsSample;

/// A 2-D point (metres), the projection of a 3-D [`Position`](crate::world::Position) onto the
/// x/y plane the GUI draws.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct ScenePoint {
    pub x: f64,
    pub y: f64,
}

/// A node as the GUI draws it: where it is + the metric badges worth showing at a glance.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SceneNode {
    pub id: usize,
    pub label: String,
    pub x: f64,
    pub y: f64,
    pub faces: u64,
    pub pit_depth: u64,
    pub cs_hit_rate: f64,
    pub in_interests: u64,
    pub out_data: u64,
}

/// An undirected link edge between two nodes; `distance_m` is set when both ends are placed
/// (the basis for "links light up by RSSI" once a propagation model is consulted).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SceneLink {
    pub from: usize,
    pub to: usize,
    pub distance_m: Option<f64>,
}

/// The world extent the GUI viewports onto.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct SceneBounds {
    pub min_x: f64,
    pub min_y: f64,
    pub max_x: f64,
    pub max_y: f64,
}

impl SceneBounds {
    pub fn width(&self) -> f64 {
        (self.max_x - self.min_x).max(f64::MIN_POSITIVE)
    }
    pub fn height(&self) -> f64 {
        (self.max_y - self.min_y).max(f64::MIN_POSITIVE)
    }
}

/// A radio reachability edge: `from` can hear `to` at `rssi_dbm` (from positions + propagation).
/// This is what "links light up by RSSI" draws — distinct from wired [`SceneLink`]s.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RadioLink {
    pub from: usize,
    pub to: usize,
    pub rssi_dbm: f64,
}

/// A renderable snapshot of the fabric — the `world_snapshot()` the GUI draws each frame.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SceneSnapshot {
    pub virtual_time_ns: u64,
    pub nodes: Vec<SceneNode>,
    pub links: Vec<SceneLink>,
    /// Radio reachability edges (empty unless a radio medium is present).
    #[serde(default)]
    pub radio_links: Vec<RadioLink>,
    pub bounds: SceneBounds,
}

/// Deterministic fallback layout: place nodes evenly on a circle (id order) so a wired topology
/// with no spatial [`World`](crate::world::World) still renders sensibly.
pub fn circle_layout(node_ids: &[usize], radius: f64) -> HashMap<usize, ScenePoint> {
    let n = node_ids.len().max(1);
    node_ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            let theta = std::f64::consts::TAU * (i as f64) / (n as f64);
            (*id, ScenePoint { x: radius * theta.cos(), y: radius * theta.sin() })
        })
        .collect()
}

/// Project a topology + metrics + node positions into a [`SceneSnapshot`]. Pure — the fabric
/// gathers the inputs; this assembles the drawable scene.
pub fn project_scene(
    topology: &TopologySnapshot,
    metrics: &[MetricsSample],
    positions: &HashMap<usize, ScenePoint>,
    virtual_time_ns: u64,
) -> SceneSnapshot {
    let metric_of = |node: usize| metrics.iter().find(|m| m.node.0 == node);

    let nodes: Vec<SceneNode> = topology
        .nodes
        .iter()
        .map(|n| {
            let p = positions.get(&n.id.0).copied().unwrap_or(ScenePoint { x: 0.0, y: 0.0 });
            let m = metric_of(n.id.0);
            SceneNode {
                id: n.id.0,
                label: n.label.clone(),
                x: p.x,
                y: p.y,
                faces: m.map(|m| m.faces).unwrap_or(0),
                pit_depth: m.map(|m| m.pit_depth).unwrap_or(0),
                cs_hit_rate: m.map(MetricsSample::cs_hit_rate).unwrap_or(0.0),
                in_interests: m.map(|m| m.in_interests).unwrap_or(0),
                out_data: m.map(|m| m.out_data).unwrap_or(0),
            }
        })
        .collect();

    // Collapse the directed topology faces into undirected edges (a < b), deduped.
    let mut seen = std::collections::HashSet::new();
    let mut links = Vec::new();
    for l in &topology.links {
        let (a, b) = (l.from.0.min(l.to.0), l.from.0.max(l.to.0));
        if a != b && seen.insert((a, b)) {
            let distance_m = match (positions.get(&a), positions.get(&b)) {
                (Some(pa), Some(pb)) => {
                    Some(((pa.x - pb.x).powi(2) + (pa.y - pb.y).powi(2)).sqrt())
                }
                _ => None,
            };
            links.push(SceneLink { from: a, to: b, distance_m });
        }
    }

    let bounds = bounds_of(&nodes);
    // radio_links are filled by the fabric (it has the radio bus + positions); pure projection
    // leaves them empty.
    SceneSnapshot { virtual_time_ns, nodes, links, radio_links: Vec::new(), bounds }
}

fn bounds_of(nodes: &[SceneNode]) -> SceneBounds {
    if nodes.is_empty() {
        return SceneBounds { min_x: -1.0, min_y: -1.0, max_x: 1.0, max_y: 1.0 };
    }
    let mut b = SceneBounds {
        min_x: f64::INFINITY,
        min_y: f64::INFINITY,
        max_x: f64::NEG_INFINITY,
        max_y: f64::NEG_INFINITY,
    };
    for n in nodes {
        b.min_x = b.min_x.min(n.x);
        b.min_y = b.min_y.min(n.y);
        b.max_x = b.max_x.max(n.x);
        b.max_y = b.max_y.max(n.y);
    }
    // Pad by 10% (and avoid a zero-size box for a single node).
    let pad_x = (b.max_x - b.min_x).abs().max(1.0) * 0.1;
    let pad_y = (b.max_y - b.min_y).abs().max(1.0) * 0.1;
    SceneBounds {
        min_x: b.min_x - pad_x,
        min_y: b.min_y - pad_y,
        max_x: b.max_x + pad_x,
        max_y: b.max_y + pad_y,
    }
}

/// Render the scene as a 2-D topology **SVG** (links, then labelled nodes). Coordinates are the
/// scene's own (the `viewBox` is the world bounds); SVG y grows downward. Node colour shades by
/// CS hit-rate (cool = cold cache, warm = hot) — a glanceable health cue.
pub fn render_topology_svg(scene: &SceneSnapshot, width: u32, height: u32) -> String {
    let b = &scene.bounds;
    let mut s = String::new();
    let _ = write!(
        s,
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="{:.3} {:.3} {:.3} {:.3}">"#,
        b.min_x,
        b.min_y,
        b.width(),
        b.height()
    );
    // Stroke/marker sizes scale with the world extent so they're visible at any zoom.
    let unit = (b.width().max(b.height())) / 100.0;
    let stroke = unit.max(f64::MIN_POSITIVE);
    let r = (unit * 3.0).max(f64::MIN_POSITIVE);

    let pos: HashMap<usize, (f64, f64)> =
        scene.nodes.iter().map(|n| (n.id, (n.x, n.y))).collect();
    for l in &scene.links {
        if let (Some(&(x1, y1)), Some(&(x2, y2))) = (pos.get(&l.from), pos.get(&l.to)) {
            let _ = write!(
                s,
                r##"<line x1="{x1:.3}" y1="{y1:.3}" x2="{x2:.3}" y2="{y2:.3}" stroke="#888" stroke-width="{stroke:.3}"/>"##
            );
        }
    }
    for n in &scene.nodes {
        let fill = hit_rate_color(n.cs_hit_rate);
        let _ = write!(
            s,
            r##"<circle cx="{:.3}" cy="{:.3}" r="{r:.3}" fill="{fill}" stroke="#222" stroke-width="{stroke:.3}"><title>{}</title></circle>"##,
            n.x,
            n.y,
            xml_escape(&format!(
                "{} (faces={}, pit={}, cs_hit={:.0}%)",
                n.label,
                n.faces,
                n.pit_depth,
                n.cs_hit_rate * 100.0
            ))
        );
        let _ = write!(
            s,
            r##"<text x="{:.3}" y="{:.3}" font-size="{:.3}" text-anchor="middle" fill="#111">{}</text>"##,
            n.x,
            n.y - r * 1.4,
            r * 1.2,
            xml_escape(&n.label)
        );
    }
    s.push_str("</svg>");
    s
}

/// Render a metric time-series as a tiny **SVG sparkline** — the live-chart primitive the
/// scrubber/inspector draws. `samples` are `(virtual_time_ns, value)`.
pub fn render_sparkline(samples: &[(u64, f64)], width: u32, height: u32) -> String {
    if samples.is_empty() {
        return format!(
            r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"/>"#
        );
    }
    let (t0, t1) = (samples[0].0, samples[samples.len() - 1].0);
    let span_t = (t1.saturating_sub(t0)).max(1) as f64;
    let (mut lo, mut hi) = (f64::INFINITY, f64::NEG_INFINITY);
    for &(_, v) in samples {
        lo = lo.min(v);
        hi = hi.max(v);
    }
    let span_v = (hi - lo).max(f64::MIN_POSITIVE);

    let mut points = String::new();
    for &(t, v) in samples {
        let x = (t.saturating_sub(t0) as f64 / span_t) * width as f64;
        // SVG y grows downward → invert so higher values sit higher.
        let y = height as f64 - ((v - lo) / span_v) * height as f64;
        let _ = write!(points, "{x:.2},{y:.2} ");
    }
    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"><polyline fill="none" stroke="#0a7" stroke-width="1.5" points="{}"/></svg>"##,
        points.trim_end()
    )
}

fn hit_rate_color(rate: f64) -> &'static str {
    match (rate.clamp(0.0, 1.0) * 4.0) as u32 {
        0 => "#2b6cb0", // cold cache
        1 => "#3182ce",
        2 => "#38a169",
        3 => "#dd6b20",
        _ => "#e53e3e", // hot cache
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{LinkInfo, NodeInfo, TopologySnapshot};
    use crate::NodeId;

    fn topo() -> TopologySnapshot {
        TopologySnapshot {
            nodes: vec![
                NodeInfo { id: NodeId(0), label: "a".into() },
                NodeInfo { id: NodeId(1), label: "b".into() },
            ],
            // directed both ways → one undirected edge
            links: vec![
                LinkInfo { from: NodeId(0), to: NodeId(1), face: 1 },
                LinkInfo { from: NodeId(1), to: NodeId(0), face: 2 },
            ],
        }
    }

    #[test]
    fn projects_positions_metrics_and_dedups_links() {
        let mut positions = HashMap::new();
        positions.insert(0, ScenePoint { x: 0.0, y: 0.0 });
        positions.insert(1, ScenePoint { x: 30.0, y: 40.0 }); // 50 m away
        let scene = project_scene(&topo(), &[], &positions, 123);

        assert_eq!(scene.virtual_time_ns, 123);
        assert_eq!(scene.nodes.len(), 2);
        assert_eq!(scene.links.len(), 1, "directed faces collapse to one edge");
        assert_eq!(scene.links[0].distance_m, Some(50.0));
        // Bounds enclose both nodes (with padding).
        assert!(scene.bounds.min_x <= 0.0 && scene.bounds.max_x >= 30.0);
    }

    #[test]
    fn circle_layout_is_deterministic_and_spreads_nodes() {
        let a = circle_layout(&[0, 1, 2], 100.0);
        let b = circle_layout(&[0, 1, 2], 100.0);
        assert_eq!(a, b, "layout replays identically");
        assert_ne!(a[&0], a[&1], "distinct nodes get distinct positions");
    }

    #[test]
    fn topology_svg_has_a_node_and_link_for_each() {
        let positions = circle_layout(&[0, 1], 50.0);
        let scene = project_scene(&topo(), &[], &positions, 0);
        let svg = render_topology_svg(&scene, 400, 400);
        assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
        assert_eq!(svg.matches("<circle").count(), 2, "one circle per node");
        assert_eq!(svg.matches("<line").count(), 1, "one line per edge");
        assert!(svg.contains(">a</text>") && svg.contains(">b</text>"), "node labels");
    }

    #[test]
    fn sparkline_plots_points() {
        let svg = render_sparkline(&[(0, 1.0), (1_000, 5.0), (2_000, 3.0)], 100, 20);
        assert!(svg.contains("<polyline"));
        assert_eq!(svg.matches(',').count(), 3, "three plotted points");
        // Empty input still yields a valid (empty) svg.
        assert!(render_sparkline(&[], 100, 20).contains("<svg"));
    }
}
