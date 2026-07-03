//! `FabricControl` — the single control + introspection surface over a running fabric
//! (ndn-lab).
//!
//! This is the seam every front-end speaks: tests and the scenario runner today; the GUI,
//! MCP server, and an NDN-named / RPC control plane in later slices. Keeping it ONE
//! declarative API (rather than ad-hoc methods per front-end) is what makes ndn-lab a hub
//! and not a silo — anything the GUI can do, MCP can do, and vice-versa.
//!
//! `RunningSimulation` implements it via inherent methods (so tests need no trait import)
//! and the `FabricControl` trait (so a front-end can hold `Arc<dyn FabricControl>`).

use std::sync::Arc;

use anyhow::Result;
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_transport::{FaceId, FaceLifecycleSink};

use crate::tracer::{EventKind, SimTracer};
use crate::{LinkConfig, NodeId, NodeProfile};

/// One node in a [`TopologySnapshot`].
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NodeInfo {
    pub id: NodeId,
    pub label: String,
}

/// One directed link face in a [`TopologySnapshot`] (`from`'s face toward `to`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LinkInfo {
    pub from: NodeId,
    pub to: NodeId,
    pub face: u64,
}

/// A point-in-time view of the fabric graph — for the GUI, MCP introspection, and tests.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct TopologySnapshot {
    pub nodes: Vec<NodeInfo>,
    pub links: Vec<LinkInfo>,
}

/// The declarative control surface over a running fabric. Object-safe so a front-end holds
/// `Arc<dyn FabricControl>`; `RunningSimulation` also exposes the same operations as inherent
/// methods.
#[async_trait::async_trait]
pub trait FabricControl: Send + Sync {
    /// Spawn a new node from `profile` on the running fabric; returns its handle.
    async fn spawn_node(&self, profile: NodeProfile) -> Result<NodeId>;
    /// Remove a node (shutting its engine down) and drop its links.
    async fn remove_node(&self, node: NodeId) -> Result<()>;
    /// Connect two live nodes with a symmetric link.
    fn connect(&self, a: NodeId, b: NodeId, config: LinkConfig) -> Result<()>;
    /// Install a FIB route at `node`: `prefix` → the link face toward `nexthop`.
    fn route(&self, node: NodeId, prefix: &Name, nexthop: NodeId) -> Result<()>;
    /// The node's engine handle (a cheap clone), or `None` if no such node.
    fn engine_of(&self, node: NodeId) -> Option<ForwarderEngine>;
    /// A snapshot of the current topology.
    fn topology(&self) -> TopologySnapshot;
    /// Number of live nodes.
    fn nodes(&self) -> usize;
}

/// Adapter that records a node's face up/down events into the shared [`SimTracer`], so the
/// fabric has a live event timeline without the engine knowing about the tracer. Installed
/// per node via `engine.set_face_lifecycle_sink`.
pub(crate) struct TracerFaceSink {
    pub(crate) tracer: Arc<SimTracer>,
    pub(crate) node: usize,
}

impl FaceLifecycleSink for TracerFaceSink {
    fn on_up(&self, face_id: FaceId) {
        self.tracer.record_now(
            self.node,
            Some(face_id.0 as u32),
            EventKind::FaceUp,
            "",
            None,
        );
    }
    fn on_down(&self, face_id: FaceId) {
        self.tracer.record_now(
            self.node,
            Some(face_id.0 as u32),
            EventKind::FaceDown,
            "",
            None,
        );
    }
}
