//! `NodeProfile` — a named template for a fabric node (ndn-lab).
//!
//! A profile bundles everything needed to instantiate one node so a node can be referred to
//! by one name (`"edge-router"`, `"drone"`, `"phone"`) instead of a pile of config. For
//! this slice it carries a label + the engine [`EngineConfig`]; later slices grow it with
//! apps, strategy/CS choices, and face set. Keeping it a distinct type now is what lets the
//! control API / MCP / GUI spawn nodes from a small palette.

use ndn_engine::builder::EngineConfig;

/// A template for instantiating a fabric node. (Not `Clone`: `EngineConfig` isn't `Clone`;
/// build a fresh profile per node.)
pub struct NodeProfile {
    /// Human label, surfaced in topology snapshots and the tracer.
    pub label: String,
    /// Engine configuration for the node's `ForwarderEngine`.
    pub config: EngineConfig,
}

impl NodeProfile {
    /// A profile with the given label and a default engine config.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            config: EngineConfig::default(),
        }
    }

    /// Override the engine config.
    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }
}

impl Default for NodeProfile {
    fn default() -> Self {
        Self::new("node")
    }
}
