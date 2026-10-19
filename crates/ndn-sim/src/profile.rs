//! `NodeProfile` — a named template for a fabric node (ndn-lab).
//!
//! A profile bundles everything needed to instantiate one node so a node can be referred to
//! by one name (`"edge-router"`, `"drone"`, `"phone"`) instead of a pile of config. For
//! this slice it carries a label + the engine [`EngineConfig`]; later slices grow it with
//! apps, strategy/CS choices, and face set. Keeping it a distinct type now is what lets the
//! control API / MCP / GUI spawn nodes from a small palette.

use std::sync::Arc;

use ndn_engine::builder::EngineConfig;
use ndn_security::SecurityProfile;
use ndn_transport::FaceFactory;

/// A template for instantiating a fabric node. (Not `Clone`: `EngineConfig` isn't `Clone`;
/// build a fresh profile per node.)
pub struct NodeProfile {
    /// Human label, surfaced in topology snapshots and the tracer.
    pub label: String,
    /// Engine configuration for the node's `ForwarderEngine`.
    pub config: EngineConfig,
    /// Face factories registered on this node's engine (empty by default). With one registered, the
    /// node's own engine can stand real faces up via `add_face_of_kind` — e.g. a `UdpFaceFactory`
    /// lets a resolver actuate a bearer ON the sim node itself, instead of on a hand-built sibling
    /// engine. `Arc<dyn FaceFactory>` is cheaply cloneable, so it does not reintroduce the
    /// non-`Clone` constraint `EngineConfig` imposes.
    pub factories: Vec<Arc<dyn FaceFactory>>,
    /// How the node validates Data arriving on its sim links (non-local faces). Default
    /// [`SecurityProfile::Default`], as a forwarder's: a plain node has no security manager,
    /// hence no trust anchors, so it fails closed — every key-signed Data crossing a link into
    /// it is refused `untrusted-root` (DigestSha256 Data passes; its own apps' Data, on local
    /// faces, is never validated). Choose [`SecurityProfile::AcceptSigned`] (signature only) or
    /// [`SecurityProfile::Disabled`] (the application validates end to end) explicitly with
    /// [`Self::with_security_profile`], or add anchors to the node's validator. A config-booted
    /// node takes its `[security]` table instead.
    pub security: SecurityProfile,
}

impl NodeProfile {
    /// A profile with the given label, a default engine config and the `Default` security
    /// profile.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            config: EngineConfig::default(),
            factories: Vec::new(),
            security: SecurityProfile::Default,
        }
    }

    /// Override the engine config.
    pub fn with_config(mut self, config: EngineConfig) -> Self {
        self.config = config;
        self
    }

    /// Override how the node validates Data from its links (see [`Self::security`]).
    pub fn with_security_profile(mut self, profile: SecurityProfile) -> Self {
        self.security = profile;
        self
    }

    /// Register a face factory on this node's engine, so `add_face_of_kind` for that `FaceKind`
    /// builds a real face on the node itself (rather than returning `NoFactory`). Chainable.
    pub fn with_face_factory(mut self, factory: Arc<dyn FaceFactory>) -> Self {
        self.factories.push(factory);
        self
    }
}

impl Default for NodeProfile {
    fn default() -> Self {
        Self::new("node")
    }
}
