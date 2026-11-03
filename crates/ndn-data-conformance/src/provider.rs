//! How an implementation of the `ndn-data` contract plugs into the cases.

use std::sync::Arc;

use ndn_data::{DataLayer, Name};
use ndn_sim::{Fabric, NodeId, NodeProfile};

use crate::feature::Feature;

/// One device in a case: a person's device, or a thief's node.
#[derive(Clone, Debug)]
pub struct DeviceSpec {
    /// The person whose device it is, by namespace (`/alice`, `/home/bob`).
    pub person: Name,
    /// The device's label within the person (`laptop`, `phone`, `repo`).
    pub device: String,
    /// Its forwarder in the fabric.
    pub node: NodeId,
}

impl DeviceSpec {
    /// The device's name: the person's namespace plus the device label
    /// (`/alice/laptop`, `/home/bob/laptop`). Cases name a device in a seal audience by it, so a
    /// provider must use it as the device's name.
    pub fn name(&self) -> Name {
        self.person.clone().append(self.device.as_bytes())
    }
}

/// Which node a [`Provider::node_profile`] is asked about.
#[derive(Clone, Copy, Debug)]
pub enum NodeRole<'a> {
    /// The forwarder every device links to (the network between devices).
    Hub,
    /// A device.
    Device(&'a DeviceSpec),
}

/// Counters an implementation keeps across all its devices, read before and after a case.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Signatures made, cumulative.
    pub signatures: u64,
    /// Stored copies of versions across all holders, now.
    pub copies: u64,
}

/// An implementation of the data layer, as the cases drive it.
///
/// Keys, trust anchors, trust schemas and routes beyond the harness's default topology are the
/// provider's business; the cases only use the seven verbs and the hooks below.
#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    /// The implementation's name, as the report shows it.
    fn name(&self) -> &str;

    /// Whether it implements `feature`. A case runs only when every feature it needs is
    /// implemented; otherwise the report names what is missing.
    fn supports(&self, feature: Feature) -> bool;

    /// The forwarder profile for a node (its engine config and data-path security). The default
    /// is a plain node with the forwarder's fail-closed default validation.
    fn node_profile(&self, role: NodeRole<'_>) -> NodeProfile {
        match role {
            NodeRole::Hub => NodeProfile::new("hub"),
            NodeRole::Device(d) => NodeProfile::new(format!("{}/{}", d.person, d.device)),
        }
    }

    /// Set up what spans devices once the fabric runs and before any device attaches: keys,
    /// certificates, trust anchors on every node (`hub` included), routes. The default does
    /// nothing.
    async fn prepare(
        &self,
        fabric: &Fabric,
        hub: NodeId,
        devices: &[DeviceSpec],
    ) -> anyhow::Result<()> {
        let _ = (fabric, hub, devices);
        Ok(())
    }

    /// The data layer of `device`, on its node in `fabric`, signing with the device's own key.
    async fn attach(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn DataLayer>>;

    /// A data layer on `thief`'s node that signs with a copy of `victim`'s key: the stolen-key
    /// adversary. It may choose any sequence number and dates by its own (skewed) clock.
    async fn attach_stolen(
        &self,
        fabric: &Fabric,
        victim: &DeviceSpec,
        thief: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn DataLayer>>;

    /// `by`, holding the namespace's authority, revokes `device`'s key in the trust context (what
    /// `ndn-namespace` revoke does). Revocation is not one of the seven verbs; it reaches the
    /// layer as a cut (slice 5).
    async fn revoke(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        device: &DeviceSpec,
    ) -> anyhow::Result<()>;

    /// The implementation's counters now.
    fn tally(&self) -> Tally;
}
