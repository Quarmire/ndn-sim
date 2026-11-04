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
    /// A holder: it keeps its person's collections for their owners under custody leases
    /// (answers their hold asks and audits).
    pub holds: bool,
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

/// How a malicious holder alters the packet of a block it stores ([`Provider::tamper`]). Either
/// way the packet keeps the block's name and its signature bytes, so it claims the writer's
/// signature over content the writer never signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tamper {
    /// The entry at index `entry` has a field value altered.
    Forge {
        /// The entry's 0-based index in the block.
        entry: u32,
    },
    /// The entry at index `entry` is replaced by the entry at index `their` of block `from`
    /// (another block of the same writer, genuinely signed there).
    Splice {
        /// The entry's 0-based index in the block.
        entry: u32,
        /// The block the substitute entry comes from, by its name.
        from: Name,
        /// The substitute's index in `from`.
        their: u32,
    },
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

    /// The signatures `device`'s data layer has made, cumulative: what a constrained producer
    /// pays in signing.
    fn signed_by(&self, device: &DeviceSpec) -> u64;

    /// `device`'s host drops its own copies of the pieces of the large versions under `name` (a
    /// version's name or a collection), leaving them to the holders that keep them: the host's
    /// storage policy, not a verb. Returns how many pieces it dropped; a refusal (nothing it
    /// audited as kept holds them) is an error naming why.
    async fn release(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        name: &Name,
    ) -> anyhow::Result<u64>;

    /// Fault injection: `device`'s storage silently loses every `every`-th stored piece of
    /// `collection` (1 = all), in name order. A piece is a log entry of any writer about the
    /// collection, or a chunk or manifest node of such an entry. Returns how many it lost.
    fn lose(&self, device: &DeviceSpec, collection: &Name, every: u32) -> u64;

    /// The octets of the pieces `device` stores under `prefix`: of a collection, every piece as
    /// [`lose`](Self::lose) counts them; of a version's name, its log entry and its chunks and
    /// manifest nodes.
    fn stored(&self, device: &DeviceSpec, prefix: &Name) -> u64;

    /// Fault injection: from now on `device` answers the audit asks addressed to it through a
    /// relay that keeps nothing: it fetches each asked piece from the network, fresh (past every
    /// cache, so from a device that serves it), and signs it as `device`'s answer. The holder
    /// that stores nothing yet passes audits by fetching from the auditor (spec §13.4). A
    /// provider that cannot inject it says so.
    async fn relay_audits(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<()> {
        let _ = fabric;
        anyhow::bail!(
            "this provider cannot make {} answer audits by relaying",
            device.name()
        )
    }

    /// Fault injection: the packet of block `version` in `device`'s store is replaced as `how`
    /// says, keeping its name and signature bytes: a malicious holder serving a forged or spliced
    /// entry under the writer's signature. A provider that cannot inject it says so.
    fn tamper(&self, device: &DeviceSpec, version: &Name, how: Tamper) -> anyhow::Result<()> {
        let _ = how;
        anyhow::bail!(
            "this provider cannot make {} alter the stored block {version}",
            device.name()
        )
    }

    /// Fault injection: `device`'s node fetches now, fresh (past every cache), the packet
    /// answering `prefix` (CanBePrefix), and from then on answers every Interest under `prefix`
    /// that reaches it with that packet, ignoring its FreshnessPeriod: a replaying cache. A
    /// provider that cannot inject it says so.
    async fn replay(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        prefix: &Name,
    ) -> anyhow::Result<()> {
        let _ = fabric;
        anyhow::bail!(
            "this provider cannot make {} replay what answers {prefix}",
            device.name()
        )
    }
}
