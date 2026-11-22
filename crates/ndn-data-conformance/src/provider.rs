//! How an implementation of the `ndn-data` contract plugs into the cases.

use std::net::SocketAddr;
use std::sync::Arc;

use ndn_data::{
    Code, DataLayer, Departure, Grant, Joined, JoinedFolder, Name, Offer, Timestamp, VersionId,
};
use ndn_security::Signer;
use ndn_sim::{Fabric, NodeId, NodeProfile};
use ndn_surface::signal::Signals;

use crate::feature::Feature;

/// What a host was told of a grant, in the order it was told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantEvent {
    /// `Introducer::grant`.
    Granted(Grant),
    /// `Introducer::departure`: a held record let the person go.
    Departed(Departure),
    /// `Introducer::revoke_grant`, with the key and the folder whose grant ended.
    Revoked {
        /// The person's device key.
        key: [u8; 32],
        /// The folder whose grant ended.
        folder: Name,
    },
}

/// A device's grants: what its host was told, and what its layer lists now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantLog {
    /// Every call of the host's `grant`, `departure` and `revoke_grant`, oldest first.
    pub told: Vec<GrantEvent>,
    /// `Device::grants` now.
    pub now: Vec<Grant>,
    /// `Device::departures` now.
    pub departures: Vec<Departure>,
}

/// One call a device's host was made of its link layer during an introduction, in the order it
/// was made ([`Provider::link_calls`]): the dials the joiner's layer asks for and the links it
/// takes down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkCall {
    /// `Introducer::dial_first`: the one address a short code names, no key to expect.
    DialFirst {
        /// The inviter's device the code names.
        inviter: Name,
        /// The address dialled.
        addr: SocketAddr,
        /// Whether a device answered there: a link was made.
        answered: bool,
    },
    /// `Introducer::dial`: by a link hint (a compact link's, or the hint record's) that names
    /// the key to prove.
    Dial {
        /// The inviter's device.
        inviter: Name,
        /// The key the link must prove.
        key: [u8; 32],
        /// The addresses tried, in order.
        candidates: Vec<SocketAddr>,
        /// Whether a candidate answered with the key: a link was made.
        answered: bool,
    },
    /// `Introducer::undial`: a failed join takes down what its dial made.
    Undial {
        /// The inviter's device.
        inviter: Name,
        /// The key of the link taken down.
        key: [u8; 32],
        /// The addresses the dial was made at.
        candidates: Vec<SocketAddr>,
    },
}

/// The folders a device joined, as its layer lists them, and the generation of that list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JoinedList {
    /// `Device::joined_folders` now: what the device's link layer routes for each folder it was
    /// let into, derived from the record in force.
    pub folders: Vec<JoinedFolder>,
    /// The value of `Device::joined_changes` now: it moves (and never repeats) whenever the
    /// list above changed.
    pub generation: u64,
}

/// One device in a case: a person's device, or a thief's node.
#[derive(Clone, Debug)]
pub struct DeviceSpec {
    /// The person whose device it is, by namespace (`/alice`, `/home/bob`).
    pub person: Name,
    /// The device's role in the namespace when it has one between the namespace and its label
    /// (`guest` for a friend's device `/alice/guest/bob`); `None` for the person's own devices
    /// (`/alice/phone`).
    pub role: Option<String>,
    /// The device's label within the person (`laptop`, `phone`, `repo`).
    pub device: String,
    /// Its forwarder in the fabric.
    pub node: NodeId,
    /// The merge rules its program knows beyond the standard ones.
    pub program: Program,
    /// A stranger to every other person: its node holds its own person's trust context and
    /// certificates only, until an introduction adopts another's.
    pub stranger: bool,
    /// For a self-certifying person (`/user/<hash>`), the Ed25519 secret of its genesis root:
    /// the key `person` is named from (ndn-cert's `GenesisKey`), which signs version 1 of its
    /// trust context. `None` for a person named otherwise.
    pub genesis: Option<[u8; 32]>,
    /// Its host's introductions make link grants (`IntroPolicy::grant_for` is the default);
    /// `false`: `grant_for` is zero, and the device grants no link.
    pub link_grants: bool,
}

/// The merge rules a device's program knows beyond the standard ones every program knows
/// (`/merge/yrs`). A provider registers them on the device's data layer by their names.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Program {
    /// The cases' element rule ([`crate::element`], `/conformance/merge/element/v=1`), as
    /// written.
    #[default]
    Element,
    /// None beyond the standard ones: a program older than the element rule.
    Standard,
    /// The element rule, named alike, but with a check that refuses nothing
    /// ([`Element::lax`](crate::element::Element::lax)): a faulty or hostile writer's program,
    /// whose versions only honest readers judge.
    LaxElement,
}

impl DeviceSpec {
    /// The device's name: the person's namespace, its role if it has one, and the device label
    /// (`/alice/laptop`, `/home/bob/laptop`, `/alice/guest/bob`). Cases name a device in a seal
    /// audience by it, so a provider must use it as the device's name.
    pub fn name(&self) -> Name {
        let ns = match &self.role {
            Some(role) => self.person.clone().append(role.as_bytes()),
            None => self.person.clone(),
        };
        ns.append(self.device.as_bytes())
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

/// One device's seal-key grants, cumulative ([`Provider::grants`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Grants {
    /// Epoch keys it asked others to grant it: one per epoch asked for, whatever the number of
    /// devices asked or of collections read in that epoch.
    pub asked: u64,
    /// Grants it signed for askers.
    pub answered: u64,
}

/// Which certificates of a device's key [`Provider::expire`] lets expire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Certs {
    /// Every certificate of the key issued so far.
    All,
    /// Every one but the newest: the ones a renewal superseded.
    Superseded,
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
            NodeRole::Device(d) => NodeProfile::new(d.name().to_string()),
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

    /// The owner reports `device` lost, and `by`, the namespace's root device, marks its key
    /// suspected since `since` (by `by`'s own clock): from now on `by`'s data layer takes no new
    /// log entry of that key — neither fetched, applied nor stored — while it keeps what it
    /// held, until the revocation is signed. A provider that cannot says so.
    async fn suspect(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        device: &DeviceSpec,
        since: Timestamp,
    ) -> anyhow::Result<()> {
        let _ = (fabric, since);
        anyhow::bail!(
            "this provider cannot make {} suspect {}'s key",
            by.name(),
            device.name()
        )
    }

    /// `by`, holding its namespace's authority, revokes `device`'s key (what `ndn-namespace`
    /// revoke does): it signs the next version of the namespace's trust context, adding a
    /// Revocation of the key and its cut, and `by`'s node adopts it. The cut is bounded by `by`'s
    /// own observation: the log entries of that key `by`'s data layer holds verified and first
    /// verified strictly before `lost` (the time the owner says the device was lost, by `by`'s
    /// clock), each bound to its bytes. Other nodes adopt the version, and can fetch what binds
    /// the cut to bytes, when [`spread`](Self::spread) reaches them. Returns the entries of the
    /// key `by` holds but left out of the cut (first verified at or after `lost`), each by its
    /// full name ending in its implicit digest, for the owner to re-admit one by one
    /// ([`readmit_name`](Self::readmit_name)). Revocation is not one of the seven verbs; it
    /// reaches the layer as a cut.
    async fn revoke(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        device: &DeviceSpec,
        lost: Timestamp,
    ) -> anyhow::Result<Vec<Name>>;

    /// `node` follows its namespaces' trust contexts to the newest version each has signed (each
    /// version checked against the one it holds: signed by one of its anchors, newer) and
    /// adopts them, as context sync brings them to a node. A provider without signed context
    /// versions says so.
    async fn spread(&self, fabric: &Fabric, node: NodeId) -> anyhow::Result<()> {
        let _ = fabric;
        anyhow::bail!("this provider cannot bring new trust-context versions to node {node}")
    }

    /// `by`, holding its namespace's authority, re-admits the version `id` of `collection`
    /// exactly: by its name and the implicit digest of the packet `from` holds refused by the
    /// revocation of its key. It signs the next context version adding that one name to the
    /// key's cut, and `by`'s node adopts it ([`spread`](Self::spread) brings it to the others).
    /// A provider that cannot re-admit says so.
    async fn readmit(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        from: &DeviceSpec,
        collection: &Name,
        id: &VersionId,
    ) -> anyhow::Result<()> {
        let _ = (fabric, from, id);
        anyhow::bail!(
            "this provider cannot make {} re-admit a version of {collection}",
            by.name()
        )
    }

    /// `by`, holding its namespace's authority, re-admits exactly the packet `full` (a log
    /// entry's full name ending in its implicit digest, as a revocation listed it left out of the
    /// cut): it signs the next context version adding that one name to the cut of the key that
    /// signed it, and `by`'s node adopts it ([`spread`](Self::spread) brings it to the others).
    /// A provider that cannot re-admit says so.
    async fn readmit_name(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        full: &Name,
    ) -> anyhow::Result<()> {
        let _ = fabric;
        anyhow::bail!("this provider cannot make {} re-admit {full}", by.name())
    }

    /// The stolen-key adversary: the thief takes `victim`'s device — its key and a copy of
    /// everything it stores — and from now on a data layer runs on `thief`'s node, signing with
    /// that key and writing on from the victim's own log, at any date its (skewed) clock gives.
    /// Until then the thief's node runs no data layer: a key in two places at once is the theft,
    /// not the setup. Returns the thief's data layer.
    async fn steal(
        &self,
        fabric: &Fabric,
        victim: &DeviceSpec,
        thief: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn DataLayer>>;

    /// `device` renews its certificate: its namespace's authority now certifies the same key
    /// again, valid from now, and every node can find the new certificate. A provider that
    /// cannot says so.
    async fn renew(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<()> {
        let _ = fabric;
        anyhow::bail!("this provider cannot renew {}'s certificate", device.name())
    }

    /// `which` certificates of `device`'s key expire: every node, and the device itself, holds
    /// each of them only with a validity period that ended before now by the host's clock (the
    /// clock validators read). For [`end_keys`](Self::end_keys), the key's authority ended now,
    /// in the case's time: what its devices verified before this call came before its end. A
    /// provider that cannot says so.
    async fn expire(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        which: Certs,
    ) -> anyhow::Result<()> {
        let _ = (fabric, which);
        anyhow::bail!(
            "this provider cannot let {}'s certificates expire",
            device.name()
        )
    }

    /// `by`, the root device of its namespace and able to sign unattended, ends the keys whose
    /// authority over data ended without a revocation (what the root does for a lapsed guest
    /// certificate or a replaced key): for each such key of its namespace it signs a
    /// revoke-with-cut, the cut bounded by what `by`'s data layer first verified before the key's
    /// end (its certificate's NotAfter, a replacement's enrollment), and `by`'s node adopts it.
    /// Returns the keys it ended. A provider that cannot says so.
    async fn end_keys(&self, fabric: &Fabric, by: &DeviceSpec) -> anyhow::Result<Vec<Name>> {
        let _ = fabric;
        anyhow::bail!(
            "this provider cannot make {} end the lapsed keys of {}",
            by.name(),
            by.person
        )
    }

    /// `device`'s data layer stops (its host shuts it down): it serves, syncs and adopts nothing
    /// until [`restart`](Self::restart), and keeps what it stored. A provider that cannot says
    /// so.
    async fn stop(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<()> {
        let _ = fabric;
        anyhow::bail!("this provider cannot stop {}'s data layer", device.name())
    }

    /// `device`'s data layer, stopped ([`stop`](Self::stop)), starts again on what it stored,
    /// with the same key, judging what it restores against the trust context its node holds
    /// now. Returns the new data layer. A provider that cannot says so.
    async fn restart(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn DataLayer>> {
        let _ = fabric;
        anyhow::bail!(
            "this provider cannot restart {}'s data layer",
            device.name()
        )
    }

    /// `by`, holding its namespace's authority, makes a recovery kit: the next context version
    /// adds the kit's key as a recovery anchor, and `by`'s node adopts it. A provider that
    /// cannot says so.
    async fn recovery_kit(&self, fabric: &Fabric, by: &DeviceSpec) -> anyhow::Result<()> {
        let _ = fabric;
        anyhow::bail!(
            "this provider cannot make a recovery kit for {}'s namespace",
            by.person
        )
    }

    /// `by`'s namespace root was compromised; `by` recovers the namespace with its recovery kit
    /// (what `ndn-namespace` recover with a compromised old root does): the kit signs the next
    /// version (a new root, the old root removed and revoked, every revocation and cut carried,
    /// each key revoked with a cut certified again by the new root), and the new root signs
    /// the one after it. `by`'s node adopts both; the new root is the namespace's authority from
    /// then on. A provider that cannot recover says so.
    async fn recover(&self, fabric: &Fabric, by: &DeviceSpec) -> anyhow::Result<()> {
        let _ = fabric;
        anyhow::bail!(
            "this provider cannot recover {}'s namespace with a recovery kit",
            by.person
        )
    }

    /// The implementation's counters now.
    fn tally(&self) -> Tally;

    /// The signatures `device`'s data layer has made, cumulative: what a constrained producer
    /// pays in signing.
    fn signed_by(&self, device: &DeviceSpec) -> u64;

    /// The seal-key grants `device`'s data layer has asked for and answered, cumulative.
    fn grants(&self, device: &DeviceSpec) -> Grants;

    /// The octets of the pieces `device` stores under `prefix`: of a collection, every piece (a
    /// log entry of any writer about the collection, or a chunk or manifest node of such an
    /// entry); of a version's name, its log entry and its chunks and manifest nodes.
    fn stored(&self, device: &DeviceSpec, prefix: &Name) -> u64;

    /// How many pieces of the version named `version` (its chunks and manifest nodes, not its
    /// log entry) `device` stores: whether it fetched the payload, not just the signed record.
    fn pieces_stored(&self, device: &DeviceSpec, version: &Name) -> u64;

    /// An older build: `device`'s data layer, stopped ([`stop`](Self::stop)), finds in its store
    /// its newest members record of `subject` (a collection or folder) as a build from before
    /// removal cuts bound bytes signed it — the same record, its cuts keeping the same seqs
    /// without `CutBytes`, no cut manifest stored — signed with the device's key in place of
    /// what it signed. [`restart`](Self::restart) then starts the current build on that store:
    /// the upgrade. Returns the record's name. A provider that cannot says so.
    fn sign_unbound(&self, device: &DeviceSpec, subject: &Name) -> anyhow::Result<Name> {
        anyhow::bail!(
            "this provider cannot make {} hold its record of {subject} as an older build signed \
             it",
            device.name()
        )
    }

    /// `by`, a device of the folder's owner that signs its members records, makes a one-use
    /// offer of `folder` ([`Device::offer`](ndn_data::Device::offer)) and returns its code. A
    /// refusal carries the layer's [`DataError`](ndn_data::DataError) as its source. A provider
    /// without introductions says so.
    async fn offer(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        folder: &Name,
        offer: Offer,
    ) -> anyhow::Result<Code> {
        let _ = (fabric, folder, offer);
        anyhow::bail!(
            "this provider cannot make {} offer a folder by a code",
            by.name()
        )
    }

    /// `by`, the device that made the offer `offer`, closes it
    /// ([`Device::close_offer`](ndn_data::Device::close_offer)): the offer admits no one new
    /// afterwards, and still answers a retry of the writer it admitted until it expires. A
    /// refusal carries the layer's [`DataError`](ndn_data::DataError) as its source. A provider
    /// without introductions says so.
    async fn close_offer(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        offer: &Name,
    ) -> anyhow::Result<()> {
        let _ = (fabric, offer);
        anyhow::bail!("this provider cannot make {} close an offer", by.name())
    }

    /// What `device`'s host was told of its link grants (`Introducer::grant`,
    /// `Introducer::revoke_grant`, in order, across restarts of its layer) and what its layer
    /// lists as in force now (`Device::grants`). A provider without introductions says so.
    async fn link_grants(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<GrantLog> {
        let _ = fabric;
        anyhow::bail!("this provider cannot tell {}'s link grants", device.name())
    }

    /// The folders `device`'s layer lists as joined (`Device::joined_folders`: for each live
    /// mirror entry the record in force still lists it in, the inviter, the owner, its own role
    /// and the other writers' namespaces) and the generation of that list
    /// (`Device::joined_changes`). A provider without introductions says so.
    async fn joined_folders(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
    ) -> anyhow::Result<JoinedList> {
        let _ = fabric;
        anyhow::bail!(
            "this provider cannot list {}'s joined folders",
            device.name()
        )
    }

    /// The public-key digest of `device`'s own key: what a link's handshake proves, and the key a
    /// grant to that device names. A provider without introductions says so.
    async fn link_key(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<[u8; 32]> {
        let _ = fabric;
        anyhow::bail!("this provider cannot tell {}'s link key", device.name())
    }

    /// What `device`'s host was asked of its link layer in introductions (`Introducer::dial_first`,
    /// `dial`, `undial`), in order, across restarts of its layer: the host has no real link, so
    /// each dial answers at once for a device at the address (or key) it dials. A provider
    /// without introductions says so.
    async fn link_calls(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
    ) -> anyhow::Result<Vec<LinkCall>> {
        let _ = fabric;
        anyhow::bail!("this provider cannot tell {}'s link calls", device.name())
    }

    /// Fault injection: `device`'s node fetches now, fresh, the packet answering `prefix`
    /// (CanBePrefix), and from then on answers every Interest under `prefix` that the device's
    /// own layer (or any other face of the node) sends, with that packet **altered**: its last
    /// octet, the last octet of its signature, flipped. It stands for whoever answers at a first
    /// contact's address: it serves the device what it likes. The genuine copy it fetched sits
    /// in the caches of the forwarders it crossed; the caller empties them. A provider that
    /// cannot inject it says so.
    async fn replay_altered(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        prefix: &Name,
    ) -> anyhow::Result<()> {
        let _ = fabric;
        anyhow::bail!(
            "this provider cannot make {} answer {prefix} with an altered packet",
            device.name()
        )
    }

    /// `device`, a person let go of `folder`, takes the members record `record` its inviter's
    /// link layer named to it ([`Device::take_departure`](ndn_data::Device::take_departure)):
    /// fetched and taken as any held record, so `device`'s own folder members no longer list it.
    /// `from` is the device that told it: the peer of the link the notice came over, whose
    /// certificate the link layer validated; only a device under the folder's namespace lets a
    /// member go of it, so a notice from another is refused. A refusal carries the layer's
    /// [`DataError`](ndn_data::DataError) as its source. A provider without introductions says so.
    async fn take_departure(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        from: &DeviceSpec,
        folder: &Name,
        record: &Name,
    ) -> anyhow::Result<()> {
        let _ = (fabric, from, folder, record);
        anyhow::bail!(
            "this provider cannot make {} take a departure",
            device.name()
        )
    }

    /// `device`'s host adopts the namespace the anchor link `link` (an `ndn-trust://anchor`
    /// URI) names, as `ndn-ctl adopt` adopts one: a link carrying the namespace's signed trust
    /// context is checked against it; a self-certifying namespace (`/user/<hash>`) may be named
    /// alone, its versions then fetched by name and version 1 checked as its genesis (signed by
    /// the key the name hashes). Once adopted, `device`'s node validates the namespace and
    /// carries and routes its sync group. A refusal carries ndn-cert's
    /// [`AdoptError`](ndn_cert::AdoptError) as its source (`downcast_ref`). A provider that
    /// cannot adopt anchor links says so.
    async fn adopt(&self, fabric: &Fabric, device: &DeviceSpec, link: &str) -> anyhow::Result<()> {
        let _ = (fabric, link);
        anyhow::bail!(
            "this provider cannot make {}'s host adopt an anchor link",
            device.name()
        )
    }

    /// What `at`'s forwarder — its node's validator, the one that judges every packet the node
    /// forwards — says of the packet `from`'s data layer stores under `name`: `Ok(())` when it
    /// accepts it, else why not (the validator's refusal). A namespace a data layer adopted for
    /// judging one folder's data alone stays refused here. A provider that cannot ask says so.
    async fn forwarder_verdict(
        &self,
        fabric: &Fabric,
        at: &DeviceSpec,
        from: &DeviceSpec,
        name: &Name,
    ) -> anyhow::Result<Result<(), String>> {
        let _ = (fabric, from, name);
        anyhow::bail!(
            "this provider cannot ask {}'s forwarder for its verdict on a packet",
            at.name()
        )
    }

    /// `device` joins the folder a code offers, given only the code (its link or its words):
    /// its host adopts the inviter's anchor on its node when the answer comes. A refusal
    /// carries the layer's [`DataError`](ndn_data::DataError) as its source. A provider without
    /// introductions says so.
    async fn join(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        code: &str,
    ) -> anyhow::Result<Joined> {
        let _ = (fabric, code);
        anyhow::bail!(
            "this provider cannot make {} join a folder by a code",
            device.name()
        )
    }

    /// `device`'s host starts signals for its data layer (`ndn_surface::signal::Signals`, spec
    /// signals §2) as a host does: on a connection of its own to its node's forwarder, gated by
    /// the device's data layer, with the device's own namespace's sync group (`<ns>/32=sync`,
    /// where members push for it) routed to that connection's face as its node routes the data
    /// layer's sync face. Started once; asked again it answers the same one. A provider without
    /// signals says so.
    async fn signals(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<Signals> {
        let _ = fabric;
        anyhow::bail!("this provider cannot start signals on {}", device.name())
    }

    /// Fault injection: `device`'s host routes the sync group `group` — another namespace's,
    /// where it is not pushed to — to its signals' connection too, as an eavesdropper on its own
    /// node does ([`signals`](Self::signals) starts them first). A provider that cannot says so.
    async fn listen(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        group: &Name,
    ) -> anyhow::Result<()> {
        let _ = fabric;
        anyhow::bail!(
            "this provider cannot route {group} to {}'s signals",
            device.name()
        )
    }

    /// The `ndn-data` [`Device`](ndn_data::Device) behind `device`'s data layer, whose signal gate
    /// (`ndn_data::signal`: the signal keys it holds, the run headers it signs) a program on the
    /// device can ask beside the seven verbs — what a member that turns hostile holds. A
    /// provider that is no `ndn-data` Device says so.
    fn gate(&self, device: &DeviceSpec) -> anyhow::Result<ndn_data::Device> {
        anyhow::bail!("this provider has no ndn-data Device on {}", device.name())
    }

    /// `device`'s own signing key, as a hostile program on the device holds it: it signs
    /// whatever it is given, past every gate. A provider that cannot hand it out says so.
    fn signer(&self, device: &DeviceSpec) -> anyhow::Result<Arc<dyn Signer>> {
        anyhow::bail!("this provider cannot hand out {}'s key", device.name())
    }

    /// The name of every packet `device`'s data layer stores, in name order. A provider that
    /// cannot list its store says so.
    fn stored_names(&self, device: &DeviceSpec) -> anyhow::Result<Vec<Name>> {
        anyhow::bail!("this provider cannot list what {} stores", device.name())
    }
}
