//! What the providers of the suite share: the world a case's devices live in.
//!
//! Every person is a namespace (`/alice`, or `/home/bob` of several components) with a key
//! (`<person>/KEY/…`, self-signed) that certifies each of their devices' keys
//! (`<person>/<device>/KEY/…`). Every forwarder — the hub and each device — holds every person's
//! trust context (namespace `<person>`, the hierarchical schema, the person's key its anchor) and
//! every device certificate in its cache, so its fail-closed validator admits exactly the case's
//! people ([`Common::prepare`]). In a case of strangers ([`DeviceSpec::stranger`]) a device's
//! forwarder holds its own person's context and certificates only, until an adoption. A device's
//! link to the hub stands in for its links to the other devices of every namespace it holds, so
//! each person's sync group (`<person>/32=sync`) is set up on it by the libraries a daemon uses
//! (`ndn_namespace::sync_group::carry`, `ndn_link::group_routes`). The hub's default routes
//! stand in for the network between devices.
//!
//! The person's key signs their trust context as version 1 (listing every device role among
//! those whose data needs a cut once their certificate lapsed, as `ndn-fwd init` does), and acts
//! as the namespace's root device from then on: a revocation with a cut, the end of a lapsed
//! key, a re-admission, a recovery kit and a recovery after the root's compromise are the next
//! versions, signed with `ndn-cert`'s functions as the root flow signs them. A node takes them
//! one at a time as context sync brings them ([`Common::spread`]), each checked against the
//! version it holds, and from then on keeps and serves the manifest packets of its cuts by full
//! name, as a node keeping contexts does. A renewed or expired certificate is handed to every
//! node's cache in place of the copy it held.
//!
//! A self-certifying person (`/user/<hash>`, [`DeviceSpec::genesis`]) has its genesis root as its
//! key, so version 1 is the genesis its name hashes; each of its devices serves what an adopter
//! fetches (its namespace's versions by name, its own certificate).
//!
//! What a provider adds is what its data layer decides: the revocation cut is computed from what
//! the layer holds verified ([`Cutter`]), and each provider starts its own layer on its node.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use ndn_app::{Consumer, EngineAppExt, ForwarderEngine, Node, ServeGuard};
use ndn_cert::{AnchorLink, GenesisKey, OldRoot, RecoveryPlan, RecoverySeed};
use ndn_data::Name;
use ndn_link::{EngineFaces, FaceSink};
use ndn_namespace::publish::{OwnCertificates, PublishedContexts};
use ndn_namespace::{ContextStore, StoredContext};
use ndn_packet::Data;
use ndn_packet::encode::InterestBuilder;
use ndn_security::cert_name::{DEFAULT_ISSUER, new_cert_name};
use ndn_security::self_certifying::Genesis;
use ndn_security::{
    Certificate, RevocationCut, ScopedContext, SecurityManager, SignedTrustContext, Signer,
    encode_cert_data,
};
use ndn_sim::{Fabric, NodeId};
use tokio_util::sync::CancellationToken;

use crate::provider::{Certs, DeviceSpec};

/// Certificates live far longer than any case (they are checked against the host's real clock).
const VALIDITY_MS: u64 = 10 * 365 * 24 * 3600 * 1000;
/// A day in nanoseconds, the unit of certificate validity periods.
const DAY_NS: u64 = 24 * 3600 * 1_000_000_000;
/// How many times a replaying cache ([`Common::replay_altered_packet`]) asks for the packet it
/// will replay before giving up: each ask lives 2 s, so on the faulty profile (drop 0.2 each
/// way, blocks) eight asks all go unanswered about once in three thousand runs, and on a clean
/// path the first ask is answered.
const REPLAY_TRIES: u32 = 8;

/// A certificate of a device's key and the key that signed it.
#[derive(Clone)]
struct Issued {
    cert: Certificate,
    issuer: Arc<dyn Signer>,
}

/// A person's namespace as its root device keeps it.
struct Namespace {
    /// The key that signs its next trust-context version and certifies its devices: its root
    /// (a new one after a recovery).
    root: Arc<dyn Signer>,
    /// Its recovery kit's key, once one is made.
    kit: Option<Arc<dyn Signer>>,
    /// The wire of every trust-context version signed, oldest first: version `i + 1` at `i`.
    versions: Vec<bytes::Bytes>,
    /// The cut-manifest packets each version added, by the version that carries their cut.
    manifests: Vec<(u64, Vec<bytes::Bytes>)>,
}

/// The cut-manifest packets a node keeps, by full name, as its server answers them.
type Kept = Arc<Mutex<BTreeMap<Name, bytes::Bytes>>>;

/// One case's keys and namespaces.
#[derive(Default)]
struct Case {
    /// Each device's key store, by device name.
    keys: HashMap<Name, Arc<SecurityManager>>,
    /// Every certificate issued for each device's key, oldest first, by device name.
    certs: HashMap<Name, Vec<Issued>>,
    /// When each device's certificates were let expire ([`Common::expire`]), by the fabric's true
    /// clock in milliseconds: the end of its key's authority, for [`Common::end_keys`].
    lapsed: HashMap<Name, u64>,
    /// Each person's namespace: its authority and the trust-context versions it signed.
    namespaces: BTreeMap<Name, Namespace>,
    /// Every forwarder: the hub, then each device's.
    nodes: Vec<NodeId>,
    /// The cut-manifest packets each node keeps and serves, per namespace, by full name.
    kept: HashMap<(NodeId, Name), Kept>,
    /// The replaying caches and manifest servers injected
    /// ([`Common::replay_altered_packet`], [`Common::keep_manifests`]), served while the case
    /// runs.
    relays: Vec<(Node, ServeGuard)>,
    /// The publisher of each node of a self-certifying person: its namespace's trust-context
    /// versions by name (RDR), as a daemon publishes them, so another adopts it by name.
    published: HashMap<(NodeId, Name), PublishedContexts>,
    /// The certificate server of each device of a self-certifying person, serving its own
    /// certificate to the validators that meet its packets after adopting its namespace by name.
    certificates: Vec<Arc<OwnCertificates>>,
}

/// A revocation cut a data layer vouches for, as the root flow signs it into the next trust
/// context.
pub(crate) struct Proposed {
    /// The cut, with the digest of the public key that verified its entries and the full name of
    /// its manifest's root.
    pub cut: RevocationCut,
    /// The manifest's packets, root first.
    pub manifest: Vec<bytes::Bytes>,
    /// The entries of the key the layer holds that the bound left out, each by its full name
    /// ending in its implicit digest.
    pub left_out: Vec<Name>,
}

/// What a provider decides in a revocation: the cut its data layer vouches for.
pub(crate) trait Cutter: Sync {
    /// The cut `by`'s data layer vouches for if `key` is revoked now, bounded by what it first
    /// verified strictly before `held_before` (milliseconds by its own clock).
    fn cut(&self, by: &DeviceSpec, key: &Name, held_before: u64) -> anyhow::Result<Proposed>;
}

/// Carry and route a newly adopted person's sync group on a node: what the daemon's link library
/// does on the trust event.
pub(crate) type Route = Arc<dyn Fn(&Name) + Send + Sync>;

/// The world of a case, as the providers share it: keys, certificates, namespaces and their
/// trust-context versions, the manifest servers, the flows of a namespace's root.
#[derive(Default)]
pub(crate) struct Common {
    case: Mutex<Case>,
}

/// Each device's one key: `<device>/KEY/1`.
pub(crate) fn device_key(device: &Name) -> Name {
    device.clone().append("KEY").append("1")
}

/// The device whose key is `key` (`<device>/KEY/1`).
pub(crate) fn key_device(key: &Name) -> anyhow::Result<Name> {
    let device = Name::from_components(
        key.components()[..key.len().saturating_sub(2)]
            .iter()
            .cloned(),
    );
    anyhow::ensure!(
        device_key(&device) == *key,
        "{key} is no device key of this provider (<device>/KEY/1)"
    );
    Ok(device)
}

/// Now by the host's clock, the one validators read, in nanoseconds since the Unix epoch.
fn host_now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
}

/// A certificate named `name` of the public key `public`, signed by `issuer`, valid from
/// `from` until `until` (nanoseconds by the host's clock).
async fn issue(
    name: Name,
    public: &[u8],
    issuer: &dyn Signer,
    from: u64,
    until: u64,
) -> anyhow::Result<Certificate> {
    let wire = encode_cert_data(&name, public, issuer, from, until).await?;
    Ok(Certificate::decode(&decode_data(&wire)?)?)
}

/// The packet `wire` encodes.
pub(crate) fn decode_data(wire: &bytes::Bytes) -> anyhow::Result<Data> {
    Data::decode(wire.clone()).map_err(|e| anyhow::anyhow!("an undecodable packet: {e:?}"))
}

/// What a self-certifying person's device holds of its namespace's trust context when its
/// publisher starts (`ndn_namespace::publish::prepare` reads it once): version 1, its genesis,
/// as the root signed it. The provider keeps every version its roots sign; a version a node
/// adopts later is published as it adopts it (`spread`), so nothing is persisted here.
struct FirstVersion {
    data: Data,
}

impl FirstVersion {
    fn stored(&self) -> Vec<StoredContext> {
        let read = Data::decode(self.data.raw().clone())
            .map_err(|e| format!("{e:?}"))
            .and_then(|data| {
                ndn_cert::open_signed_context(&data)
                    .map(|(ctx, _)| (ctx, data))
                    .map_err(|e| e.to_string())
            });
        vec![StoredContext {
            location: self.location(),
            read,
        }]
    }
}

impl ContextStore for FirstVersion {
    fn location(&self) -> String {
        format!("the conformance provider's memory of {}", self.data.name)
    }

    fn persist(&self, ctx: &SignedTrustContext, _data: &Data) -> Result<String, String> {
        Err(format!(
            "{} version {} is not kept here: the conformance provider keeps every version its \
             roots sign and publishes the ones a node adopts as it adopts them",
            ctx.namespace(),
            ctx.version()
        ))
    }

    fn stored_contexts(&self) -> Result<Vec<StoredContext>, String> {
        Ok(self.stored())
    }

    fn stored_versions(&self, namespace: &Name) -> Result<Vec<StoredContext>, String> {
        Ok(
            if self.data.name.has_prefix(&ndn_cert::rdr_prefix(namespace)) {
                self.stored()
            } else {
                Vec::new()
            },
        )
    }

    /// The conformance provider signs for every root itself; no device holds a root key.
    fn holds_root_key(&self, _ctx: &SignedTrustContext) -> bool {
        false
    }

    fn persist_cut_manifest(
        &self,
        namespace: &Name,
        _wire: &bytes::Bytes,
    ) -> Result<String, String> {
        Err(format!(
            "a cut manifest of {namespace} is not kept here: the conformance provider's nodes \
             keep and serve the manifests of the versions they adopt (`keep_manifests`)"
        ))
    }

    /// Version 1 carries no cut.
    fn stored_cut_manifests(&self, _namespace: &Name) -> Result<Vec<bytes::Bytes>, String> {
        Ok(Vec::new())
    }
}

/// A host's adoption of a namespace for a data layer's judging of one space alone: fetched by
/// name through the node's engine, adopted into no keyring (the node's forwarder keeps refusing
/// the namespace), and carried in transit, once each, until the layer releases it.
pub(crate) struct Scoped {
    /// Its node's engine, the network an adoption fetches over.
    engine: ForwarderEngine,
    /// Carry and route a newly adopted person's sync group.
    route: Route,
    /// The namespaces adopted for the layer alone that its engine carries in transit.
    carried: Mutex<HashSet<Name>>,
}

impl Scoped {
    /// The adoption of the host of the node whose engine is `engine`.
    pub(crate) fn new(engine: ForwarderEngine, route: Route) -> Self {
        Self {
            engine,
            route,
            carried: Mutex::new(HashSet::new()),
        }
    }

    /// Adopt `namespace` for the layer, refreshed from `held` when the layer keeps a version.
    pub(crate) async fn adopt(
        &self,
        namespace: &Name,
        held: Option<&ScopedContext>,
    ) -> Result<ScopedContext, String> {
        // Fetched by name through the node's engine, its validator expecting the versions,
        // and adopted into no keyring: the node's forwarder keeps refusing the namespace.
        let scoped = ndn_identity::adopt_scoped_via_engine(&self.engine, namespace, held)
            .await
            .map_err(|e| e.to_string())?;
        // Carried once adopted, whether refreshed from a version the layer held (one it
        // kept across a restart included) or not: as a forwarder carries a namespace it does
        // not hold for a device that validates it end to end — its Data forwarded
        // unvalidated, never cached; its group routed.
        if self
            .carried
            .lock()
            .expect("the host's lock")
            .insert(namespace.clone())
        {
            self.engine.transit().add(namespace, || {});
            (self.route)(namespace);
        }
        Ok(scoped)
    }

    /// The layer lists `namespace` no more: stop carrying it.
    pub(crate) fn release(&self, namespace: &Name) {
        if self
            .carried
            .lock()
            .expect("the host's lock")
            .remove(namespace)
        {
            self.engine.transit().remove(namespace, || {});
        }
    }
}

impl Common {
    /// The key store of `device`.
    pub(crate) fn keys_of(&self, device: &Name) -> anyhow::Result<Arc<SecurityManager>> {
        self.case
            .lock()
            .expect("the provider's lock")
            .keys
            .get(device)
            .cloned()
            .with_context(|| format!("{device} was not prepared"))
    }

    /// `device`'s own signing key, as a hostile program on the device holds it.
    pub(crate) fn signer_of(&self, device: &DeviceSpec) -> anyhow::Result<Arc<dyn Signer>> {
        let keys = self.keys_of(&device.name())?;
        Ok(keys.get_signer_sync(&device_key(&device.name()))?)
    }

    /// The public key of `device`'s own key.
    pub(crate) fn public_key_of(&self, device: &Name) -> anyhow::Result<Vec<u8>> {
        let keys = self.keys_of(device)?;
        keys.get_signer_sync(&device_key(device))?
            .public_key()
            .context("an Ed25519 key")
            .map(|public| public.to_vec())
    }

    /// Every person's namespace of the case.
    pub(crate) fn persons(&self) -> Vec<Name> {
        self.case
            .lock()
            .expect("the provider's lock")
            .namespaces
            .keys()
            .cloned()
            .collect()
    }

    /// The hub's node: the first the case lists.
    pub(crate) fn hub(&self) -> anyhow::Result<NodeId> {
        self.case
            .lock()
            .expect("the provider's lock")
            .nodes
            .first()
            .copied()
            .context("prepare lists the hub first")
    }

    /// The newest signed version of `ns`'s trust context, as its root signed it.
    pub(crate) fn anchor(&self, ns: &Name, device: &Name) -> anyhow::Result<bytes::Bytes> {
        self.case
            .lock()
            .expect("the provider's lock")
            .namespaces
            .get(ns)
            .and_then(|n| n.versions.last().cloned())
            .with_context(|| format!("{device}'s namespace {ns} is no namespace of this case"))
    }

    /// Carry and route a person's sync group on `node`: the group is carried with the multicast
    /// strategy and routed over the node's link to the hub.
    pub(crate) fn route(&self, fabric: &Fabric, node: NodeId) -> anyhow::Result<Route> {
        let hub = self.hub()?;
        let engine = fabric
            .engine_of(node)
            .with_context(|| format!("no engine on node {node}"))?;
        let link = fabric
            .face_between(node, hub)
            .with_context(|| format!("node {node} has no link to the hub"))?;
        Ok(Arc::new(move |person: &Name| {
            ndn_namespace::sync_group::carry(&engine, person);
            EngineFaces(engine.clone())
                .add_routes(link, &ndn_link::group_routes(std::iter::once(person), 0));
        }))
    }

    /// Set up what spans devices once the fabric runs and before any device attaches: keys,
    /// certificates, trust anchors on every node (`hub` included), routes.
    pub(crate) async fn prepare(
        &self,
        fabric: &Fabric,
        hub: NodeId,
        devices: &[DeviceSpec],
    ) -> anyhow::Result<()> {
        // Ordered by person, so trust contexts, carried groups and group routes are set up in the
        // same order every run.
        let mut anchors: BTreeMap<Name, (Arc<dyn Signer>, Certificate)> = BTreeMap::new();
        let mut certs = Vec::new();
        // The certificate packet of each device of a self-certifying person, which it serves.
        let mut served: HashMap<Name, bytes::Bytes> = HashMap::new();
        // A self-certifying namespace enters a keyring only from its genesis, checked.
        let mut geneses: HashMap<Name, Genesis> = HashMap::new();
        let mut case = Case::default();
        let now = host_now_ns();
        for spec in devices {
            if !anchors.contains_key(&spec.person) {
                let mgr = SecurityManager::new();
                let name = spec.person.clone().append("KEY").append("ns");
                // A self-certifying person's root is the key its name hashes: its genesis root.
                let key = match &spec.genesis {
                    Some(genesis) => {
                        let named = GenesisKey::from_seed(*genesis).namespace();
                        anyhow::ensure!(
                            named == spec.person,
                            "{} is planned with a genesis key that names {named}",
                            spec.person
                        );
                        mgr.generate_ed25519_from_seed(name, genesis)?
                    }
                    None => mgr.generate_ed25519(name)?,
                };
                let signer = mgr.get_signer_sync(&key)?;
                let cert = if spec.genesis.is_some() {
                    // As `ndn-fwd init --self-certifying`: its version 1, the genesis, lists the
                    // root alone under a fixed validity — the same bytes whenever its key signs it.
                    let genesis = ndn_cert::sign_genesis(signer.as_ref()).await?;
                    let cert = genesis.root().clone();
                    geneses.insert(spec.person.clone(), genesis);
                    cert
                } else {
                    let public = signer.public_key().context("an Ed25519 key")?;
                    mgr.issue_self_signed(&key, public, VALIDITY_MS)?
                };
                anchors.insert(spec.person.clone(), (signer, cert));
            }
            let (issuer, _) = &anchors[&spec.person];
            let device = spec.name();
            let keys = Arc::new(SecurityManager::new());
            let key = keys.generate_ed25519(device_key(&device))?;
            let public = keys
                .get_signer_sync(&key)?
                .public_key()
                .context("an Ed25519 key")?;
            let wire = encode_cert_data(
                &new_cert_name(&key, DEFAULT_ISSUER),
                &public,
                issuer.as_ref(),
                now,
                now.saturating_add(VALIDITY_MS * 1_000_000),
            )
            .await?;
            let cert = Certificate::decode(&decode_data(&wire)?)?;
            if spec.genesis.is_some() {
                served.insert(device.clone(), wire);
            }
            keys.cert_cache().insert(cert.clone());
            certs.push((spec.person.clone(), cert.clone()));
            case.certs.insert(
                device.clone(),
                vec![Issued {
                    cert,
                    issuer: Arc::clone(issuer),
                }],
            );
            case.keys.insert(device, keys);
        }
        // Each person's namespace is a trust context (hierarchical schema, the person's key its
        // anchor) on every forwarder: the validator verifies a packet under the context whose
        // namespace is the longest prefix of its name, and a device's data layer takes its own
        // namespace from the context governing its name (spec §3). Its root signs it as version
        // 1 — version 2 for a self-certifying person, whose version 1 is its genesis — the
        // version later ones (revocations, a recovery) follow from. As a new context from
        // `ndn-fwd init`, it lists every device role (admin, member, node, guest) among those
        // whose data needs a cut once their certificate lapsed.
        let mut contexts: Vec<Arc<SignedTrustContext>> = Vec::with_capacity(anchors.len());
        for (person, (root, anchor)) in &anchors {
            let genesis = geneses.get(person);
            let ctx = ndn_cert::Role::DATA_REQUIRES_CUT.into_iter().fold(
                SignedTrustContext::hierarchical(person.clone())
                    .with_version(if genesis.is_some() { 2 } else { 1 }),
                |ctx, role| ctx.with_data_requires_cut(role.as_str()),
            );
            anyhow::ensure!(
                ctx.add_anchor(anchor.clone()),
                "{person}'s namespace key is not valid now"
            );
            let signed = ctx.sign_into_data(root.as_ref())?;
            let mut versions = Vec::with_capacity(2);
            if let Some(genesis) = genesis {
                ndn_cert::open_context_update(genesis.context(), &signed)
                    .await
                    .with_context(|| {
                        format!("{person}'s version 2 does not follow from its genesis")
                    })?;
                versions.push(genesis.data().raw().clone());
            }
            versions.push(signed.raw().clone());
            case.namespaces.insert(
                person.clone(),
                Namespace {
                    root: Arc::clone(root),
                    kit: None,
                    versions,
                    manifests: Vec::new(),
                },
            );
            contexts.push(Arc::new(ctx));
        }
        case.nodes = std::iter::once(hub)
            .chain(devices.iter().map(|d| d.node))
            .collect();
        // A stranger's node holds its own person's context and certificates only: it validates
        // nothing of another person until an introduction adopts that person's anchor. The hub
        // stands in for the network and its relays, which carry every person's packets.
        let own: HashMap<NodeId, &Name> = devices
            .iter()
            .filter(|d| d.stranger)
            .map(|d| (d.node, &d.person))
            .collect();
        let holds = |node: NodeId, person: &Name| own.get(&node).is_none_or(|p| *p == person);
        for &node in &case.nodes {
            let engine = fabric
                .engine_of(node)
                .with_context(|| format!("no engine on node {node}"))?;
            let validator = engine
                .validator()
                .with_context(|| format!("node {node} has no validator to hold the contexts"))?;
            for ctx in contexts.iter().filter(|c| holds(node, c.namespace())) {
                // A self-certifying person's version 2 was checked against its genesis above.
                let adopted = match geneses.get(ctx.namespace()) {
                    Some(genesis) => validator.keyring().adopt_genesis(genesis, Arc::clone(ctx)),
                    None => validator.adopt_context(Arc::clone(ctx)),
                };
                adopted.map_err(|refusal| {
                    anyhow::anyhow!(
                        "node {node} refused {}'s trust context: {refusal}",
                        ctx.namespace()
                    )
                })?;
            }
            for (_, cert) in certs.iter().filter(|(p, _)| holds(node, p)) {
                validator.cert_cache().insert(cert.clone());
            }
            // As a daemon's forwarder does: what its validator lacks (a certificate, a cut's
            // manifest packet) it fetches through the engine instead of dropping the Data.
            ndn_app::install_engine_cert_fetcher(&engine, CancellationToken::new());
        }
        // A self-certifying person is adopted by its name alone: each of its devices serves what
        // an adopter fetches, as a daemon does — its namespace's trust-context versions by name
        // (RDR: its genesis, then the version 2 it holds, and the versions its node adopts later
        // as it adopts them, `spread`) and its own certificate.
        for spec in devices.iter().filter(|d| d.genesis.is_some()) {
            let engine = fabric
                .engine_of(spec.node)
                .with_context(|| format!("no engine on node {}", spec.node))?;
            let validator = engine
                .validator()
                .with_context(|| format!("node {} has no validator", spec.node))?;
            let versions = &case.namespaces[&spec.person].versions;
            let genesis = FirstVersion {
                data: decode_data(&versions[0])?,
            };
            let (face, publisher) =
                ndn_namespace::publish::prepare(&genesis, engine.faces().alloc_id());
            engine.add_face(face, CancellationToken::new());
            let published = publisher.spawn(&engine);
            let held = contexts
                .iter()
                .find(|c| *c.namespace() == spec.person)
                .expect("every person's namespace has a context");
            published.publish(held, &decode_data(&versions[1])?);
            case.published
                .insert((spec.node, spec.person.clone()), published);
            let cert = served
                .remove(&spec.name())
                .expect("each device of a self-certifying person has its certificate");
            case.certificates.push(OwnCertificates::spawn(
                &engine,
                vec![cert],
                &[],
                validator.keyring(),
                CancellationToken::new(),
            ));
        }
        // Every device holds every person's namespace (a stranger only its own), and its link to
        // the hub carries them.
        for spec in devices {
            let engine = fabric
                .engine_of(spec.node)
                .with_context(|| format!("no engine on node {}", spec.node))?;
            let link = fabric
                .face_between(spec.node, hub)
                .with_context(|| format!("node {} has no link to the hub", spec.node))?;
            let people: Vec<&Name> = anchors.keys().filter(|p| holds(spec.node, p)).collect();
            for person in &people {
                ndn_namespace::sync_group::carry(&engine, person);
            }
            EngineFaces(engine).add_routes(link, &ndn_link::group_routes(people, 0));
        }
        *self.case.lock().expect("the provider's lock") = case;
        Ok(())
    }

    /// The key that signs `person`'s next trust-context version, and the newest one signed.
    fn authority(&self, person: &Name) -> anyhow::Result<(Arc<dyn Signer>, Data)> {
        let case = self.case.lock().expect("the provider's lock");
        let ns = case
            .namespaces
            .get(person)
            .with_context(|| format!("{person} is no namespace of this case"))?;
        let newest = ns
            .versions
            .last()
            .expect("prepare signs every namespace's first version");
        Ok((Arc::clone(&ns.root), decode_data(newest)?))
    }

    /// Record `versions` as the newest of `person`'s trust context, in order.
    fn publish(&self, person: &Name, versions: impl IntoIterator<Item = Data>) {
        let mut case = self.case.lock().expect("the provider's lock");
        let ns = case
            .namespaces
            .get_mut(person)
            .expect("only a namespace of the case signs versions");
        ns.versions
            .extend(versions.into_iter().map(|d| d.raw().clone()));
    }

    /// Every validator of the case and every device's key store can find `cert` from now on:
    /// it is in each of their certificate caches, in place of one of the same name.
    async fn hand_out(&self, fabric: &Fabric, cert: &Certificate) -> anyhow::Result<()> {
        let (nodes, keys): (Vec<NodeId>, Vec<Arc<SecurityManager>>) = {
            let case = self.case.lock().expect("the provider's lock");
            (case.nodes.clone(), case.keys.values().cloned().collect())
        };
        for node in nodes {
            let engine = fabric
                .engine_of(node)
                .with_context(|| format!("no engine on node {node}"))?;
            let validator = engine
                .validator()
                .with_context(|| format!("node {node} has no validator to hold certificates"))?;
            validator.cert_cache().insert(cert.clone());
            // A copy cached on the way is gone too: only the one handed out answers now.
            engine.cs().evict_prefix_erased(&cert.name, None).await;
        }
        for k in keys {
            if k.cert_cache().get(&cert.name).is_some() {
                k.cert_cache().insert(cert.clone());
            }
        }
        Ok(())
    }

    /// Hand out a new certificate of `device`'s key signed by `issuer` (valid from now, as
    /// long as the case's certificates), into the device's own key store too.
    async fn certify(
        &self,
        fabric: &Fabric,
        device: &Name,
        issuer: Arc<dyn Signer>,
    ) -> anyhow::Result<()> {
        let keys = self.keys_of(device)?;
        let key = device_key(device);
        let public = keys
            .get_signer_sync(&key)?
            .public_key()
            .context("an Ed25519 key")?;
        let now = host_now_ns();
        let cert = issue(
            new_cert_name(&key, DEFAULT_ISSUER),
            &public,
            issuer.as_ref(),
            now,
            now.saturating_add(VALIDITY_MS * 1_000_000),
        )
        .await?;
        keys.cert_cache().insert(cert.clone());
        self.adopt_cert(fabric, device, Issued { cert, issuer })
            .await
    }

    /// Record `issued` as the newest certificate of `device`'s key and hand it out.
    async fn adopt_cert(
        &self,
        fabric: &Fabric,
        device: &Name,
        issued: Issued,
    ) -> anyhow::Result<()> {
        self.hand_out(fabric, &issued.cert).await?;
        self.case
            .lock()
            .expect("the provider's lock")
            .certs
            .entry(device.clone())
            .or_default()
            .push(issued);
        Ok(())
    }

    /// `by`, holding its namespace's authority, signs the next trust-context version revoking
    /// each key with its cut, keeps the cuts' manifest packets with that version, and its node
    /// adopts it (keeping and serving the manifests from then on).
    async fn sign_revocations(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        revoked: Vec<(Name, Proposed)>,
    ) -> anyhow::Result<()> {
        let (root, held) = self.authority(&by.person)?;
        let (keys, proposals): (Vec<Name>, Vec<Proposed>) = revoked.into_iter().unzip();
        let cuts: Vec<_> = proposals.iter().map(|p| p.cut.clone()).collect();
        let bump = ndn_cert::bump_context_revoking(root.as_ref(), &held, &keys, &cuts)
            .await?
            .with_context(|| format!("{keys:?} are revoked already; nothing to sign"))?;
        let version = bump.context.version();
        let manifests = proposals.into_iter().flat_map(|p| p.manifest).collect();
        self.case
            .lock()
            .expect("the provider's lock")
            .namespaces
            .get_mut(&by.person)
            .expect("authority found it")
            .manifests
            .push((version, manifests));
        self.publish(&by.person, [bump.data]);
        self.spread(fabric, by.node).await
    }

    /// `by`, the root of `device`'s namespace, revokes `device`'s key with the cut its layer
    /// vouches for, bounded by what it first verified before `lost` (milliseconds by its own
    /// clock): never what it heard listed nor what it took after. Returns the entries of the key
    /// the layer holds but left out of the cut.
    pub(crate) async fn revoke(
        &self,
        fabric: &Fabric,
        cutter: &dyn Cutter,
        by: &DeviceSpec,
        device: &DeviceSpec,
        lost: u64,
    ) -> anyhow::Result<Vec<Name>> {
        anyhow::ensure!(
            by.person == device.person,
            "{} holds the authority of {}, not of {}'s namespace {}: only a namespace's root \
             revokes its devices",
            by.name(),
            by.person,
            device.name(),
            device.person
        );
        let key = device_key(&device.name());
        let proposal = cutter.cut(by, &key, lost)?;
        let left_out = proposal.left_out.clone();
        self.sign_revocations(fabric, by, vec![(key, proposal)])
            .await?;
        Ok(left_out)
    }

    /// `by`, holding its namespace's authority, re-admits exactly the packet `full`, which `key`
    /// signed, and its node adopts the new version.
    pub(crate) async fn readmit_full(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        key: &Name,
        full: &Name,
    ) -> anyhow::Result<()> {
        let (root, held) = self.authority(&by.person)?;
        let bump = ndn_cert::bump_context_readmitting(
            root.as_ref(),
            &held,
            key,
            std::slice::from_ref(full),
        )
        .await?
        .with_context(|| format!("{full} is re-admitted already; nothing to sign"))?;
        self.publish(&by.person, [bump.data]);
        self.spread(fabric, by.node).await
    }

    /// `node`, holding version `upto` of `ns`'s trust context, keeps and serves the manifest
    /// packets of the cuts in every version up to it, as a node keeping contexts does: an
    /// Interest by full name (or by name) gets the packet, so a validator missing one fetches it
    /// from any such node.
    async fn keep_manifests(
        &self,
        fabric: &Fabric,
        node: NodeId,
        ns: &Name,
        upto: u64,
    ) -> anyhow::Result<()> {
        let (packets, kept) = {
            let case = self.case.lock().expect("the provider's lock");
            let packets: Vec<bytes::Bytes> = case
                .namespaces
                .get(ns)
                .with_context(|| format!("{ns} is no namespace of this case"))?
                .manifests
                .iter()
                .filter(|(v, _)| *v <= upto)
                .flat_map(|(_, p)| p.iter().cloned())
                .collect();
            (packets, case.kept.get(&(node, ns.clone())).cloned())
        };
        if packets.is_empty() {
            return Ok(());
        }
        let kept = match kept {
            Some(kept) => kept,
            None => {
                let kept = Kept::default();
                let engine = fabric
                    .engine_of(node)
                    .with_context(|| format!("no engine on node {node}"))?;
                let app = engine.app_node(CancellationToken::new());
                let prefix: Name = format!("{ns}/32=trust-context/32=cut")
                    .parse()
                    .with_context(|| format!("no cut-manifest prefix under {ns}"))?;
                let packets = Arc::clone(&kept);
                let guard = app
                    .serve(prefix, move |interest, responder| {
                        let packets = Arc::clone(&packets);
                        async move {
                            let asked = &*interest.name;
                            let wire = {
                                let held = packets.lock().expect("the manifest store's lock");
                                held.get(asked)
                                    .or_else(|| {
                                        held.iter()
                                            .find(|(full, _)| {
                                                full.len() == asked.len() + 1
                                                    && full.has_prefix(asked)
                                            })
                                            .map(|(_, wire)| wire)
                                    })
                                    .cloned()
                            };
                            if let Some(wire) = wire {
                                let _ = responder.respond_bytes(wire).await;
                            }
                        }
                    })
                    .await?;
                let mut case = self.case.lock().expect("the provider's lock");
                case.relays.push((app, guard));
                case.kept.insert((node, ns.clone()), Arc::clone(&kept));
                kept
            }
        };
        let mut held = kept.lock().expect("the manifest store's lock");
        for wire in packets {
            let data = decode_data(&wire)?;
            let full = (*data.name)
                .clone()
                .append_implicit_digest(data.implicit_digest());
            held.insert(full, wire);
        }
        Ok(())
    }

    /// `node` follows its namespaces' trust contexts to the newest version each has signed (each
    /// version checked against the one it holds: signed by one of its anchors, newer) and
    /// adopts them, as context sync brings them to a node.
    pub(crate) async fn spread(&self, fabric: &Fabric, node: NodeId) -> anyhow::Result<()> {
        let keyring = Arc::clone(
            fabric
                .engine_of(node)
                .and_then(|e| e.validator())
                .with_context(|| format!("node {node} has no validator to hold the contexts"))?
                .keyring(),
        );
        let namespaces: Vec<(Name, Vec<bytes::Bytes>)> = self
            .case
            .lock()
            .expect("the provider's lock")
            .namespaces
            .iter()
            .map(|(ns, n)| (ns.clone(), n.versions.clone()))
            .collect();
        for (ns, versions) in namespaces {
            // One version at a time, each checked against the one held (signed by one of its
            // anchors, newer): how a node follows a recovery's N+1 and N+2.
            loop {
                let held = keyring
                    .contexts()
                    .into_iter()
                    .find(|c| *c.namespace() == ns)
                    .with_context(|| format!("node {node} holds no trust context of {ns}"))?;
                let next = usize::try_from(held.version())
                    .ok()
                    .and_then(|v| versions.get(v));
                let Some(next) = next else { break };
                let next = decode_data(next)?;
                let (ctx, _) = ndn_cert::open_context_update(&held, &next)
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "node {node} refused version {} of {ns}'s trust context: {e}",
                            held.version() + 1
                        )
                    })?;
                let ctx = Arc::new(ctx);
                keyring
                    .adopt_update_from(&held, Arc::clone(&ctx))
                    .map_err(|now| {
                        anyhow::anyhow!(
                            "node {node} did not adopt version {} of {ns}'s trust context: it \
                             holds {now:?} meanwhile",
                            held.version() + 1
                        )
                    })?;
                // A node publishing the namespace publishes each version it adopts.
                if let Some(published) = self
                    .case
                    .lock()
                    .expect("the provider's lock")
                    .published
                    .get(&(node, ns.clone()))
                {
                    published.publish(&ctx, &next);
                }
            }
            // A node keeping the context keeps and serves what binds its cuts to bytes.
            let upto = keyring
                .contexts()
                .into_iter()
                .find(|c| *c.namespace() == ns)
                .map_or(0, |c| c.version());
            self.keep_manifests(fabric, node, &ns, upto).await?;
        }
        Ok(())
    }

    /// `device` renews its certificate: its namespace's authority now certifies the same key
    /// again, valid from now, and every node can find the new certificate.
    pub(crate) async fn renew(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<()> {
        let (root, _) = self.authority(&device.person)?;
        self.certify(fabric, &device.name(), root).await
    }

    /// `which` certificates of `device`'s key expire: every node, and the device itself, holds
    /// each of them only with a validity period that ended before now by the host's clock. The
    /// key's authority ended now, in the case's time.
    pub(crate) async fn expire(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        which: Certs,
    ) -> anyhow::Result<()> {
        let name = device.name();
        let issued = self
            .case
            .lock()
            .expect("the provider's lock")
            .certs
            .get(&name)
            .cloned()
            .with_context(|| format!("{name} was not prepared"))?;
        let expiring = match which {
            Certs::All => &issued[..],
            Certs::Superseded => &issued[..issued.len().saturating_sub(1)],
        };
        anyhow::ensure!(
            !expiring.is_empty(),
            "{name} has no certificate a renewal superseded; renew it first"
        );
        // Each one as it is once its NotAfter passed: valid for a year, until a day ago.
        let until = host_now_ns().saturating_sub(DAY_NS);
        let from = until.saturating_sub(365 * DAY_NS);
        let mut renamed = Vec::with_capacity(expiring.len());
        for Issued { cert, issuer } in expiring {
            let expired = issue(
                (*cert.name).clone(),
                &cert.public_key,
                issuer.as_ref(),
                from,
                until,
            )
            .await?;
            self.hand_out(fabric, &expired).await?;
            renamed.push(expired);
        }
        let mut case = self.case.lock().expect("the provider's lock");
        let held = case.certs.get_mut(&name).expect("read above");
        for (slot, expired) in held.iter_mut().zip(renamed) {
            slot.cert = expired;
        }
        if which == Certs::All {
            case.lapsed
                .insert(name, fabric.clock().now_ns() / 1_000_000);
        }
        Ok(())
    }

    /// `by`, the root device of its namespace, ends the keys whose authority over data ended
    /// without a revocation (a lapsed guest certificate, a replaced key): for each such key of
    /// its namespace it signs a revoke-with-cut, the cut bounded by what `by`'s layer first
    /// verified before the key's end, and `by`'s node adopts it. Returns the keys it ended.
    pub(crate) async fn end_keys(
        &self,
        fabric: &Fabric,
        cutter: &dyn Cutter,
        by: &DeviceSpec,
    ) -> anyhow::Result<Vec<Name>> {
        let ns = &by.person;
        let held = fabric
            .engine_of(by.node)
            .and_then(|e| e.validator())
            .with_context(|| format!("node {} has no validator to hold the contexts", by.node))?
            .keyring()
            .contexts()
            .into_iter()
            .find(|c| c.namespace() == ns)
            .with_context(|| format!("{} holds no trust context of {ns}", by.name()))?;
        let (issued, lapsed) = {
            let case = self.case.lock().expect("the provider's lock");
            // Every certificate the root issued for the namespace's devices.
            let issued: Vec<Certificate> = case
                .certs
                .iter()
                .filter(|(device, _)| device.has_prefix(ns))
                .flat_map(|(_, issued)| issued.iter().map(|i| i.cert.clone()))
                .collect();
            (issued, case.lapsed.clone())
        };
        let ending = ndn_cert::ending_keys(&held, &issued, host_now_ns() / 1_000_000);
        anyhow::ensure!(
            !ending.is_empty(),
            "no key of {ns} ended without a revocation (none of a role needing a cut lapsed, \
             none replaced); nothing to sign"
        );
        // Validators here read the host's clock, data layers their node's (virtual) one, so a
        // key's end is the moment the case let its certificates lapse, read on `by`'s clock.
        let true_now = fabric.clock().now_ns() / 1_000_000;
        let by_now = fabric.node_clock(by.node)?.now_ns() / 1_000_000;
        let skew = i64::try_from(i128::from(by_now) - i128::from(true_now))
            .context("a clock skew beyond ±292 million years")?;
        let mut revoked = Vec::with_capacity(ending.len());
        for e in ending {
            let device = key_device(&e.key)?;
            let at = lapsed.get(&device).with_context(|| {
                format!(
                    "{} ended ({:?}) at a moment this provider cannot place on {}'s clock: it \
                     ends only keys whose certificates it let expire",
                    e.key,
                    e.why,
                    by.name()
                )
            })?;
            let held_before = at.saturating_add_signed(skew);
            let proposal = cutter.cut(by, &e.key, held_before)?;
            revoked.push((e.key, proposal));
        }
        let keys = revoked.iter().map(|(k, _)| k.clone()).collect();
        self.sign_revocations(fabric, by, revoked).await?;
        Ok(keys)
    }

    /// `by`, holding its namespace's authority, makes a recovery kit: the next context version
    /// adds the kit's key as a recovery anchor, and `by`'s node adopts it.
    pub(crate) async fn recovery_kit(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
    ) -> anyhow::Result<()> {
        let ns = &by.person;
        let (root, held) = self.authority(ns)?;
        let kit: Arc<dyn Signer> = Arc::new(RecoverySeed::generate()?.signer(ns));
        let anchor = ndn_cert::recovery_anchor(Arc::clone(&kit)).await?;
        let bump = ndn_cert::add_recovery_anchor(root.as_ref(), &held, &anchor).await?;
        self.publish(ns, [bump.data]);
        self.case
            .lock()
            .expect("the provider's lock")
            .namespaces
            .get_mut(ns)
            .expect("authority found it")
            .kit = Some(kit);
        self.spread(fabric, by.node).await
    }

    /// `by`'s namespace root was compromised; `by` recovers the namespace with its recovery kit:
    /// the kit signs the next version (a new root, the old root removed and revoked, every
    /// revocation and cut carried, each key revoked with a cut certified again by the new root),
    /// and the new root signs the one after it. `by`'s node adopts both.
    pub(crate) async fn recover(&self, fabric: &Fabric, by: &DeviceSpec) -> anyhow::Result<()> {
        let ns = &by.person;
        let (_, held) = self.authority(ns)?;
        let (kit, held_certs) = {
            let case = self.case.lock().expect("the provider's lock");
            let kit = case.namespaces[ns].kit.clone().with_context(|| {
                format!("{ns} has no recovery kit; make one before its root is lost")
            })?;
            // The certificates of the namespace's devices the recovering root device holds.
            let certs: Vec<Certificate> = case
                .certs
                .iter()
                .filter(|(device, _)| device.has_prefix(ns))
                .flat_map(|(_, issued)| issued.iter().map(|i| i.cert.clone()))
                .collect();
            (kit, certs)
        };
        let mgr = SecurityManager::new();
        let key = mgr.generate_ed25519(ns.clone().append("KEY").append("recovered"))?;
        let new_root = mgr.get_signer_sync(&key)?;
        let public = new_root.public_key().context("an Ed25519 key")?;
        let anchor = mgr.issue_self_signed(&key, public, VALIDITY_MS)?;
        let plan = RecoveryPlan {
            new_root: &anchor,
            new_root_device_keys: &[],
            old_root: OldRoot::Compromised,
            kept_kits: &[],
            cuts: &[],
        };
        // N+1 by the kit, N+2 by the new root.
        let recovery = ndn_cert::recovery_version(kit.as_ref(), &held, &plan).await?;
        let reissued = ndn_cert::reissue_version(new_root.as_ref(), &recovery.bump.data).await?;
        // Every key revoked with a cut is certified again by the new root, so its versions in
        // the cut keep a chain to an anchor once the old root is revoked.
        let recertified =
            ndn_cert::recertify_cut_keys(Arc::clone(&new_root), &reissued.context, &held_certs)
                .await?;
        anyhow::ensure!(
            recertified.unheld.is_empty(),
            "the recovering root device holds no certificate of the cut keys {:?}, so their \
             versions in the cut stay refused until they are certified again",
            recertified.unheld
        );
        self.publish(ns, [recovery.bump.data, reissued.data]);
        self.case
            .lock()
            .expect("the provider's lock")
            .namespaces
            .get_mut(ns)
            .expect("authority found it")
            .root = Arc::clone(&new_root);
        for cert in recertified.issued {
            let device = key_device(&cert.key_name())?;
            let issued = Issued {
                cert,
                issuer: Arc::clone(&new_root),
            };
            self.adopt_cert(fabric, &device, issued).await?;
        }
        self.spread(fabric, by.node).await
    }

    /// `device`'s node fetches now, fresh, the packet answering `prefix` (CanBePrefix), and from
    /// then on answers every Interest under `prefix` that the device's own layer (or any other
    /// face of the node) sends, with that packet **altered**: its last octet, the last octet of
    /// its signature, flipped.
    pub(crate) async fn replay_altered_packet(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        prefix: &Name,
    ) -> anyhow::Result<()> {
        let engine = fabric
            .engine_of(device.node)
            .with_context(|| format!("no engine on node {}", device.node))?;
        let node = engine.app_node(CancellationToken::new());
        // The altered packet reaches the device's own node from a party that validates
        // nothing (the party at a first contact's address, a link): the node carries the
        // name in transit, unvalidated and never cached, as it carries a first contact's
        // hint record, for the genuine record it fetches first as for the altered one it
        // serves. (A forwarder that holds the namespace, the hub, validates and drops it.)
        engine.transit().add(prefix, || {});
        // Fresh, past every cache: what a device serving `prefix` answers now. An attacker on a
        // lossy path asks again, a bounded number of times, until an answer arrives: the attack
        // needs the packet, and a lost Interest or Data is no defence.
        let mut tries = 0;
        let packet = loop {
            tries += 1;
            let ask = InterestBuilder::new(prefix.clone())
                .can_be_prefix()
                .must_be_fresh()
                .lifetime(std::time::Duration::from_secs(2));
            match Consumer::new(node.connection()).fetch_with(ask).await {
                Ok(packet) => break packet.raw().clone(),
                Err(e) if tries >= REPLAY_TRIES => {
                    return Err(anyhow::Error::new(e).context(format!(
                        "nothing answered {prefix} to replay in {REPLAY_TRIES} asks"
                    )));
                }
                Err(_) => {}
            }
        };
        let mut octets = packet.to_vec();
        *octets.last_mut().context("an empty packet")? ^= 1;
        let packet = bytes::Bytes::from(octets);
        // Served on the device's own node under `prefix`: the hub forwards every Interest to
        // every device, and this node's longest match for `prefix` is the replayer, not the
        // device's data layer. Every Interest under it gets the same packet, however stale.
        self.serve_packets(node, prefix, move |_| Some(packet.clone()))
            .await
    }

    /// Serve every Interest under `prefix` on `node`, which the engine's app face of that node
    /// carries, with `answer(name)`: the packet that answers it, or nothing. The relay lives as
    /// long as the case.
    pub(crate) async fn serve_packets(
        &self,
        node: Node,
        prefix: &Name,
        answer: impl Fn(&Name) -> Option<bytes::Bytes> + Send + Sync + 'static,
    ) -> anyhow::Result<()> {
        let answer = Arc::new(answer);
        let guard = node
            .serve(prefix.clone(), move |interest, responder| {
                let answer = Arc::clone(&answer);
                async move {
                    if let Some(packet) = answer(&interest.name) {
                        let _ = responder.respond_bytes(packet).await;
                    }
                }
            })
            .await?;
        self.case
            .lock()
            .expect("the provider's lock")
            .relays
            .push((node, guard));
        Ok(())
    }

    /// `device`'s host adopts the namespace the anchor link `link` (an `ndn-trust://anchor`
    /// URI) names, as `ndn-ctl adopt` adopts one: a link carrying the namespace's signed trust
    /// context is checked against it; a self-certifying namespace may be named alone, its
    /// versions then fetched by name and version 1 checked as its genesis.
    pub(crate) async fn adopt_link(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        link: &str,
    ) -> anyhow::Result<()> {
        let link = AnchorLink::from_uri(link)?;
        let engine = fabric
            .engine_of(device.node)
            .with_context(|| format!("no engine on node {}", device.node))?;
        let validator = engine
            .validator()
            .with_context(|| format!("node {} has no validator to adopt into", device.node))?;
        // As the daemon adopts a link: the context inline, or fetched by name through the
        // node's engine, whose validator is told to expect it.
        ndn_identity::adopt_anchor_link_via_engine(&engine, validator.keyring(), &link).await?;
        // As a daemon's link library does on the trust event: carry the person's sync group and
        // route it over the link to the hub.
        (self.route(fabric, device.node)?)(&link.namespace);
        Ok(())
    }

    /// What `at`'s forwarder — its node's validator, the one that judges every packet the node
    /// forwards — says of the packet `wire`, which `name` names: `Ok(())` when it accepts it,
    /// else why not.
    pub(crate) async fn verdict(
        &self,
        fabric: &Fabric,
        at: &DeviceSpec,
        name: &Name,
        wire: bytes::Bytes,
    ) -> anyhow::Result<Result<(), String>> {
        let data = Data::decode(wire).map_err(|e| anyhow::anyhow!("{name}: {e:?}"))?;
        let validator = fabric
            .engine_of(at.node)
            .and_then(|e| e.validator())
            .with_context(|| format!("node {} has no validator", at.node))?;
        Ok(match validator.validate_durable(&data).await {
            ndn_security::ValidationResult::Valid(_) => Ok(()),
            ndn_security::ValidationResult::Invalid(e) => Err(e.to_string()),
            ndn_security::ValidationResult::Pending => Err(format!(
                "{name} waits for a certificate {}'s forwarder lacks: no verdict",
                at.name()
            )),
        })
    }
}
