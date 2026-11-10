//! The reference provider: `ndn-data`'s own [`Device`] on every device of a case.
//!
//! Every person is a namespace (`/alice`, or `/home/bob` of several components) with a key
//! (`<person>/KEY/…`, self-signed) that certifies each of their devices' keys
//! (`<person>/<device>/KEY/…`). Every forwarder — the hub and each device — holds every person's
//! trust context (namespace `<person>`, the hierarchical schema, the person's key its anchor) and
//! every device certificate in its cache, so its fail-closed validator admits exactly the case's
//! people, and a device's data layer takes its namespace from the context governing its name. In
//! a case of strangers ([`DeviceSpec::stranger`]) a device's forwarder holds its own person's
//! context and certificates only, until an introduction: its host's introducer gives its
//! namespace's signed context as its anchor and adopts another person's anchor link by
//! `ndn-cert`'s adoption (checked against the link's fingerprint), then carries and routes that
//! person's sync group as below. A
//! device's link to the hub stands in for its links to the other devices of every namespace it
//! holds, so each person's sync group (`<person>/32=sync`, spec §12) is set up on it by the
//! libraries a daemon uses: the trust-context library runs the group with the multicast strategy
//! (`ndn_namespace::sync_group::carry`) and the link library routes it over the link
//! (`ndn_link::group_routes`, added through `EngineFaces` as a daemon's links add theirs). The
//! hub's default routes stand in for the network between devices. Each device's data layer runs
//! on its own node over two in-process app faces (fetch/serve, and sync), verifies with that
//! node's validator, keeps entries in memory and its seal (X25519 recipient) secret in its key
//! store beside its signing key (`SecurityManager::put_secret`, in memory), and dates entries by
//! the node's own (possibly lying) clock.
//!
//! The person's key signs their trust context as version 1 (listing the guest role, a friend's
//! device `<person>/guest/<who>`, among those whose data needs a cut once their certificate
//! lapsed), and acts as the namespace's root device from then on: a revocation (with the cut the
//! revoking device's data layer first verified before the loss the owner states, and the
//! manifest binding it to bytes), the end of a lapsed guest key (a revocation whose cut is
//! bounded at the lapse, signed unattended), a re-admission, a recovery kit and a recovery after
//! the root's compromise are the next versions, signed with `ndn-cert`'s functions as the root
//! flow signs them. A node takes them one at a time as context sync brings them, each checked
//! against the version it holds (signed by one of its anchors, newer), and from then on keeps
//! and serves the manifest packets of its cuts by full name, as a node keeping contexts does;
//! like a daemon's, every forwarder fetches what its validator lacks (a certificate, a
//! manifest packet) through its engine. A renewed or expired certificate is handed to every
//! node's cache in place of the copy it held; the validators judge validity by the host's
//! clock. A device's data layer can stop and start again on its store, re-judging what it
//! restores. Each device's program registers the standard merge rules and the ones its
//! [`Program`] names — the cases' element rule ([`crate::element`]), as written or lax — so a
//! case can give one device a program that lacks a rule, or one that signs what the rule refuses.
//!
//! A self-certifying person (`/user/<hash>`, [`DeviceSpec::genesis`]) has its genesis root as
//! its key, so version 1 is the genesis its name hashes. It is adopted by its name alone: each of
//! its devices serves what an adopter fetches, as a daemon does — its namespace's
//! trust-context versions by name (`ndn_namespace::publish`, each later version as its node
//! adopts it) and its own certificate (`OwnCertificates`) — and a host adopts an anchor link
//! ([`Provider::adopt`]) through its node's engine as the daemon does
//! (`ndn_identity::adopt_anchor_link_via_engine`), then carries and routes that person's sync
//! group as after an introduction.
//!
//! A device's host starts signals (`ndn_surface::signal::Signals`) when a case asks for them,
//! on an app face of their own on the device's node, gated by the device's data layer and dating
//! by the node's clock; the face takes the device's namespace group (`<ns>/32=sync`), which the
//! node already carries with the multicast strategy and routes over its link. Every device is
//! its own host, so signals open no local ring: in one process one device's ring would be
//! another's, and every signal crosses the simulated links.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use ndn_app::{Connection, Consumer, EngineAppExt, Node, ServeGuard};
use ndn_cert::{AnchorLink, GenesisKey, OldRoot, RecoveryPlan, RecoverySeed};
use ndn_data::intro::{Adopting, Scoping};
use ndn_data::wire::{
    AuditAnswer, AuditAsk, NONCE_LEN, Record, VersionBody, audit_ask_name, decode_record,
    encode_audit_answer, encode_record, log_name, parse_audit_ask_name, parse_log_name,
    parse_piece_name, piece_names, version_proof,
};
use ndn_data::{
    Code, Config, CutBound, CutProposal, DataLayer, Device, Entropy, Introducer, Joined,
    MergeRules, Name, Offer, Timestamp, Transport, VersionId,
};
use ndn_link::{EngineFaces, FaceSink};
use ndn_namespace::publish::{OwnCertificates, PublishedContexts};
use ndn_namespace::{ContextStore, StoredContext};
use ndn_packet::Data;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_security::cert_name::{DEFAULT_ISSUER, new_cert_name};
use ndn_security::self_certifying::Genesis;
use ndn_security::{
    Certificate, ScopedContext, SecurityManager, SignedTrustContext, Signer, Validator,
    anchor_fingerprint, encode_cert_data,
};
use ndn_sim::{Fabric, NodeId};
use ndn_surface::signal::{SignalOptions, Signals};
use ndn_sync::{DataStore, MemoryStore, SvsConfig};
use ndn_trust_envelope::TrustEnvelope;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::element::Element;
use crate::feature::Feature;
use crate::provider::{Certs, DeviceSpec, Grants, Program, Provider, Tally, Tamper};

/// Certificates live far longer than any case (they are checked against the host's real clock).
const VALIDITY_MS: u64 = 10 * 365 * 24 * 3600 * 1000;
/// A day in nanoseconds, the unit of certificate validity periods.
const DAY_NS: u64 = 24 * 3600 * 1_000_000_000;
/// How many times a replaying cache ([`Provider::replay`]) asks for the packet it will replay
/// before giving up: each ask lives 2 s, so on the faulty profile (drop 0.2 each way, blocks)
/// eight asks all go unanswered about once in three thousand runs, and on a clean path the
/// first ask is answered.
const REPLAY_TRIES: u32 = 8;

/// One case's keys and devices.
#[derive(Default)]
struct Case {
    /// Each device's key store, by device name.
    keys: HashMap<Name, Arc<SecurityManager>>,
    /// Every certificate issued for each device's key, oldest first, by device name.
    certs: HashMap<Name, Vec<Issued>>,
    /// When each device's certificates were let expire ([`Provider::expire`]), by the fabric's
    /// true clock: the end of its key's authority, for [`Provider::end_keys`].
    lapsed: HashMap<Name, Timestamp>,
    /// Each person's namespace: its authority and the trust-context versions it signed.
    namespaces: BTreeMap<Name, Namespace>,
    /// Every forwarder: the hub, then each device's.
    nodes: Vec<NodeId>,
    /// Every data layer attached, with its store, by node (a thief's layer carries its victim's
    /// name, so names do not tell them apart).
    devices: BTreeMap<NodeId, Attached>,
    /// The cut-manifest packets each node keeps and serves, per namespace, by full name.
    kept: HashMap<(NodeId, Name), Kept>,
    /// The audit relays, replaying caches and manifest servers injected
    /// ([`Provider::relay_audits`], [`Provider::replay`], [`Reference::keep_manifests`]),
    /// served while the case runs.
    relays: Vec<(Node, ServeGuard)>,
    /// The publisher of each node of a self-certifying person: its namespace's trust-context
    /// versions by name (RDR), as a daemon publishes them, so another adopts it by name.
    published: HashMap<(NodeId, Name), PublishedContexts>,
    /// The certificate server of each device of a self-certifying person, serving its own
    /// certificate to the validators that meet its packets after adopting its namespace by
    /// name.
    certificates: Vec<Arc<OwnCertificates>>,
    /// Each device's signals and the connection of their own they run on, by node
    /// ([`Provider::signals`]).
    signals: HashMap<NodeId, (Signals, Arc<dyn Connection>)>,
}

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

/// One attached data layer and the store it keeps its packets in.
struct Attached {
    layer: Device,
    store: Arc<MemoryStore>,
    /// How many times it started: 1, then one more per [`Provider::restart`].
    runs: u64,
    /// Ends its app faces when it stops.
    cancel: CancellationToken,
}

/// `ndn-data`'s [`Device`] as a conformance provider.
#[derive(Default)]
pub struct Reference {
    case: Mutex<Case>,
}

impl Reference {
    /// The provider, for the runner's list.
    pub fn provider() -> Arc<dyn Provider> {
        Arc::new(Self::default())
    }

    async fn start(
        &self,
        fabric: &Fabric,
        node: NodeId,
        device: Name,
        keys: Arc<SecurityManager>,
        host: Host,
        store: Arc<MemoryStore>,
    ) -> anyhow::Result<Arc<dyn DataLayer>> {
        let engine = fabric
            .engine_of(node)
            .with_context(|| format!("no engine on node {node}"))?;
        let validator = engine
            .validator()
            .context("the node's forwarder validates nothing; the layer verifies with it")?;
        let cancel = CancellationToken::new();
        let transport = Transport {
            node: engine.app_node(cancel.child_token()),
            sync: engine.app_face(cancel.child_token()),
        };
        // A layer started again on its node draws other randomness than its earlier runs.
        let runs = self
            .case
            .lock()
            .expect("the provider's lock")
            .devices
            .get(&node)
            .map_or(1, |a| a.runs + 1);
        let clock = fabric.node_clock(node)?;
        let introducer = self.introducer(fabric, node, &device, &validator)?;
        let config = Config {
            clock: Arc::new(move || Timestamp(clock.now_ns() / 1_000_000)),
            svs: SvsConfig::default(),
            hold_for: host.hold_for,
            rules: rules(host.program),
            entropy: seeded(&device, runs),
            introducer: Some(introducer),
            ..Config::new()
        };
        let layer = Device::start(
            transport,
            device.clone(),
            keys,
            validator,
            Arc::clone(&store) as Arc<dyn DataStore>,
            config,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{device}: {e}"))?;
        self.case
            .lock()
            .expect("the provider's lock")
            .devices
            .insert(
                node,
                Attached {
                    layer: layer.clone(),
                    store,
                    runs,
                    cancel,
                },
            );
        Ok(Arc::new(layer))
    }

    /// The introducer of the host of `device` on `node`: its namespace's newest signed trust
    /// context as the anchor it gives, its node's validator to adopt into, and its link to the
    /// hub to route an adopted person's sync group over.
    fn introducer(
        &self,
        fabric: &Fabric,
        node: NodeId,
        device: &Name,
        validator: &Arc<Validator>,
    ) -> anyhow::Result<Arc<dyn Introducer>> {
        let ns = validator.keyring().context_for(device).namespace().clone();
        let (anchor, hub) = {
            let case = self.case.lock().expect("the provider's lock");
            let anchor = case
                .namespaces
                .get(&ns)
                .and_then(|n| n.versions.last().cloned())
                .with_context(|| {
                    format!("{device}'s namespace {ns} is no namespace of this case")
                })?;
            (
                anchor,
                *case.nodes.first().context("prepare lists the hub first")?,
            )
        };
        let engine = fabric
            .engine_of(node)
            .with_context(|| format!("no engine on node {node}"))?;
        let link = fabric
            .face_between(node, hub)
            .with_context(|| format!("node {node} has no link to the hub"))?;
        Ok(Arc::new(Introduce {
            anchor,
            validator: Arc::clone(validator),
            engine: engine.clone(),
            route: Box::new(move |person: &Name| {
                ndn_namespace::sync_group::carry(&engine, person);
                EngineFaces(engine.clone())
                    .add_routes(link, &ndn_link::group_routes(std::iter::once(person), 0));
            }),
            carried: std::sync::Mutex::new(std::collections::HashSet::new()),
        }))
    }

    /// The store of the layer attached on `device`'s node.
    fn store(&self, device: &DeviceSpec) -> Arc<MemoryStore> {
        let case = self.case.lock().expect("the provider's lock");
        let attached = case
            .devices
            .get(&device.node)
            .unwrap_or_else(|| panic!("{} has no data layer attached", device.name()));
        Arc::clone(&attached.store)
    }

    /// The data layer attached on `device`'s node.
    fn layer(&self, device: &DeviceSpec) -> anyhow::Result<Device> {
        self.case
            .lock()
            .expect("the provider's lock")
            .devices
            .get(&device.node)
            .map(|a| a.layer.clone())
            .with_context(|| format!("{} has no data layer attached", device.name()))
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
        let keys = self
            .case
            .lock()
            .expect("the provider's lock")
            .keys
            .get(device)
            .cloned()
            .with_context(|| format!("{device} was not prepared"))?;
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

    /// The cut `by`'s data layer vouches for if `key` is revoked now, bounded by what it first
    /// verified before `held_before` (by its own clock).
    fn cut_of(
        &self,
        by: &DeviceSpec,
        key: &Name,
        held_before: Timestamp,
    ) -> anyhow::Result<CutProposal> {
        let bound = CutBound {
            held_before: Some(held_before),
            ..CutBound::default()
        };
        self.layer(by)?.revocation_cut(key, &bound).map_err(|e| {
            anyhow::anyhow!(
                "{} cannot vouch for a cut of {key}: {e} (next step: {:?})",
                by.name(),
                e.next()
            )
        })
    }

    /// `by`, holding its namespace's authority, signs the next trust-context version revoking
    /// each key with its cut, keeps the cuts' manifest packets with that version, and its node
    /// adopts it (keeping and serving the manifests from then on).
    async fn sign_revocations(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        revoked: Vec<(Name, CutProposal)>,
    ) -> anyhow::Result<()> {
        let (root, held) = self.authority(&by.person)?;
        let (keys, proposals): (Vec<Name>, Vec<CutProposal>) = revoked.into_iter().unzip();
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

    /// `by`, holding its namespace's authority, re-admits exactly the packet `full`, which `key`
    /// signed, and its node adopts the new version.
    async fn readmit_full(
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
}

/// What a device's host configures its data layer with.
struct Host {
    /// The namespaces it holds collections of for their owners.
    hold_for: Vec<Name>,
    /// The merge rules its program knows beyond the standard ones.
    program: Program,
}

/// How `device`'s host configures its layer: a holder keeps the collections of its own person's
/// namespace; the program registers the merge rules the case gave it.
fn host(device: &DeviceSpec) -> Host {
    Host {
        hold_for: if device.holds {
            vec![device.person.clone()]
        } else {
            Vec::new()
        },
        program: device.program,
    }
}

/// What a device's host does for introductions (`Config::introducer`): it gives its
/// namespace's signed trust context as its anchor, and adopts another person's anchor link into
/// its node's validator through its node's engine, as the daemon does
/// (`ndn_identity::adopt_anchor_link_via_engine`): an inline context checked against the link's
/// expected fingerprint, a self-certifying namespace not held adopted by name (its inline version
/// 1 only compared with the fetched one) — after which its node carries that person's sync group
/// and routes it over its link to the hub, as a daemon's link library does on the trust event.
struct Introduce {
    /// The newest signed version of its namespace's trust context when the layer started.
    anchor: bytes::Bytes,
    /// Its node's validator.
    validator: Arc<Validator>,
    /// Its node's engine, the network an adoption fetches over.
    engine: ndn_app::ForwarderEngine,
    /// Carry and route a newly adopted person's sync group.
    route: Box<dyn Fn(&Name) + Send + Sync>,
    /// The namespaces adopted for the layer alone that its engine carries in transit, once
    /// each, until the layer releases them.
    carried: std::sync::Mutex<std::collections::HashSet<Name>>,
}

impl Introducer for Introduce {
    fn anchor(&self) -> Option<bytes::Bytes> {
        Some(self.anchor.clone())
    }

    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> Adopting<'a> {
        Box::pin(async move {
            let TrustEnvelope::Anchor {
                namespace: Some(ns),
                fingerprint: Some(fingerprint),
                ..
            } = link
            else {
                return Err("not an anchor link naming its namespace and fingerprint".into());
            };
            let ns: Name = ns
                .parse()
                .map_err(|_| format!("the anchor link names {ns}, which is no name"))?;
            let keyring = self.validator.keyring();
            match keyring
                .contexts()
                .into_iter()
                .find(|c| *c.namespace() == ns)
            {
                Some(held)
                    if held
                        .anchors()
                        .iter()
                        .any(|a| anchor_fingerprint(a.value()) == *fingerprint) =>
                {
                    Ok(())
                }
                Some(_) => Err(format!(
                    "this node trusts {ns} under another anchor than the link's"
                )),
                None => {
                    let link = AnchorLink::from_envelope(link).map_err(|e| e.to_string())?;
                    ndn_identity::adopt_anchor_link_via_engine(&self.engine, keyring, &link)
                        .await
                        .map_err(|e| e.to_string())?;
                    (self.route)(&ns);
                    Ok(())
                }
            }
        })
    }

    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ScopedContext>,
    ) -> Scoping<'a> {
        Box::pin(async move {
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
        })
    }

    fn release_scoped(&self, namespace: &Name) {
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

/// The merge rules a device running `program` registers.
fn rules(program: Program) -> MergeRules {
    let standard = MergeRules::standard();
    match program {
        Program::Standard => standard,
        Program::Element => standard.with(Arc::new(Element::new())),
        Program::LaxElement => standard.with(Arc::new(Element::lax())),
    }
}

/// Each device's one key: `<device>/KEY/1`.
fn device_key(device: &Name) -> Name {
    device.clone().append("KEY").append("1")
}

/// The device whose key is `key` (`<device>/KEY/1`).
fn key_device(key: &Name) -> anyhow::Result<Name> {
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
fn decode_data(wire: &bytes::Bytes) -> anyhow::Result<Data> {
    Data::decode(wire.clone()).map_err(|e| anyhow::anyhow!("an undecodable packet: {e:?}"))
}

/// Randomness that replays: SHA-256 over the device's name and a counter, block after block, so
/// an audit samples the same pieces with the same nonces every run (`--check-determinism`). A
/// layer started again on its node (its `run` past the first) seeds with the run too, so it
/// does not draw its first run's numbers again.
fn seeded(device: &Name, run: u64) -> Entropy {
    let seed = match run {
        1 => device.to_string(),
        n => format!("{device}#{n}"),
    };
    let counter = AtomicU64::new(0);
    Arc::new(move |buf: &mut [u8]| {
        for block in buf.chunks_mut(32) {
            let n = counter.fetch_add(1, Ordering::Relaxed);
            let mut h = Sha256::new();
            h.update(seed.as_bytes());
            h.update(n.to_be_bytes());
            let digest: [u8; 32] = h.finalize().into();
            block.copy_from_slice(&digest[..block.len()]);
        }
    })
}

/// The stored pieces of `prefix` among `stored` (in name order): of a version's name (a log
/// entry name), that entry and its chunks and manifest nodes; of a collection, every log entry
/// of any writer about it and their chunks and manifest nodes.
fn pieces_of<'s>(
    stored: &'s [(Name, bytes::Bytes)],
    prefix: &'s Name,
) -> impl Iterator<Item = &'s (Name, bytes::Bytes)> {
    let version = parse_log_name(prefix).is_some();
    stored.iter().filter(move |(name, _)| {
        if version {
            name == prefix || parse_piece_name(name).is_some_and(|p| p.version == *prefix)
        } else {
            parse_log_name(name).is_some_and(|l| l.subject.as_ref() == Some(prefix))
                || parse_piece_name(name).is_some_and(|p| p.log.subject.as_ref() == Some(prefix))
        }
    })
}

#[async_trait::async_trait]
impl Provider for Reference {
    fn name(&self) -> &str {
        "ndn-data"
    }

    fn supports(&self, feature: Feature) -> bool {
        matches!(
            feature,
            Feature::Merge
                | Feature::WritersAcrossPrefixes
                | Feature::Snapshot
                | Feature::RemovalCut
                | Feature::CutRecheck
                | Feature::Seal
                | Feature::Log
                | Feature::PruneScope
                | Feature::Custody
                | Feature::Prune
                | Feature::LargePayloads
                | Feature::Blocks
                | Feature::OneKey
                | Feature::Expiry
                | Feature::RangeReads
                | Feature::Revocation
                | Feature::Readmit
                | Feature::RevocationRecheck
                | Feature::KeyLifetime
                | Feature::Recovery
                | Feature::BoundedCut
                | Feature::CutManifest
                | Feature::UnboundCut
                | Feature::GuestExpiry
                | Feature::IssuerRecheck
                | Feature::RuleByName
                | Feature::AppOps
                | Feature::MergePieces
                | Feature::Groups
                | Feature::FolderMembers
                | Feature::FolderWatch
                | Feature::Introduction
                | Feature::SelfCertifying
                | Feature::Signals
        )
    }

    async fn prepare(
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
        // `ndn-fwd init`, it lists the guest role among those whose data needs a cut once their
        // certificate lapsed.
        let mut contexts: Vec<Arc<SignedTrustContext>> = Vec::with_capacity(anchors.len());
        for (person, (root, anchor)) in &anchors {
            let genesis = geneses.get(person);
            let ctx = SignedTrustContext::hierarchical(person.clone())
                .with_version(if genesis.is_some() { 2 } else { 1 })
                .with_data_requires_cut("guest");
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

    async fn attach(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn DataLayer>> {
        let keys = self
            .case
            .lock()
            .expect("the provider's lock")
            .keys
            .get(&device.name())
            .cloned()
            .with_context(|| format!("{} was not prepared", device.name()))?;
        self.start(
            fabric,
            device.node,
            device.name(),
            keys,
            host(device),
            Arc::new(MemoryStore::new()),
        )
        .await
    }

    async fn suspect(
        &self,
        _fabric: &Fabric,
        by: &DeviceSpec,
        device: &DeviceSpec,
        since: Timestamp,
    ) -> anyhow::Result<()> {
        let key = device_key(&device.name());
        self.layer(by)?.suspect(&key, since).map_err(|e| {
            anyhow::anyhow!(
                "{} cannot suspect {key}: {e} (next step: {:?})",
                by.name(),
                e.next()
            )
        })
    }

    async fn revoke(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        device: &DeviceSpec,
        lost: Timestamp,
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
        // The cut is what the root device first verified of the key before the loss, never what
        // it heard listed nor what it took after.
        let proposal = self.cut_of(by, &key, lost)?;
        let left_out = proposal.left_out.clone();
        self.sign_revocations(fabric, by, vec![(key, proposal)])
            .await?;
        Ok(left_out)
    }

    async fn spread(&self, fabric: &Fabric, node: NodeId) -> anyhow::Result<()> {
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

    async fn readmit(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        from: &DeviceSpec,
        collection: &Name,
        id: &VersionId,
    ) -> anyhow::Result<()> {
        let key = id.writer.key().clone();
        let log = log_name(&key_device(&key)?, Some(collection), id.seq.0);
        // Exactly the packet `from` holds refused: its name and implicit digest, as the host
        // shows the owner.
        let full = self
            .layer(from)?
            .refused_by_revocation(&key)
            .into_iter()
            .find(|n| n.len() == log.len() + 1 && n.has_prefix(&log))
            .with_context(|| {
                format!(
                    "{} holds no version {log} refused by the revocation of {key}; re-admission \
                     names the exact packet a device holds refused",
                    from.name()
                )
            })?;
        self.readmit_full(fabric, by, &key, &full).await
    }

    async fn readmit_name(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        full: &Name,
    ) -> anyhow::Result<()> {
        let entry = Name::from_components(
            full.components()[..full.len().saturating_sub(1)]
                .iter()
                .cloned(),
        );
        let log = parse_log_name(&entry).with_context(|| {
            format!(
                "{full} names no log entry (<device>/32=log/…/seq=<n>/<digest>); a re-admission \
                 names one entry of a revoked key exactly"
            )
        })?;
        self.readmit_full(fabric, by, &device_key(&log.device), full)
            .await
    }

    async fn steal(
        &self,
        fabric: &Fabric,
        victim: &DeviceSpec,
        thief: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn DataLayer>> {
        let (keys, copy) = {
            let case = self.case.lock().expect("the provider's lock");
            anyhow::ensure!(
                !case.devices.contains_key(&thief.node),
                "{}'s node runs a data layer already; a thief steals once",
                thief.name()
            );
            let keys = case
                .keys
                .get(&victim.name())
                .cloned()
                .with_context(|| format!("{} was not prepared", victim.name()))?;
            let stored = case
                .devices
                .get(&victim.node)
                .with_context(|| format!("{} has no data layer attached", victim.name()))?
                .store
                .scan_under(&Name::root(), 0);
            let copy = MemoryStore::new();
            for (name, wire) in stored {
                copy.insert(name, wire);
            }
            (keys, Arc::new(copy))
        };
        // The thief runs the stolen device's program; it holds nothing for others.
        let thief_host = Host {
            hold_for: Vec::new(),
            program: victim.program,
        };
        self.start(fabric, thief.node, victim.name(), keys, thief_host, copy)
            .await
    }

    async fn renew(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<()> {
        let (root, _) = self.authority(&device.person)?;
        self.certify(fabric, &device.name(), root).await
    }

    async fn expire(
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
            let now = Timestamp(fabric.clock().now_ns() / 1_000_000);
            case.lapsed.insert(name, now);
        }
        Ok(())
    }

    async fn end_keys(&self, fabric: &Fabric, by: &DeviceSpec) -> anyhow::Result<Vec<Name>> {
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
            let held_before = Timestamp(at.0.saturating_add_signed(skew));
            let proposal = self.cut_of(by, &e.key, held_before)?;
            revoked.push((e.key, proposal));
        }
        let keys = revoked.iter().map(|(k, _)| k.clone()).collect();
        self.sign_revocations(fabric, by, revoked).await?;
        Ok(keys)
    }

    async fn stop(&self, _fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<()> {
        let mut case = self.case.lock().expect("the provider's lock");
        // The device's signals end with it: a restart starts them again over the restarted
        // device, as a host's process restarting does.
        if let Some((signals, _)) = case.signals.remove(&device.node) {
            signals.shutdown();
        }
        let attached = case
            .devices
            .get(&device.node)
            .with_context(|| format!("{} has no data layer attached", device.name()))?;
        attached.layer.shutdown();
        attached.cancel.cancel();
        Ok(())
    }

    async fn restart(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn DataLayer>> {
        let (keys, store) = {
            let case = self.case.lock().expect("the provider's lock");
            let attached = case
                .devices
                .get(&device.node)
                .with_context(|| format!("{} has no data layer attached", device.name()))?;
            anyhow::ensure!(
                attached.cancel.is_cancelled(),
                "{}'s data layer runs; stop it before starting it again",
                device.name()
            );
            let keys = case
                .keys
                .get(&device.name())
                .cloned()
                .with_context(|| format!("{} was not prepared", device.name()))?;
            (keys, Arc::clone(&attached.store))
        };
        self.start(
            fabric,
            device.node,
            device.name(),
            keys,
            host(device),
            store,
        )
        .await
    }

    async fn recovery_kit(&self, fabric: &Fabric, by: &DeviceSpec) -> anyhow::Result<()> {
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

    async fn recover(&self, fabric: &Fabric, by: &DeviceSpec) -> anyhow::Result<()> {
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

    fn tally(&self) -> Tally {
        let case = self.case.lock().expect("the provider's lock");
        Tally {
            signatures: case.devices.values().map(|a| a.layer.signatures()).sum(),
            copies: case.devices.values().map(|a| a.layer.held()).sum(),
        }
    }

    fn signed_by(&self, device: &DeviceSpec) -> u64 {
        let case = self.case.lock().expect("the provider's lock");
        case.devices
            .get(&device.node)
            .map_or(0, |a| a.layer.signatures())
    }

    fn grants(&self, device: &DeviceSpec) -> Grants {
        let case = self.case.lock().expect("the provider's lock");
        case.devices
            .get(&device.node)
            .map_or(Grants::default(), |a| Grants {
                asked: a.layer.grants_asked(),
                answered: a.layer.grants_answered(),
            })
    }

    async fn release(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        name: &Name,
    ) -> anyhow::Result<u64> {
        let layer = self
            .case
            .lock()
            .expect("the provider's lock")
            .devices
            .get(&device.node)
            .map(|a| a.layer.clone())
            .with_context(|| format!("{} has no data layer attached", device.name()))?;
        match layer.release(name).await {
            Ok(released) => Ok(u64::from(released.pieces)),
            Err(e) => {
                let next = e.next();
                Err(anyhow::Error::new(e).context(format!(
                    "{} refused to release {name} (next step: {next:?})",
                    device.name()
                )))
            }
        }
    }

    fn lose(&self, device: &DeviceSpec, collection: &Name, every: u32) -> u64 {
        let store = self.store(device);
        let stored = store.scan_under(&Name::root(), 0);
        let every = every.max(1) as usize;
        let mut lost = 0;
        for (i, (name, _)) in pieces_of(&stored, collection).enumerate() {
            if (i + 1) % every == 0 {
                store.remove(name);
                lost += 1;
            }
        }
        lost
    }

    fn pieces_stored(&self, device: &DeviceSpec, version: &Name) -> u64 {
        let stored = self.store(device).scan_under(&Name::root(), 0);
        stored
            .iter()
            .filter(|(name, _)| parse_piece_name(name).is_some_and(|p| p.version == *version))
            .count() as u64
    }

    fn stored(&self, device: &DeviceSpec, prefix: &Name) -> u64 {
        let stored = self.store(device).scan_under(&Name::root(), 0);
        pieces_of(&stored, prefix)
            .map(|(_, wire)| wire.len() as u64)
            .sum()
    }

    fn tamper(&self, device: &DeviceSpec, version: &Name, how: Tamper) -> anyhow::Result<()> {
        let store = self.store(device);
        let block = |name: &Name| -> anyhow::Result<(Data, VersionBody)> {
            let wire = store
                .get(name)
                .with_context(|| format!("{} stores no packet {name}", device.name()))?;
            let data = Data::decode(wire).map_err(|e| anyhow::anyhow!("{name}: {e:?}"))?;
            let content = data.content().cloned().unwrap_or_default();
            let Record::Version(body) = decode_record(content)? else {
                anyhow::bail!("{name} is no version");
            };
            anyhow::ensure!(
                body.sealed.is_none(),
                "{name} is sealed: its entries are inside the ciphertext, which a holder cannot \
                 alter entry by entry"
            );
            anyhow::ensure!(body.block.is_some(), "{name} is no block");
            Ok((data, body))
        };
        let (data, mut body) = block(version)?;
        let entries = body.block.as_mut().expect("checked a block");
        let (Tamper::Forge { entry } | Tamper::Splice { entry, .. }) = how;
        let len = entries.len();
        anyhow::ensure!(
            (entry as usize) < len,
            "{version} has {len} entries, none at {entry}"
        );
        let e = &mut entries[entry as usize];
        match how {
            Tamper::Forge { .. } => {
                let (field, value) = e
                    .fields
                    .fields()
                    .next()
                    .map(|(f, v)| (f.to_owned(), v.clone()))
                    .with_context(|| format!("entry {entry} of {version} has no field"))?;
                let mut forged = value.to_vec();
                forged.extend_from_slice(b"-forged");
                e.fields = std::mem::take(&mut e.fields).with(field, forged);
            }
            Tamper::Splice { from, their, .. } => {
                let (_, other) = block(&from)?;
                let other = other.block.expect("checked a block");
                e.fields = other
                    .get(their as usize)
                    .with_context(|| {
                        format!("{from} has {} entries, none at {their}", other.len())
                    })?
                    .fields
                    .clone();
            }
        }
        let content = encode_record(&Record::Version(body));
        // The same name, freshness and signature info, and the original signature bytes over
        // content its writer never signed.
        let sig = data
            .sig_info()
            .with_context(|| format!("{version} carries no signature info"))?;
        let key = sig.key_locator_name();
        let mut builder = DataBuilder::new((*data.name).clone(), &content);
        if let Some(f) = data.meta_info().and_then(|m| m.freshness_period) {
            builder = builder.freshness(f);
        }
        let value = bytes::Bytes::copy_from_slice(data.sig_value());
        let forged = builder.sign_sync(sig.sig_type, key.as_deref(), |_| value);
        store.insert(version.clone(), forged);
        Ok(())
    }

    fn sign_unbound(&self, device: &DeviceSpec, subject: &Name) -> anyhow::Result<Name> {
        let name = device.name();
        let (keys, store) = {
            let case = self.case.lock().expect("the provider's lock");
            let attached = case
                .devices
                .get(&device.node)
                .with_context(|| format!("{name} has no data layer attached"))?;
            anyhow::ensure!(
                attached.cancel.is_cancelled(),
                "{name}'s data layer runs; stop it before an older build's store is made"
            );
            let keys = case
                .keys
                .get(&name)
                .cloned()
                .with_context(|| format!("{name} was not prepared"))?;
            (keys, Arc::clone(&attached.store))
        };
        // Its newest members record of `subject`, in its own log.
        let log = log_name(&name, Some(subject), 0);
        let log = Name::from_components(log.components()[..log.len() - 1].iter().cloned());
        let (record, data, mut body) = store
            .scan_under(&log, 0)
            .into_iter()
            .filter(|(n, _)| n.len() == log.len() + 1)
            .filter_map(|(n, wire)| {
                let data = Data::decode(wire).ok()?;
                match decode_record(data.content()?.clone()).ok()? {
                    Record::Members(body) => Some((n, data, body)),
                    _ => None,
                }
            })
            .max_by_key(|(n, ..)| parse_log_name(n).map(|l| l.seq))
            .with_context(|| format!("{name} stores no members record of {subject}"))?;
        // The same cuts, keeping the same seqs, bound to no bytes.
        for cut in &mut body.cuts {
            let mut unbound = ndn_data::collection::Accepted::new();
            for (c, w, runs) in cut.accept.iter() {
                for &(lo, hi) in runs {
                    for seq in lo..=hi {
                        unbound.insert(
                            c,
                            &VersionId {
                                writer: w.clone(),
                                seq: ndn_data::Seq(seq),
                            },
                        );
                    }
                }
            }
            cut.accept = unbound;
        }
        let content = encode_record(&Record::Members(body));
        let identity = keys.signing_identity_for(&name)?;
        let signer = &identity.signer;
        let mut builder = DataBuilder::new(record.clone(), &content);
        if let Some(f) = data.meta_info().and_then(|m| m.freshness_period) {
            builder = builder.freshness(f);
        }
        let wire = builder.sign_sync(signer.sig_type(), Some(&identity.key), |region| {
            signer.sign_sync(region).unwrap_or_default()
        });
        // An older build stored no cut manifest, and recorded the digest of what it signed
        // (ndn-data's store: `/localhost/ndn-data/written/<entry>`, the entry's implicit digest),
        // so the restarted layer takes the entry as its own.
        for (n, _) in store.scan_under(&record, 0) {
            if n != record {
                store.remove(&n);
            }
        }
        let written: Name = "/localhost/ndn-data/written".parse().expect("a valid name");
        let written = Name::from_components(
            written
                .components()
                .iter()
                .chain(record.components())
                .cloned(),
        );
        store.insert(
            written,
            bytes::Bytes::copy_from_slice(&Sha256::digest(&wire)),
        );
        store.insert(record.clone(), wire);
        Ok(record)
    }

    async fn relay_audits(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<()> {
        let name = device.name();
        let keys = self
            .case
            .lock()
            .expect("the provider's lock")
            .keys
            .get(&name)
            .cloned()
            .with_context(|| format!("{name} was not prepared"))?;
        let identity = keys.signing_identity_for(&name)?;
        let engine = fabric
            .engine_of(device.node)
            .with_context(|| format!("no engine on node {}", device.node))?;
        let node = engine.app_node(CancellationToken::new());
        // `<device>/32=audit`: longer than the device's own prefix, so every audit ask reaches
        // the relay, not the data layer.
        let any = audit_ask_name(
            &name,
            &AuditAsk {
                nonce: [0; NONCE_LEN],
                piece: name.clone(),
                whole: false,
                asker: bytes::Bytes::new(),
            },
        );
        let prefix = Name::from_components(any.components()[..any.len() - 1].iter().cloned());
        let fetcher = node.connection();
        let guard = node
            .serve(prefix, move |interest, responder| {
                let (fetcher, identity) = (fetcher.clone(), identity.clone());
                async move {
                    let Some((_, ask)) = parse_audit_ask_name(&interest.name) else {
                        return;
                    };
                    // Every packet asked is fetched fresh: from a device that serves it, past
                    // every cache.
                    let fresh = |name: Name| {
                        let fetcher = fetcher.clone();
                        async move {
                            let b = InterestBuilder::new(name)
                                .must_be_fresh()
                                .lifetime(std::time::Duration::from_secs(2));
                            Consumer::new(fetcher).fetch_with(b).await.ok()
                        }
                    };
                    let answer = if ask.whole {
                        // A proof over every piece: the log entry, then each piece it lists.
                        let Some(entry) = fresh(ask.piece.clone()).await else {
                            return;
                        };
                        let chunks = entry
                            .content()
                            .and_then(|c| decode_record(c.clone()).ok())
                            .and_then(|r| match r {
                                Record::Version(v) => v.chunks,
                                _ => None,
                            });
                        let Some(chunks) = chunks else { return };
                        let mut wires = vec![entry.raw().clone()];
                        for p in piece_names(&ask.piece, &chunks) {
                            let Some(d) = fresh(p).await else { return };
                            wires.push(d.raw().clone());
                        }
                        AuditAnswer::Proof(version_proof(
                            &ask.nonce,
                            wires.iter().map(|w| w.as_ref()),
                        ))
                    } else {
                        let Some(piece) = fresh(ask.piece.clone()).await else {
                            return;
                        };
                        AuditAnswer::Piece(piece.raw().clone())
                    };
                    let answer = encode_audit_answer(&answer);
                    let signer = &identity.signer;
                    let wire = DataBuilder::new((*interest.name).clone(), &answer)
                        .freshness(std::time::Duration::ZERO)
                        .sign_sync(signer.sig_type(), Some(&identity.key), |region| {
                            signer.sign_sync(region).unwrap_or_default()
                        });
                    let _ = responder.respond_bytes(wire).await;
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

    async fn replay(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        prefix: &Name,
    ) -> anyhow::Result<()> {
        let engine = fabric
            .engine_of(device.node)
            .with_context(|| format!("no engine on node {}", device.node))?;
        let node = engine.app_node(CancellationToken::new());
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
        // Served on the device's own node under `prefix`: the hub forwards every Interest to
        // every device, and this node's longest match for `prefix` is the replayer, not the
        // device's data layer. Every Interest under it gets the same packet, however stale.
        let guard = node
            .serve(prefix.clone(), move |_interest, responder| {
                let packet = packet.clone();
                async move {
                    let _ = responder.respond_bytes(packet).await;
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

    async fn offer(
        &self,
        _fabric: &Fabric,
        by: &DeviceSpec,
        folder: &Name,
        offer: Offer,
    ) -> anyhow::Result<Code> {
        self.layer(by)?
            .offer(folder, offer)
            .await
            .map_err(anyhow::Error::new)
    }

    async fn join(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        code: &str,
    ) -> anyhow::Result<Joined> {
        self.layer(device)?
            .join(code)
            .await
            .map_err(anyhow::Error::new)
    }

    async fn adopt(&self, fabric: &Fabric, device: &DeviceSpec, link: &str) -> anyhow::Result<()> {
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
        let hub = *self
            .case
            .lock()
            .expect("the provider's lock")
            .nodes
            .first()
            .context("prepare lists the hub first")?;
        let to_hub = fabric
            .face_between(device.node, hub)
            .with_context(|| format!("node {} has no link to the hub", device.node))?;
        ndn_namespace::sync_group::carry(&engine, &link.namespace);
        EngineFaces(engine).add_routes(
            to_hub,
            &ndn_link::group_routes(std::iter::once(&link.namespace), 0),
        );
        Ok(())
    }

    async fn forwarder_verdict(
        &self,
        fabric: &Fabric,
        at: &DeviceSpec,
        from: &DeviceSpec,
        name: &Name,
    ) -> anyhow::Result<Result<(), String>> {
        let wire = self
            .store(from)
            .get(name)
            .with_context(|| format!("{} stores no packet {name}", from.name()))?;
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

    /// A host's signals: their own app face on the device's node, gated by the device's data
    /// layer, dating by the node's (possibly lying) clock. `Signals::start` registers the device's
    /// namespace group on that face, which on an in-process engine installs the route to it (an
    /// `EngineConnection`), as the data layer's sync face is routed. Every device of a case is its
    /// own host, yet the sim runs them all in one process, where one device's ring would be
    /// another's local ring: rings are off, so every signal crosses the simulated links.
    async fn signals(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<Signals> {
        if let Some((signals, _)) = self
            .case
            .lock()
            .expect("the provider's lock")
            .signals
            .get(&device.node)
        {
            return Ok(signals.clone());
        }
        let layer = self.layer(device)?;
        let engine = fabric
            .engine_of(device.node)
            .with_context(|| format!("no engine on node {}", device.node))?;
        let conn = engine.app_face(CancellationToken::new());
        let clock = fabric.node_clock(device.node)?;
        // The sim's hub is a plain forwarder on the fabric, with no ndn-link serving quota
        // (ndn-link §15.3) for the default push budget to keep a device under; e10's four
        // members push 64 packets/s into four groups, 256 push Interests/s each.
        let options = SignalOptions {
            local_ring: false,
            clock: Some(Arc::new(move || clock.now_ns() / 1_000)),
            push_rate: std::num::NonZeroU32::new(10_000).expect("not 0"),
            push_burst: std::num::NonZeroU32::new(20_000).expect("not 0"),
            ..SignalOptions::default()
        };
        let signals = Signals::start(layer, Arc::clone(&conn), options)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "{}'s signals did not start: {e} (next step: {:?})",
                    device.name(),
                    e.next()
                )
            })?;
        self.case
            .lock()
            .expect("the provider's lock")
            .signals
            .insert(device.node, (signals.clone(), conn));
        Ok(signals)
    }

    async fn listen(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        group: &Name,
    ) -> anyhow::Result<()> {
        let conn = self
            .case
            .lock()
            .expect("the provider's lock")
            .signals
            .get(&device.node)
            .map(|(_, conn)| Arc::clone(conn))
            .with_context(|| format!("{} runs no signals", device.name()))?;
        conn.register_prefix(group)
            .await
            .map_err(|e| anyhow::anyhow!("{group} not routed to {}: {e}", device.name()))
    }

    fn gate(&self, device: &DeviceSpec) -> anyhow::Result<Device> {
        self.layer(device)
    }

    fn signer(&self, device: &DeviceSpec) -> anyhow::Result<Arc<dyn Signer>> {
        let keys = self
            .case
            .lock()
            .expect("the provider's lock")
            .keys
            .get(&device.name())
            .cloned()
            .with_context(|| format!("{} was not prepared", device.name()))?;
        Ok(keys.get_signer_sync(&device_key(&device.name()))?)
    }

    fn stored_names(&self, device: &DeviceSpec) -> anyhow::Result<Vec<Name>> {
        Ok(self
            .store(device)
            .scan_under(&Name::root(), 0)
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }
}
