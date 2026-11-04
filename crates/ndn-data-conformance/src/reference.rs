//! The reference provider: `ndn-data`'s own [`Device`] on every device of a case.
//!
//! Every person is a namespace (`/alice`, or `/home/bob` of several components) with a key
//! (`<person>/KEY/…`, self-signed) that certifies each of their devices' keys
//! (`<person>/<device>/KEY/…`). Every forwarder — the hub and each device — holds every person's
//! trust context (namespace `<person>`, the hierarchical schema, the person's key its anchor) and
//! every device certificate in its cache, so its fail-closed validator admits exactly the case's
//! people, and a device's data layer takes its namespace from the context governing its name. A
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
//! The person's key signs their trust context as version 1, and acts as the namespace's root
//! device from then on: a revocation (with the cut the revoking device's data layer holds
//! verified), a re-admission, a recovery kit and a recovery after the root's compromise are the
//! next versions, signed with `ndn-cert`'s functions as the root flow signs them. A node takes
//! them one at a time as context sync brings them, each checked against the version it holds
//! (signed by one of its anchors, newer). A renewed or expired certificate is handed to every
//! node's cache in place of the copy it held; the validators judge validity by the host's clock.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use ndn_app::{Consumer, EngineAppExt, Node, ServeGuard};
use ndn_cert::{OldRoot, RecoveryPlan, RecoverySeed};
use ndn_data::wire::{
    AuditAnswer, AuditAsk, NONCE_LEN, Record, VersionBody, audit_ask_name, decode_record,
    encode_audit_answer, encode_record, log_name, parse_audit_ask_name, parse_log_name,
    parse_piece_name, piece_names, version_proof,
};
use ndn_data::{Config, DataLayer, Device, Entropy, Name, Timestamp, Transport, VersionId};
use ndn_link::{EngineFaces, FaceSink};
use ndn_packet::Data;
use ndn_packet::encode::{DataBuilder, InterestBuilder};
use ndn_security::cert_name::{DEFAULT_ISSUER, new_cert_name};
use ndn_security::{Certificate, SecurityManager, SignedTrustContext, Signer, encode_cert_data};
use ndn_sim::{Fabric, NodeId};
use ndn_sync::{DataStore, MemoryStore, SvsConfig};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::feature::Feature;
use crate::provider::{Certs, DeviceSpec, Provider, Tally, Tamper};

/// Certificates live far longer than any case (they are checked against the host's real clock).
const VALIDITY_MS: u64 = 10 * 365 * 24 * 3600 * 1000;
/// A day in nanoseconds, the unit of certificate validity periods.
const DAY_NS: u64 = 24 * 3600 * 1_000_000_000;

/// One case's keys and devices.
#[derive(Default)]
struct Case {
    /// Each device's key store, by device name.
    keys: HashMap<Name, Arc<SecurityManager>>,
    /// Every certificate issued for each device's key, oldest first, by device name.
    certs: HashMap<Name, Vec<Issued>>,
    /// Each person's namespace: its authority and the trust-context versions it signed.
    namespaces: BTreeMap<Name, Namespace>,
    /// Every forwarder: the hub, then each device's.
    nodes: Vec<NodeId>,
    /// Every data layer attached, with its store, by node (a thief's layer carries its victim's
    /// name, so names do not tell them apart).
    devices: BTreeMap<NodeId, Attached>,
    /// The audit relays and replaying caches injected ([`Provider::relay_audits`],
    /// [`Provider::replay`]), served while the case runs.
    relays: Vec<(Node, ServeGuard)>,
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
}

/// One attached data layer and the store it keeps its packets in.
struct Attached {
    layer: Device,
    store: Arc<MemoryStore>,
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
        hold_for: Vec<Name>,
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
        let clock = fabric.node_clock(node)?;
        let config = Config {
            clock: Arc::new(move || Timestamp(clock.now_ns() / 1_000_000)),
            svs: SvsConfig::default(),
            hold_for,
            entropy: seeded(&device),
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
                },
            );
        Ok(Arc::new(layer))
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
/// an audit samples the same pieces with the same nonces every run (`--check-determinism`).
fn seeded(device: &Name) -> Entropy {
    let seed = device.to_string();
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
        let mut case = Case::default();
        let now = host_now_ns();
        for spec in devices {
            if !anchors.contains_key(&spec.person) {
                let mgr = SecurityManager::new();
                let key = mgr.generate_ed25519(spec.person.clone().append("KEY").append("ns"))?;
                let signer = mgr.get_signer_sync(&key)?;
                let public = signer.public_key().context("an Ed25519 key")?;
                let cert = mgr.issue_self_signed(&key, public, VALIDITY_MS)?;
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
            let cert = issue(
                new_cert_name(&key, DEFAULT_ISSUER),
                &public,
                issuer.as_ref(),
                now,
                now.saturating_add(VALIDITY_MS * 1_000_000),
            )
            .await?;
            keys.cert_cache().insert(cert.clone());
            certs.push(cert.clone());
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
        // 1, the version later ones (revocations, a recovery) follow from.
        let mut contexts: Vec<Arc<SignedTrustContext>> = Vec::with_capacity(anchors.len());
        for (person, (root, anchor)) in &anchors {
            let ctx = SignedTrustContext::hierarchical(person.clone()).with_version(1);
            anyhow::ensure!(
                ctx.add_anchor(anchor.clone()),
                "{person}'s namespace key is not valid now"
            );
            let signed = ctx.sign_into_data(root.as_ref())?;
            case.namespaces.insert(
                person.clone(),
                Namespace {
                    root: Arc::clone(root),
                    kit: None,
                    versions: vec![signed.raw().clone()],
                },
            );
            contexts.push(Arc::new(ctx));
        }
        case.nodes = std::iter::once(hub)
            .chain(devices.iter().map(|d| d.node))
            .collect();
        for &node in &case.nodes {
            let validator = fabric
                .engine_of(node)
                .and_then(|e| e.validator())
                .with_context(|| format!("node {node} has no validator to hold the contexts"))?;
            for ctx in &contexts {
                anyhow::ensure!(
                    validator.adopt_context(Arc::clone(ctx)),
                    "node {node} refused {}'s trust context",
                    ctx.namespace()
                );
            }
            for cert in &certs {
                validator.cert_cache().insert(cert.clone());
            }
        }
        // Every device holds every person's namespace, and its link to the hub carries them all.
        for spec in devices {
            let engine = fabric
                .engine_of(spec.node)
                .with_context(|| format!("no engine on node {}", spec.node))?;
            let link = fabric
                .face_between(spec.node, hub)
                .with_context(|| format!("node {} has no link to the hub", spec.node))?;
            for person in anchors.keys() {
                ndn_namespace::sync_group::carry(&engine, person);
            }
            EngineFaces(engine).add_routes(link, &ndn_link::group_routes(anchors.keys(), 0));
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
        // A holder keeps the collections of its own person's namespace.
        let hold_for = if device.holds {
            vec![device.person.clone()]
        } else {
            Vec::new()
        };
        self.start(
            fabric,
            device.node,
            device.name(),
            keys,
            hold_for,
            Arc::new(MemoryStore::new()),
        )
        .await
    }

    async fn revoke(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        device: &DeviceSpec,
    ) -> anyhow::Result<()> {
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
        let (root, held) = self.authority(&by.person)?;
        // The cut is what the root device holds verified of the key, never what it heard listed.
        let cut = self.layer(by)?.revocation_cut(&key);
        let bump = ndn_cert::bump_context_revoking(
            root.as_ref(),
            &held,
            std::slice::from_ref(&key),
            Some(&cut),
        )
        .await?
        .with_context(|| format!("{key} is revoked already; nothing to sign"))?;
        self.publish(&by.person, [bump.data]);
        self.spread(fabric, by.node).await
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
                keyring
                    .adopt_update_from(&held, Arc::new(ctx))
                    .map_err(|now| {
                        anyhow::anyhow!(
                            "node {node} did not adopt version {} of {ns}'s trust context: it \
                             holds {now:?} meanwhile",
                            held.version() + 1
                        )
                    })?;
            }
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
        let (root, held) = self.authority(&by.person)?;
        let bump = ndn_cert::bump_context_readmitting(
            root.as_ref(),
            &held,
            &key,
            std::slice::from_ref(&full),
        )
        .await?
        .with_context(|| format!("{full} is re-admitted already; nothing to sign"))?;
        self.publish(&by.person, [bump.data]);
        self.spread(fabric, by.node).await
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
        self.start(fabric, thief.node, victim.name(), keys, Vec::new(), copy)
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
        Ok(())
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
            Err(e) => anyhow::bail!(
                "{} refused to release {name}: {e} (next step: {:?})",
                device.name(),
                e.next()
            ),
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
        // Fresh, past every cache: what a device serving `prefix` answers now.
        let ask = InterestBuilder::new(prefix.clone())
            .can_be_prefix()
            .must_be_fresh()
            .lifetime(std::time::Duration::from_secs(2));
        let packet = Consumer::new(node.connection())
            .fetch_with(ask)
            .await
            .with_context(|| format!("nothing answered {prefix} to replay"))?
            .raw()
            .clone();
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
}
