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

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use ndn_app::EngineAppExt;
use ndn_data::wire::{parse_log_name, parse_piece_name};
use ndn_data::{Config, DataLayer, Device, Entropy, Name, Timestamp, Transport};
use ndn_link::{EngineFaces, FaceSink};
use ndn_security::{Certificate, SecurityManager, SignedTrustContext};
use ndn_sim::{Fabric, NodeId};
use ndn_sync::{DataStore, MemoryStore, SvsConfig};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::feature::Feature;
use crate::provider::{DeviceSpec, Provider, Tally};

/// Certificates live far longer than any case (they are checked against the host's real clock).
const VALIDITY_MS: u64 = 10 * 365 * 24 * 3600 * 1000;

/// One case's keys and devices.
#[derive(Default)]
struct Case {
    /// Each device's key store, by device name.
    keys: HashMap<Name, Arc<SecurityManager>>,
    /// Every data layer attached, with its store, by node (a thief's layer carries its victim's
    /// name, so names do not tell them apart).
    devices: BTreeMap<NodeId, Attached>,
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
        let store = Arc::new(MemoryStore::new());
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
        let mut anchors: BTreeMap<Name, (Arc<SecurityManager>, Name, Certificate)> =
            BTreeMap::new();
        let mut certs = Vec::new();
        let mut case = Case::default();
        for spec in devices {
            if !anchors.contains_key(&spec.person) {
                let mgr = Arc::new(SecurityManager::new());
                let key = mgr.generate_ed25519(spec.person.clone().append("KEY").append("ns"))?;
                let public = mgr
                    .get_signer_sync(&key)?
                    .public_key()
                    .context("an Ed25519 key")?;
                let cert = mgr.issue_self_signed(&key, public, VALIDITY_MS)?;
                anchors.insert(spec.person.clone(), (mgr, key, cert));
            }
            let (authority, issuer, _) = &anchors[&spec.person];
            let device = spec.name();
            let keys = Arc::new(SecurityManager::new());
            let key = keys.generate_ed25519(device.clone().append("KEY").append("1"))?;
            let public = keys
                .get_signer_sync(&key)?
                .public_key()
                .context("an Ed25519 key")?;
            let cert = authority.certify(&key, public, issuer, VALIDITY_MS).await?;
            keys.cert_cache().insert(cert.clone());
            certs.push(cert);
            case.keys.insert(device, keys);
        }
        // Each person's namespace is a trust context (hierarchical schema, the person's key its
        // anchor) on every forwarder: the validator verifies a packet under the context whose
        // namespace is the longest prefix of its name, and a device's data layer takes its own
        // namespace from the context governing its name (spec §3).
        let contexts: Vec<Arc<SignedTrustContext>> = anchors
            .iter()
            .map(|(person, (_, _, anchor))| {
                let ctx = SignedTrustContext::hierarchical(person.clone());
                anyhow::ensure!(
                    ctx.add_anchor(anchor.clone()),
                    "{person}'s namespace key is not valid now"
                );
                Ok(Arc::new(ctx))
            })
            .collect::<anyhow::Result<_>>()?;
        let nodes = std::iter::once(hub).chain(devices.iter().map(|d| d.node));
        for node in nodes {
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
        self.start(fabric, device.node, device.name(), keys, hold_for)
            .await
    }

    async fn attach_stolen(
        &self,
        fabric: &Fabric,
        victim: &DeviceSpec,
        thief: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn DataLayer>> {
        let keys = self
            .case
            .lock()
            .expect("the provider's lock")
            .keys
            .get(&victim.name())
            .cloned()
            .with_context(|| format!("{} was not prepared", victim.name()))?;
        self.start(fabric, thief.node, victim.name(), keys, Vec::new())
            .await
    }

    async fn revoke(
        &self,
        _fabric: &Fabric,
        _by: &DeviceSpec,
        device: &DeviceSpec,
    ) -> anyhow::Result<()> {
        anyhow::bail!(
            "revoking {} is a cut in the trust context (data-layer slice 5), which this provider \
             does not implement",
            device.name()
        )
    }

    fn tally(&self) -> Tally {
        let case = self.case.lock().expect("the provider's lock");
        Tally {
            signatures: case.devices.values().map(|a| a.layer.signatures()).sum(),
            copies: case.devices.values().map(|a| a.layer.held()).sum(),
        }
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
}
