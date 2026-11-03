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
//! node's validator, keeps entries in memory and dates them by the node's own (possibly lying)
//! clock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use ndn_app::EngineAppExt;
use ndn_data::{Config, DataLayer, Device, Name, Timestamp, Transport};
use ndn_link::{EngineFaces, FaceSink};
use ndn_security::{Certificate, SecurityManager, SignedTrustContext};
use ndn_sim::{Fabric, NodeId};
use ndn_sync::{MemoryStore, SvsConfig};
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
    /// Every data layer attached, for the counters.
    devices: Vec<Device>,
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
            ..Config::new()
        };
        let layer = Device::start(
            transport,
            device.clone(),
            keys,
            validator,
            Arc::new(MemoryStore::new()),
            config,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{device}: {e}"))?;
        self.case
            .lock()
            .expect("the provider's lock")
            .devices
            .push(layer.clone());
        Ok(Arc::new(layer))
    }
}

#[async_trait::async_trait]
impl Provider for Reference {
    fn name(&self) -> &str {
        "ndn-data"
    }

    fn supports(&self, feature: Feature) -> bool {
        matches!(
            feature,
            Feature::Merge | Feature::WritersAcrossPrefixes | Feature::Snapshot
        )
    }

    async fn prepare(
        &self,
        fabric: &Fabric,
        hub: NodeId,
        devices: &[DeviceSpec],
    ) -> anyhow::Result<()> {
        let mut anchors: HashMap<Name, (Arc<SecurityManager>, Name, Certificate)> = HashMap::new();
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
        self.start(fabric, device.node, device.name(), keys).await
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
        self.start(fabric, thief.node, victim.name(), keys).await
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
            signatures: case.devices.iter().map(Device::signatures).sum(),
            copies: case.devices.iter().map(Device::held).sum(),
        }
    }
}
