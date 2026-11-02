//! The reference provider: `ndn-data`'s own [`Device`] on every device of a case.
//!
//! Every person gets a namespace key (`/<person>/KEY/…`, self-signed) that certifies each of
//! their devices' keys (`/<person>/<device>/KEY/…`). Every forwarder — the hub and each device —
//! holds every person's namespace key as a trust anchor and every device certificate in its cache,
//! so its fail-closed validator admits exactly the case's people. Nothing is set up for a
//! person's sync group (`/<person>/32=sync`): each device's forwarder carries it by its own rule
//! (spec §12) over the default route the topology gives it toward the hub, which stands in for
//! the network between devices. Each device's data layer runs on its own node over two
//! in-process app faces (fetch/serve, and sync), verifies with that node's validator, keeps
//! entries in memory and dates them by the node's own (possibly lying) clock.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use ndn_app::EngineAppExt;
use ndn_data::{Config, DataLayer, Device, Name, Timestamp, Transport};
use ndn_security::{Certificate, SecurityManager};
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
        let nodes = std::iter::once(hub).chain(devices.iter().map(|d| d.node));
        for node in nodes {
            let validator = fabric
                .engine_of(node)
                .and_then(|e| e.validator())
                .with_context(|| format!("node {node} has no validator to hold the anchors"))?;
            for (_, _, anchor) in anchors.values() {
                validator.add_trust_anchor(anchor.clone());
            }
            for cert in &certs {
                validator.cert_cache().insert(cert.clone());
            }
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
