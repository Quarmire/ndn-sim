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
//! The person's key signs their trust context as version 1 (listing every device role — admin,
//! member, node and guest, devices `<person>/<role>/<who>` — among those whose data needs a cut
//! once their certificate lapsed, as `ndn-fwd init` does), and acts as the namespace's root device
//! from then on: a revocation (with the cut the
//! revoking device's data layer first verified before the loss the owner states, and the
//! manifest binding it to bytes), the end of a lapsed key (a revocation whose cut is
//! bounded at the lapse, signed unattended), a re-admission, a recovery kit and a recovery after
//! the root's compromise are the next versions, signed with `ndn-cert`'s functions as the root
//! flow signs them. A node takes them one at a time as context sync brings them, each checked
//! against the version it holds (signed by one of its anchors, newer), and from then on keeps
//! and serves the manifest packets of its cuts by full name, as a node keeping contexts does;
//! like a daemon's, every forwarder fetches what its validator lacks (a certificate, a
//! manifest packet) through its engine. A renewed or expired certificate is handed to every
//! node's cache in place of the copy it held; the validators judge validity by the host's
//! clock. A device's data layer can stop and start again on its store, re-judging what it
//! restores.
//!
//! A self-certifying person (`/user/<hash>`, [`DeviceSpec::genesis`]) has its genesis root as
//! its key, so version 1 is the genesis its name hashes. It is adopted by its name alone: each of
//! its devices serves what an adopter fetches, as a daemon does — its namespace's
//! trust-context versions by name (`ndn_namespace::publish`, each later version as its node
//! adopts it) and its own certificate (`OwnCertificates`) — and a host adopts an anchor link
//! ([`Provider::adopt`]) through its node's engine as the daemon does
//! (`ndn_identity::adopt_anchor_link_via_engine`), then carries and routes that person's sync
//! group as after an introduction.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use ndn_app::EngineAppExt;
use ndn_cert::AnchorLink;
use ndn_data::intro::{
    Adopting, Dialing, FirstDialing, HintCandidate, HintKind, LinkHint, Scoping, hint_prefix,
};
use ndn_data::wire::{
    Record, decode_record, encode_record, log_name, parse_log_name, parse_piece_name,
};
use ndn_data::{
    Config, CutBound, DataLayer, Departure, Device, Entropy, Grant, IntroPolicy, Introducer, Name,
    Timestamp, Transport, VersionId,
};
use ndn_packet::Data;
use ndn_packet::encode::DataBuilder;
use ndn_security::{
    ScopedContext, SecurityManager, Signer, Validator, anchor_fingerprint, public_key_digest,
};
use ndn_sim::{Fabric, NodeId};
use ndn_sync::{DataStore, MemoryStore, SvsConfig};
use ndn_trust_envelope::TrustEnvelope;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::feature::Feature;
use crate::host::{IntroduceCore, Listening, link_address};
use crate::invite::{
    GrantLog, InviteCode, InviteJoined, InviteOffer, InviteShort, InviteShortError, JoinedList,
    LinkCall,
};
use crate::old_invite;
use crate::old_spaces::OldSpaces;
use crate::provider::{Certs, DeviceSpec, Grants, Provider, Tally};
use crate::spaces::{SpaceEntry, Spaces};
use crate::world_common::{Common, Cutter, Proposed, Route, Scoped, device_key, key_device};

/// What one run's data layers and hosts are: the part of a case that is `ndn-data`'s alone.
#[derive(Default)]
struct Own {
    /// Every data layer attached, with its store, by node (a thief's layer carries its victim's
    /// name, so names do not tell them apart).
    devices: BTreeMap<NodeId, Attached>,
    /// What each device's host was told of grants and asked of its link layer, in order, across
    /// restarts of its layer, by node ([`Provider::link_grants`], [`Provider::link_calls`]).
    hosts: HashMap<NodeId, Arc<IntroduceCore>>,
    /// Where each device's host listens: the address it gives in its link hint and the key its
    /// link proves, by address. A dial answers for a device that listens at the address it
    /// dials (the handshake proving that device's key), and for no other.
    listening: Listening,
}

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
    common: Common,
    own: Mutex<Own>,
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
    ) -> anyhow::Result<Arc<dyn Spaces>> {
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
            .own
            .lock()
            .expect("the provider's lock")
            .devices
            .get(&node)
            .map_or(1, |a| a.runs + 1);
        let clock = fabric.node_clock(node)?;
        let introducer = self.introducer(fabric, node, &device, &validator, &keys)?;
        let config = Config {
            clock: Arc::new(move || Timestamp(clock.now_ns() / 1_000_000)),
            svs: SvsConfig::default(),
            entropy: seeded(&device, runs),
            introducer: Some(introducer),
            intro: IntroPolicy {
                grant_for: host.grant_for,
                ..IntroPolicy::new()
            },
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
        self.own
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
        Ok(Arc::new(OldSpaces::new(layer, self.persons())))
    }

    /// The introducer of the host of `device` on `node`: its namespace's newest signed trust
    /// context as the anchor it gives, its node's validator to adopt into, its link to the
    /// hub to route an adopted person's sync group over, and, as its link layer, an address it
    /// listens at (`keys`' key proved there) that a dial of another device's host answers for.
    fn introducer(
        &self,
        fabric: &Fabric,
        node: NodeId,
        device: &Name,
        validator: &Arc<Validator>,
        keys: &SecurityManager,
    ) -> anyhow::Result<Arc<dyn Introducer>> {
        let ns = validator.keyring().context_for(device).namespace().clone();
        let public = keys
            .get_signer_sync(&device_key(device))?
            .public_key()
            .context("an Ed25519 key")?;
        let hint = LinkHint {
            key: public_key_digest(&public),
            candidates: vec![HintCandidate {
                kind: HintKind::Host,
                addr: link_address(node)?,
            }],
        };
        let anchor = self.common.anchor(&ns, device)?;
        let core = {
            let mut own = self.own.lock().expect("the provider's lock");
            let listening = Arc::clone(&own.listening);
            Arc::clone(own.hosts.entry(node).or_insert_with(|| {
                Arc::new(IntroduceCore::new(
                    listening,
                    hint.candidates[0].addr,
                    hint.key,
                ))
            }))
        };
        let engine = fabric
            .engine_of(node)
            .with_context(|| format!("no engine on node {node}"))?;
        let route = self.common.route(fabric, node)?;
        Ok(Arc::new(Introduce {
            anchor,
            validator: Arc::clone(validator),
            engine: engine.clone(),
            scoped: Scoped::new(engine, Arc::clone(&route)),
            route,
            core,
            hint,
        }))
    }

    /// The store of the layer attached on `device`'s node.
    fn store(&self, device: &DeviceSpec) -> Arc<MemoryStore> {
        let own = self.own.lock().expect("the provider's lock");
        let attached = own
            .devices
            .get(&device.node)
            .unwrap_or_else(|| panic!("{} has no data layer attached", device.name()));
        Arc::clone(&attached.store)
    }

    /// The data layer attached on `device`'s node.
    fn attached(&self, device: &DeviceSpec) -> anyhow::Result<Device> {
        self.own
            .lock()
            .expect("the provider's lock")
            .devices
            .get(&device.node)
            .map(|a| a.layer.clone())
            .with_context(|| format!("{} has no data layer attached", device.name()))
    }

    /// Every person's namespace of the case.
    fn persons(&self) -> Vec<Name> {
        self.common.persons()
    }

    /// The spaces of the data layer attached on `device`'s node, as a fresh view of it.
    fn spaces_of(&self, device: &DeviceSpec) -> anyhow::Result<OldSpaces> {
        Ok(OldSpaces::new(self.attached(device)?, self.persons()))
    }
}

impl Cutter for Reference {
    /// The cut `by`'s data layer vouches for if `key` is revoked now, bounded by what it first
    /// verified before `held_before` (by its own clock).
    fn cut(&self, by: &DeviceSpec, key: &Name, held_before: u64) -> anyhow::Result<Proposed> {
        let bound = CutBound {
            held_before: Some(Timestamp(held_before)),
            ..CutBound::default()
        };
        let proposal = self
            .attached(by)?
            .revocation_cut(key, &bound)
            .map_err(|e| {
                anyhow::anyhow!(
                    "{} cannot vouch for a cut of {key}: {e} (next step: {:?})",
                    by.name(),
                    e.next()
                )
            })?;
        Ok(Proposed {
            cut: proposal.cut,
            manifest: proposal.manifest,
            left_out: proposal.left_out,
        })
    }
}

/// What a device's host configures its data layer with.
struct Host {
    /// How long a grant lasts: `Some(ZERO)` for a host that makes none.
    grant_for: Option<std::time::Duration>,
}

/// How `device`'s host configures its layer.
fn host(device: &DeviceSpec) -> Host {
    Host {
        grant_for: if device.link_grants {
            IntroPolicy::new().grant_for
        } else {
            Some(std::time::Duration::ZERO)
        },
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
    route: Route,
    /// The adoption of namespaces for the layer alone.
    scoped: Scoped,
    /// What the host was told and asked, and how its link layer answers, across restarts of its
    /// layer ([`Own::hosts`]).
    core: Arc<IntroduceCore>,
    /// The hint the host gives for an offer's code: its device's key and the address it
    /// listens at.
    hint: LinkHint,
}

/// The addresses of a hint's candidates, in order.
fn addresses(hint: &LinkHint) -> Vec<SocketAddr> {
    hint.candidates.iter().map(|c| c.addr).collect()
}

impl Introducer for Introduce {
    fn anchor(&self) -> Option<bytes::Bytes> {
        Some(self.anchor.clone())
    }

    /// The host's link layer is this stand-in: the world already routes every name through the
    /// hub, so a dial that answers is a link by name. It gives the hint of the device's own
    /// key at the address it listens at.
    fn link_hint(&self) -> Option<LinkHint> {
        Some(self.hint.clone())
    }

    /// Answers when a device listens at one of the candidates and proves the hint's key, as a
    /// handshake would; no other address or key makes a link.
    fn dial<'a>(
        &'a self,
        hint: &'a LinkHint,
        inviter: &'a Name,
        _within: std::time::Duration,
    ) -> Dialing<'a> {
        let answered = self.core.dial(inviter, hint.key, &addresses(hint));
        Box::pin(async move {
            if answered {
                Ok(())
            } else {
                Err(format!(
                    "no address of the hint answered with the key it names (tried {} of them)",
                    hint.candidates.len()
                ))
            }
        })
    }

    /// Answers with the key of the device that listens at `addr`, which a handshake proves;
    /// an address nobody listens at does not answer. The link carries the inviter's hint
    /// record, signed by a namespace this node does not hold yet, as ndn-link's first-contact
    /// link does (it routes the introduction prefixes of the device whatever answers): the
    /// node's forwarder takes that name in transit, unvalidated, until the link is taken down.
    fn dial_first<'a>(
        &'a self,
        inviter: &'a Name,
        addr: SocketAddr,
        _within: std::time::Duration,
    ) -> FirstDialing<'a> {
        let proved = self.core.dial_first(inviter, addr);
        if proved.is_some() {
            self.engine.transit().add(&hint_prefix(inviter), || {});
        }
        Box::pin(async move { proved.ok_or_else(|| format!("nothing answers at {addr}")) })
    }

    fn undial(&self, hint: &LinkHint, inviter: &Name) {
        // A first contact's link (the hint's candidate is the address dialled first) stops
        // carrying the hint record.
        if self.core.undial(inviter, hint.key, &addresses(hint)) {
            self.engine.transit().remove(&hint_prefix(inviter), || {});
        }
    }

    fn grant(&self, grant: &Grant) {
        self.core.granted(old_invite::grant(grant));
    }

    fn departure(&self, departure: &Departure) {
        self.core.departed(old_invite::departure(departure));
    }

    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {
        self.core.revoked(*key, folder);
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
        Box::pin(async move { self.scoped.adopt(namespace, held).await })
    }

    fn release_scoped(&self, namespace: &Name) {
        self.scoped.release(namespace);
    }
}

/// Randomness that replays: SHA-256 over the device's name and a counter, block after block, so
/// an audit samples the same pieces with the same nonces every run (`--check-determinism`). A
/// layer started again on its node (its `run` past the first) seeds with the run too, so it
/// does not draw its first run's numbers again.
pub(crate) fn seeded(device: &Name, run: u64) -> Entropy {
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
                | Feature::RemovalCut
                | Feature::CutRecheck
                | Feature::Seal
                | Feature::Log
                | Feature::LargePayloads
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
                | Feature::FolderMembers
                | Feature::FolderWatch
                | Feature::Introduction
                | Feature::SelfCertifying
                | Feature::OldLayer
        )
    }

    async fn prepare(
        &self,
        fabric: &Fabric,
        hub: NodeId,
        devices: &[DeviceSpec],
    ) -> anyhow::Result<()> {
        self.common.prepare(fabric, hub, devices).await?;
        *self.own.lock().expect("the provider's lock") = Own::default();
        Ok(())
    }

    async fn attach(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn Spaces>> {
        let keys = self.common.keys_of(&device.name())?;
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

    fn layer(&self, device: &DeviceSpec) -> anyhow::Result<Arc<dyn DataLayer>> {
        Ok(Arc::new(self.attached(device)?))
    }

    async fn readmit_entry(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        from: &DeviceSpec,
        entry: &SpaceEntry,
    ) -> anyhow::Result<()> {
        let log = parse_log_name(&entry.name)
            .with_context(|| format!("{} is no log entry name", entry.name))?;
        let collection = log
            .subject
            .with_context(|| format!("{} names no collection", entry.name))?;
        let id = VersionId {
            writer: ndn_data::Writer::new(device_key(&log.device)),
            seq: ndn_data::Seq(log.seq),
        };
        self.readmit(fabric, by, from, &collection, &id).await
    }

    async fn sign_at(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        space: &Name,
        path: &Name,
        bytes: bytes::Bytes,
        seq: u64,
    ) -> anyhow::Result<SpaceEntry> {
        let entry = self
            .spaces_of(device)?
            .put(space, path, bytes)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        anyhow::ensure!(
            entry.seq == seq,
            "{} signed its entry {} at seq {}, not at {seq}: this provider writes at the next seq \
             of the device's own log",
            device.name(),
            entry.name,
            entry.seq
        );
        Ok(entry)
    }

    async fn suspect(
        &self,
        _fabric: &Fabric,
        by: &DeviceSpec,
        device: &DeviceSpec,
        since: Timestamp,
    ) -> anyhow::Result<()> {
        let key = device_key(&device.name());
        self.attached(by)?.suspect(&key, since).map_err(|e| {
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
        self.common.revoke(fabric, self, by, device, lost.0).await
    }

    async fn spread(&self, fabric: &Fabric, node: NodeId) -> anyhow::Result<()> {
        self.common.spread(fabric, node).await
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
            .attached(from)?
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
        self.common.readmit_full(fabric, by, &key, &full).await
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
        self.common
            .readmit_full(fabric, by, &device_key(&log.device), full)
            .await
    }

    async fn steal(
        &self,
        fabric: &Fabric,
        victim: &DeviceSpec,
        thief: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn Spaces>> {
        let keys = self.common.keys_of(&victim.name())?;
        let copy = {
            let own = self.own.lock().expect("the provider's lock");
            anyhow::ensure!(
                !own.devices.contains_key(&thief.node),
                "{}'s node runs a data layer already; a thief steals once",
                thief.name()
            );
            let stored = own
                .devices
                .get(&victim.node)
                .with_context(|| format!("{} has no data layer attached", victim.name()))?
                .store
                .scan_under(&Name::root(), 0);
            let copy = MemoryStore::new();
            for (name, wire) in stored {
                copy.insert(name, wire);
            }
            Arc::new(copy)
        };
        let thief_host = Host {
            grant_for: IntroPolicy::new().grant_for,
        };
        self.start(fabric, thief.node, victim.name(), keys, thief_host, copy)
            .await
    }

    async fn renew(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<()> {
        self.common.renew(fabric, device).await
    }

    async fn expire(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        which: Certs,
    ) -> anyhow::Result<()> {
        self.common.expire(fabric, device, which).await
    }

    async fn end_keys(&self, fabric: &Fabric, by: &DeviceSpec) -> anyhow::Result<Vec<Name>> {
        self.common.end_keys(fabric, self, by).await
    }

    async fn stop(&self, _fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<()> {
        let own = self.own.lock().expect("the provider's lock");
        let attached = own
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
    ) -> anyhow::Result<Arc<dyn Spaces>> {
        let keys = self.common.keys_of(&device.name())?;
        let store = {
            let own = self.own.lock().expect("the provider's lock");
            let attached = own
                .devices
                .get(&device.node)
                .with_context(|| format!("{} has no data layer attached", device.name()))?;
            anyhow::ensure!(
                attached.cancel.is_cancelled(),
                "{}'s data layer runs; stop it before starting it again",
                device.name()
            );
            Arc::clone(&attached.store)
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
        self.common.recovery_kit(fabric, by).await
    }

    async fn recover(&self, fabric: &Fabric, by: &DeviceSpec) -> anyhow::Result<()> {
        self.common.recover(fabric, by).await
    }

    fn tally(&self) -> Tally {
        let own = self.own.lock().expect("the provider's lock");
        Tally {
            signatures: own.devices.values().map(|a| a.layer.signatures()).sum(),
            copies: own.devices.values().map(|a| a.layer.held()).sum(),
        }
    }

    fn signed_by(&self, device: &DeviceSpec) -> u64 {
        let own = self.own.lock().expect("the provider's lock");
        own.devices
            .get(&device.node)
            .map_or(0, |a| a.layer.signatures())
    }

    fn grants(&self, device: &DeviceSpec) -> Grants {
        let own = self.own.lock().expect("the provider's lock");
        own.devices
            .get(&device.node)
            .map_or(Grants::default(), |a| Grants {
                asked: a.layer.grants_asked(),
                answered: a.layer.grants_answered(),
            })
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

    fn sign_unbound(&self, device: &DeviceSpec, subject: &Name) -> anyhow::Result<Name> {
        let name = device.name();
        let keys = self.common.keys_of(&name)?;
        let store = {
            let own = self.own.lock().expect("the provider's lock");
            let attached = own
                .devices
                .get(&device.node)
                .with_context(|| format!("{name} has no data layer attached"))?;
            anyhow::ensure!(
                attached.cancel.is_cancelled(),
                "{name}'s data layer runs; stop it before an older build's store is made"
            );
            Arc::clone(&attached.store)
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

    async fn replay_altered(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        prefix: &Name,
    ) -> anyhow::Result<()> {
        self.common
            .replay_altered_packet(fabric, device, prefix)
            .await
    }

    async fn link_calls(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
    ) -> anyhow::Result<Vec<LinkCall>> {
        Ok(self
            .own
            .lock()
            .expect("the provider's lock")
            .hosts
            .get(&device.node)
            .map(|host| host.calls())
            .unwrap_or_default())
    }

    async fn offer(
        &self,
        _fabric: &Fabric,
        by: &DeviceSpec,
        space: &Name,
        offer: InviteOffer,
    ) -> anyhow::Result<InviteCode> {
        let code = self
            .attached(by)?
            .offer(space, old_invite::offer(&offer))
            .await
            .map_err(old_invite::error)?;
        old_invite::code(code, &by.name())
    }

    async fn close_offer(
        &self,
        _fabric: &Fabric,
        by: &DeviceSpec,
        offer: &Name,
    ) -> anyhow::Result<()> {
        self.attached(by)?
            .close_offer(offer)
            .await
            .map_err(old_invite::error)
    }

    async fn link_grants(&self, _fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<GrantLog> {
        let told = self
            .own
            .lock()
            .expect("the provider's lock")
            .hosts
            .get(&device.node)
            .map(|host| host.told())
            .unwrap_or_default();
        let layer = self.attached(device)?;
        Ok(GrantLog {
            told,
            now: layer.grants().iter().map(old_invite::grant).collect(),
            departures: layer
                .departures()
                .iter()
                .map(old_invite::departure)
                .collect(),
        })
    }

    async fn joined_folders(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
    ) -> anyhow::Result<JoinedList> {
        let layer = self.attached(device)?;
        // The spaces are read after the generation: a change between the two reads only makes
        // the list newer than its generation, never older.
        let generation = *layer.joined_changes().borrow();
        Ok(JoinedList {
            spaces: layer
                .joined_folders()
                .iter()
                .map(old_invite::joined_space)
                .collect(),
            generation,
        })
    }

    async fn take_departure(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        from: &DeviceSpec,
        space: &Name,
        record: &Name,
    ) -> anyhow::Result<()> {
        self.attached(device)?
            .take_departure(&from.name(), space, record)
            .await
            .map_err(old_invite::error)
    }

    async fn link_key(&self, _fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<[u8; 32]> {
        Ok(public_key_digest(
            &self.common.public_key_of(&device.name())?,
        ))
    }

    async fn join(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        code: &str,
    ) -> anyhow::Result<InviteJoined> {
        self.attached(device)?
            .join(code)
            .await
            .map(old_invite::joined)
            .map_err(old_invite::error)
    }

    async fn end_grant_in(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        key: &[u8; 32],
        space: &Name,
    ) -> anyhow::Result<bool> {
        self.attached(device)?
            .end_grant_in(key, space)
            .await
            .map_err(old_invite::error)
    }

    async fn end_grant(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        key: &[u8; 32],
    ) -> anyhow::Result<bool> {
        self.attached(device)?
            .end_grant(key)
            .await
            .map_err(old_invite::error)
    }

    fn short_read(&self, line: &str) -> Result<InviteShort, InviteShortError> {
        old_invite::short_read(line)
    }

    fn short_write(&self, short: &InviteShort) -> Result<String, InviteShortError> {
        old_invite::short_write(short)
    }

    async fn adopt(&self, fabric: &Fabric, device: &DeviceSpec, link: &str) -> anyhow::Result<()> {
        self.common.adopt_link(fabric, device, link).await
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
        self.common.verdict(fabric, at, name, wire).await
    }

    fn signer(&self, device: &DeviceSpec) -> anyhow::Result<Arc<dyn Signer>> {
        self.common.signer_of(device)
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
