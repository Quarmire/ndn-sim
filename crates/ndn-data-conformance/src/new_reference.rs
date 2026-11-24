//! The second provider: `ndn-heap`'s [`Node`] on every device of a case.
//!
//! The world is the one every provider shares ([`Common`]): people as namespaces with keys
//! certifying their devices, a trust context on every forwarder, the hub standing for the
//! network, the root flows (revocation, renewal, expiry, recovery) signed with `ndn-cert`.
//! What this provider adds is the layer itself: each device runs a [`Node`] on its own forwarder
//! over two in-process app faces, verifies with that forwarder's validator, dates entries by the
//! node's own (possibly lying) clock, and keeps what it holds in a [`CrashStore`], a memory store
//! with a disk's write cache, so a case can cut the power, kill the process, copy or restore the
//! disk, stall the flush and fail it.
//!
//! A space is a name `<O>/32=data/<c>`, a path a name below it. The neutral [`Spaces`] verbs map
//! one to one: `create` to `Node::create`, `change` to `Heap::change`, `put` to `Heap::put` (the
//! default durability: durable at once while no peer is known), `get` to `Heap::get`, `watch` to
//! `Heap::watch` from the empty frontier, `applied` to `Heap::applied`. A device follows a space
//! from its first verb on it (`Node::open`), as the old adapter's device follows a collection
//! from its first read.
//!
//! The revocation cut the root flows sign is `Node::revocation_cut` of the root device's node
//! ([`Cutter`]).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_data::{Name, Timestamp};
use ndn_heap::wire::{self, Body, Entry, Payload, PutBody};
use ndn_heap::{
    Adopter, Alert, Change, Changes, Config, CutBound, EntryId, Frontier, Heap, HeapError, Item,
    MembersChange, NextStep, Node, PutOptions, Readers, Refusal, Scoping, Share, Transport,
};
use ndn_packet::{Data, NameComponent};
use ndn_security::{ScopedContext, SecurityManager, Signer};
use ndn_sim::{Fabric, NodeId};
use ndn_sync::DataStore;
use tokio_util::sync::CancellationToken;

use crate::case::Failure;
use crate::crash_store::CrashStore;
use crate::feature::Feature;
use crate::provider::{Certs, DeviceSpec, Grants, Image, Provider, Tally};
use crate::spaces::{
    AlertKind, EntryRead, RefusalKind, SpaceAlert, SpaceChange, SpaceChanges, SpaceEntry,
    SpaceEntryKey, SpaceEvent, SpaceItem, SpaceMembers, SpaceShare, Spaces,
};
use crate::world_common::{Common, Cutter, Proposed, Scoped, device_key};

/// How many seqs one durable reservation covers: small, so a short case shows a reservation
/// extended (and what a crash leaves above the head) without a thousand writes.
const RESERVE_BLOCK: u64 = 8;

/// How long a removal looks for entries of the removed person's devices heard of and not held.
const FIRST_LOOK: Duration = Duration::from_millis(50);

/// How long [`Provider::stop`] waits for the verbs in flight to let go of the node.
const STOP_WAIT: Duration = Duration::from_secs(60);

/// One run of a device's node and the store it runs on.
struct Run {
    /// The name the node signs as (a thief's carries its victim's).
    device: Name,
    /// The key store the node signs with.
    keys: Arc<SecurityManager>,
    /// The node while it runs; `None` once stopped, crashed or killed.
    node: Mutex<Option<Arc<Node>>>,
    /// What the node keeps its entries in.
    store: Arc<CrashStore>,
    /// Ends the node's app faces.
    cancel: CancellationToken,
}

impl Run {
    fn node(&self) -> Option<Arc<Node>> {
        self.node.lock().expect("the run's lock").clone()
    }

    fn take(&self) -> Option<Arc<Node>> {
        self.node.lock().expect("the run's lock").take()
    }
}

/// What the provider keeps of the devices of one case.
#[derive(Default)]
struct Own {
    /// The newest run of the node on each forwarder.
    runs: BTreeMap<NodeId, Arc<Run>>,
    /// The signatures the earlier runs of each node made.
    retired: HashMap<NodeId, u64>,
}

/// `ndn-heap`'s [`Node`] as a conformance provider.
#[derive(Default)]
pub struct NewReference {
    common: Common,
    own: Mutex<Own>,
}

/// What a host does so that persons a space lists can be judged: adopt their namespaces for the
/// layer alone, through its node's engine.
struct Adopt(Scoped);

impl Adopter for Adopt {
    fn adopt_scoped<'a>(
        &'a self,
        namespace: &'a Name,
        held: Option<&'a ScopedContext>,
    ) -> Scoping<'a> {
        Box::pin(async move { self.0.adopt(namespace, held).await })
    }

    fn release_scoped(&self, namespace: &Name) {
        self.0.release(namespace);
    }
}

impl NewReference {
    /// The provider, for the runner's list.
    pub fn provider() -> Arc<dyn Provider> {
        Arc::new(Self::default())
    }

    /// Start a node of `device` on `node`'s forwarder over `store`.
    async fn start(
        &self,
        fabric: &Fabric,
        node: NodeId,
        device: Name,
        keys: Arc<SecurityManager>,
        store: Arc<CrashStore>,
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
        let clock = fabric.node_clock(node)?;
        let scoped = Scoped::new(engine.clone(), self.common.route(fabric, node)?);
        let config = Config {
            clock: Arc::new(move || ndn_heap::Timestamp(clock.now_ns() / 1_000_000)),
            first_look: FIRST_LOOK,
            reserve_block: RESERVE_BLOCK,
            adopter: Some(Arc::new(Adopt(scoped))),
            ..Config::new()
        };
        let started = Node::start(
            transport,
            device.clone(),
            Arc::clone(&keys),
            validator,
            Arc::clone(&store) as Arc<dyn DataStore>,
            config,
        )
        .await
        .map_err(|e| anyhow::anyhow!("{device}: {e}"))?;
        let run = Arc::new(Run {
            device,
            keys,
            node: Mutex::new(Some(Arc::new(started))),
            store,
            cancel,
        });
        self.own
            .lock()
            .expect("the provider's lock")
            .runs
            .insert(node, Arc::clone(&run));
        Ok(Arc::new(NewSpaces {
            run,
            persons: self.common.persons(),
        }))
    }

    /// The newest run on `device`'s forwarder.
    fn run(&self, device: &DeviceSpec) -> anyhow::Result<Arc<Run>> {
        self.own
            .lock()
            .expect("the provider's lock")
            .runs
            .get(&device.node)
            .cloned()
            .with_context(|| format!("{} has no data layer attached", device.name()))
    }

    /// The node `device` runs now.
    fn node_of(&self, device: &DeviceSpec) -> anyhow::Result<Arc<Node>> {
        self.run(device)?
            .node()
            .with_context(|| format!("{}'s data layer is not running", device.name()))
    }

    /// The node of `device`, if it runs, taken from its run: no verb reaches it from now on.
    /// Its signatures are kept in the tally.
    fn retire(&self, device: &DeviceSpec) -> anyhow::Result<(Arc<Run>, Option<Arc<Node>>)> {
        let run = self.run(device)?;
        let node = run.take();
        if let Some(node) = &node {
            *self
                .own
                .lock()
                .expect("the provider's lock")
                .retired
                .entry(device.node)
                .or_default() += node.signatures();
        }
        Ok((run, node))
    }

    /// `device`'s node ends with no close (a dead process, a cut power): what its store holds is
    /// `image` of the store it ran on; a node starts on a store holding it.
    async fn relaunch(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        image: impl FnOnce(&CrashStore) -> BTreeMap<Name, Bytes>,
    ) -> anyhow::Result<Arc<dyn Spaces>> {
        let (run, node) = self.retire(device)?;
        if let Some(node) = node {
            node.shutdown();
        }
        run.cancel.cancel();
        // A flush held when the node died ends with it: a thread waiting on it must not outlive
        // the case.
        run.store.hold(false);
        let store = Arc::new(CrashStore::booted(image(&run.store)));
        self.start(
            fabric,
            device.node,
            run.device.clone(),
            Arc::clone(&run.keys),
            store,
        )
        .await
    }
}

impl Cutter for NewReference {
    /// The cut `by`'s node vouches for if `key` is revoked now, bounded by what it first
    /// verified before `held_before` (by its own clock).
    fn cut(&self, by: &DeviceSpec, key: &Name, held_before: u64) -> anyhow::Result<Proposed> {
        let bound = CutBound {
            held_before: Some(ndn_heap::Timestamp(held_before)),
            ..CutBound::default()
        };
        let proposal = self.node_of(by)?.revocation_cut(key, &bound).map_err(|e| {
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

// -- Names ---------------------------------------------------------------------------------

/// A packet name of the layer: `<device>/32=log/<space>/seq=<n>` and what follows it (a piece).
struct Parsed {
    device: Name,
    space: Name,
    seq: u64,
    /// The components after the seq: none for an entry.
    after: usize,
}

fn parse_entry(name: &Name) -> Option<Parsed> {
    let log = NameComponent::keyword(Bytes::from_static(b"log"));
    let comps = name.components();
    let at = comps.iter().position(|c| *c == log)?;
    let seq_at = at
        + 1
        + comps[at + 1..]
            .iter()
            .position(|c| c.as_sequence_num().is_some())?;
    Some(Parsed {
        device: Name::from_components(comps[..at].iter().cloned()),
        space: Name::from_components(comps[at + 1..seq_at].iter().cloned()),
        seq: comps[seq_at].as_sequence_num()?,
        after: comps.len() - seq_at - 1,
    })
}

/// Whether `name` is a piece of an entry (a chunk or a manifest node of its value).
fn is_piece(name: &Name, entry: &Name) -> bool {
    let piece = NameComponent::keyword(Bytes::from_static(b"piece"));
    name.len() > entry.len() && name.has_prefix(entry) && name.components()[entry.len()] == piece
}

/// The packets of `store`: every name that is no record of the layer's own (those lie under
/// `/localhost/ndn-heap`).
fn packets(store: &CrashStore) -> Vec<(Name, Bytes)> {
    let local: Name = "/localhost".parse().expect("a valid name");
    store
        .scan_under(&Name::root(), 0)
        .into_iter()
        .filter(|(name, _)| !name.has_prefix(&local))
        .collect()
}

/// The thief's edit of its copy of a device's store: for each space the copy holds, the
/// reservation record says the last run closed cleanly with its reservation at the head the copy
/// holds (`/localhost/ndn-heap/reserve/<S>`: the reserved seq in 8 octets big-endian, then 1 for
/// a clean close; spec §4.3). A copy of a live disk carries the reservation above the head, and
/// its node would sign past a gap statement at the next block, never at the very seq the key's
/// other copy signs; a thief that wants that name claims a clean close. It is the strongest
/// thief the layer faces, and what the cases that sign "at the name of an entry" need.
fn claim_clean(image: &mut BTreeMap<Name, Bytes>, device: &Name) {
    let root: Name = "/localhost/ndn-heap/reserve".parse().expect("a valid name");
    let spaces: Vec<(Name, Name)> = image
        .keys()
        .filter(|key| key.has_prefix(&root) && key.len() > root.len())
        .map(|key| {
            (
                key.clone(),
                Name::from_components(key.components()[root.len()..].iter().cloned()),
            )
        })
        .collect();
    for (key, space) in spaces {
        let head = image
            .keys()
            .filter_map(parse_entry)
            .filter(|p| p.after == 0 && p.device == *device && p.space == space)
            .map(|p| p.seq)
            .max()
            .unwrap_or(0);
        let mut record = head.to_be_bytes().to_vec();
        record.push(1);
        image.insert(key, Bytes::from(record));
    }
}

// -- Errors --------------------------------------------------------------------------------

/// The failure a verb answers for `e`: its words, the next step and the kind of refusal.
fn failure(e: HeapError) -> Failure {
    let next = match e.next() {
        NextStep::None => "None",
        NextStep::RetryLater => "RetryLater",
        NextStep::AskOwner => "AskOwner",
        NextStep::UseOwnerDevice => "UseOwnerDevice",
        NextStep::FixLocal => "FixLocal",
        NextStep::FixName => "FixName",
        NextStep::FixRequest => "FixRequest",
    };
    let kind = match &e {
        HeapError::Unavailable { .. } => "Unavailable",
        HeapError::NotReady { .. } => "NotReady",
        HeapError::BadName { .. } => "BadName",
        HeapError::TooLarge { .. } => "TooLarge",
        HeapError::NotAllowed { .. } => "NotAllowed",
        HeapError::Sealed { .. } => "Sealed",
        HeapError::NotOwner { .. } => "NotOwner",
        HeapError::Refused { .. } => "Refused",
        HeapError::BadRequest { .. } => "BadRequest",
        HeapError::Local { .. } => "Local",
    };
    Failure::answered(
        format!("verb failed: {e} (next step: {:?})", e.next()),
        next,
        kind,
    )
}

fn refusal_kind(why: &Refusal) -> RefusalKind {
    match why {
        Refusal::OutsideCut(_) => RefusalKind::OutsideCut,
        Refusal::Untrusted { .. } => RefusalKind::Untrusted,
        _ => RefusalKind::Other,
    }
}

// -- The spaces of one run -------------------------------------------------------------------

/// One run of a device's node as [`Spaces`].
pub struct NewSpaces {
    run: Arc<Run>,
    /// Every person's namespace of the case: a device's person is the longest that is a prefix
    /// of its name.
    persons: Vec<Name>,
}

/// The members of a space as the neutral surface states them.
fn members_of(members: ndn_heap::Members) -> SpaceMembers {
    let (readers, public) = match members.readers {
        Readers::Anyone => (Vec::new(), true),
        Readers::Persons(persons) => (persons, false),
    };
    SpaceMembers::new(&members.owner, members.writers, readers, public)
}

/// The entry `id` of `space`, by its identity.
fn key_of(space: &Name, id: &EntryId) -> SpaceEntryKey {
    SpaceEntryKey {
        name: wire::log_name(&id.device, space, id.seq),
        writer: id.device.clone(),
        seq: id.seq,
    }
}

fn entry_of(space: &Name, id: &EntryId) -> SpaceEntry {
    SpaceEntry {
        name: wire::log_name(&id.device, space, id.seq),
        writer: id.device.clone(),
        seq: id.seq,
        signed: id.digest,
    }
}

impl NewSpaces {
    fn node(&self) -> Result<Arc<Node>, Failure> {
        self.run
            .node()
            .ok_or_else(|| Failure::new(format!("{} is not running", self.run.device)))
    }

    /// The space `space` of this node, opened (followed) on first use.
    async fn heap(&self, space: &Name) -> Result<Heap, Failure> {
        let node = self.node()?;
        if let Some(heap) = node.space(space) {
            return Ok(heap);
        }
        node.open(space).await.map_err(failure)
    }

    /// The person whose namespace `device` lies under.
    fn person_of(&self, device: &Name) -> Name {
        self.persons
            .iter()
            .filter(|p| device.has_prefix(p))
            .max_by_key(|p| p.len())
            .cloned()
            .unwrap_or_else(|| device.clone())
    }

    /// The decoded entry the store holds at `name`.
    fn stored(&self, name: &Name) -> Option<(Bytes, Entry)> {
        let wire = self.run.store.get(name)?;
        let data = Data::decode(wire.clone()).ok()?;
        let entry = Entry::decode(data.content()?).ok()?;
        Some((wire, entry))
    }

    /// The entries the entry named `name` of `space` superseded, from its packet.
    fn after_of(&self, space: &Name, name: &Name) -> Vec<SpaceEntryKey> {
        self.stored(name)
            .map(|(_, entry)| {
                entry
                    .after
                    .iter()
                    .map(|r| key_of(space, r))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    fn item(&self, space: &Name, item: &Item) -> SpaceItem {
        let key = key_of(space, &item.id);
        SpaceItem {
            path: item.path.clone(),
            bytes: item.bytes.clone(),
            by: item.by.clone(),
            after: self.after_of(space, &key.name),
            name: key.name,
            writer: item.id.device.clone(),
            seq: item.id.seq,
            signed: item.id.digest,
        }
    }

    /// What `heap` lists now, without waiting for anything new: the heads it holds and the
    /// alerts standing.
    async fn listing(&self, heap: &Heap) -> Result<Vec<Change>, Failure> {
        let mut changes = heap.watch(&Frontier::new()).await.map_err(failure)?;
        let mut listed = Vec::new();
        while let Ok(Some(change)) =
            tokio::time::timeout(Duration::from_millis(1), changes.next()).await
        {
            listed.push(change.map_err(failure)?);
        }
        Ok(listed)
    }

    /// Why `heap` refuses the entry `id`, if it does: from its standing alerts.
    async fn refusal(
        &self,
        heap: &Heap,
        id: &EntryId,
    ) -> Result<Option<(RefusalKind, String)>, Failure> {
        let same = |other: &EntryId| other.device == id.device && other.seq == id.seq;
        for change in self.listing(heap).await? {
            match change {
                Change::Alert(Alert::OutsideCut { id: other }) if same(&other) => {
                    return Ok(Some((
                        RefusalKind::OutsideCut,
                        format!("{} is outside a removal cut", id.device),
                    )));
                }
                Change::Alert(Alert::Refused { id: other, why, .. })
                | Change::Withdrawn { id: other, why }
                    if same(&other) =>
                {
                    return Ok(Some((refusal_kind(&why), why.to_string())));
                }
                _ => {}
            }
        }
        Ok(None)
    }

    /// What the applied entry `id` of `space`, whose packet is `entry`, wrote.
    async fn read(
        &self,
        heap: &Heap,
        space: &Name,
        id: &EntryId,
        entry: &Entry,
    ) -> Result<SpaceItem, Failure> {
        let key = key_of(space, id);
        let read = |path: Name, bytes: Bytes| SpaceItem {
            path,
            bytes,
            by: self.person_of(&id.device),
            after: entry.after.iter().map(|r| key_of(space, r)).collect(),
            name: key.name.clone(),
            writer: id.device.clone(),
            seq: id.seq,
            signed: id.digest,
        };
        match &entry.body {
            Body::Put(PutBody {
                path,
                payload: Payload::Inline(bytes),
            }) => Ok(read(path.clone(), bytes.clone())),
            Body::Put(PutBody { path, .. }) => match heap.get(path).await.map_err(failure)? {
                Some(head) if head.id == *id => Ok(read(path.clone(), head.bytes)),
                _ => Err(Failure::new(format!(
                    "{}: its value is in pieces and it is no longer the head at {path}, whose \
                     bytes the public surface gives only for a head",
                    key.name
                ))),
            },
            Body::Sealed(_) => {
                // A sealed entry is opened by the node; the public surface gives its bytes for
                // a head of its path.
                for change in self.listing(heap).await? {
                    if let Change::Put(head) | Change::Removed(head) = change
                        && head.id == *id
                    {
                        return Ok(read(head.path, head.bytes));
                    }
                }
                Err(Failure::new(format!(
                    "{}: it is sealed and no longer a head of its path; the public surface \
                     opens a sealed entry only as a head",
                    key.name
                )))
            }
            Body::Members(_) | Body::Epoch(_) => Err(Failure::new(format!(
                "{} is no write: it is a members or an epoch entry",
                key.name
            ))),
        }
    }
}

#[async_trait::async_trait]
impl Spaces for NewSpaces {
    async fn create(&self, space: &Name, share: SpaceShare) -> Result<(), Failure> {
        let readers = if share.anyone {
            Readers::Anyone
        } else {
            Readers::Persons(share.readers)
        };
        self.node()?
            .create(
                space,
                Share {
                    readers,
                    writers: share.writers,
                },
            )
            .await
            .map(drop)
            .map_err(failure)
    }

    async fn change(&self, space: &Name, change: SpaceChange) -> Result<(), Failure> {
        self.heap(space)
            .await?
            .change(MembersChange {
                add_writers: change.add_writers,
                add_readers: change.add_readers,
                remove: change.remove,
            })
            .await
            .map(drop)
            .map_err(failure)
    }

    async fn members(&self, space: &Name) -> Result<SpaceMembers, Failure> {
        let members = self.heap(space).await?.members();
        if members.owner.is_empty() {
            return Err(Failure::answered(
                format!("{space}: no members record is held yet"),
                "RetryLater",
                "NotReady",
            ));
        }
        Ok(members_of(members))
    }

    async fn put(&self, space: &Name, path: &Name, bytes: Bytes) -> Result<SpaceEntry, Failure> {
        let id = self
            .heap(space)
            .await?
            .put(path, bytes, PutOptions { durable: None })
            .await
            .map_err(failure)?;
        Ok(entry_of(space, &id))
    }

    async fn get(&self, space: &Name, path: &Name) -> Result<Option<SpaceItem>, Failure> {
        let got = self.heap(space).await?.get(path).await;
        match got {
            Ok(item) => Ok(item.map(|item| self.item(space, &item))),
            Err(HeapError::Unavailable { .. }) => Ok(None),
            Err(e) => Err(failure(e)),
        }
    }

    async fn watch(&self, space: &Name) -> Result<Box<dyn SpaceChanges>, Failure> {
        let heap = self.heap(space).await?;
        let changes = heap.watch(&Frontier::new()).await.map_err(failure)?;
        let members = heap.members();
        Ok(Box::new(NewChanges {
            changes,
            view: NewSpaces {
                run: Arc::clone(&self.run),
                persons: self.persons.clone(),
            },
            space: space.clone(),
            members: (!members.owner.is_empty()).then(|| members_of(members)),
        }))
    }

    async fn open(&self, space: &Name) -> Result<(), Failure> {
        self.heap(space).await.map(drop)
    }

    async fn applied(&self, space: &Name, entry: &SpaceEntry) -> Result<bool, Failure> {
        Ok(self.heap(space).await?.applied(&EntryId {
            device: entry.writer.clone(),
            seq: entry.seq,
            digest: entry.signed,
        }))
    }

    async fn epoch(&self, space: &Name) -> Result<Option<SpaceEpoch>, Failure> {
        let heap = self.heap(space).await?;
        if heap.members().owner.is_empty() {
            return Err(Failure::answered(
                format!("{space}: no members record is held yet"),
                "RetryLater",
                "NotReady",
            ));
        }
        Ok(heap.epoch().map(|(epoch, complete)| SpaceEpoch {
            creator: epoch.creator,
            seq: epoch.seq,
            complete,
        }))
    }

    async fn entry(&self, space: &Name, name: &Name) -> Result<EntryRead, Failure> {
        let Some(parsed) = parse_entry(name).filter(|p| p.after == 0) else {
            return Err(Failure::new(format!("{name} is no log entry name")));
        };
        if parsed.space != *space {
            return Err(Failure::new(format!(
                "{name} is an entry of {}, not of {space}",
                parsed.space
            )));
        }
        let heap = self.heap(space).await?;
        let Some((wire, entry)) = self.stored(name) else {
            return Ok(EntryRead::NotHeld);
        };
        let id = EntryId {
            device: parsed.device,
            seq: parsed.seq,
            digest: wire::signed_digest(&wire),
        };
        if heap.applied(&id) {
            return self
                .read(&heap, space, &id, &entry)
                .await
                .map(EntryRead::Read);
        }
        Ok(match self.refusal(&heap, &id).await? {
            Some((kind, text)) => EntryRead::Refused { kind, text },
            None => EntryRead::NotHeld,
        })
    }
}

/// A watch of a space, as neutral events.
struct NewChanges {
    changes: Changes,
    view: NewSpaces,
    space: Name,
    /// The members in force when the watch began, told first: the layer lists the heads it holds
    /// and tells a members change as it happens, and a watch of a space states what is in force.
    members: Option<SpaceMembers>,
}

impl NewChanges {
    fn event(&self, change: Change) -> SpaceEvent {
        let space = &self.space;
        match change {
            Change::Put(item) => SpaceEvent::Put(self.view.item(space, &item)),
            Change::Removed(item) => SpaceEvent::Removed(self.view.item(space, &item)),
            Change::Withdrawn { id, why } => SpaceEvent::Withdrawn {
                entry: key_of(space, &id),
                kind: refusal_kind(&why),
                why: why.to_string(),
            },
            Change::Members(members) => SpaceEvent::Members(members_of(members)),
            Change::Lagged { .. } => SpaceEvent::Lagged,
            Change::Alert(alert) => SpaceEvent::Alert(alert_of(alert)),
        }
    }
}

/// An alert as the neutral surface states it, by its variant.
fn alert_of(alert: Alert) -> SpaceAlert {
    let detail = format!("{alert:?}");
    let kind = match alert {
        Alert::Equivocation { device, seq } => AlertKind::Equivocation { device, seq },
        Alert::OutsideCut { .. } => AlertKind::OutsideCut,
        Alert::Refused { .. } => AlertKind::Refused,
        Alert::RolledBack { .. } => AlertKind::RolledBack,
        Alert::GapSigned { .. } => AlertKind::GapSigned,
        Alert::UnbackedCounter { .. } => AlertKind::UnbackedCounter,
        Alert::StoreFailed { .. } => AlertKind::StoreFailed,
    };
    SpaceAlert { kind, detail }
}

#[async_trait::async_trait]
impl SpaceChanges for NewChanges {
    async fn next(&mut self) -> Option<Result<SpaceEvent, Failure>> {
        if let Some(members) = self.members.take() {
            return Some(Ok(SpaceEvent::Members(members)));
        }
        Some(match self.changes.next().await? {
            Ok(change) => Ok(self.event(change)),
            Err(e) => Err(failure(e)),
        })
    }
}

// -- The provider --------------------------------------------------------------------------

#[async_trait::async_trait]
impl Provider for NewReference {
    fn name(&self) -> &str {
        "ndn-heap"
    }

    /// What the cases of the first stage need of the layer. Not Introduction (a join by a code is
    /// stage 5), Signals (the layer's run headers are not the old signals), nor UnboundCut (a
    /// cut without bytes does not exist in the new wire). Members are persons by exact
    /// namespace, which is all the cases that need [`Feature::WritersAcrossPrefixes`] ask: a
    /// writer under another person's namespace, listed by its own.
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
                | Feature::GuestExpiry
                | Feature::IssuerRecheck
                | Feature::FolderMembers
                | Feature::FolderWatch
                | Feature::SelfCertifying
                | Feature::Crash
                | Feature::Chain
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
            Arc::new(CrashStore::default()),
        )
        .await
    }

    async fn readmit_entry(
        &self,
        fabric: &Fabric,
        by: &DeviceSpec,
        from: &DeviceSpec,
        entry: &SpaceEntry,
    ) -> anyhow::Result<()> {
        let key = device_key(&entry.writer);
        // Exactly the packet `from` holds refused, by its name and implicit digest, as the host
        // shows the owner.
        let full = self
            .node_of(from)?
            .refused_by_revocation(&key)
            .into_iter()
            .find(|n| n.len() == entry.name.len() + 1 && n.has_prefix(&entry.name))
            .with_context(|| {
                format!(
                    "{} holds no entry {} refused by the revocation of {key}; re-admission names \
                     the exact packet a device holds refused",
                    from.name(),
                    entry.name
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
        let parsed = parse_entry(&entry).filter(|p| p.after == 0).with_context(|| {
            format!(
                "{full} names no log entry (<device>/32=log/…/seq=<n>/<digest>); a re-admission \
                 names one entry of a revoked key exactly"
            )
        })?;
        self.common
            .readmit_full(fabric, by, &device_key(&parsed.device), full)
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
        self.node_of(by)?
            .suspect(&key, ndn_heap::Timestamp(since.0))
            .map_err(|e| {
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

    async fn steal(
        &self,
        fabric: &Fabric,
        victim: &DeviceSpec,
        thief: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn Spaces>> {
        anyhow::ensure!(
            !self
                .own
                .lock()
                .expect("the provider's lock")
                .runs
                .contains_key(&thief.node),
            "{}'s node runs a data layer already; a thief steals once",
            thief.name()
        );
        let keys = self.common.keys_of(&victim.name())?;
        // A copy of everything the victim's store holds, as a cloned disk, which its thief then
        // edits so that its node writes on from the entries the copy holds ([`claim_clean`]).
        let mut copy = self.run(victim)?.store.live();
        claim_clean(&mut copy, &victim.name());
        self.start(
            fabric,
            thief.node,
            victim.name(),
            keys,
            Arc::new(CrashStore::booted(copy)),
        )
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
        let (run, node) = self.retire(device)?;
        let mut node =
            node.with_context(|| format!("{}'s data layer is stopped", device.name()))?;
        // The verbs in flight let go of the node; then it closes cleanly (`close` takes it).
        let waited = tokio::time::Instant::now();
        let node = loop {
            match Arc::try_unwrap(node) {
                Ok(node) => break node,
                Err(held) => {
                    anyhow::ensure!(
                        waited.elapsed() < STOP_WAIT,
                        "{}'s node is still held by a verb after {STOP_WAIT:?}",
                        device.name()
                    );
                    node = held;
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }
        };
        node.close().await;
        run.cancel.cancel();
        Ok(())
    }

    async fn restart(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
    ) -> anyhow::Result<Arc<dyn Spaces>> {
        let run = self.run(device)?;
        anyhow::ensure!(
            run.node().is_none(),
            "{}'s data layer runs; stop it before starting it again",
            device.name()
        );
        self.start(
            fabric,
            device.node,
            run.device.clone(),
            Arc::clone(&run.keys),
            Arc::clone(&run.store),
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
        let nodes: Vec<Arc<Node>> = own.runs.values().filter_map(|r| r.node()).collect();
        Tally {
            signatures: own.retired.values().sum::<u64>()
                + nodes.iter().map(|n| n.signatures()).sum::<u64>(),
            copies: nodes.iter().map(|n| n.held()).sum(),
        }
    }

    fn signed_by(&self, device: &DeviceSpec) -> u64 {
        let own = self.own.lock().expect("the provider's lock");
        own.retired.get(&device.node).copied().unwrap_or(0)
            + own
                .runs
                .get(&device.node)
                .and_then(|r| r.node())
                .map_or(0, |n| n.signatures())
    }

    /// The layer counts no grants it asked for or answered: they are signatures, counted in
    /// [`Provider::signed_by`], and the public surface does not tell them apart. Always zero.
    fn grants(&self, _device: &DeviceSpec) -> Grants {
        Grants::default()
    }

    fn stored(&self, device: &DeviceSpec, prefix: &Name) -> u64 {
        let Ok(run) = self.run(device) else { return 0 };
        let version = parse_entry(prefix).is_some_and(|p| p.after == 0);
        packets(&run.store)
            .iter()
            .filter(|(name, _)| {
                if version {
                    name.has_prefix(prefix)
                } else {
                    parse_entry(name).is_some_and(|p| p.space == *prefix)
                }
            })
            .map(|(_, wire)| wire.len() as u64)
            .sum()
    }

    fn pieces_stored(&self, device: &DeviceSpec, version: &Name) -> u64 {
        let Ok(run) = self.run(device) else { return 0 };
        packets(&run.store)
            .iter()
            .filter(|(name, _)| is_piece(name, version))
            .count() as u64
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
            .run(from)?
            .store
            .get(name)
            .with_context(|| format!("{} stores no packet {name}", from.name()))?;
        self.common.verdict(fabric, at, name, wire).await
    }

    fn signer(&self, device: &DeviceSpec) -> anyhow::Result<Arc<dyn Signer>> {
        self.common.signer_of(device)
    }

    fn stored_names(&self, device: &DeviceSpec) -> anyhow::Result<Vec<Name>> {
        Ok(packets(&self.run(device)?.store)
            .into_iter()
            .map(|(name, _)| name)
            .collect())
    }

    /// The device signs `bytes` at `path` as its own entry number `seq`, through its node, as a
    /// copy of a key does: a node signs at its next seq, so when that is below `seq` the device
    /// first signs entries at `/pad` (a stolen key's writes the cases never read) until the next
    /// is `seq`, and when it is above, the call fails. The entry is chained, sealed in a private
    /// space, applied by the device as its own, served and announced, as any write is; it is
    /// what another copy of the key signed at the same name when it is.
    async fn sign_at(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        space: &Name,
        path: &Name,
        bytes: Bytes,
        seq: u64,
    ) -> anyhow::Result<SpaceEntry> {
        anyhow::ensure!(seq >= 1, "a log starts at seq 1");
        let run = self.run(device)?;
        let spaces = NewSpaces {
            run: Arc::clone(&run),
            persons: self.common.persons(),
        };
        let heap = spaces
            .heap(space)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let me = run.device.clone();
        let mut next = 1 + packets(&run.store)
            .iter()
            .filter_map(|(name, _)| parse_entry(name))
            .filter(|p| p.after == 0 && p.device == me && p.space == *space)
            .map(|p| p.seq)
            .max()
            .unwrap_or(0);
        anyhow::ensure!(
            next <= seq,
            "{} has signed its log of {space} up to seq {}: it cannot sign at {seq}",
            device.name(),
            next - 1
        );
        let pad: Name = "/pad".parse().expect("a valid name");
        let unwaiting = PutOptions {
            durable: Some(false),
        };
        while next < seq {
            let id = heap
                .put(&pad, Bytes::from_static(b"pad"), unwaiting.clone())
                .await
                .map_err(|e| anyhow::anyhow!("{} cannot pad its log: {e}", device.name()))?;
            anyhow::ensure!(
                id.seq == next,
                "{} signed its padding at seq {}, not at {next}",
                device.name(),
                id.seq
            );
            next += 1;
        }
        let id = heap
            .put(path, bytes, unwaiting)
            .await
            .map_err(|e| anyhow::anyhow!("{} cannot sign at {seq}: {e}", device.name()))?;
        anyhow::ensure!(
            id.seq == seq,
            "{} signed at seq {}, not at {seq}",
            device.name(),
            id.seq
        );
        Ok(entry_of(space, &id))
    }

    async fn crash(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<Arc<dyn Spaces>> {
        self.relaunch(fabric, device, CrashStore::durable).await
    }

    async fn kill(&self, fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<Arc<dyn Spaces>> {
        self.relaunch(fabric, device, CrashStore::live).await
    }

    async fn image(&self, _fabric: &Fabric, device: &DeviceSpec) -> anyhow::Result<Image> {
        let run = self.run(device)?;
        // A backup taken now holds everything written so far: the flush comes first, unless the
        // disk is stalled (then the backup holds what it had made durable).
        if let Some(node) = run.node()
            && !run.store.held()
        {
            let _ = node.flush().await;
        }
        Ok(Image::new(run.store.durable()))
    }

    async fn restore(
        &self,
        fabric: &Fabric,
        device: &DeviceSpec,
        image: Image,
    ) -> anyhow::Result<Arc<dyn Spaces>> {
        let image = image
            .into_inner::<BTreeMap<Name, Bytes>>()
            .map_err(|_| anyhow::anyhow!("this image was not taken from an ndn-heap device"))?;
        self.relaunch(fabric, device, move |_| image).await
    }

    async fn block_flush(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        on: bool,
    ) -> anyhow::Result<()> {
        let run = self.run(device)?;
        let node = run.node();
        if on {
            // What returned before the call is durable; what comes after waits.
            if let Some(node) = node
                && !run.store.held()
            {
                let _ = node.flush().await;
            }
            run.store.hold(true);
        } else {
            run.store.hold(false);
            if let Some(node) = node {
                let _ = node.flush().await;
            }
        }
        Ok(())
    }

    async fn fail_flush(
        &self,
        _fabric: &Fabric,
        device: &DeviceSpec,
        reason: Option<&str>,
    ) -> anyhow::Result<()> {
        self.run(device)?.store.fail(reason);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ndn_sim::VirtualKernel;

    use super::*;
    use crate::cases::kit::{
        LIMIT, LOOK, agree, drain_until, has, heads, item, item_of, look, members_now, n, octets,
        people, private, required, winning,
    };
    use crate::world::{Dev, Plan, World};

    const LAPTOP: Dev = Dev(0);
    const PHONE: Dev = Dev(1);

    /// The same flow as the kit's proof over the old provider, over `ndn-heap`: a space is
    /// created by its owner, followed and written by a member's device, read alike on both,
    /// watched, overwritten, removed, and its members changed, and `applied` says what each
    /// device holds.
    #[test]
    fn a_space_over_ndn_heap_is_created_written_read_watched_and_changed() {
        VirtualKernel::new().run(|k| async move {
            let mut plan = Plan::new();
            plan.device("alice", "laptop");
            plan.device("bob", "phone");
            let w = World::build(k, &plan, NewReference::provider())
                .await
                .expect("the world builds");
            let space = n("/alice/32=data/notes");
            let path = n("/shopping");
            let (laptop, phone) = (w.spaces(LAPTOP), w.spaces(PHONE));

            laptop
                .create(&space, private(&["/bob"], &["/bob"]))
                .await
                .expect("the owner creates the space");
            w.retry_later(|| phone.open(&space))
                .await
                .expect("bob's phone follows the space");
            let owner = n("/alice");
            let both = SpaceMembers::new(&owner, people(&["/bob"]), people(&["/bob"]), false);
            // The record arrives in entries (the creation, then the additions): the device shows
            // what it holds, so the test waits for the whole of it.
            w.until("bob's phone holds the owner's record", LIMIT, || async {
                Ok(members_now(&*phone, &space).await?.as_ref() == Some(&both))
            })
            .await
            .expect("bob's phone receives the record, the owner listed once in both roles");

            // Bob writes; the owner's device converges on the same item.
            let first = w
                .space_put(PHONE, &space, &path, octets("milk"))
                .await
                .expect("bob writes");
            assert_eq!(first.writer, n("/bob/phone"));
            assert!(first.name.has_prefix(&first.writer), "{}", first.name);
            assert_eq!(first.name, wire::log_name(&first.writer, &space, first.seq));
            w.until("both devices agree on bob's write", LIMIT, || async {
                agree(&[&*laptop, &*phone], &space, &path, &[&first]).await
            })
            .await
            .expect("the devices agree");
            let read = required(&*laptop, &space, &path).await.unwrap();
            assert_eq!(read.bytes, octets("milk"));
            assert_eq!(read.by, n("/bob"), "the writer's person");
            assert_eq!(read.entry(), first, "the item names the entry bob signed");
            assert!(read.after.is_empty(), "the first write supersedes nothing");
            assert_eq!(read.path, path);

            // The entry read by its name, while it is the head of its path.
            match laptop.entry(&space, &first.name).await.unwrap() {
                EntryRead::Read(i) => assert_eq!(i.bytes, octets("milk")),
                other => panic!("the entry was read as {other:?}"),
            }

            // A watch lists the write and the record in force.
            let listing = look(&*laptop, &space, LOOK).await.unwrap();
            let listed = item_of(&listing, &first.key()).expect("the listing has bob's entry");
            assert_eq!(listed.bytes, octets("milk"));
            assert_eq!(heads(&listing, &path).len(), 1);
            assert!(
                listing
                    .iter()
                    .any(|e| matches!(e, SpaceEvent::Members(m) if *m == both)),
                "the listing starts with the members in force: {listing:?}"
            );

            // The owner overwrites it, knowing bob's write: it supersedes it, and wins.
            let second = w
                .space_put(LAPTOP, &space, &path, octets("eggs"))
                .await
                .expect("the owner writes");
            w.until("bob's phone applies the owner's write", LIMIT, || {
                has(&*phone, &space, &second)
            })
            .await
            .expect("the phone applies it");
            let over = winning(&*phone, &space, &path, &[&second]).await.unwrap();
            assert_eq!(over.bytes, octets("eggs"));
            assert!(
                over.after.iter().any(|a| a.covers(&first.key())),
                "the later write lists the earlier among what it superseded: {:?}",
                over.after
            );
            assert!(
                has(&*phone, &space, &first).await.unwrap(),
                "an applied entry stays applied once superseded"
            );
            let listing = look(&*phone, &space, LOOK).await.unwrap();
            assert_eq!(
                heads(&listing, &path)
                    .iter()
                    .map(|i| i.key())
                    .collect::<Vec<_>>(),
                [second.key()],
                "only the later write is a head"
            );

            // A removal is an empty write: the path holds nothing, and the watch reports it.
            let mut feed = laptop.watch(&space).await.unwrap();
            let gone = w
                .space_put(LAPTOP, &space, &path, bytes::Bytes::new())
                .await
                .expect("the owner removes the path");
            let mut events = Vec::new();
            drain_until(
                &mut *feed,
                &mut events,
                "the watch reports the removal",
                LIMIT,
                |seen| {
                    seen.iter()
                        .any(|e| matches!(e, SpaceEvent::Removed(i) if i.key() == gone.key()))
                },
            )
            .await
            .expect("the removal is reported");
            w.until("bob's phone sees the path removed", LIMIT, || async {
                Ok(has(&*phone, &space, &gone).await?
                    && item(&*phone, &space, &path).await?.is_none())
            })
            .await
            .expect("the removal arrives");

            // The owner removes bob from both roles.
            laptop
                .change(
                    &space,
                    SpaceChange {
                        remove: people(&["/bob"]),
                        ..SpaceChange::default()
                    },
                )
                .await
                .expect("the owner removes bob");
            let after = members_now(&*laptop, &space).await.unwrap().unwrap();
            assert_eq!(
                after,
                SpaceMembers::new(&owner, Vec::new(), Vec::new(), false)
            );
            w.shutdown().await;
        });
    }
}

#[cfg(test)]
mod durability_tests {
    use ndn_sim::VirtualKernel;

    use super::*;
    use crate::cases::kit::{n, octets, public, required};
    use crate::world::{Dev, Plan, World};

    const LAPTOP: Dev = Dev(0);

    /// What each way a device ends leaves in its store: a clean stop everything, a killed process
    /// everything its store accepted, a cut power what a flush covered, and a backup restored the
    /// backup's contents. A write by a device that knows no peer is durable when it returns, so
    /// the cut loses nothing here; the backup is what shows the store is the image's.
    #[test]
    fn a_device_restarts_on_what_its_store_holds_after_each_way_it_ends() {
        VirtualKernel::new().run(|k| async move {
            let mut plan = Plan::new();
            plan.device("alice", "laptop");
            let w = World::build(k, &plan, NewReference::provider())
                .await
                .expect("the world builds");
            let space = n("/alice/32=data/notes");
            let path = n("/a");
            let laptop = w.spaces(LAPTOP);
            laptop
                .create(&space, public(&[]))
                .await
                .expect("the owner creates the space");
            let one = w
                .space_put(LAPTOP, &space, &path, octets("one"))
                .await
                .expect("the first write");

            // A clean stop and a start on the same store: nothing is lost, and the next entry
            // follows the last with no hole.
            w.stop(LAPTOP).await.expect("the device stops");
            let again = w.restart(LAPTOP).await.expect("the device restarts");
            let read = required(&*again, &space, &path).await.unwrap();
            assert_eq!(read.entry(), one);
            let backup = w.image(LAPTOP).await.expect("a backup is taken");
            let two = w
                .space_put(LAPTOP, &space, &path, octets("two"))
                .await
                .expect("the device writes after a clean close");
            assert_eq!(two.seq, one.seq + 1, "a clean close leaves no hole");

            // A cut power: the writes returned are durable, so the device has both.
            let crashed = w.crash(LAPTOP).await.expect("the device crashes");
            let read = required(&*crashed, &space, &path).await.unwrap();
            assert_eq!(read.entry(), two, "the device restarts on both writes");

            // A killed process keeps what its store accepted.
            let killed = w.kill(LAPTOP).await.expect("the device is killed");
            let read = required(&*killed, &space, &path).await.unwrap();
            assert_eq!(read.entry(), two);

            // The backup put back: the device holds what the backup held.
            let restored = w
                .restore(LAPTOP, backup)
                .await
                .expect("the backup is restored");
            let read = required(&*restored, &space, &path).await.unwrap();
            assert_eq!(read.entry(), one, "the device holds the backup's contents");
            assert!(
                w.signed_by(LAPTOP) >= 3,
                "the signatures of the earlier runs are kept: {}",
                w.signed_by(LAPTOP)
            );
            w.shutdown().await;
        });
    }
}
