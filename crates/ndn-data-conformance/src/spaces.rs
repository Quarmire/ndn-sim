//! The neutral surface of a shared space, as the cases drive it: [`Spaces`], one device's view of
//! the spaces it follows, and the plain data it speaks in.
//!
//! A **space** is a name `<O>/32=data/<c1>[/<c2>..]`, owned by the namespace `<O>`. Inside it a
//! **path** (a name relative to the space) holds one register: the bytes of the newest write,
//! where the newest is the head with the highest signed digest ([`SpaceItem::signed`]) of the
//! entries nothing supersedes ([`SpaceItem::after`]); an empty write removes the path. A member is
//! a **person**, by namespace, matched exactly; the owner is an implicit writer and, in a space
//! that is not public, an implicit reader.
//!
//! Every type here is plain data (`Clone + Debug + PartialEq`): what a provider answers is
//! compared and kept by the cases without knowing which provider it came from. A refusal a verb
//! answers is a [`Failure`], whose `next` names the next step (`"RetryLater"`, …) by kind.

use bytes::Bytes;
use ndn_data::Name;

use crate::case::Failure;

/// Who may write and read a space, as its owner creates it ([`Spaces::create`]).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpaceShare {
    /// Anyone reads: the space is public, and `readers` is not consulted.
    pub anyone: bool,
    /// The persons (by namespace) that may read, besides the owner. With `anyone == false` and
    /// no readers either, the owner alone reads.
    pub readers: Vec<Name>,
    /// The persons (by namespace) that may write, besides the owner.
    pub writers: Vec<Name>,
}

/// A change to a space's members, signed by the owner against the record in force when it signs
/// ([`Spaces::change`]): a person added meanwhile stays.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpaceChange {
    /// Persons to add as writers.
    pub add_writers: Vec<Name>,
    /// Persons to add as readers.
    pub add_readers: Vec<Name>,
    /// Persons to remove from **both** roles, exactly as listed. A removed writer is cut at what
    /// the owner had seen of it; a removed reader loses the keys of later epochs.
    pub remove: Vec<Name>,
}

/// The members in force over a space, as a device holds them ([`Spaces::members`]).
///
/// Normalised so the same assertions hold on every provider: `writers` is every person that may
/// write, the owner included; `readers` is every person that may read, the owner included, and
/// empty exactly when the space is `public`; both are sorted in [`Name`] order (the canonical
/// NDN order: shorter components first, so `/bob` sorts before `/alice`) and without duplicates.
/// A writer is not thereby a reader. A provider builds it, and a case states what it expects,
/// with [`SpaceMembers::new`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpaceMembers {
    /// Every writer, owner included.
    pub writers: Vec<Name>,
    /// Every reader, owner included; empty when the space is public.
    pub readers: Vec<Name>,
    /// Anyone reads.
    pub public: bool,
}

impl SpaceMembers {
    /// The normalised members of a space owned by `owner`: `writers` and `readers` are what the
    /// record lists besides the owner (or with it), `public` that anyone reads.
    pub fn new(owner: &Name, writers: Vec<Name>, readers: Vec<Name>, public: bool) -> Self {
        let normalise = |mut names: Vec<Name>| {
            names.push(owner.clone());
            names.sort();
            names.dedup();
            names
        };
        Self {
            writers: normalise(writers),
            readers: if public {
                Vec::new()
            } else {
                normalise(readers)
            },
            public,
        }
    }
}

/// The identity of a signed log entry: what a later entry's [`SpaceItem::after`] names, what a
/// cut, a withdrawal and a re-admission speak of.
///
/// `name` is the entry's name without its implicit digest, `<writer>/32=log/<…>/seq=<n>`; a
/// provider fills `writer` and `seq` from it. Two keys are equal when they name the same entry.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpaceEntryKey {
    /// The entry's log name, ending in `seq=<n>`.
    pub name: Name,
    /// The writing device.
    pub writer: Name,
    /// Its sequence number in the writer's log.
    pub seq: u64,
}

impl SpaceEntryKey {
    /// Whether this key supersedes `other`: the same writer's log, at this seq or after. A write
    /// lists the tips of what it had applied, and a tip stands for every earlier entry of its
    /// writer's log.
    pub fn covers(&self, other: &SpaceEntryKey) -> bool {
        let (mine, theirs) = (self.name.components(), other.name.components());
        self.seq >= other.seq
            && self.writer == other.writer
            && mine.len() == theirs.len()
            && mine[..mine.len().saturating_sub(1)] == theirs[..theirs.len().saturating_sub(1)]
    }
}

/// A signed log entry a device wrote ([`Spaces::put`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceEntry {
    /// The entry's full name, `<writer>/32=log/<…>/seq=<n>` without its implicit digest: the
    /// name a cut and a re-admission speak of. The provider fills it.
    pub name: Name,
    /// The writing device.
    pub writer: Name,
    /// Its sequence number in the writer's log.
    pub seq: u64,
    /// The digest of the entry's signed region: what the register breaks ties by, the same on
    /// every copy of the packet.
    pub signed: [u8; 32],
}

impl SpaceEntry {
    /// The entry's identity.
    pub fn key(&self) -> SpaceEntryKey {
        SpaceEntryKey {
            name: self.name.clone(),
            writer: self.writer.clone(),
            seq: self.seq,
        }
    }
}

/// What a path holds, with the entry that wrote it ([`Spaces::get`], [`SpaceEvent::Put`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceItem {
    /// The path, relative to the space.
    pub path: Name,
    /// The octets written; empty for a removal ([`SpaceEvent::Removed`]).
    pub bytes: Bytes,
    /// The writer's person: the namespace of the context that validates its key.
    pub by: Name,
    /// The entry's full name ([`SpaceEntry::name`]).
    pub name: Name,
    /// The writing device.
    pub writer: Name,
    /// The entry's sequence number in the writer's log.
    pub seq: u64,
    /// The entry's signed-region digest ([`SpaceEntry::signed`]).
    pub signed: [u8; 32],
    /// The heads this write superseded: the entries its writer had applied when it signed.
    pub after: Vec<SpaceEntryKey>,
}

impl SpaceItem {
    /// The entry's identity.
    pub fn key(&self) -> SpaceEntryKey {
        SpaceEntryKey {
            name: self.name.clone(),
            writer: self.writer.clone(),
            seq: self.seq,
        }
    }

    /// The entry that wrote it.
    pub fn entry(&self) -> SpaceEntry {
        SpaceEntry {
            name: self.name.clone(),
            writer: self.writer.clone(),
            seq: self.seq,
            signed: self.signed,
        }
    }
}

/// Why a log entry is refused or withdrawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalKind {
    /// A removal cut keeps the writer's entries up to a tip, and this one lies outside it.
    OutsideCut,
    /// The writer's key or its chain of certificates is no longer trusted (a revoked issuer).
    Untrusted,
    /// Anything else: a lapsed key, a person that is no member, a bad signature, …
    Other,
}

/// What reading a log entry by its full name answered ([`Spaces::entry`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntryRead {
    /// The entry, applied or held: what it wrote.
    Read(SpaceItem),
    /// The device holds or fetched the entry and refuses it.
    Refused {
        /// Why, by kind.
        kind: RefusalKind,
        /// Why, in words.
        text: String,
    },
    /// The device does not hold the entry and no holder answered.
    NotHeld,
}

/// The epoch a sealed space is sealed in, as a device's fold of the owner's entries holds it
/// ([`Spaces::epoch`]): the one writers seal in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceEpoch {
    /// The owner device that signed the epoch's entry.
    pub creator: Name,
    /// That entry's sequence number in its creator's log; `(creator, seq)` names the epoch.
    pub seq: u64,
    /// Whether every person that reads the space holds the epoch's key or is to be given it, and
    /// nobody else ever was: nothing left for an owner device to repair.
    pub complete: bool,
}

/// What kind of event a device raises beside the changes it applies ([`SpaceAlert`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AlertKind {
    /// Two different entries at one `(writer, seq)`: evidence against `device`'s key.
    Equivocation {
        /// The device whose key signed both.
        device: Name,
        /// The sequence number of the two entries.
        seq: u64,
    },
    /// An entry the device refuses as outside a cut.
    OutsideCut,
    /// The device finds its own store behind what its peers hold of its log: restored from an
    /// image.
    RolledBack,
    /// A signed statement that a stretch of a log was lost: the entries in it will never come.
    GapSigned,
    /// A counter heard of a log above the entries that back it: reported, never trusted.
    UnbackedCounter,
    /// An entry or request refused.
    Refused,
    /// The device's store failed to keep something.
    StoreFailed,
    /// Anything else, described in [`SpaceAlert::detail`].
    Other,
}

/// A report a device raises beside the changes it applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpaceAlert {
    /// What kind.
    pub kind: AlertKind,
    /// In words.
    pub detail: String,
}

/// One item of a watch ([`SpaceChanges::next`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpaceEvent {
    /// An entry the device applied (or one it listed when the watch began): a path now holds
    /// these octets.
    Put(SpaceItem),
    /// An entry the device applied that removes its path (empty bytes).
    Removed(SpaceItem),
    /// An entry delivered before is no longer accepted: a cut or a revocation arrived later and
    /// refuses it.
    Withdrawn {
        /// The entry.
        entry: SpaceEntryKey,
        /// Why, by kind.
        kind: RefusalKind,
        /// Why, in words.
        why: String,
    },
    /// The members in force over the space changed.
    Members(SpaceMembers),
    /// A report beside the changes.
    Alert(SpaceAlert),
    /// The watcher fell behind and changes were dropped: read the space again.
    Lagged,
}

/// The stream a [`Spaces::watch`] returns: first what the device has applied, then everything
/// new. It ends only when the device stops.
#[async_trait::async_trait]
pub trait SpaceChanges: Send {
    /// The next event, or `None` when the device has stopped. Cancel-safe: a dropped future loses
    /// nothing, so a caller may wait with a timeout and ask again.
    async fn next(&mut self) -> Option<Result<SpaceEvent, Failure>>;
}

/// One device's view of the spaces it follows.
///
/// A refusal is a [`Failure`] with `next` set when the verb named a next step: `"RetryLater"`
/// when the device has not yet received what the verb needs (a members record that admits it,
/// the keys of an epoch), which a case waits out ([`crate::world::World::retry_later`]).
#[async_trait::async_trait]
pub trait Spaces: Send + Sync {
    /// The owner, on one of its devices, creates `space` with these members. The space's first
    /// members record; its owner is the namespace before `32=data`.
    async fn create(&self, space: &Name, share: SpaceShare) -> Result<(), Failure>;

    /// The owner changes the members in force: persons added, persons removed from both roles.
    /// A change that changes nothing signs nothing.
    async fn change(&self, space: &Name, change: SpaceChange) -> Result<(), Failure>;

    /// The members in force over `space` as this device holds them ([`SpaceMembers`]);
    /// `RetryLater` while it holds none.
    async fn members(&self, space: &Name) -> Result<SpaceMembers, Failure>;

    /// Write `bytes` at `path` of `space` (a non-empty name relative to the space, spelled with
    /// its leading slash: `/shopping`), as a new entry superseding what the device had applied;
    /// empty `bytes` remove the path. Visible on this device at once. Returns the signed entry.
    async fn put(&self, space: &Name, path: &Name, bytes: Bytes) -> Result<SpaceEntry, Failure>;

    /// What `path` of `space` holds now by this device's applied entries: the head that wins,
    /// with its octets. `None` when nothing was written there, when the last write removed it,
    /// or when the device holds nothing of the path yet.
    async fn get(&self, space: &Name, path: &Name) -> Result<Option<SpaceItem>, Failure>;

    /// Watch `space`: every path under it, those first written after the watch began included.
    async fn watch(&self, space: &Name) -> Result<Box<dyn SpaceChanges>, Failure>;

    /// Start following `space` on this device and keep following it (join its sync group, fetch
    /// its members record and entries) without anyone watching.
    async fn open(&self, space: &Name) -> Result<(), Failure>;

    /// Whether this device has applied the entry: its state covers it. Entries the device refuses
    /// or has not received are not applied.
    async fn applied(&self, space: &Name, entry: &SpaceEntry) -> Result<bool, Failure>;

    /// Read the log entry whose name (`<writer>/32=log/<…>/seq=<n>`) is `name`, as a reader that
    /// asks for it by that name: what it wrote, the refusal of the device that holds it, or that
    /// it holds none.
    async fn entry(&self, space: &Name, name: &Name) -> Result<EntryRead, Failure>;

    /// The epoch in force over the sealed `space`, as this device's fold holds it. `None` for a
    /// public space, or while no epoch is in force (a removal's repair not signed yet).
    /// A provider whose spaces have no epochs of this kind answers a refusal.
    async fn epoch(&self, space: &Name) -> Result<Option<SpaceEpoch>, Failure> {
        let _ = space;
        Err(Failure::new(
            "this provider does not report the epoch in force",
        ))
    }
}
