//! `ndn-data`'s [`Device`] as [`Spaces`]: the adapter that lets the neutral cases run on the old
//! provider until it leaves the suite.
//!
//! A space is a folder (`share_folder`), a path under it a register collection (`put_op`, the
//! built-in newest-wins rule): the collection of a path is the space's name followed by the path.
//! Old logs are per collection, so an entry's name is the log name of the collection
//! (`<device>/32=log/<space>/<path>/seq=<n>`) and its seq the collection's.
//!
//! The mapping, verb by verb:
//!
//! * `create`: `Sharing::Whole` with the register rule; the owner joins the writers, and, unless
//!   the space is public (no readers listed, which the old record reads as unsealed), the readers.
//! * `change`: `Sharing::Change`; `remove` removes from the writers and the readers.
//! * `members`: the record in force, normalised ([`SpaceMembers`]).
//! * `put`: `put_op` of the path's collection; the entry's digest is read back by its name.
//! * `get`: the merged state; its tips are read by name and the head with the highest signed
//!   digest, which nothing supersedes, gives the item's writer, seq, digest and `after`.
//! * `watch`: `Device::watch` from the empty frontier; versions are puts, or removals when they
//!   write no octets; summaries are skipped.
//! * `open`: a watch the adapter keeps, which keeps the device following the space.

use std::sync::Mutex;

use bytes::Bytes;
use futures::StreamExt;
use ndn_data::merge::NEWEST;
use ndn_data::wire::{device_of, log_name, namespace_of, parse_log_name};
use ndn_data::{
    Answer, Audience, Change, Changes, DataError, DataLayer, Device, Frontier, Got, Keep, Name,
    Payload, PutOptions, Refusal, Rule, Seq, Share, ShareChange, Sharing, TypeId, Version,
    VersionId, Writer,
};

use crate::case::Failure;
use crate::reference::device_key;
use crate::spaces::{
    AlertKind, EntryRead, RefusalKind, SpaceAlert, SpaceChange, SpaceChanges, SpaceEntry,
    SpaceEntryKey, SpaceEvent, SpaceItem, SpaceMembers, SpaceShare, Spaces,
};

/// One `ndn-data` device as [`Spaces`].
pub struct OldSpaces {
    layer: Device,
    /// Every person's namespace of the case: a device's person is the longest that is a prefix
    /// of its name.
    persons: Vec<Name>,
    /// The watches [`Spaces::open`] keeps, so the device keeps following their spaces.
    held: Mutex<Vec<Changes>>,
}

impl OldSpaces {
    /// `layer`'s spaces, for a case whose people are `persons`.
    pub fn new(layer: Device, persons: Vec<Name>) -> Self {
        Self {
            layer,
            persons,
            held: Mutex::new(Vec::new()),
        }
    }

    fn view(&self) -> View<'_> {
        View {
            persons: &self.persons,
        }
    }
}

/// What turns old versions into neutral items.
#[derive(Clone, Copy)]
struct View<'a> {
    persons: &'a [Name],
}

/// The bytes of a register write: the old register's value is `by ‖ bytes`.
const BY: usize = 32;

/// The type of the bytes a register write carries.
fn bytes_type() -> TypeId {
    TypeId {
        name: "/types/note".parse().expect("a valid name"),
        revision: 1,
    }
}

fn join(space: &Name, path: &Name) -> Name {
    Name::from_components(space.components().iter().chain(path.components()).cloned())
}

fn collection_of(space: &Name, path: &Name) -> Result<Name, Failure> {
    if path.is_empty() {
        return Err(Failure::new(format!(
            "a write into {space} needs a path: the old provider keeps one register per path"
        )));
    }
    Ok(join(space, path))
}

fn owner_of(space: &Name) -> Result<Name, Failure> {
    namespace_of(space).ok_or_else(|| Failure::new(format!("{space} is no space name")))
}

fn register() -> Rule {
    Rule::Merge {
        function: NEWEST.parse().expect("the register's name"),
    }
}

fn audience_name(a: &Audience) -> &Name {
    match a {
        Audience::Person(n) | Audience::Device(n) | Audience::Group(n) => n,
    }
}

/// The record `share` as the normalised members of a space owned by `owner`.
fn normalised(owner: &Name, share: &Share) -> SpaceMembers {
    SpaceMembers::new(
        owner,
        share.writers.clone(),
        share
            .readers
            .iter()
            .map(|a| audience_name(a).clone())
            .collect(),
        share.readers.is_empty(),
    )
}

fn refusal_kind(why: &Refusal) -> RefusalKind {
    match why {
        Refusal::OutsideCut(_) => RefusalKind::OutsideCut,
        Refusal::Untrusted { .. } => RefusalKind::Untrusted,
        _ => RefusalKind::Other,
    }
}

impl View<'_> {
    /// The person whose namespace `device` lies under.
    fn person_of(&self, device: &Name) -> Name {
        self.persons
            .iter()
            .filter(|p| device.has_prefix(p))
            .max_by_key(|p| p.len())
            .cloned()
            .unwrap_or_else(|| device.clone())
    }

    fn writer_device(id: &VersionId) -> Result<Name, Failure> {
        device_of(id.writer.key())
            .ok_or_else(|| Failure::new(format!("{} is no device key", id.writer.key())))
    }

    /// The key of the entry `id` of `collection`.
    fn key_of(id: &VersionId, collection: &Name) -> Result<SpaceEntryKey, Failure> {
        let writer = Self::writer_device(id)?;
        Ok(SpaceEntryKey {
            name: log_name(&writer, Some(collection), id.seq.0),
            writer,
            seq: id.seq.0,
        })
    }

    /// The version `v` of a collection under `space` as an item that wrote `bytes`.
    fn item(&self, space: &Name, v: &Version, bytes: Bytes) -> Result<SpaceItem, Failure> {
        let key = Self::key_of(&v.id, &v.collection)?;
        let path = if v.collection.has_prefix(space) {
            Name::from_components(v.collection.components()[space.len()..].iter().cloned())
        } else {
            v.collection.clone()
        };
        let mut after = Vec::new();
        for (writer, seq) in v.parents.iter() {
            after.push(Self::key_of(
                &VersionId {
                    writer: writer.clone(),
                    seq,
                },
                &v.collection,
            )?);
        }
        Ok(SpaceItem {
            path,
            bytes,
            by: self.person_of(&key.writer),
            name: key.name,
            writer: key.writer,
            seq: key.seq,
            signed: v.signed,
            after,
        })
    }
}

#[async_trait::async_trait]
impl Spaces for OldSpaces {
    async fn create(&self, space: &Name, share: SpaceShare) -> Result<(), Failure> {
        let owner = owner_of(space)?;
        let mut writers = share.writers;
        if !writers.contains(&owner) {
            writers.push(owner.clone());
        }
        let readers = if share.anyone {
            Vec::new()
        } else {
            let mut readers = share.readers;
            if !readers.contains(&owner) {
                readers.push(owner);
            }
            readers.into_iter().map(Audience::Person).collect()
        };
        self.layer
            .share_folder(
                space,
                Sharing::Whole(Share {
                    rule: register(),
                    writers,
                    readers,
                }),
            )
            .await?;
        Ok(())
    }

    async fn change(&self, space: &Name, change: SpaceChange) -> Result<(), Failure> {
        let person = |names: Vec<Name>| names.into_iter().map(Audience::Person).collect();
        self.layer
            .share_folder(
                space,
                Sharing::Change(ShareChange {
                    add_writers: change.add_writers,
                    remove_writers: change.remove.clone(),
                    add_readers: person(change.add_readers),
                    remove_readers: person(change.remove),
                }),
            )
            .await?;
        Ok(())
    }

    async fn members(&self, space: &Name) -> Result<SpaceMembers, Failure> {
        let share = self.layer.members(space).await?;
        Ok(normalised(&owner_of(space)?, &share))
    }

    async fn put(&self, space: &Name, path: &Name, bytes: Bytes) -> Result<SpaceEntry, Failure> {
        let collection = collection_of(space, path)?;
        let options = PutOptions {
            type_id: bytes_type(),
            keep: Keep::Forever,
        };
        let id = self.layer.put_op(&collection, bytes, options).await?;
        let key = View::key_of(&id, &collection)?;
        let signed = match self.layer.get(&key.name).await? {
            Answer {
                got: Got::Version(v),
                ..
            } => v.signed,
            Answer { got, .. } => {
                return Err(Failure::new(format!(
                    "get of the entry {} just written answered {got:?}, not the version",
                    key.name
                )));
            }
        };
        Ok(SpaceEntry {
            name: key.name,
            writer: key.writer,
            seq: key.seq,
            signed,
        })
    }

    async fn get(&self, space: &Name, path: &Name) -> Result<Option<SpaceItem>, Failure> {
        let collection = collection_of(space, path)?;
        let answer = match self.layer.get(&collection).await {
            Ok(answer) => answer,
            Err(DataError::NotFound { .. } | DataError::Unavailable { .. }) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let Got::State(state) = answer.got else {
            return Err(Failure::new(format!(
                "get on the register {collection} answered {:?}; it must answer the merged state",
                answer.got
            )));
        };
        let bytes = state
            .value
            .bytes()
            .map(|b| b.slice(BY.min(b.len())..))
            .unwrap_or_default();
        if bytes.is_empty() {
            return Ok(None);
        }
        // The tips of the state: each writer's newest applied version. The heads are the tips
        // no other tip lists among its parents; the register reads the head with the highest
        // signed digest.
        let mut tips = Vec::new();
        for (writer, seq) in state.at.iter() {
            let id = VersionId {
                writer: writer.clone(),
                seq,
            };
            let name = View::key_of(&id, &collection)?.name;
            match self.layer.get(&name).await? {
                Answer {
                    got: Got::Version(v),
                    ..
                } => tips.push(v),
                Answer { got, .. } => {
                    return Err(Failure::new(format!(
                        "get of the tip {name} answered {got:?}, not the version"
                    )));
                }
            }
        }
        let head = tips
            .iter()
            .filter(|v| {
                !tips
                    .iter()
                    .any(|o| o.id != v.id && o.parents.contains(&v.id))
            })
            .max_by_key(|v| v.signed)
            .ok_or_else(|| {
                Failure::new(format!(
                    "the state of {collection} holds a value and no version"
                ))
            })?;
        self.view().item(space, head, bytes).map(Some)
    }

    async fn watch(&self, space: &Name) -> Result<Box<dyn SpaceChanges>, Failure> {
        let stream = self.layer.watch(space, &Frontier::new()).await?;
        Ok(Box::new(OldChanges {
            stream,
            layer: self.layer.clone(),
            space: space.clone(),
            persons: self.persons.clone(),
            pending: None,
        }))
    }

    async fn open(&self, space: &Name) -> Result<(), Failure> {
        let stream = self.layer.watch(space, &Frontier::new()).await?;
        self.held.lock().expect("the held watches").push(stream);
        Ok(())
    }

    async fn applied(&self, _space: &Name, entry: &SpaceEntry) -> Result<bool, Failure> {
        let log = parse_log_name(&entry.name)
            .ok_or_else(|| Failure::new(format!("{} is no log entry name", entry.name)))?;
        let collection = log
            .subject
            .ok_or_else(|| Failure::new(format!("{} names no collection", entry.name)))?;
        let id = VersionId {
            writer: Writer::new(device_key(&log.device)),
            seq: Seq(log.seq),
        };
        match self.layer.get(&collection).await {
            Ok(Answer {
                got: Got::State(state),
                ..
            }) => Ok(state.at.contains(&id)),
            Ok(Answer { got, .. }) => Err(Failure::new(format!(
                "get on the register {collection} answered {got:?}, not its state"
            ))),
            Err(DataError::NotFound { .. } | DataError::Unavailable { .. }) => Ok(false),
            Err(e) if e.next() == ndn_data::NextStep::RetryLater => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    async fn entry(&self, space: &Name, name: &Name) -> Result<EntryRead, Failure> {
        match self.layer.get(name).await {
            Ok(Answer {
                got: Got::Version(v),
                ..
            }) => {
                let bytes = match v.op.clone() {
                    Some(op) => op,
                    None => {
                        return Err(Failure::new(format!(
                            "{name} was read, and its octets are not open on this device"
                        )));
                    }
                };
                Ok(EntryRead::Read(self.view().item(space, &v, bytes)?))
            }
            Ok(Answer { got, .. }) => Err(Failure::new(format!(
                "get of the entry {name} answered {got:?}, not the version"
            ))),
            Err(DataError::Refused { id, why }) => Ok(EntryRead::Refused {
                kind: refusal_kind(&why),
                text: DataError::Refused { id, why }.to_string(),
            }),
            Err(DataError::NotFound { .. } | DataError::Unavailable { .. }) => {
                Ok(EntryRead::NotHeld)
            }
            Err(e) => Err(e.into()),
        }
    }
}

/// A watch of a space, as neutral events.
struct OldChanges {
    stream: Changes,
    layer: Device,
    space: Name,
    persons: Vec<Name>,
    /// The change being turned into an event, kept while the turning waits, so a cancelled
    /// [`SpaceChanges::next`] loses nothing.
    pending: Option<Change>,
}

impl OldChanges {
    /// `change` as an event, if it is one. Takes the parts of the watch it needs and not the
    /// watch itself, whose stream is not `Sync`.
    async fn event(
        layer: &Device,
        space: &Name,
        persons: &[Name],
        change: Change,
    ) -> Result<Option<SpaceEvent>, Failure> {
        let view = View { persons };
        Ok(Some(match change {
            Change::Summary(_) => return Ok(None),
            Change::Version(v) => {
                let bytes = match v.op.clone() {
                    Some(op) => Some(op),
                    // A large operation travels in pieces: reading the version by its name
                    // reads it whole.
                    None if matches!(v.payload, Payload::Large { .. }) => {
                        match layer.get(&v.name).await {
                            Ok(Answer {
                                got: Got::Version(whole),
                                ..
                            }) => whole.op,
                            _ => None,
                        }
                    }
                    None => None,
                };
                match bytes {
                    Some(bytes) if bytes.is_empty() => {
                        SpaceEvent::Removed(view.item(space, &v, bytes)?)
                    }
                    Some(bytes) => SpaceEvent::Put(view.item(space, &v, bytes)?),
                    None => SpaceEvent::Alert(SpaceAlert {
                        kind: AlertKind::Other,
                        detail: format!("{}: its octets are not open on this device", v.name),
                    }),
                }
            }
            Change::Withdrawn {
                collection,
                id,
                why,
            } => SpaceEvent::Withdrawn {
                entry: View::key_of(&id, &collection)?,
                kind: refusal_kind(&why),
                why: format!("{why:?}"),
            },
            Change::Equivocation {
                collection,
                first,
                second,
            } => {
                let id = first.id();
                SpaceEvent::Alert(SpaceAlert {
                    kind: AlertKind::Equivocation {
                        device: View::writer_device(id)?,
                        seq: id.seq.0,
                    },
                    detail: format!(
                        "two versions at seq {} of {collection}: {} and {}",
                        id.seq.0,
                        first.name(),
                        second.name()
                    ),
                })
            }
            Change::Lagged { .. } => SpaceEvent::Lagged,
            Change::Untracked {
                collection,
                writer,
                why,
            } => SpaceEvent::Alert(SpaceAlert {
                kind: AlertKind::Other,
                detail: format!("{collection} of {} is not followed: {why}", writer.key()),
            }),
            Change::NotAdopted {
                collection, why, ..
            } => SpaceEvent::Alert(SpaceAlert {
                kind: AlertKind::Other,
                detail: format!("namespaces of {collection} are not adopted: {why}"),
            }),
            Change::Members { collection, share } => {
                SpaceEvent::Members(normalised(&owner_of(&collection)?, &share))
            }
        }))
    }
}

#[async_trait::async_trait]
impl SpaceChanges for OldChanges {
    async fn next(&mut self) -> Option<Result<SpaceEvent, Failure>> {
        loop {
            if self.pending.is_none() {
                match self.stream.next().await? {
                    Ok(change) => self.pending = Some(change),
                    Err(e) => return Some(Err(e.into())),
                }
            }
            let change = self.pending.clone().expect("set above");
            let event = Self::event(&self.layer, &self.space, &self.persons, change).await;
            self.pending = None;
            match event {
                Ok(Some(event)) => return Some(Ok(event)),
                Ok(None) => {}
                Err(e) => return Some(Err(e)),
            }
        }
    }
}
