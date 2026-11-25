//! The kit the cases written over [`Spaces`] share: names and octets, reading a path on several
//! devices, watching a space and looking for what a watch reported, and the helpers of the
//! keys-over-time cases. Everything here speaks the neutral types of [`crate::spaces`], so a
//! case that imports only from here runs on every provider.
//!
//! The cases import their kit from this module explicitly (`use super::kit::{...}`).
//!
//! A register path holds the bytes of the head with the highest signed digest
//! ([`SpaceItem::signed`]) among the heads (the entries no other entry's `after` supersedes):
//! every device converges to one value ([`agree`]), and the value is what the heads say
//! ([`winning`]) — rule R.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;

use crate::case::Failure;
use crate::ensure;
use crate::spaces::{
    AlertKind, RefusalKind, SpaceChanges, SpaceEntry, SpaceEntryKey, SpaceEvent, SpaceItem,
    SpaceMembers, SpaceShare, Spaces,
};
use crate::world::{Dev, World};

/// How long devices that can reach each other get to agree.
pub const LIMIT: Duration = Duration::from_secs(120);
/// How long a device that reaches a writer's data only through a copy another device holds gets
/// to read it. A walk asks the unreachable writer first, in each of its three tries, before it
/// asks a device that holds the packet for it, so each packet of the walk (root, folder,
/// collection, page, entry) costs about 7 s of virtual time before it is had: 39 s with no loss
/// at all, and 43 to 100 s at 20 % loss over fault seeds 0 to 159 (i20, i22 once 133 s),
/// against a [`LIMIT`] of 120 s.
pub const RELAYED: Duration = Duration::from_secs(300);
/// How long a case lets the network run before asserting that something did *not* happen.
pub const SETTLE: Duration = Duration::from_secs(60);
/// How long a watch is drained for one look at a space.
pub const LOOK: Duration = Duration::from_secs(5);
/// A day.
pub const DAY: Duration = Duration::from_secs(24 * 3600);

/// The name `s`.
pub fn n(s: &str) -> Name {
    s.parse().expect("case names are valid NDN names")
}

/// The names of `people`: persons (`"/alice"`) or paths.
pub fn people(people: &[&str]) -> Vec<Name> {
    people.iter().map(|p| n(p)).collect()
}

/// The octets of `s`.
pub fn octets(s: &str) -> Bytes {
    Bytes::copy_from_slice(s.as_bytes())
}

/// Whether `part` appears in `bytes`.
pub fn contains(bytes: &[u8], part: &[u8]) -> bool {
    !part.is_empty() && bytes.windows(part.len()).any(|w| w == part)
}

/// A photo's octets: about 1.6 MB, some 390 chunks of 4096 octets.
pub const IMAGE: usize = 1_600_000;

/// The octets of a photo named `file` of `len` octets, the same every run: they come from a
/// generator (xorshift) seeded by the name, so no store can shrink them.
pub fn picture(file: &str, len: usize) -> Bytes {
    let mut x = file.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    let mut image = Vec::with_capacity(len + 8);
    while image.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        image.extend_from_slice(&x.to_le_bytes());
    }
    image.truncate(len);
    Bytes::from(image)
}

/// A space only its members read: `writers` write beside the owner, `readers` read beside it.
pub fn private(writers: &[&str], readers: &[&str]) -> SpaceShare {
    SpaceShare {
        anyone: false,
        readers: people(readers),
        writers: people(writers),
    }
}

/// A public space: anyone reads, `writers` write beside the owner.
pub fn public(writers: &[&str]) -> SpaceShare {
    SpaceShare {
        anyone: true,
        readers: Vec::new(),
        writers: people(writers),
    }
}

/// What `spaces` holds at `path` of `space` now; `None` while it holds nothing there, or while
/// the device answers `"RetryLater"` (a record admitting it not received or walked to yet: read
/// again).
pub async fn item(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
) -> Result<Option<SpaceItem>, Failure> {
    match spaces.get(space, path).await {
        Ok(item) => Ok(item),
        Err(e) if e.retry_later() => Ok(None),
        Err(e) => Err(e),
    }
}

/// The octets at `path` of `space` now ([`item`]'s); `None` while nothing is held there.
pub async fn value_now(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
) -> Result<Option<Bytes>, Failure> {
    Ok(item(spaces, space, path).await?.map(|i| i.bytes))
}

/// What `path` holds, which must exist.
pub async fn required(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
) -> Result<SpaceItem, Failure> {
    item(spaces, space, path)
        .await?
        .ok_or_else(|| Failure::new(format!("nothing is held at {path} of {space}")))
}

/// Whether `spaces` reads the write of `entry` at `path` of `space` now. A device that is no
/// longer a reader may answer the read with a refusal (`AskOwner`, a sealed path) or with what it
/// held before; either way it does not read `entry`, so a refusal is `false`, and so is the wait
/// for a record (`"RetryLater"`). A failure of any other kind is returned.
pub async fn reads_entry(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
    entry: &SpaceEntry,
) -> Result<bool, Failure> {
    match spaces.get(space, path).await {
        Ok(read) => Ok(read.is_some_and(|read| read.key() == entry.key())),
        Err(e) if e.retry_later() || e.next_is("AskOwner") || e.kind_is("Sealed") => Ok(false),
        Err(e) => Err(e),
    }
}

/// Whether `spaces` has applied `entry`; `false` while the device answers `"RetryLater"`.
pub async fn has(spaces: &dyn Spaces, space: &Name, entry: &SpaceEntry) -> Result<bool, Failure> {
    match spaces.applied(space, entry).await {
        Ok(applied) => Ok(applied),
        Err(e) if e.retry_later() => Ok(false),
        Err(e) => Err(e),
    }
}

/// Whether `spaces` holds the key of the epoch in force of the sealed `space`, so a put seals now
/// ([`Spaces::holds_epoch_key`]); `false` while the device answers `"RetryLater"`. A device that
/// is to write while it is cut off from the others (offline) first waits for this: the key comes
/// by one exchange on the network, which on a lossy one takes seconds.
pub async fn holds_key(spaces: &dyn Spaces, space: &Name) -> Result<bool, Failure> {
    match spaces.holds_epoch_key(space).await {
        Ok(held) => Ok(held),
        Err(e) if e.retry_later() => Ok(false),
        Err(e) => Err(e),
    }
}

/// Whether `a` and `b` hold the same epoch in force of the sealed `space`: the owner's devices
/// each sign an epoch for the readers they see and the greatest one is in force, so until each
/// has learned of the other's, the epoch in force of one may still change. `false` while either
/// answers `"RetryLater"`; `true` for a provider that reports no epochs.
pub async fn same_epoch(a: &dyn Spaces, b: &dyn Spaces, space: &Name) -> Result<bool, Failure> {
    let id = |e: Option<crate::spaces::SpaceEpoch>| e.map(|e| (e.creator, e.seq));
    match (a.epoch(space).await, b.epoch(space).await) {
        (Ok(a), Ok(b)) => Ok(id(a) == id(b)),
        (Err(e), _) | (_, Err(e)) if e.retry_later() => Ok(false),
        (Err(_), _) | (_, Err(_)) => Ok(true),
    }
}

/// Whether `spaces` knows the space's members record, so its writes go into the space as shared.
pub async fn known(spaces: &dyn Spaces, space: &Name) -> Result<bool, Failure> {
    Ok(members_now(spaces, space).await?.is_some())
}

/// What a person is listed as in a space's members record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Listed among the writers.
    Writer,
    /// Listed among the readers (or the space is public).
    Reader,
}

/// Wait until the device of `spaces` has applied the members change that lists `person` as
/// `role` of `space`: its [`Spaces::members`] lists the person. A device holding a record older
/// than the change cannot know it was added, so for as long as it holds that one it refuses the
/// person's verbs as an outsider's (`AskOwner`) and reads nothing: a case that writes or reads as
/// the new member waits for this first, as the refusal's next step says to wait for the owner's
/// record.
pub async fn joined(
    w: &World,
    spaces: &dyn Spaces,
    space: &Name,
    person: &Name,
    role: Role,
) -> Result<(), Failure> {
    w.until(
        &format!("the device lists {person} as {role:?} of {space}"),
        LIMIT,
        || async {
            Ok(members_now(spaces, space)
                .await?
                .is_some_and(|m| match role {
                    Role::Writer => m.writers.contains(person),
                    Role::Reader => m.public || m.readers.contains(person),
                }))
        },
    )
    .await?;
    Ok(())
}

/// The members `spaces` holds over `space`; `None` while it holds none (`"RetryLater"`).
pub async fn members_now(
    spaces: &dyn Spaces,
    space: &Name,
) -> Result<Option<SpaceMembers>, Failure> {
    match spaces.members(space).await {
        Ok(members) => Ok(Some(members)),
        Err(e) if e.retry_later() => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether every device holds the same item at `path` of `space`, with every entry in `entries`
/// applied. Every device is read at each poll: a device's first read of a space is its first look,
/// from which it follows the space, so reading a device only once those before it hold would begin
/// its look late and time the devices one after another rather than side by side.
pub async fn agree(
    spaces: &[&dyn Spaces],
    space: &Name,
    path: &Name,
    entries: &[&SpaceEntry],
) -> Result<bool, Failure> {
    agree_reading(spaces, space, path, entries, false).await
}

/// [`agree`] for a wait in which a device is still being admitted (added by a record it has not
/// received yet): meanwhile the device may refuse the read (`AskOwner`, a sealed path), because on
/// the record it holds it is no member, and that counts as not yet. The wait still ends only when
/// every device holds the same item, so a device never admitted fails the case by timeout.
pub async fn agree_admitted(
    spaces: &[&dyn Spaces],
    space: &Name,
    path: &Name,
    entries: &[&SpaceEntry],
) -> Result<bool, Failure> {
    agree_reading(spaces, space, path, entries, true).await
}

async fn agree_reading(
    spaces: &[&dyn Spaces],
    space: &Name,
    path: &Name,
    entries: &[&SpaceEntry],
    refusal_is_not_yet: bool,
) -> Result<bool, Failure> {
    let mut items = Vec::with_capacity(spaces.len());
    let mut applied = true;
    for s in spaces {
        match item(*s, space, path).await {
            Ok(held) => items.push(held),
            Err(e) if refusal_is_not_yet && (e.next_is("AskOwner") || e.kind_is("Sealed")) => {
                items.push(None);
            }
            Err(e) => return Err(e),
        }
        for entry in entries {
            match has(*s, space, entry).await {
                Ok(held) => applied &= held,
                Err(e) if refusal_is_not_yet && (e.next_is("AskOwner") || e.kind_is("Sealed")) => {
                    applied = false;
                }
                Err(e) => return Err(e),
            }
        }
    }
    let mut first: Option<&SpaceItem> = None;
    for held in &items {
        let Some(held) = held else {
            return Ok(false);
        };
        match first {
            None => first = Some(held),
            Some(f) if f != held => return Ok(false),
            Some(_) => {}
        }
    }
    Ok(applied)
}

/// Drain `stream` for `window` of virtual time.
pub async fn drain(
    stream: &mut dyn SpaceChanges,
    window: Duration,
    into: &mut Vec<SpaceEvent>,
) -> Result<(), Failure> {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) | Ok(None) => return Ok(()),
            Ok(Some(event)) => into.push(event?),
        }
    }
}

/// Drain `stream` into `into` until `done` holds of everything received, for at most `limit` of
/// virtual time; returns how long it took.
pub async fn drain_until(
    stream: &mut dyn SpaceChanges,
    into: &mut Vec<SpaceEvent>,
    what: &str,
    limit: Duration,
    mut done: impl FnMut(&[SpaceEvent]) -> bool,
) -> Result<Duration, Failure> {
    let start = tokio::time::Instant::now();
    loop {
        if done(into) {
            return Ok(start.elapsed());
        }
        let left = limit.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Err(Failure::new(format!(
                "{what}: not reached within {limit:?} of virtual time"
            )));
        }
        drain(stream, LOOK.min(left), into).await?;
    }
}

/// Everything `spaces` reports for `space` within `window`: a new watch's listing, and what comes.
/// A device outside the space's audience (a reader that was removed) may be refused the watch
/// itself, as it is refused a read (`"AskOwner"`, a sealed space): it is told nothing, so it lists
/// nothing, exactly as [`reads_entry`] reads nothing. A failure of any other kind is returned.
pub async fn look(
    spaces: &dyn Spaces,
    space: &Name,
    window: Duration,
) -> Result<Vec<SpaceEvent>, Failure> {
    let mut stream = match spaces.watch(space).await {
        Ok(stream) => stream,
        Err(e) if e.next_is("AskOwner") || e.kind_is("Sealed") => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    drain(&mut *stream, window, &mut out).await?;
    Ok(out)
}

/// The items `events` put or removed, in order.
pub fn items(events: &[SpaceEvent]) -> impl Iterator<Item = &SpaceItem> {
    events.iter().filter_map(|e| match e {
        SpaceEvent::Put(i) | SpaceEvent::Removed(i) => Some(i),
        _ => None,
    })
}

/// The item `events` report for the entry `key`.
pub fn item_of<'e>(events: &'e [SpaceEvent], key: &SpaceEntryKey) -> Option<&'e SpaceItem> {
    items(events).find(|i| i.key() == *key)
}

/// Whether the entry wrote exactly the octets of `s`.
pub fn op_is(item: &SpaceItem, s: &str) -> bool {
    item.bytes == s.as_bytes()
}

/// Whether the entry wrote octets that carry `part`.
pub fn wrote(item: &SpaceItem, part: &str) -> bool {
    contains(&item.bytes, part.as_bytes())
}

/// The heads of `path` among the items `events` report: those no other reported item supersedes
/// (no other item's `after` covers them).
pub fn heads<'e>(events: &'e [SpaceEvent], path: &Name) -> Vec<&'e SpaceItem> {
    let all: Vec<&SpaceItem> = items(events).filter(|i| i.path == *path).collect();
    all.iter()
        .copied()
        .filter(|i| {
            let key = i.key();
            !all.iter()
                .any(|o| o.key() != key && o.after.iter().any(|a| a.covers(&key)))
        })
        .collect()
}

/// Rule R (b): `spaces` reads at `path` of `space` the write of the head with the highest signed
/// digest ([`SpaceEntry::signed`]). `heads` are the entries nothing supersedes, the ones the case
/// made over no other. The winner is picked from their signed digests, which bind each entry's
/// bytes, so the read is the winner's exactly when it carries the winner's name and digest:
/// no watch listing is needed (a provider may list only each path's winner). Returns the item.
pub async fn winning(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
    heads: &[&SpaceEntry],
) -> Result<SpaceItem, Failure> {
    let want = heads
        .iter()
        .max_by_key(|e| e.signed)
        .ok_or_else(|| Failure::new(format!("no head of {path} was given")))?;
    let got = required(spaces, space, path).await?;
    ensure!(
        got.key() == want.key() && got.signed == want.signed,
        "the register {path} reads the entry {} ({:?}); the head with the highest signed digest \
         is {}",
        got.name,
        String::from_utf8_lossy(&got.bytes),
        want.name
    );
    Ok(got)
}

/// Whether `events` report an equivocation.
pub fn equivocation(events: &[SpaceEvent]) -> bool {
    alerted(events, |k| matches!(k, AlertKind::Equivocation { .. }))
}

/// Whether `events` carry an alert whose kind satisfies `which`.
pub fn alerted(events: &[SpaceEvent], which: impl Fn(&AlertKind) -> bool) -> bool {
    events.iter().any(|e| match e {
        SpaceEvent::Alert(a) => which(&a.kind),
        _ => false,
    })
}

/// Whether `events` report the entry `key` withdrawn.
pub fn withdrawn(events: &[SpaceEvent], key: &SpaceEntryKey) -> bool {
    events
        .iter()
        .any(|e| matches!(e, SpaceEvent::Withdrawn { entry, .. } if entry == key))
}

/// Whether `events` report the entry `key` withdrawn for this kind of refusal.
pub fn withdrawn_as(events: &[SpaceEvent], key: &SpaceEntryKey, because: RefusalKind) -> bool {
    events.iter().any(|e| {
        matches!(e, SpaceEvent::Withdrawn { entry, kind, .. } if entry == key && *kind == because)
    })
}

// ---- the keys-over-time kit (c3, k1–k10, o2) --------------------------------------------------

/// The time the owner says a device was lost, by the clock of `root` (the namespace's root
/// device, which bounds the revocation's cut by what it first verified before then): a second
/// after everything the case saw so far, so what `root` held by now came strictly before it.
pub async fn loss_time(w: &World, root: Dev) -> ndn_heap::Timestamp {
    w.sleep(Duration::from_secs(1)).await;
    w.net().date(root)
}

/// The full name among `names` (each a name plus an implicit digest) of the packet named
/// `entry` (a log entry's name, [`SpaceEntry::name`]).
pub fn full_name_of<'n>(names: &'n [Name], entry: &Name) -> Option<&'n Name> {
    names
        .iter()
        .find(|n| n.len() == entry.len() + 1 && n.has_prefix(entry))
}

/// The thief `thief` takes the stolen device and switches it on: its spaces, once it holds
/// `entry` of `space` as the device did and, in a sealed space, the key of the epoch in force
/// (the copy of the storage holds the keys the device held; one it lacks the thief asks for as
/// the device would, the key not being revoked yet). A thief that signs afterwards signs with
/// that key, as the device could.
pub async fn stolen(
    w: &World,
    thief: Dev,
    space: &Name,
    entry: &SpaceEntry,
) -> Result<Arc<dyn Spaces>, Failure> {
    w.steal(thief).await?;
    let spaces = w.spaces(thief);
    w.until(
        "the stolen device, switched on by the thief, holds what it held",
        LIMIT,
        || has(&*spaces, space, entry),
    )
    .await?;
    w.until(
        "the stolen device holds the key of the epoch in force",
        LIMIT,
        || holds_key(&*spaces, space),
    )
    .await?;
    Ok(spaces)
}
