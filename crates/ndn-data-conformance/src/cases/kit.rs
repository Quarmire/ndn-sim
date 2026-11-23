//! The kit the cases written over [`Spaces`] share: names and octets, reading a path on several
//! devices, watching a space and looking for what a watch reported, and the helpers of the
//! keys-over-time cases. Everything here speaks the neutral types of [`crate::spaces`], so a
//! case that imports only from here runs on every provider.
//!
//! The cases not yet ported keep the older kit of [`super`] over `ndn_data::DataLayer`; a ported
//! case imports from this module explicitly (`use super::kit::{...}`) and not through
//! `use super::*`, whose names of the same spelling are the old ones.
//!
//! A register path holds the bytes of the head with the highest signed digest
//! ([`SpaceItem::signed`]) among the heads (the entries no other entry's `after` supersedes):
//! every device converges to one value ([`agree`]), and the value is what the heads say
//! ([`winning`]) — rule R.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_data::Name;

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
/// to read it: a walk asks the unreachable writer first, in each of its three tries, before it
/// asks a device that holds the packet for it (see the older kit's note in [`super`]).
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

/// Whether `spaces` knows the space's members record, so its writes go into the space as shared.
pub async fn known(spaces: &dyn Spaces, space: &Name) -> Result<bool, Failure> {
    Ok(members_now(spaces, space).await?.is_some())
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
    let mut items = Vec::with_capacity(spaces.len());
    let mut applied = true;
    for s in spaces {
        items.push(item(*s, space, path).await?);
        for entry in entries {
            applied &= has(*s, space, entry).await?;
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
pub async fn look(
    spaces: &dyn Spaces,
    space: &Name,
    window: Duration,
) -> Result<Vec<SpaceEvent>, Failure> {
    let mut stream = spaces.watch(space).await?;
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

/// Rule R (b): `spaces` reads at `path` of `space` what the head with the highest signed digest
/// ([`SpaceItem::signed`]) wrote. `heads` are the entries nothing supersedes, the ones the case
/// made over no other, as `spaces` lists them with the octets each wrote. Returns the item.
pub async fn winning(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
    heads: &[&SpaceEntry],
) -> Result<SpaceItem, Failure> {
    let looked = look(spaces, space, LOOK).await?;
    let mut picks: Vec<&SpaceItem> = Vec::with_capacity(heads.len());
    for entry in heads {
        let listed = item_of(&looked, &entry.key())
            .ok_or_else(|| Failure::new(format!("the watch does not list head {}", entry.name)))?;
        picks.push(listed);
    }
    let want = picks
        .into_iter()
        .max_by_key(|i| i.signed)
        .ok_or_else(|| Failure::new(format!("no head of {path} was given")))?
        .bytes
        .clone();
    let got = required(spaces, space, path).await?;
    ensure!(
        got.bytes == want,
        "the register {path} reads {:?}; the head with the highest signed digest wrote {:?}",
        String::from_utf8_lossy(&got.bytes),
        String::from_utf8_lossy(&want)
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
pub async fn loss_time(w: &World, root: Dev) -> ndn_data::Timestamp {
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
/// `entry` of `space` as the device did.
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
    Ok(spaces)
}

#[cfg(test)]
mod tests {
    use ndn_sim::VirtualKernel;

    use super::*;
    use crate::reference::Reference;
    use crate::spaces::{EntryRead, SpaceChange};
    use crate::world::Plan;

    const LAPTOP: Dev = Dev(0);
    const PHONE: Dev = Dev(1);

    /// The kit and the old provider's adapter carry a space through its life: created by its owner,
    /// followed and written by a member's device, read alike on both, watched, overwritten,
    /// removed, and its members changed.
    #[test]
    fn a_space_over_the_old_provider_is_created_written_read_watched_and_changed() {
        VirtualKernel::new().run(|k| async move {
            let mut plan = Plan::new();
            plan.device("alice", "laptop");
            plan.device("bob", "phone");
            let w = World::build(k, &plan, Reference::provider())
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
            let seen = w
                .retry_later(|| phone.members(&space))
                .await
                .expect("bob's phone receives the record");
            assert_eq!(
                seen, both,
                "the owner is a writer and a reader, listed once"
            );

            // Bob writes; the owner's device converges on the same item.
            let first = w
                .space_put(PHONE, &space, &path, octets("milk"))
                .await
                .expect("bob writes");
            assert_eq!(first.writer, n("/bob/phone"));
            assert_eq!(first.seq, 1);
            assert!(first.name.has_prefix(&first.writer), "{}", first.name);
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
            let listing = look(&*phone, &space, LOOK).await.unwrap();
            assert_eq!(
                heads(&listing, &path)
                    .iter()
                    .map(|i| i.key())
                    .collect::<Vec<_>>(),
                [second.key()],
                "only the later write is a head"
            );

            // The log entry read by its name.
            match laptop.entry(&space, &first.name).await.unwrap() {
                EntryRead::Read(i) => assert_eq!(i.bytes, octets("milk")),
                other => panic!("the entry was read as {other:?}"),
            }

            // A removal is an empty write: the path holds nothing, and the watch reports it.
            let mut feed = laptop.watch(&space).await.unwrap();
            let gone = w
                .space_put(LAPTOP, &space, &path, Bytes::new())
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
