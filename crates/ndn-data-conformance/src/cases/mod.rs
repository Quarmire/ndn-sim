//! The cases, in study order: the twelve use cases (`c1`…`c12`), with slice 3's custody of
//! large data (`h1`…`h6`) beside the use case it grew from (c5), the items left open after the
//! model's fixes (`o1`…`o4`), and the slice-2 security review (`r1`…`r4`): the attacks it found
//! and the concurrent share its merge must keep.
//! Each file states the story, the devices, and the invariant it asserts.

use std::time::Duration;

use futures::StreamExt;
use ndn_data::{
    Answer, Audience, Change, Changes, Content, Custody, DataError, DataLayer, Frontier, Got, Hold,
    Keep, Lease, Name, Payload, PutOptions, Rule, Share, State, TypeId, Version, VersionId,
};

use crate::case::{Case, Failure};
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

mod c01_offline_notes;
mod c02_removed_offline;
mod c03_stolen_key;
mod c04_lens_seal;
mod c05_prune_vs_custody;
mod c06_sensor_blocks;
mod c07_unknown_fields;
mod c08_nested_summaries;
mod c09_family_chat;
mod c10_others_comment;
mod c11_cite_state;
mod c12_still_pass;
mod h1_large_photo;
mod h2_dropping_holder;
mod h3_subset_holder;
mod h4_lease_keep;
mod h5_prune_ends_leases;
mod h6_sealed_non_reader;
mod o1_cut_recheck;
mod o2_readmit;
mod o3_many_writers;
mod o4_sustained_writes;
mod r1_concurrent_shares;
mod r2_group_removal;
mod r3_own_device_removed;
mod r4_concurrent_add_remove;

/// Every case, in study order.
pub const CASES: &[Case] = &[
    c01_offline_notes::CASE,
    c02_removed_offline::CASE,
    c03_stolen_key::CASE,
    c04_lens_seal::CASE,
    c05_prune_vs_custody::CASE,
    h1_large_photo::CASE,
    h2_dropping_holder::CASE,
    h3_subset_holder::CASE,
    h4_lease_keep::CASE,
    h5_prune_ends_leases::CASE,
    h6_sealed_non_reader::CASE,
    c06_sensor_blocks::CASE,
    c07_unknown_fields::CASE,
    c08_nested_summaries::CASE,
    c09_family_chat::CASE,
    c10_others_comment::CASE,
    c11_cite_state::CASE,
    c12_still_pass::CASE,
    o1_cut_recheck::CASE,
    o2_readmit::CASE,
    o3_many_writers::CASE,
    o4_sustained_writes::CASE,
    r1_concurrent_shares::CASE,
    r2_group_removal::CASE,
    r3_own_device_removed::CASE,
    r4_concurrent_add_remove::CASE,
];

// ---- the kit the cases share ------------------------------------------------------------------

/// How long devices that can reach each other get to agree.
const LIMIT: Duration = Duration::from_secs(120);
/// How long a case lets the network run before asserting that something did *not* happen.
const SETTLE: Duration = Duration::from_secs(60);
/// How long a watch is drained for one look at a collection.
const LOOK: Duration = Duration::from_secs(5);
const DAY: Duration = Duration::from_secs(24 * 3600);

fn n(s: &str) -> Name {
    s.parse().expect("case names are valid NDN names")
}

fn person(s: &str) -> Audience {
    Audience::Person(n(s))
}

/// The merge rule the cases use (the plan's recommended CRDT).
fn merge() -> Rule {
    Rule::Merge {
        function: n("/merge/yrs"),
    }
}

/// The note type: revision 1 has `text`; revision 2 adds `tags`.
fn note(revision: u64) -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

/// The photo type: revision 1 has `file` (the photo's name) and `image` (its octets).
fn photo(keep: Keep) -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/photo"),
            revision: 1,
        },
        keep,
        batch: None,
    }
}

/// A photo's octets for the custody cases: about 1.6 MB, some 390 chunks of 4096 octets.
const IMAGE: usize = 1_600_000;

/// A photo named `file` of `len` octets, the same every run: the octets come from a generator
/// (xorshift) seeded by the name.
fn picture(file: &str, len: usize) -> Content {
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
    Content::new()
        .with("file", bytes::Bytes::copy_from_slice(file.as_bytes()))
        .with("image", bytes::Bytes::from(image))
}

/// The custody cases' devices: Alice's phone (`Dev(0)`, which writes the photos and asks for
/// custody), her home repo (`Dev(1)`, a holder) and her laptop (`Dev(2)`, a reader).
fn custody_plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.holder("alice", "repo");
    p.device("alice", "laptop");
    p
}

/// Whether `lease` is signed by a key of the device named `device`.
fn leased_by(lease: &Lease, device: &Name) -> bool {
    lease.holder.key().has_prefix(device)
}

/// `d` asks for custody of `prefix`, recording what the call cost `d` on its links (the hold
/// asks it sent, every audit it ran, any repair) as `<what>: Interests` and `<what>: bytes
/// received`.
async fn hold_on(
    w: &World,
    d: Dev,
    prefix: &Name,
    want: Hold,
    what: &str,
) -> Result<Custody, Failure> {
    let before = w.net().device_wire(d);
    let custody = w.at(d).hold(prefix, want).await?;
    let spent = w.net().device_wire(d) - before;
    w.measure(format!("{what}: Interests"), spent.interests, "round trips");
    w.measure(format!("{what}: bytes received"), spent.in_bytes, "bytes");
    Ok(custody)
}

/// The version `id` of `collection` as `layer` lists it: a device lists its own writes at once.
async fn listed(
    layer: &dyn DataLayer,
    collection: &Name,
    id: &VersionId,
) -> Result<Version, Failure> {
    let seen = look(layer, collection, &Frontier::new(), LOOK).await?;
    version(&seen, id).cloned().ok_or_else(|| {
        Failure::new(format!(
            "the writer's own watch of {collection} does not list version {} it wrote",
            id.seq.0
        ))
    })
}

/// The octets a version carries in pieces; `None` when it is carried inline.
fn large(v: &Version) -> Option<u64> {
    match v.payload {
        Payload::Large { size } => Some(size),
        _ => None,
    }
}

/// What `holders` store of `prefix`, per mille of the `payload` octets it carries.
fn overhead(w: &World, holders: &[Dev], prefix: &Name, payload: u64) -> u64 {
    holders.iter().map(|d| w.stored(*d, prefix)).sum::<u64>() * 1000 / payload.max(1)
}

/// `d` reads the version `name` whole: `get` until it answers the entry `expected` (while no
/// path or holder answers, it asks again). Records the read's cost to `d` on its links as
/// `<what>: Interests` and `<what>: bytes received`.
async fn read_whole(
    w: &World,
    d: Dev,
    name: &Name,
    expected: &Content,
    what: &str,
) -> Result<(), Failure> {
    let layer = w.at(d);
    let before = w.net().device_wire(d);
    w.until(what, LIMIT, || async {
        match layer.get(name).await {
            Ok(Answer {
                got: Got::Version(v),
                ..
            }) => match &v.payload {
                Payload::Entry(c) if c == expected => Ok(true),
                Payload::Entry(c) => Err(Failure::new(format!(
                    "{what}: {name} read as other content than was written ({} octets of \
                     `image`, {} written)",
                    c.get("image").map_or(0, |b| b.len()),
                    expected.get("image").map_or(0, |b| b.len())
                ))),
                Payload::Large { size } => Err(Failure::new(format!(
                    "{what}: get of {name} answered its size ({size} octets), not the entry \
                     read whole"
                ))),
                Payload::Block(entries) => Err(Failure::new(format!(
                    "{what}: get of {name} answered a block of {} entries, not the photo",
                    entries.len()
                ))),
            },
            Ok(answer) => Err(Failure::new(format!(
                "{what}: get of version {name} answered {:?}, not the version",
                answer.got
            ))),
            Err(DataError::Unavailable { .. } | DataError::NotFound { .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    })
    .await?;
    let spent = w.net().device_wire(d) - before;
    w.measure(format!("{what}: Interests"), spent.interests, "round trips");
    w.measure(format!("{what}: bytes received"), spent.in_bytes, "bytes");
    Ok(())
}

fn content(fields: &[(&str, &str)]) -> Content {
    fields.iter().fold(Content::new(), |c, (k, v)| {
        c.with(*k, bytes::Bytes::copy_from_slice(v.as_bytes()))
    })
}

fn text(s: &str) -> Content {
    content(&[("text", s)])
}

/// A members record: `writers` are key-name prefixes.
fn members(rule: Rule, writers: &[&str], readers: &[Audience]) -> Share {
    Share {
        rule,
        writers: writers.iter().map(|w| n(w)).collect(),
        readers: readers.to_vec(),
        readmit: Vec::new(),
    }
}

/// The field `f` of `c` as text.
fn field<'c>(c: &'c Content, f: &str) -> Option<&'c str> {
    c.get(f).and_then(|v| std::str::from_utf8(v).ok())
}

/// The merged state of a merge collection as `layer` sees it now; `None` while it has nothing.
async fn state_now(layer: &dyn DataLayer, collection: &Name) -> Result<Option<State>, Failure> {
    match layer.get(collection).await {
        Ok(answer) => match answer.got {
            Got::State(s) => Ok(Some(s)),
            other => Err(Failure::new(format!(
                "get on merge collection {collection} answered {other:?}; it must answer the \
                 merged state at a frontier (M10)"
            ))),
        },
        Err(DataError::Unavailable { .. } | DataError::NotFound { .. }) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The field `f` of any entry a version carries inline (a large payload carries none: `get` of
/// the version's name reads it).
fn field_of<'v>(v: &'v Version, f: &str) -> Option<&'v str> {
    match &v.payload {
        Payload::Entry(c) => field(c, f),
        Payload::Block(entries) => entries.iter().find_map(|c| field(c, f)),
        Payload::Large { .. } => None,
    }
}

/// How many entries a version carries (a large payload is one entry, carried in pieces).
fn entries(v: &Version) -> usize {
    match &v.payload {
        Payload::Entry(_) | Payload::Large { .. } => 1,
        Payload::Block(e) => e.len(),
    }
}

/// The merged state, which must exist.
async fn state(layer: &dyn DataLayer, collection: &Name) -> Result<State, Failure> {
    state_now(layer, collection)
        .await?
        .ok_or_else(|| Failure::new(format!("no state of {collection} is held")))
}

/// Whether `layer`'s merged state of `collection` includes `id`.
async fn has(layer: &dyn DataLayer, collection: &Name, id: &VersionId) -> Result<bool, Failure> {
    Ok(state_now(layer, collection)
        .await?
        .is_some_and(|s| s.at.contains(id)))
}

/// Whether every layer holds the same merged state, including every id in `ids`.
async fn agree(
    layers: &[&dyn DataLayer],
    collection: &Name,
    ids: &[&VersionId],
) -> Result<bool, Failure> {
    let mut first: Option<State> = None;
    for layer in layers {
        let Some(s) = state_now(*layer, collection).await? else {
            return Ok(false);
        };
        if !ids.iter().all(|id| s.at.contains(id)) {
            return Ok(false);
        }
        match &first {
            None => first = Some(s),
            Some(f) if f.at != s.at || f.value != s.value => return Ok(false),
            Some(_) => {}
        }
    }
    Ok(true)
}

/// Drain `stream` for `window` of virtual time.
async fn drain(
    stream: &mut Changes,
    window: Duration,
    into: &mut Vec<Change>,
) -> Result<(), Failure> {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) | Ok(None) => return Ok(()),
            Ok(Some(item)) => into.push(item?),
        }
    }
}

/// Drain `stream` into `into` until `done` holds of everything received, for at most `limit` of
/// virtual time; returns how long it took.
async fn drain_until(
    stream: &mut Changes,
    into: &mut Vec<Change>,
    what: &str,
    limit: Duration,
    mut done: impl FnMut(&[Change]) -> bool,
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

/// Everything `layer` reports for `collection` beyond `since`, within `window`.
async fn look(
    layer: &dyn DataLayer,
    collection: &Name,
    since: &Frontier,
    window: Duration,
) -> Result<Vec<Change>, Failure> {
    let mut stream = layer.watch(collection, since).await?;
    let mut out = Vec::new();
    drain(&mut stream, window, &mut out).await?;
    Ok(out)
}

/// The versions among `changes`.
fn versions(changes: &[Change]) -> impl Iterator<Item = &Version> {
    changes.iter().filter_map(|c| match c {
        Change::Version(v) => Some(v),
        _ => None,
    })
}

/// The version `id` among `changes`.
fn version<'c>(changes: &'c [Change], id: &VersionId) -> Option<&'c Version> {
    versions(changes).find(|v| v.id == *id)
}

/// Whether `changes` report an equivocation.
fn equivocation(changes: &[Change]) -> bool {
    changes
        .iter()
        .any(|c| matches!(c, Change::Equivocation { .. }))
}
