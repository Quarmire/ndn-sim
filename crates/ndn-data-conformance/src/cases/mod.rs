//! The cases, in study order: the twelve use cases (`c1`…`c12`) and the three items left open
//! after the model's fixes (`o1`…`o3`). Each file states the story, the devices, and the
//! invariant it asserts.

use std::time::Duration;

use futures::StreamExt;
use ndn_data::{
    Audience, Change, Changes, Content, DataError, DataLayer, Frontier, Got, Keep, Name, Payload,
    PutOptions, Rule, Share, State, TypeId, Version, VersionId,
};

use crate::case::{Case, Failure};
use crate::feature::Feature;

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
mod o1_cut_recheck;
mod o2_readmit;
mod o3_many_writers;

/// Every case, in study order.
pub const CASES: &[Case] = &[
    c01_offline_notes::CASE,
    c02_removed_offline::CASE,
    c03_stolen_key::CASE,
    c04_lens_seal::CASE,
    c05_prune_vs_custody::CASE,
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

/// The field `f` of any entry a version carries.
fn field_of<'v>(v: &'v Version, f: &str) -> Option<&'v str> {
    match &v.payload {
        Payload::Entry(c) => field(c, f),
        Payload::Block(entries) => entries.iter().find_map(|c| field(c, f)),
    }
}

/// How many entries a version carries.
fn entries(v: &Version) -> usize {
    match &v.payload {
        Payload::Entry(_) => 1,
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
