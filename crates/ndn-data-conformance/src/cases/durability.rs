//! What the durability cases (`d9`…`d16`) share: a public space two devices of one person follow
//! and the writes of a device whose flush is held. Everything speaks the neutral [`Spaces`].
//!
//! The space is public so that no seal epoch (a structural entry, which always waits for its
//! flush) comes into a case that is about the flush of ordinary entries.
//!
//! A `put` returns when its entry is signed, stored and applied; it also waits for the flush that
//! covers it exactly when no other device is known in the space (the contract's default,
//! `durable = no_peers`). So a case that lets a device write ahead of its flush first lets that
//! device hear a peer ([`peers`]), and a case that needs a write the flush has covered writes
//! before any peer is there.

use bytes::Bytes;
use ndn_heap::Name;

use super::kit::{LIMIT, has, known, n, octets, public};
use crate::case::Failure;
use crate::ensure;
use crate::spaces::{SpaceEntry, SpaceEvent, Spaces};
use crate::world::{Dev, World};

/// The space the cases write in: owned by alice, public.
pub fn space() -> Name {
    n("/alice/32=data/ledger")
}

/// `owner` creates the public space; no other device is told of it yet.
pub async fn create(w: &World, owner: Dev, space: &Name) -> Result<(), Failure> {
    w.spaces(owner).create(space, public(&[])).await
}

/// `follower` follows `space` until it holds its members record, then writes `/phone`, and
/// `owner` applies that entry: from then on `owner` has heard a peer, and its writes do not wait
/// for the flush. Returns the follower's entry.
pub async fn peers(
    w: &World,
    owner: Dev,
    follower: Dev,
    space: &Name,
) -> Result<SpaceEntry, Failure> {
    let (own, theirs) = (w.spaces(owner), w.spaces(follower));
    w.retry_later(|| theirs.open(space)).await?;
    w.until("the follower holds the space's members", LIMIT, || {
        known(&*theirs, space)
    })
    .await?;
    let entry = w
        .space_put(follower, space, &n("/phone"), octets("phone"))
        .await?;
    w.until("the owner applies the follower's entry", LIMIT, || {
        has(&*own, space, &entry)
    })
    .await?;
    Ok(entry)
}

/// `d` writes `bytes` at `path` while its flush is held. It must return all the same: a device
/// that hears a peer does not make a write wait for its flush.
pub async fn write_ahead(
    w: &World,
    d: Dev,
    space: &Name,
    path: &str,
    bytes: &str,
) -> Result<SpaceEntry, Failure> {
    let path = n(path);
    let bytes: Bytes = octets(bytes);
    match tokio::time::timeout(LIMIT, w.space_put(d, space, &path, bytes)).await {
        Ok(entry) => entry,
        Err(_) => Err(Failure::new(format!(
            "a put at {path} waited for a flush that is held: with a peer heard, a put returns \
             when it is applied, and the flush follows"
        ))),
    }
}

/// Whether `spaces` has applied `entry` and reads its octets at the entry's path.
pub async fn holds(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
    entry: &SpaceEntry,
    bytes: &str,
) -> Result<bool, Failure> {
    Ok(has(spaces, space, entry).await?
        && super::kit::value_now(spaces, space, path).await? == Some(octets(bytes)))
}

/// No two entries at one `(writer, seq)` among the entries `events` report: a seq signed twice
/// by one device is what a crash must never produce.
pub fn one_entry_per_seq(who: &str, events: &[SpaceEvent]) -> Result<(), Failure> {
    let items: Vec<_> = super::kit::items(events).collect();
    for (i, a) in items.iter().enumerate() {
        for b in &items[i + 1..] {
            ensure!(
                !(a.writer == b.writer && a.seq == b.seq && a.signed != b.signed),
                "{who} was shown two different entries of {} at seq {}",
                a.writer,
                a.seq
            );
        }
    }
    Ok(())
}
