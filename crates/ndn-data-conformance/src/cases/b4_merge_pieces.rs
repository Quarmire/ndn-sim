//! Slice 6, b4 — a large operation and a large checkpoint in a merge collection.
//!
//! Alice's notes app keeps a long note body in one element and, now and then, writes a
//! checkpoint: the element's whole state, so a device opening it later need not replay its
//! history. Before slice 6 a merge collection carried every operation inline, so a 20 KiB edit
//! or a 100 KiB checkpoint was refused as too large. The fix: a merge version carries its payload
//! in verifiable pieces like any version; a reader fetches them, waits for the version as for a
//! missing parent, and applies it once whole. Her tablet, offline throughout, comes back after
//! the checkpoint and learns of the edit and the checkpoint together: the checkpoint covers the
//! edit, so the tablet holds the edit's signed record but never fetches its pieces.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "b4",
    title: "A large operation and a large checkpoint in a merge collection",
    slice: 6,
    needs: &[Feature::Merge, Feature::AppOps, Feature::MergePieces],
    model: &[],
    guards: "A merge version of any size within the payload limit reaches another device whole \
             and applies there; a checkpoint replaces the state of its past, so a device that \
             comes back later reaches the same value from it, never fetching the pieces of the \
             edit it covers.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const TABLET: Dev = Dev(2);

/// The note body: 20 KiB.
const BODY: usize = 20 * 1024;
/// The archive a checkpoint carries besides: 100 KiB.
const ARCHIVE: usize = 100 * 1024;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("alice", "tablet");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let note = n("/alice/32=data/notes/long");
        let (laptop, phone, tablet) = (w.at(LAPTOP), w.at(PHONE), w.at(TABLET));
        w.net().offline(TABLET);
        laptop
            .share(
                &note,
                members(element_rule(), &["/alice"], &[person("/alice")]),
            )
            .await?;
        let body = prose("body", BODY);
        let edit = element_op(w, LAPTOP, &note, |op| {
            op.then(0, Edit::Create("note".into()))
                .set("body", body.clone())
        })
        .await?;
        w.measure("the edit's operation", edit.encode().len() as u64, "bytes");
        let before = w.net().device_wire(PHONE);
        let large = laptop.put_op(&note, edit.encode(), element_type()).await?;
        w.until("the phone applies the 20 KiB edit", LIMIT, || {
            has(&*phone, &note, &large)
        })
        .await?;
        let spent = w.net().device_wire(PHONE) - before;
        w.measure(
            "the phone takes the edit: Interests",
            spent.interests,
            "round trips",
        );
        w.measure(
            "the phone takes the edit: bytes received",
            spent.in_bytes,
            "bytes",
        );
        let (_, v) = element_state(&*phone, &note).await?;
        ensure!(
            setting(&v, "body") == Some(body.as_str()),
            "the phone's note body is {} characters, not the {BODY} written",
            setting(&v, "body").map_or(0, str::len)
        );

        // A checkpoint: the whole state, and an archive besides.
        let (_, mine) = element_state(&*laptop, &note).await?;
        let mut whole = mine.state.clone();
        let archive = prose("archive", ARCHIVE);
        whole.settings.insert("archive".into(), archive.clone());
        let checkpoint =
            element_op(w, LAPTOP, &note, |op| op.then(0, Edit::Checkpoint(whole))).await?;
        w.measure(
            "the checkpoint's operation",
            checkpoint.encode().len() as u64,
            "bytes",
        );
        let before = w.net().device_wire(PHONE);
        let cp = laptop
            .put_op(&note, checkpoint.encode(), element_type())
            .await?;
        w.until(
            "the phone applies the 100 KiB checkpoint",
            LIMIT,
            || async { agree(&[&*laptop, &*phone], &note, &[&cp]).await },
        )
        .await?;
        let spent = w.net().device_wire(PHONE) - before;
        w.measure(
            "the phone takes the checkpoint: Interests",
            spent.interests,
            "round trips",
        );
        w.measure(
            "the phone takes the checkpoint: bytes received",
            spent.in_bytes,
            "bytes",
        );
        let (_, v) = element_state(&*phone, &note).await?;
        ensure!(
            setting(&v, "archive") == Some(archive.as_str())
                && setting(&v, "body") == Some(body.as_str()),
            "the phone's note after the checkpoint lacks the body or the archive whole"
        );

        // The tablet comes back after the checkpoint.
        let before = w.net().device_wire(TABLET);
        w.net().online(TABLET);
        let took = w
            .converge("the tablet reaches the laptop's note", LIMIT, || async {
                agree(&[&*laptop, &*tablet], &note, &[&cp, &large]).await
            })
            .await?;
        let spent = w.net().device_wire(TABLET) - before;
        w.measure(
            "the late tablet catches up: Interests",
            spent.interests,
            "round trips",
        );
        w.measure(
            "the late tablet catches up: bytes received",
            spent.in_bytes,
            "bytes",
        );
        w.measure(
            "the late tablet catches up: time",
            took.as_millis() as u64,
            "ms",
        );
        let covered = log_entry(w, LAPTOP, &note, &large);
        w.measure(
            "octets of the covered edit the late tablet stores",
            w.stored(TABLET, &covered),
            "bytes",
        );
        ensure!(
            w.pieces_stored(TABLET, &covered) == 0,
            "the late tablet fetched {} pieces of the edit the checkpoint it holds covers",
            w.pieces_stored(TABLET, &covered)
        );
        w.measure(
            "octets of the checkpoint the late tablet stores",
            w.stored(TABLET, &log_entry(w, LAPTOP, &note, &cp)),
            "bytes",
        );
        let (_, v) = element_state(&*tablet, &note).await?;
        ensure!(
            setting(&v, "archive") == Some(archive.as_str())
                && setting(&v, "body") == Some(body.as_str()),
            "the tablet's note from the checkpoint lacks the body or the archive whole"
        );
        Ok(())
    })
}
