//! Slice 6, w1 — a 1,000-paragraph note; the other person adds a paragraph; my screen shows it.
//!
//! An app such as ndf keeps a document as a folder with one collection per element, often
//! thousands, and its read engine watches by dependency across elements. A watch per collection
//! meant as many watch calls as elements, and an element created later went unseen until someone
//! looked at it. `watch(folder)` is one stream for every collection under the folder — those
//! created after the watch began included, by any writer, local or remote — carrying every kind
//! of change, each tagged with the collection it is about.
//!
//! Alice keeps a note as a folder of 1,000 paragraphs, one element collection each, shared with
//! Bob as a writer and a reader by one folder record. Both watch the folder. Bob adds a paragraph:
//! Alice's watch reports it, tagged with the new paragraph. Alice adds one: Bob's watch reports it.
//! Alice adds one more: her own watch reports it. While Bob is offline, Alice (the owner) locks one
//! paragraph's text and Bob, not having seen the lock, sets it: Alice's watch reports Bob's version
//! not counted, then counted once she unlocks, each tagged with that paragraph. No watch is handed
//! one version twice. The case measures the
//! Interests the watching device sent from each add to its delivery, and the time it took.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "w1",
    title: "A 1,000-paragraph note: the other person adds a paragraph, my screen shows it",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::AppOps,
        Feature::FolderMembers,
        Feature::FolderWatch,
    ],
    model: &["M8", "M15"],
    guards: "One watch of a folder reports every collection under it, those created after the \
             watch began included, whoever creates them, with every kind of change (versions, \
             NotCounted, Counted) each tagged with its collection, and never hands one watch the \
             same version twice.",
    budget: Duration::from_secs(12 * 3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const WHO: [(&str, Dev); 2] = [("Alice", ALICE), ("Bob", BOB)];

/// Paragraphs in the note before anyone adds one.
const PARAGRAPHS: usize = 1000;
/// The paragraph whose text Alice locks.
const LOCKED: usize = 7;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

fn note() -> Name {
    n("/alice/32=data/note")
}

fn paragraph(i: usize) -> Name {
    note().append(format!("p{i:04}").as_str())
}

/// `d` writes paragraph `i` as a new element: its first operation, over nothing.
async fn add_paragraph(w: &World, d: Dev, i: usize) -> Result<VersionId, Failure> {
    let op = Operation::by(&w.net().spec(d).name())
        .then(0, Edit::Create("paragraph".into()))
        .set("text", prose(&format!("paragraph {i}"), 80));
    Ok(w.at(d)
        .put_op(&paragraph(i), op.encode(), element_type())
        .await?)
}

/// The change among `seen` that `pick` accepts, which must exist.
fn found(seen: &[Change], pick: impl Fn(&Change) -> bool) -> &Change {
    seen.iter()
        .find(|c| pick(c))
        .expect("drained until it came")
}

/// Every change a folder watch of `who` reported is tagged with the folder or a collection under
/// it, and no version came twice.
fn well_tagged(who: &str, seen: &[Change]) -> Result<(), Failure> {
    let folder = note();
    let mut times: BTreeMap<&VersionId, usize> = BTreeMap::new();
    for c in seen {
        let t = c.collection();
        ensure!(
            t.has_prefix(&folder),
            "{who}'s watch of {folder} tagged a change with {t}, outside the folder: {c:?}"
        );
        if let Change::Version(v) = c {
            ensure!(
                *t == v.collection,
                "{who}'s watch tagged version {:?} of {} with {t}",
                v.id,
                v.collection
            );
            *times.entry(&v.id).or_default() += 1;
        }
    }
    if let Some((id, k)) = times.into_iter().find(|(_, k)| *k > 1) {
        return Err(Failure::new(format!(
            "{who}'s watch of {folder} delivered version {id:?} {k} times"
        )));
    }
    Ok(())
}

/// `watcher`'s feed reports `id`, a new paragraph `c` written by another device or by itself,
/// tagged with `c`; records the Interests `watcher` sent and the time from the add until it came.
async fn reports_added(
    w: &World,
    (watcher, feed, seen): (Dev, &mut Changes, &mut Vec<Change>),
    what: &str,
    add: impl Future<Output = Result<VersionId, Failure>>,
    c: &Name,
) -> Result<Duration, Failure> {
    let sent = w.net().device_wire(watcher).interests;
    let start = tokio::time::Instant::now();
    let id = add.await?;
    let deadline = start + LIMIT;
    while version(seen, &id).is_none() {
        match tokio::time::timeout_at(deadline, feed.next()).await {
            Ok(Some(item)) => seen.push(item?),
            Ok(None) => return Err(Failure::new(format!("{what}: the watch ended"))),
            Err(_) => {
                return Err(Failure::new(format!(
                    "{what}: not reached within {LIMIT:?} of virtual time"
                )));
            }
        }
    }
    let took = start.elapsed();
    let interests = w.net().device_wire(watcher).interests - sent;
    let change = found(seen, |ch| matches!(ch, Change::Version(v) if v.id == id));
    ensure!(
        change.collection() == c,
        "{what}: the version of {c} came tagged with {}",
        change.collection()
    );
    w.measure(format!("{what}: Interests sent"), interests, "Interests");
    w.measure(
        format!("{what}: time"),
        took.as_millis() as u64,
        "ms of virtual time",
    );
    Ok(took)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = note();
        let alice = w.at(ALICE);
        alice
            .share_folder(
                &folder,
                members(
                    element_rule(),
                    &["/alice", "/bob"],
                    &[person("/alice"), person("/bob")],
                )
                .into(),
            )
            .await?;
        for i in 0..PARAGRAPHS {
            add_paragraph(w, ALICE, i).await?;
        }
        let locked_c = paragraph(LOCKED);

        // Both watch the note from nothing: the listing, then everything new, in one stream each.
        let mut feeds = Vec::new();
        for (who, d) in WHO {
            let mut feed = w.at(d).watch(&folder, &Frontier::new()).await?;
            let mut seen = Vec::new();
            drain_until(
                &mut feed,
                &mut seen,
                &format!("setup: {who}'s watch lists every paragraph"),
                10 * LIMIT,
                |seen| {
                    let held: BTreeSet<&Name> = versions(seen).map(|v| &v.collection).collect();
                    held.len() >= PARAGRAPHS
                },
            )
            .await?;
            feeds.push((d, feed, seen));
        }
        let [(_, alice_feed, alice_seen), (_, bob_feed, bob_seen)] = &mut feeds[..] else {
            unreachable!("two watchers");
        };

        // The workload is the adds and what they make the watches report; the note is setup.
        w.report_from(w.mark());
        w.gesture();
        let bobs_add = paragraph(PARAGRAPHS);
        let took = reports_added(
            w,
            (ALICE, alice_feed, alice_seen),
            "Bob adds a paragraph, Alice's folder watch reports it",
            add_paragraph(w, BOB, PARAGRAPHS),
            &bobs_add,
        )
        .await?;
        w.converged(took);

        w.gesture();
        let alices_add = paragraph(PARAGRAPHS + 1);
        reports_added(
            w,
            (BOB, bob_feed, bob_seen),
            "Alice adds a paragraph, Bob's folder watch reports it",
            add_paragraph(w, ALICE, PARAGRAPHS + 1),
            &alices_add,
        )
        .await?;

        w.gesture();
        let own_add = paragraph(PARAGRAPHS + 2);
        reports_added(
            w,
            (ALICE, alice_feed, alice_seen),
            "Alice adds a paragraph, her own folder watch reports it",
            add_paragraph(w, ALICE, PARAGRAPHS + 2),
            &own_add,
        )
        .await?;

        // Bob, offline, sets a paragraph's text Alice locks meanwhile: made apart from the lock,
        // it waits until she unlocks (spec §5.1) — not counted, then counted, reported on the one
        // folder watch, tagged with the paragraph.
        w.gesture();
        w.net().offline(BOB);
        put_element(w, ALICE, &locked_c, |op| {
            op.then(0, Edit::Lock("text".into()))
        })
        .await?;
        let bobs = put_element(w, BOB, &locked_c, |op| op.set("text", "bob's text")).await?;
        w.net().online(BOB);
        drain_until(
            alice_feed,
            alice_seen,
            "Alice's folder watch reports Bob's version not counted",
            LIMIT,
            |seen| reported_not_counted(seen, &bobs),
        )
        .await?;
        let not_counted = found(
            alice_seen,
            |c| matches!(c, Change::NotCounted { id, .. } if *id == bobs),
        );
        ensure!(
            *not_counted.collection() == locked_c,
            "Bob's version of {locked_c} was reported not counted tagged with {}",
            not_counted.collection()
        );
        w.gesture();
        put_element(w, ALICE, &locked_c, |op| {
            op.then(0, Edit::Unlock("text".into()))
        })
        .await?;
        drain_until(
            alice_feed,
            alice_seen,
            "Alice's folder watch reports Bob's version counted",
            LIMIT,
            |seen| reported_counted(seen, &bobs),
        )
        .await?;
        let counted = found(
            alice_seen,
            |c| matches!(c, Change::Counted { id, .. } if *id == bobs),
        );
        ensure!(
            *counted.collection() == locked_c,
            "Bob's version of {locked_c} was reported counted tagged with {}",
            counted.collection()
        );

        // Whatever else came meanwhile (summaries, the other adds) settles; then every change of
        // both watches is tagged within the folder, and no version came twice.
        drain(alice_feed, LOOK, alice_seen).await?;
        drain(bob_feed, LOOK, bob_seen).await?;
        for ((who, _), (_, _, seen)) in WHO.iter().zip(&feeds) {
            well_tagged(who, seen)?;
        }
        Ok(())
    })
}
