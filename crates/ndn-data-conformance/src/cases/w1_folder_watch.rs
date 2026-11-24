//! Slice 6, w1 — a 1,000-paragraph note; the other person adds a paragraph; my screen shows it.
//!
//! An app such as ndf keeps a document as a space with one path per paragraph, often thousands,
//! and its read engine watches by dependency across elements. A watch per path meant as many
//! watch calls as elements, and an element created later went unseen until someone looked at it.
//! `watch(space)` is one stream for every path under the space — those created after the watch
//! began included, by any writer, local or remote — carrying every kind of change, each tagged
//! with the path it is about.
//!
//! Alice keeps a note as a space of 1,000 paragraphs, one register path each, shared with Bob as
//! a writer and a reader by one members record. Both watch the space. Bob adds a paragraph:
//! Alice's watch reports it, tagged with the new paragraph. Alice adds one: Bob's watch reports it.
//! Alice adds one more: her own watch reports it. While Bob is offline, Alice and Bob each rewrite
//! one paragraph: Alice's watch reports Bob's entry, tagged with that paragraph, and both devices
//! read the head with the highest digest. No watch is handed one entry twice. The case measures
//! the Interests the watching device sent from each add to its delivery, and the time it took.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use ndn_data::Name;

use super::kit::{
    LIMIT, LOOK, agree, drain, drain_until, item_of, items, n, octets, private, winning,
};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{SpaceChanges, SpaceEntry, SpaceEntryKey, SpaceEvent};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "w1",
    title: "A 1,000-paragraph note: the other person adds a paragraph, my screen shows it",
    slice: 6,
    needs: &[Feature::Merge, Feature::FolderMembers, Feature::FolderWatch],
    model: &["M8", "M15"],
    guards: "One watch of a folder reports every collection under it, those created after the \
             watch began included, whoever creates them, every version tagged with its \
             collection — a concurrent one in a register that exists included — and never hands \
             one watch the same version twice.",
    budget: Duration::from_secs(12 * 3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const WHO: [(&str, Dev); 2] = [("Alice", ALICE), ("Bob", BOB)];

/// Paragraphs in the note before anyone adds one.
const PARAGRAPHS: usize = 1000;
/// The paragraph both people rewrite at once.
const EDITED: usize = 7;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

fn note() -> Name {
    n("/alice/32=data/note")
}

/// The path of paragraph `i` in the note.
fn paragraph(i: usize) -> Name {
    n(&format!("/p{i:04}"))
}

/// `d` writes paragraph `i` as a new register path: its first entry, over nothing.
async fn add_paragraph(w: &World, d: Dev, i: usize) -> Result<SpaceEntry, Failure> {
    w.space_put(d, &note(), &paragraph(i), octets(&format!("paragraph {i}")))
        .await
}

/// Every change a watch of `who` reported is tagged with a paragraph of the note, and no entry
/// came twice.
fn well_tagged(who: &str, seen: &[SpaceEvent]) -> Result<(), Failure> {
    let space = note();
    let paragraphs: BTreeSet<Name> = (0..PARAGRAPHS + 3).map(paragraph).collect();
    let mut times: BTreeMap<SpaceEntryKey, usize> = BTreeMap::new();
    for item in items(seen) {
        ensure!(
            paragraphs.contains(&item.path),
            "{who}'s watch of {space} tagged an entry with {}, no paragraph of the note: {item:?}",
            item.path
        );
        *times.entry(item.key()).or_default() += 1;
    }
    if let Some((key, k)) = times.into_iter().find(|(_, k)| *k > 1) {
        return Err(Failure::new(format!(
            "{who}'s watch of {space} delivered entry {key:?} {k} times"
        )));
    }
    Ok(())
}

/// `watcher`'s feed reports the entry `add` writes, a new paragraph `c` written by another device
/// or by itself, tagged with `c`; records the Interests `watcher` sent and the time from the add
/// until it came.
async fn reports_added(
    w: &World,
    (watcher, feed, seen): (Dev, &mut dyn SpaceChanges, &mut Vec<SpaceEvent>),
    what: &str,
    add: impl Future<Output = Result<SpaceEntry, Failure>>,
    c: &Name,
) -> Result<Duration, Failure> {
    let sent = w.net().device_wire(watcher).interests;
    let start = tokio::time::Instant::now();
    let entry = add.await?;
    let deadline = start + LIMIT;
    while item_of(seen, &entry.key()).is_none() {
        match tokio::time::timeout_at(deadline, feed.next()).await {
            Ok(Some(event)) => seen.push(event?),
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
    let reported = item_of(seen, &entry.key()).expect("drained until it came");
    ensure!(
        reported.path == *c,
        "{what}: the entry of {c} came tagged with {}",
        reported.path
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
        let space = note();
        let alice = w.spaces(ALICE);
        alice.create(&space, private(&["/bob"], &["/bob"])).await?;
        for i in 0..PARAGRAPHS {
            alice
                .put(&space, &paragraph(i), octets(&format!("paragraph {i}")))
                .await?;
        }
        let edited = paragraph(EDITED);

        // Both watch the note from nothing: the listing, then everything new, in one stream each.
        let mut feeds = Vec::new();
        for (who, d) in WHO {
            let spaces = w.spaces(d);
            let mut feed = w.retry_later(|| spaces.watch(&space)).await?;
            let mut seen = Vec::new();
            drain_until(
                &mut *feed,
                &mut seen,
                &format!("setup: {who}'s watch lists every paragraph"),
                10 * LIMIT,
                |seen| {
                    let held: BTreeSet<&Name> = items(seen).map(|i| &i.path).collect();
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
            (ALICE, &mut **alice_feed, alice_seen),
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
            (BOB, &mut **bob_feed, bob_seen),
            "Alice adds a paragraph, Bob's folder watch reports it",
            add_paragraph(w, ALICE, PARAGRAPHS + 1),
            &alices_add,
        )
        .await?;

        w.gesture();
        let own_add = paragraph(PARAGRAPHS + 2);
        reports_added(
            w,
            (ALICE, &mut **alice_feed, alice_seen),
            "Alice adds a paragraph, her own folder watch reports it",
            add_paragraph(w, ALICE, PARAGRAPHS + 2),
            &own_add,
        )
        .await?;

        // Bob, offline, rewrites a paragraph Alice rewrites meanwhile: the two entries are heads
        // of one register. Alice's one watch of the space reports the register's new value when
        // he is back — the entry with the highest digest, which may be Bob's — tagged with the
        // paragraph; both devices apply both entries and read that head. (A provider may report
        // only the winning head, not the entry it superseded, so the case does not ask the
        // watch for the loser.)
        w.gesture();
        w.net().offline(BOB);
        let alices = w
            .space_put(ALICE, &space, &edited, octets("alice's text"))
            .await?;
        let bobs = w
            .space_put(BOB, &space, &edited, octets("bob's text"))
            .await?;
        w.net().online(BOB);
        let head = if alices.signed > bobs.signed {
            &alices
        } else {
            &bobs
        };
        drain_until(
            &mut **alice_feed,
            alice_seen,
            "Alice's folder watch reports the head with the highest digest",
            LIMIT,
            |seen| item_of(seen, &head.key()).is_some(),
        )
        .await?;
        let reported = item_of(alice_seen, &head.key()).expect("drained until it came");
        ensure!(
            reported.path == edited,
            "the head of {edited} was reported tagged with {}",
            reported.path
        );
        let (a, b) = (w.spaces(ALICE), w.spaces(BOB));
        w.converge(
            "Alice and Bob agree on the paragraph with both rewrites",
            LIMIT,
            || async { agree(&[&*a, &*b], &space, &edited, &[&alices, &bobs]).await },
        )
        .await?;
        for spaces in [&a, &b] {
            winning(&**spaces, &space, &edited, &[&alices, &bobs]).await?;
        }

        // Whatever else came meanwhile (the other adds) settles; then every change of both
        // watches is tagged within the note, and no entry came twice.
        drain(&mut **alice_feed, LOOK, alice_seen).await?;
        drain(&mut **bob_feed, LOOK, bob_seen).await?;
        for ((who, _), (_, _, seen)) in WHO.iter().zip(&feeds) {
            well_tagged(who, seen)?;
        }
        Ok(())
    })
}
