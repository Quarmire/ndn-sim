//! Case 8 — a laptop returns after four months.
//!
//! 10,000 notes, each its own collection of versions; 37 changed while the laptop was away. One
//! flat summary per collection meant checking 10,000 summaries to find 37 changes. The fix (M8):
//! summaries nest — the notes folder summarises its children by digest — and watch descends only
//! into the branches that changed.

use std::collections::BTreeSet;
use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c8",
    title: "A laptop returns after four months",
    slice: 1,
    needs: &[Feature::Merge],
    model: &["M8"],
    guards: "Watching a folder after a long absence descends only into changed branches: it \
             reports exactly the changed notes, never an unchanged note's summary, and costs far \
             fewer round trips than one per note.",
    budget: Duration::from_secs(130 * 24 * 3600),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(2);

const NOTES: usize = 10_000;
const CHANGED: usize = 37;
/// Catching up must cost fewer round trips than one per this many notes.
const NOTES_PER_ROUND_TRIP: u64 = 10;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "repo");
    p.device("alice", "laptop");
    p
}

fn note_name(i: usize) -> Name {
    n(&format!("/alice/notes/n{i}"))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/notes");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        let mut feed = laptop.watch(&folder, &Frontier::new()).await?;
        for i in 0..NOTES {
            let note_i = note_name(i);
            phone
                .share(&note_i, members(merge(), &["/alice"], &[person("/alice")]))
                .await?;
            phone
                .put(&note_i, text(&format!("note {i}")), note(1))
                .await?;
        }
        let mut before = Vec::new();
        drain_until(
            &mut feed,
            &mut before,
            "setup: the laptop holds every note",
            10 * LIMIT,
            |seen| versions(seen).count() >= NOTES,
        )
        .await?;
        let had: Frontier = versions(&before).map(|v| v.id.clone()).collect();
        drop(feed);

        w.net().offline(LAPTOP);
        w.skip(120 * DAY).await;
        let changed: BTreeSet<Name> = (0..CHANGED)
            .map(|k| note_name(k * NOTES / CHANGED))
            .collect();
        for c in &changed {
            phone
                .put(c, text("edited while the laptop was away"), note(1))
                .await?;
        }
        w.net().online(LAPTOP);

        let start = w.mark();
        // The workload is the laptop catching up; populating the notes is setup.
        w.report_from(start);
        let mut stream = laptop.watch(&folder, &had).await?;
        let mut after = Vec::new();
        let took = drain_until(
            &mut stream,
            &mut after,
            "the laptop learns every changed note",
            LIMIT,
            |seen| {
                let notes: BTreeSet<&Name> = versions(seen).map(|v| &v.collection).collect();
                changed.iter().all(|c| notes.contains(c))
            },
        )
        .await?;
        w.converged(took);
        let round_trips = w
            .cost_since(start)
            .round_trips
            .expect("a running world measures round trips");

        for v in versions(&after) {
            ensure!(
                changed.contains(&v.collection),
                "watch since the laptop's frontier delivered {:?} of unchanged {}",
                v.id,
                v.collection
            );
        }
        let all: BTreeSet<Name> = (0..NOTES).map(note_name).collect();
        for c in &after {
            if let Change::Summary(s) = c {
                ensure!(
                    !all.contains(&s.collection) || changed.contains(&s.collection),
                    "watch descended into unchanged note {}",
                    s.collection
                );
            }
        }
        ensure!(
            round_trips * NOTES_PER_ROUND_TRIP < NOTES as u64,
            "catching up on {CHANGED} changes of {NOTES} notes took {round_trips} round trips"
        );
        Ok(())
    })
}
