//! Case 8 — a laptop returns after four months.
//!
//! 10,000 notes, each its own path of one space; 37 changed while the laptop was away. One flat
//! summary per collection meant checking 10,000 summaries to find 37 changes. The fix (M8):
//! summaries nest — the notes folder summarises its children by digest — and watch descends only
//! into the branches that changed. Over spaces the notes are the paths `/n0`…`/n9999` of Alice's
//! space `/alice/32=data/notes`, and the laptop's watch of the space, held open across the
//! absence, reports what changed and nothing else. (The summaries themselves, and a watch that
//! starts from a frontier, are the old provider's own structure; the neutral surface has
//! neither: what it holds of the guard is that a device that comes back is told exactly what
//! changed, at a cost far below one round trip per note.)

use std::collections::BTreeSet;
use std::time::Duration;

use ndn_data::Name;

use super::kit::{DAY, LIMIT, drain_until, items, n, octets, op_is, private};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::SpaceEvent;
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
/// What the changed notes say.
const EDITED: &str = "edited while the laptop was away";

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "repo");
    p.device("alice", "laptop");
    p
}

fn note_path(i: usize) -> Name {
    n(&format!("/n{i}"))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n("/alice/32=data/notes");
        let (phone, laptop) = (w.spaces(PHONE), w.spaces(LAPTOP));
        phone.create(&space, private(&[], &[])).await?;
        w.retry_later(|| laptop.open(&space)).await?;
        let mut feed = w.retry_later(|| laptop.watch(&space)).await?;
        for i in 0..NOTES {
            phone
                .put(&space, &note_path(i), octets(&format!("note {i}")))
                .await?;
        }
        let mut before = Vec::new();
        drain_until(
            &mut *feed,
            &mut before,
            "setup: the laptop holds every note",
            10 * LIMIT,
            |seen| items(seen).count() >= NOTES,
        )
        .await?;

        w.net().offline(LAPTOP);
        w.skip(120 * DAY).await;
        let changed: BTreeSet<Name> = (0..CHANGED)
            .map(|k| note_path(k * NOTES / CHANGED))
            .collect();
        for c in &changed {
            phone.put(&space, c, octets(EDITED)).await?;
        }
        w.net().online(LAPTOP);

        let start = w.mark();
        // The workload is the laptop catching up; populating the notes is setup.
        w.report_from(start);
        let mut after = Vec::new();
        let took = drain_until(
            &mut *feed,
            &mut after,
            "the laptop learns every changed note",
            LIMIT,
            |seen| {
                changed
                    .iter()
                    .all(|c| items(seen).any(|i| i.path == *c && op_is(i, EDITED)))
            },
        )
        .await?;
        w.converged(took);
        let round_trips = w
            .cost_since(start)
            .round_trips
            .expect("a running world measures round trips");

        ensure!(
            !after.iter().any(|e| matches!(e, SpaceEvent::Lagged)),
            "the laptop's watch dropped changes while it caught up"
        );
        for item in items(&after) {
            ensure!(
                changed.contains(&item.path),
                "the watch held across the absence delivered {} of unchanged {}",
                item.name,
                item.path
            );
        }
        ensure!(
            round_trips * NOTES_PER_ROUND_TRIP < NOTES as u64,
            "catching up on {CHANGED} changes of {NOTES} notes took {round_trips} round trips"
        );
        Ok(())
    })
}
