//! Open item 4 — a reader keeps up with a writer that never pauses.
//!
//! Alice's phone autosaves her notes many times a second while her laptop starts watching the
//! folder. A summary root names its nodes by digest; if the writer stopped serving the nodes of a
//! root once newer roots superseded them, the laptop's descent would have to start over from a
//! newer root, and it would finish only once the phone paused. The fix (§7 of the spec): the
//! writer serves every node any root it signed lists, the reader finishes the descent it started
//! against the root it started from and continues from there.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "o4",
    title: "A reader keeps up with a writer that never pauses",
    slice: 1,
    needs: &[Feature::Merge],
    model: &["M8"],
    guards: "A descent finishes against the root it started from while the writer keeps putting: \
             the reader comes to hold everything written before it looked, and then every \
             version written up to any later moment, without the writer ever pausing.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const TABLET: Dev = Dev(2);

/// Notes in the folder: enough that it is paged and its fuller pages sub-paged, so one root
/// supersedes a few hundred packets.
const NOTES: usize = 1_200;
/// The phone saves one version this often, for as long as the case runs.
const PACE: Duration = Duration::from_millis(2);
/// How long the phone has been saving when the laptop starts watching.
const BEFORE_LOOK: Duration = Duration::from_secs(1);
/// Moments after the first catch-up at which the laptop must catch up again.
const ROUNDS: usize = 5;
/// How long each later catch-up may take while the phone keeps saving.
const KEEP_UP: Duration = Duration::from_secs(10);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "laptop");
    p.device("alice", "tablet");
    p
}

fn note_name(i: usize) -> Name {
    n(&format!("/alice/notes/n{i}"))
}

/// Read `feed` until every id of `want` is among the versions it reported (`held`), for at most
/// `limit` of virtual time; returns how long it took.
async fn until_held(
    feed: &mut Changes,
    held: &mut HashSet<VersionId>,
    want: &[VersionId],
    what: &str,
    limit: Duration,
) -> Result<Duration, Failure> {
    let start = tokio::time::Instant::now();
    let deadline = start + limit;
    let mut missing: Vec<&VersionId> = want.iter().filter(|id| !held.contains(id)).collect();
    while !missing.is_empty() {
        match tokio::time::timeout_at(deadline, feed.next()).await {
            Err(_) => {
                return Err(Failure::new(format!(
                    "{what}: {} of {} versions not reported within {limit:?} of virtual time \
                     (first missing {:?})",
                    missing.len(),
                    want.len(),
                    missing[0]
                )));
            }
            Ok(None) => return Err(Failure::new(format!("{what}: the watch ended"))),
            Ok(Some(change)) => {
                if let Change::Version(v) = change? {
                    held.insert(v.id);
                    missing.retain(|id| !held.contains(id));
                }
            }
        }
    }
    Ok(start.elapsed())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/notes");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        let written: RefCell<Vec<VersionId>> = RefCell::new(Vec::new());
        for i in 0..NOTES {
            let note_i = note_name(i);
            phone
                .share(&note_i, members(merge(), &["/alice"], &[person("/alice")]))
                .await?;
            let id = phone
                .put(&note_i, text(&format!("note {i}")), note(1))
                .await?;
            written.borrow_mut().push(id);
        }

        // The tablet watches throughout: each of its refreshes has the phone sign a newer root,
        // superseding the nodes of the root the laptop is descending many times over.
        let _tablet_feed = w.at(TABLET).watch(&folder, &Frontier::new()).await?;
        let stop = Cell::new(false);
        let saving = async {
            // Each save goes to another note (7 is coprime to the note count), so every save
            // supersedes another branch of the summary.
            let mut k = 0usize;
            while !stop.get() {
                let note_k = note_name(k * 7 % NOTES);
                let id = phone
                    .put(&note_k, text(&format!("autosave {k}")), note(1))
                    .await?;
                written.borrow_mut().push(id);
                k += 1;
                w.sleep(PACE).await;
            }
            Ok::<_, Failure>(())
        };
        let watching = async {
            let outcome = async {
                w.sleep(BEFORE_LOOK).await;
                let before = written.borrow().clone();
                let start = w.mark();
                w.report_from(start);
                let mut feed = laptop.watch(&folder, &Frontier::new()).await?;
                let mut held = HashSet::new();
                let took = until_held(
                    &mut feed,
                    &mut held,
                    &before,
                    "the laptop holds everything written before it looked",
                    LIMIT,
                )
                .await?;
                w.converged(took);
                for round in 1..=ROUNDS {
                    let target = written.borrow().clone();
                    until_held(
                        &mut feed,
                        &mut held,
                        &target,
                        &format!(
                            "catch-up {round}: the laptop holds all {} versions written so far",
                            target.len()
                        ),
                        KEEP_UP,
                    )
                    .await?;
                }
                Ok::<_, Failure>(())
            }
            .await;
            stop.set(true);
            outcome
        };
        let (saved, watched) = futures::future::join(saving, watching).await;
        watched?;
        saved
    })
}
