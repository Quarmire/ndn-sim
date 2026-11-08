//! Slice 6, g4 — a seq signed twice, in two collections, buys a writer nothing.
//!
//! A key's log is one sequence across its collections, and a collection holds a subset of it, so
//! nothing stops a key from signing a second entry at a seq it already used, in another
//! collection: a new name, so no same-name equivocation. Bob's phone is copied while it holds
//! Alice's two folders and has written nothing; Bob then writes on, and the copy — offline,
//! writing on from the same log — signs the same seqs elsewhere. Before the fix, a folder cut
//! listed accepted seqs per key across the whole folder, so Alice removing Bob from her trip
//! folder still accepted the copy's entries at the seqs it kept, in a collection Bob never wrote;
//! and a group's members were noted one per seq, so which of two entries at a member's seq
//! counted depended on arrival order. Now a folder cut keeps each seq in the collection it was
//! held in, and a group whose writer signed two entries at one of its seqs is malformed: every
//! reader refuses both, alike.

use std::time::Duration;

use ndn_data::Refusal;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "g4",
    title: "A seq signed twice, in two collections, buys a writer nothing",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::RemovalCut,
        Feature::CutRecheck,
        Feature::Groups,
        Feature::FolderMembers,
    ],
    model: &["M14", "M15"],
    guards: "A folder's removal cut accepts each seq only in the collection it was held in: an \
             entry of the removed key at an accepted seq, in another collection under the \
             folder, is refused OutsideCut on every reader. A group whose writer signed another \
             entry at one of its seqs, in another collection, is refused for its group on every \
             reader that holds both, whatever their order.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const COPY: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    let bob = p.device("bob", "phone");
    p.device("carol", "laptop");
    p.thief(bob);
    p
}

/// Whether `layer` answers entry `name` refused, with the reason `want` accepts.
async fn refused(
    layer: &dyn DataLayer,
    name: &Name,
    want: impl Fn(&Refusal) -> bool,
) -> Result<bool, Failure> {
    Ok(match layer.get(name).await {
        Err(DataError::Refused { why, .. }) => want(&why),
        _ => false,
    })
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let trip = n("/alice/32=data/trip");
        let [plan, budget, later] = ["plan", "budget", "later"].map(|x| trip.clone().append(x));
        let club = n("/alice/32=data/club");
        let [todo, doing, spare] = ["todo", "doing", "spare"].map(|x| club.clone().append(x));
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        let readers = [&alice, &carol];

        for f in [&trip, &club] {
            alice
                .share_folder(f, members(merge(), &["/alice", "/bob"], &[]).into())
                .await?;
        }
        let seeds = [
            alice.put(&plan, text("trip"), note(1)).await?,
            alice.put(&todo, text("club"), note(1)).await?,
        ];
        w.until("Bob holds both folders", LIMIT, || async {
            Ok(has(&*bob, &plan, &seeds[0]).await? && has(&*bob, &todo, &seeds[1]).await?)
        })
        .await?;

        // The copy: Bob's phone, key and storage, before Bob writes anything; offline.
        w.steal(COPY).await?;
        let copy = w.at(COPY);
        w.until("the copy knows both folders", LIMIT, || async {
            Ok(known(&*copy, &plan).await? && known(&*copy, &todo).await?)
        })
        .await?;
        w.net().offline(COPY);

        // Bob writes on: one version in each of two trip collections, then a group in the club.
        w.gesture();
        let kept = [
            bob.put(&plan, text("bob's plan"), note(1)).await?,
            bob.put(&budget, text("bob's budget"), note(1)).await?,
        ];
        let group = bob
            .put_group(
                vec![
                    (todo.clone(), ndn_data::Edit::Fields(text("bob's task"))),
                    (doing.clone(), ndn_data::Edit::Fields(text("bob's task"))),
                ],
                note(1),
            )
            .await?;
        w.until("Alice and Carol count what Bob wrote", LIMIT, || async {
            for layer in readers {
                for (c, id) in [
                    (&plan, &kept[0]),
                    (&budget, &kept[1]),
                    (&todo, &group[0]),
                    (&doing, &group[1]),
                ] {
                    if !has(&**layer, c, id).await? {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })
        .await?;
        // Alice removes Bob from the trip: the cut keeps exactly what she holds of him there.
        w.gesture();
        alice
            .share_folder(&trip, members(merge(), &["/alice"], &[]).into())
            .await?;

        // The copy, which has not heard of the removal, writes on from the log it holds: the seqs
        // the cut kept, in a trip collection Bob never wrote, then the group's first seq in the
        // club, and on past Bob's head.
        let mut again = Vec::new();
        for (c, what) in [
            (&later, "copy 1"),
            (&later, "copy 2"),
            (&spare, "copy 3"),
            (&spare, "copy 4"),
            (&spare, "copy 5"),
        ] {
            again.push(copy.put(c, text(what), note(1)).await?);
        }
        ensure!(
            again[0].seq == kept[0].seq && again[1].seq == kept[1].seq,
            "precondition: the copy signs again the seqs the cut kept ({:?}, {:?}), got {:?}",
            kept[0].seq,
            kept[1].seq,
            &again[..2]
        );
        ensure!(
            again[2].seq == group[0].seq && again.iter().all(|id| id.writer == kept[0].writer),
            "precondition: the copy signs as Bob at the group's first seq {:?}, got {:?}",
            group[0].seq,
            again[2]
        );
        w.net().offline(BOB);
        w.net().online(COPY);
        w.sleep(SETTLE).await;

        // The trip: the copy's entries at the kept seqs are outside the cut everywhere, and what
        // the cut kept stays.
        for layer in readers {
            for id in &again[..2] {
                let name = log_entry(w, BOB, &later, id);
                ensure!(
                    refused(&**layer, &name, |why| matches!(why, Refusal::OutsideCut(_))).await?,
                    "{name}, the removed key's entry at a seq its cut kept in another \
                     collection, is not refused OutsideCut"
                );
                ensure!(
                    !has(&**layer, &later, id).await?,
                    "a reader counts the removed key's entry {id:?} in {later}"
                );
            }
            ensure!(
                has(&**layer, &plan, &kept[0]).await? && has(&**layer, &budget, &kept[1]).await?,
                "what the trip's cut kept of Bob is no longer counted"
            );
        }

        // The club: two entries at the group's first seq, so the group counts nowhere.
        let second = log_entry(w, BOB, &spare, &again[2]);
        for layer in readers {
            let _ = layer.get(&second).await;
        }
        w.until("every reader refuses Bob's group", LIMIT, || async {
            for layer in readers {
                for (c, id) in [(&todo, &group[0]), (&doing, &group[1])] {
                    if has(&**layer, c, id).await? {
                        return Ok(false);
                    }
                    let name = log_entry(w, BOB, c, id);
                    if !refused(&**layer, &name, |why| matches!(why, Refusal::Group { .. })).await?
                    {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })
        .await?;
        Ok(())
    })
}
