//! Review 5 — other bytes at a seq a removal cut kept.
//!
//! Alice's trip folder has Bob as a writer. Bob's phone is copied, key and storage, before he
//! writes into it; Bob then writes his plan, which Alice holds, while the copy, offline, signs
//! other bytes at that very name. Alice removes Bob: the folder's cut keeps the seq of the plan
//! she held. Carol, a reader who was away all along and never held Bob's plan, comes back while
//! Bob is away and only the copy answers for his phone. A cut that named seqs only let Carol take
//! the copy's bytes as inside it, for good, while Alice reads Bob's honest plan: the removed
//! writer chose what a late reader reads at a kept seq. The fix (spec §6, §8): a removal cut
//! binds every version it keeps to its bytes — the record names a manifest of their implicit
//! digests, built from what the owner held — so Carol refuses the copy's bytes as outside the cut
//! and reads the honest plan, by its full name, once a device holding it answers.

use std::time::Duration;

use ndn_data::Refusal;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "r5",
    title: "Other bytes at a seq a removal cut kept",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::RemovalCut,
        Feature::FolderMembers,
        Feature::CutManifest,
    ],
    model: &["M3", "M14"],
    guards: "A removal cut binds the versions it keeps to their bytes: a reader that never held a \
             kept version refuses other bytes the removed writer signed at its name, \
             OutsideCut, and reads the honest version once a device holding it answers.",
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

/// The field Bob writes, and what each side signs in it.
const FIELD: &str = "bob";
const HONEST: &str = "bob's plan";
const OTHER: &str = "the copy's other bytes";

/// Whether `layer`'s state of `c` shows the copy's other bytes in Bob's field.
async fn shows_other(layer: &dyn DataLayer, c: &Name) -> Result<bool, Failure> {
    Ok(state_now(layer, c)
        .await?
        .is_some_and(|s| field(&s.value, FIELD) == Some(OTHER)))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let trip = n("/alice/32=data/trip");
        let plan = trip.clone().append("plan");
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        w.net().offline(CAROL);

        alice
            .share_folder(&trip, members(merge(), &["/alice", "/bob"], &[]))
            .await?;
        let seed = alice
            .put(&plan, content(&[("alice", "the trip")]), note(1))
            .await?;
        w.until("Bob holds the folder", LIMIT, || has(&*bob, &plan, &seed))
            .await?;

        // The copy: Bob's phone, key and storage, before Bob writes into the folder; offline.
        w.steal(COPY).await?;
        let copy = w.at(COPY);
        w.until("the copy knows the plan", LIMIT, || known(&*copy, &plan))
            .await?;
        w.net().offline(COPY);

        // Bob writes his plan, which Alice holds; the copy signs other bytes at its name.
        w.gesture();
        let kept = bob.put(&plan, content(&[(FIELD, HONEST)]), note(1)).await?;
        w.until("Alice holds Bob's plan", LIMIT, || {
            has(&*alice, &plan, &kept)
        })
        .await?;
        let other = copy.put(&plan, content(&[(FIELD, OTHER)]), note(1)).await?;
        ensure!(
            other == kept,
            "precondition: the copy signs at the name of Bob's plan ({kept:?}), got {other:?}"
        );

        // Alice removes Bob from the folder: the cut keeps the plan she holds.
        w.gesture();
        alice
            .share_folder(&trip, members(merge(), &["/alice"], &[]))
            .await?;
        w.sleep(LOOK).await;

        // Bob and Alice go away and caches on the way drop their packets; the copy answers for
        // Bob's phone. Carol comes back now, never having held Bob's plan, and takes what the
        // copy serves of the folder; then Alice comes back with the folder's record.
        w.net().offline(BOB);
        w.net().offline(ALICE);
        w.net().forget_cached(&w.net().spec(BOB).name()).await;
        w.net().forget_cached(&w.net().spec(ALICE).name()).await;
        w.net().online(COPY);
        w.net().online(CAROL);
        let name = log_entry(w, BOB, &plan, &kept);
        let _ = state_now(&*carol, &plan).await?;
        let _ = carol.get(&name).await;
        w.sleep(SETTLE).await;
        w.net().online(ALICE);
        w.until("Carol holds the folder's record", LIMIT, || {
            known(&*carol, &plan)
        })
        .await?;
        w.sleep(SETTLE).await;
        ensure!(
            !shows_other(&*carol, &plan).await?,
            "Carol, who never held Bob's plan, takes the copy's other bytes at {name}, a seq the \
             removal cut kept"
        );
        match carol.get(&name).await {
            Err(DataError::Refused {
                why: Refusal::OutsideCut(_),
                ..
            }) => {}
            Ok(answer) if matches!(&answer.got, Got::Version(v) if field_of(v, FIELD) == Some(OTHER)) =>
            {
                return Err(Failure::new(format!(
                    "Carol answers the copy's other bytes at {name}, a seq the removal cut kept"
                )));
            }
            other => {
                return Err(Failure::new(format!(
                    "Carol, reaching only the copy, answers {other:?} for {name}; the copy's \
                     other bytes are refused outside the removal cut"
                )));
            }
        }

        // Bob comes back: Carol reads his honest plan, the bytes the cut kept.
        w.net().online(BOB);
        w.converge(
            "Carol reads the plan the removal cut kept",
            LIMIT,
            || async {
                Ok(state_now(&*carol, &plan).await?.is_some_and(|s| {
                    s.at.contains(&kept) && field(&s.value, FIELD) == Some(HONEST)
                }))
            },
        )
        .await?;
        w.sleep(SETTLE).await;
        for (who, layer) in [("Carol", &carol), ("Alice", &alice)] {
            let looked = look(&**layer, &plan, &Frontier::new(), LOOK).await?;
            ensure!(
                !versions(&looked).any(|v| field_of(v, FIELD) == Some(OTHER)),
                "{who} lists the copy's other bytes at {name}"
            );
            let s = state(&**layer, &plan).await?;
            ensure!(
                field(&s.value, FIELD) == Some(HONEST) && s.at.contains(&kept),
                "{who} lacks Bob's plan the removal cut kept ({:?})",
                s.value
            );
        }
        Ok(())
    })
}
