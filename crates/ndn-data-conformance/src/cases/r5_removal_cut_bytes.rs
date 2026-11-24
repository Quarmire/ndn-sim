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

use ndn_data::Name;

use super::kit::{
    LIMIT, LOOK, SETTLE, has, item, items, known, look, n, octets, op_is, public, value_now,
    winning,
};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{EntryRead, RefusalKind, SpaceChange, Spaces};
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

/// What each side signs in Bob's plan.
const HONEST: &str = "bob's plan";
const OTHER: &str = "the copy's other bytes";

/// Whether `spaces`' register at `path` of `space` shows the copy's other bytes.
async fn shows_other(spaces: &dyn Spaces, space: &Name, path: &Name) -> Result<bool, Failure> {
    Ok(value_now(spaces, space, path)
        .await?
        .is_some_and(|bytes| bytes == OTHER.as_bytes()))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let trip = n("/alice/32=data/trip");
        let plan = n("/plan");
        let (alice, bob, carol) = (w.spaces(ALICE), w.spaces(BOB), w.spaces(CAROL));
        w.net().offline(CAROL);

        alice.create(&trip, public(&["/bob"])).await?;
        let seed = alice.put(&trip, &plan, octets("alice: the trip")).await?;
        // A device may apply a write before it has heard of the space's creation (the entries
        // reach it in any order): it holds the folder once it knows the creation as well, and
        // only then can it tell that it may write.
        w.until("Bob holds the folder", LIMIT, || async {
            Ok(has(&*bob, &trip, &seed).await? && known(&*bob, &trip).await?)
        })
        .await?;

        // The copy: Bob's phone, key and storage, before Bob writes into the folder; offline.
        w.steal(COPY).await?;
        let copy = w.spaces(COPY);
        w.until("the copy knows the plan", LIMIT, || known(&*copy, &trip))
            .await?;
        w.net().offline(COPY);

        // Bob writes his plan, which Alice holds; the copy signs other bytes at its name.
        w.gesture();
        let kept = bob.put(&trip, &plan, octets(HONEST)).await?;
        w.until("Alice holds Bob's plan", LIMIT, || {
            has(&*alice, &trip, &kept)
        })
        .await?;
        let other = w
            .sign_at(COPY, &trip, &plan, octets(OTHER), kept.seq)
            .await?;
        ensure!(
            other.name == kept.name && other.seq == kept.seq,
            "precondition: the copy signs at the name of Bob's plan ({kept:?}), got {other:?}"
        );

        // Alice removes Bob from the folder: the cut keeps the plan she holds.
        w.gesture();
        alice
            .change(
                &trip,
                SpaceChange {
                    remove: vec![n("/bob")],
                    ..SpaceChange::default()
                },
            )
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
        let name = kept.name.clone();
        let _ = item(&*carol, &trip, &plan).await?;
        let _ = carol.entry(&trip, &name).await;
        w.sleep(SETTLE).await;
        w.net().online(ALICE);
        w.until("Carol holds the folder's record", LIMIT, || {
            known(&*carol, &trip)
        })
        .await?;
        w.sleep(SETTLE).await;
        ensure!(
            !shows_other(&*carol, &trip, &plan).await?,
            "Carol, who never held Bob's plan, takes the copy's other bytes at {name}, a seq the \
             removal cut kept"
        );
        match carol.entry(&trip, &name).await? {
            EntryRead::Refused {
                kind: RefusalKind::OutsideCut,
                ..
            } => {}
            EntryRead::Read(read) if op_is(&read, OTHER) => {
                return Err(Failure::new(format!(
                    "Carol answers the copy's other bytes at {name}, a seq the removal cut kept"
                )));
            }
            // Alice, back with the record, holds Bob's plan and answers for his phone while it
            // is away (spec §13.5): Carol reads the honest bytes the cut kept, never the copy's.
            EntryRead::Read(read) if read.key() == kept.key() && op_is(&read, HONEST) => {}
            // Carol holds nothing at the name yet: she never shows the copy's bytes, and reads
            // the honest plan below once a device holding it answers.
            EntryRead::NotHeld => {}
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
                Ok(has(&*carol, &trip, &kept).await?
                    && value_now(&*carol, &trip, &plan)
                        .await?
                        .is_some_and(|bytes| bytes == HONEST.as_bytes()))
            },
        )
        .await?;
        w.sleep(SETTLE).await;
        for (who, spaces) in [("Carol", &carol), ("Alice", &alice)] {
            let looked = look(&**spaces, &trip, LOOK).await?;
            ensure!(
                !items(&looked).any(|i| op_is(i, OTHER)),
                "{who} lists the copy's other bytes at {name}"
            );
            let read = winning(&**spaces, &trip, &plan, &[&kept]).await?;
            ensure!(
                read.bytes == HONEST.as_bytes() && has(&**spaces, &trip, &kept).await?,
                "{who} lacks Bob's plan the removal cut kept ({:?})",
                String::from_utf8_lossy(&read.bytes)
            );
        }
        Ok(())
    })
}
