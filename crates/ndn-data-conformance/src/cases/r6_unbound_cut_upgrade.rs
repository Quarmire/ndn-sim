//! Round 2 review C2 — an old-form removal cut across an upgrade.
//!
//! Alice's trip folder has Bob as a writer; Bob writes two versions of the plan, which Alice and
//! Carol hold. Alice removes Bob from a build that predates removal cuts binding bytes: the
//! folder's record keeps Bob's two seqs by seq alone, with no `CutBytes`. Alice's laptop is then
//! upgraded and restarted, and opens the plan; Carol takes the old-form record and restarts on
//! the new build too. An unbound cut accepts nothing, but the versions it keeps are honest
//! history the owner held: the new build let them go — deleted from the store, never to be bound
//! again, because the owner's next record binds only bytes it holds — so Bob's pre-removal work
//! was gone for good on every updated device. The fix (spec §8): under an unbound cut the kept
//! versions are refused (`OutsideCut`) but kept, bytes and all, across restarts, wakes and new
//! records; the owner's next record binds them from those bytes, and every device takes them
//! back. Bob stays away throughout, so nothing can be fetched from him again.

use std::time::Duration;

use ndn_data::Refusal;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "r6",
    title: "An old-form removal cut across an upgrade",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::RemovalCut,
        Feature::FolderMembers,
        Feature::CutManifest,
        Feature::UnboundCut,
    ],
    model: &["M3", "M14"],
    guards: "The versions an old-form (unbound) removal cut keeps are refused but never let go: \
             after an upgrade and a restart they stay held, and the owner's next record binds \
             them from those bytes, so every device counts and serves them again.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "laptop");
    p
}

/// The field Bob writes, and what his two versions set it to.
const FIELD: &str = "bob";
const FIRST: &str = "bob's first plan";
const SECOND: &str = "bob's second plan";

/// Whether `layer`'s state of `c` holds every one of `ids`.
async fn holds_all(layer: &dyn DataLayer, c: &Name, ids: &[&VersionId]) -> Result<bool, Failure> {
    Ok(state_now(layer, c)
        .await?
        .is_some_and(|s| ids.iter().all(|id| s.at.contains(id))))
}

/// Whether `layer`'s state of `c` holds none of `ids`.
async fn holds_none(layer: &dyn DataLayer, c: &Name, ids: &[&VersionId]) -> Result<bool, Failure> {
    Ok(state_now(layer, c)
        .await?
        .is_some_and(|s| ids.iter().all(|id| !s.at.contains(id))))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let trip = n("/alice/32=data/trip");
        let plan = trip.clone().append("plan");
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));

        alice
            .share_folder(&trip, members(merge(), &["/alice", "/bob"], &[]))
            .await?;
        let seed = alice
            .put(&plan, content(&[("alice", "the trip")]), note(1))
            .await?;
        w.until("Bob holds the folder", LIMIT, || has(&*bob, &plan, &seed))
            .await?;
        w.gesture();
        let first = bob.put(&plan, content(&[(FIELD, FIRST)]), note(1)).await?;
        w.gesture();
        let second = bob.put(&plan, content(&[(FIELD, SECOND)]), note(1)).await?;
        let kept = [&first, &second];
        for (who, layer) in [("Alice", &alice), ("Carol", &carol)] {
            w.until(&format!("{who} holds Bob's plans"), LIMIT, || {
                holds_all(&**layer, &plan, &kept)
            })
            .await?;
        }

        // Bob and Carol go away; Alice removes Bob, and her record, as the older build signed it,
        // keeps his two seqs with no bytes bound.
        w.net().offline(BOB);
        w.net().offline(CAROL);
        w.gesture();
        alice
            .share_folder(&trip, members(merge(), &["/alice"], &[]))
            .await?;
        w.sleep(LOOK).await;
        w.stop(ALICE).await?;
        w.sign_unbound(ALICE, &trip)?;
        w.net().forget_cached(&w.net().spec(ALICE).name()).await;

        // The upgrade: Alice's laptop starts the current build on that store and opens the plan.
        let alice = w.restart(ALICE).await?;
        w.until("Alice, upgraded, reads the plan", LIMIT, || {
            known(&*alice, &plan)
        })
        .await?;
        let names: Vec<Name> = kept.iter().map(|id| log_entry(w, BOB, &plan, id)).collect();
        for name in &names {
            match alice.get(name).await {
                Err(DataError::Refused {
                    why: Refusal::OutsideCut(_),
                    ..
                }) => {}
                other => {
                    return Err(Failure::new(format!(
                        "precondition: under the old-form cut, upgraded Alice answers {other:?} \
                         for {name}; a version an unbound cut keeps is refused OutsideCut"
                    )));
                }
            }
        }

        // Carol comes back, takes the old-form record, and restarts on the current build too.
        w.net().online(CAROL);
        w.until("Carol takes the record removing Bob", LIMIT, || {
            holds_none(&*carol, &plan, &kept)
        })
        .await?;
        w.sleep(SETTLE).await;
        w.stop(CAROL).await?;
        let carol = w.restart(CAROL).await?;
        w.until("Carol, restarted, reads the plan", LIMIT, || {
            known(&*carol, &plan)
        })
        .await?;

        // Alice shares the folder again (Dave becomes a writer): the new record binds what the
        // old one kept, from the bytes she holds.
        w.gesture();
        alice
            .share_folder(&trip, members(merge(), &["/alice", "/dave"], &[]))
            .await?;
        for (who, layer) in [("Alice", &alice), ("Carol", &carol)] {
            let what = format!(
                "{who} holds Bob's versions the old-form removal cut kept, after the upgrade, a \
                 restart and the owner's next record"
            );
            w.until(&what, LIMIT, || holds_all(&**layer, &plan, &kept))
                .await?;
        }
        w.sleep(SETTLE).await;
        for (who, layer) in [("Alice", &alice), ("Carol", &carol)] {
            let s = state(&**layer, &plan).await?;
            ensure!(
                kept.iter()
                    .all(|id| s.at.contains(id) && !counted_not(&s, id))
                    && field(&s.value, FIELD) == Some(SECOND),
                "{who} does not count Bob's plans the old-form cut kept ({:?}, not counted {:?})",
                s.value,
                s.not_counted
            );
            for name in &names {
                match layer.get(name).await {
                    Ok(answer) if matches!(answer.got, Got::Version(_)) => {}
                    other => {
                        return Err(Failure::new(format!(
                            "{who} answers {other:?} for {name}, a version the owner's new record \
                             binds"
                        )));
                    }
                }
            }
        }
        Ok(())
    })
}

/// Whether `s` lists `id` as not counted.
fn counted_not(s: &State, id: &VersionId) -> bool {
    s.not_counted.iter().any(|(x, _)| x == id)
}
