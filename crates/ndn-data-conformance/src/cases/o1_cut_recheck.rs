//! Open item 1 — before a cut arrives.
//!
//! A reader that has not yet received a cut may accept versions the cut refuses. "Stale, never
//! wrong" then needs one more rule: when a cut arrives, everything accepted from that key is
//! re-checked against it. Here Alice removes Bob while she is offline; Carol accepts Bob's next
//! edit, then receives the cut when Alice comes back.

use std::time::Duration;

use ndn_data::{Change, Refusal};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "o1",
    title: "Cut re-checked on arrival",
    slice: 2,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::RemovalCut,
        Feature::CutRecheck,
    ],
    model: &["M3"],
    guards: "When a cut arrives, a reader re-checks what it already accepted from the cut's keys: \
             a version it accepted before the cut and the cut refuses is withdrawn from its state \
             and reported as withdrawn to its watchers.",
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
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let doc = n("/alice/32=data/docs/plan");
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        let all = [person("/alice"), person("/bob"), person("/carol")];
        alice
            .share(&doc, members(merge(), &["/alice", "/bob", "/carol"], &all))
            .await?;
        let inside = bob.put(&doc, content(&[("bob", "first")]), note(1)).await?;
        w.until("everyone holds Bob's first edit", LIMIT, || async {
            agree(&[&*alice, &*bob, &*carol], &doc, &[&inside]).await
        })
        .await?;

        // Alice, on a plane, removes Bob; the cut cannot leave her laptop yet.
        w.net().offline(ALICE);
        alice
            .share(
                &doc,
                members(
                    merge(),
                    &["/alice", "/carol"],
                    &[person("/alice"), person("/carol")],
                ),
            )
            .await?;
        w.gesture();

        let mut carols_feed = carol.watch(&doc, &Frontier::new()).await?;
        let outside = bob
            .put(&doc, content(&[("bob", "second")]), note(1))
            .await?;
        w.until(
            "Carol accepts Bob's second edit, not knowing the cut",
            LIMIT,
            || has(&*carol, &doc, &outside),
        )
        .await?;

        w.net().online(ALICE);
        let mut seen = Vec::new();
        let took = drain_until(
            &mut carols_feed,
            &mut seen,
            "Carol withdraws Bob's second edit",
            LIMIT,
            |changes| {
                changes.iter().any(|c| {
                    matches!(
                        c,
                        Change::Withdrawn { collection, id, why: Refusal::OutsideCut(cut) }
                            if *collection == doc && *id == outside && cut.refuses(&doc, id)
                    )
                })
            },
        )
        .await?;
        w.converged(took);
        let s = state(&*carol, &doc).await?;
        ensure!(
            !s.at.contains(&outside),
            "Carol's state still includes Bob's edit the cut refuses"
        );
        ensure!(
            s.at.contains(&inside),
            "the re-check also dropped Bob's edit inside the cut"
        );
        ensure!(
            field(&s.value, "bob") == Some("first"),
            "Carol shows {:?} for Bob's field after the cut",
            field(&s.value, "bob")
        );
        Ok(())
    })
}
