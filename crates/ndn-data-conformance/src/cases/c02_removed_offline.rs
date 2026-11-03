//! Case 2 — shared document: Bob removed while offline.
//!
//! Alice removes Bob from the plan. Bob, offline and with his clock set back two days, keeps
//! editing and syncs later; his edit claims a date before his removal. Under the draft model who
//! may write was unmodelled and "valid at signing time" trusted Bob's clock. The fix (M2, M3): the
//! document has an owner-signed members record, and removing Bob is a cut naming what is still
//! accepted — Bob up to the edit Alice had seen. Anything later is refused whatever its date.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c2",
    title: "Shared document: Bob removed while offline",
    slice: 2,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::RemovalCut,
    ],
    model: &["M2", "M3"],
    guards: "Removing a member is a cut: his versions inside it stay in the document, and a \
             later version by him is refused at every reader, whatever date it claims.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let doc = n("/alice/32=data/docs/plan");
        let (alice, bob) = (w.at(ALICE), w.at(BOB));
        alice
            .share(
                &doc,
                members(
                    merge(),
                    &["/alice", "/bob"],
                    &[person("/alice"), person("/bob")],
                ),
            )
            .await?;
        let seen = bob
            .put(&doc, content(&[("bob", "edit 41")]), note(1))
            .await?;
        w.until("Alice holds Bob's edit", LIMIT, || {
            has(&*alice, &doc, &seen)
        })
        .await?;

        w.net().offline(BOB);
        alice
            .share(&doc, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.gesture();
        let removed_at = w.net().true_date();

        w.net().set_clock(BOB, ClockSkew::behind(2 * DAY));
        let late = bob
            .put(&doc, content(&[("bob", "edit 42, dated earlier")]), note(1))
            .await?;
        ensure!(
            late.writer == seen.writer && late.seq > seen.seq,
            "Bob's second edit is {late:?}, expected a later seq of {:?}",
            seen.writer
        );
        let own = look(&*bob, &doc, &Frontier::new(), LOOK).await?;
        let dated = version(&own, &late)
            .ok_or_else(|| Failure::new("Bob's own watch does not list his edit"))?
            .dated;
        ensure!(
            dated < removed_at,
            "precondition: Bob's edit should claim a date before his removal ({dated:?} vs \
             {removed_at:?})"
        );
        w.net().online(BOB);
        w.sleep(SETTLE).await;

        let at_alice = look(&*alice, &doc, &Frontier::new(), LOOK).await?;
        ensure!(
            version(&at_alice, &late).is_none(),
            "Alice's watch delivered Bob's edit made after his removal"
        );
        let s = state(&*alice, &doc).await?;
        ensure!(
            s.at.contains(&seen),
            "Bob's edit from before the removal left the document"
        );
        ensure!(
            !s.at.contains(&late),
            "the document includes Bob's edit made after his removal"
        );
        ensure!(
            field(&s.value, "bob") == Some("edit 41"),
            "the document shows {:?} for Bob's field; only the edit inside the cut counts",
            field(&s.value, "bob")
        );
        Ok(())
    })
}
