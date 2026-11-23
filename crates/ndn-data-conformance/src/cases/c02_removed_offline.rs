//! Case 2 — shared document: Bob removed while offline.
//!
//! Alice removes Bob from the plan. Bob, offline and with his clock set back two days, keeps
//! editing and syncs later; his edit claims a date before his removal. Under the draft model who
//! may write was unmodelled and "valid at signing time" trusted Bob's clock. The fix (M2, M3): the
//! space has an owner-signed members record, and removing Bob is a cut naming what is still
//! accepted — Bob up to the edit Alice had seen. Anything later is refused whatever its date. The
//! plan is the path `/plan` of Alice's space `/alice/32=data/docs`.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::kit::{
    DAY, LIMIT, LOOK, SETTLE, contains, has, item_of, look, n, octets, people, private, winning,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::SpaceChange;
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
        let space = n("/alice/32=data/docs");
        let doc = n("/plan");
        let (alice, bob) = (w.spaces(ALICE), w.spaces(BOB));
        alice.create(&space, private(&["/bob"], &["/bob"])).await?;
        w.retry_later(|| bob.open(&space)).await?;
        let seen = w.space_put(BOB, &space, &doc, octets("edit 41")).await?;
        w.until("Alice holds Bob's edit", LIMIT, || {
            has(&*alice, &space, &seen)
        })
        .await?;

        w.net().offline(BOB);
        alice
            .change(
                &space,
                SpaceChange {
                    remove: people(&["/bob"]),
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.gesture();
        let removed_at = w.net().true_date();

        w.net().set_clock(BOB, ClockSkew::behind(2 * DAY));
        let late = bob
            .put(&space, &doc, octets("edit 42, dated earlier"))
            .await?;
        ensure!(
            late.writer == seen.writer && late.seq > seen.seq,
            "Bob's second edit is {late:?}, expected a later seq of {:?}",
            seen.writer
        );
        let own = look(&*bob, &space, LOOK).await?;
        ensure!(
            item_of(&own, &late.key()).is_some(),
            "Bob's own watch does not list his edit"
        );
        let dated = w.net().date(BOB);
        ensure!(
            dated < removed_at,
            "precondition: Bob's edit should claim a date before his removal ({dated:?} vs \
             {removed_at:?})"
        );
        w.net().online(BOB);
        w.sleep(SETTLE).await;

        let at_alice = look(&*alice, &space, LOOK).await?;
        ensure!(
            item_of(&at_alice, &late.key()).is_none() && !has(&*alice, &space, &late).await?,
            "Alice's device took in Bob's edit made after his removal"
        );
        let s = winning(&*alice, &space, &doc, &[&seen]).await?;
        ensure!(
            has(&*alice, &space, &seen).await?,
            "Bob's edit from before the removal left the document"
        );
        ensure!(
            s.key() == seen.key(),
            "the document is written by {:?}; only the edit inside the cut counts, {:?}",
            s.name,
            seen.name
        );
        ensure!(
            s.bytes == b"edit 41"[..] && !contains(&s.bytes, b"edit 42"),
            "the document shows {:?} for Bob; only the edit inside the cut counts",
            String::from_utf8_lossy(&s.bytes)
        );
        Ok(())
    })
}
