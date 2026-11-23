//! Open item 1 — before a cut arrives.
//!
//! A reader that has not yet received a cut may accept versions the cut refuses. "Stale, never
//! wrong" then needs one more rule: when a cut arrives, everything accepted from that key is
//! re-checked against it. Here Alice removes Bob while she is offline; Carol accepts Bob's next
//! edit, then receives the cut when Alice comes back.

use std::time::Duration;

use super::kit::{LIMIT, agree, drain_until, has, n, octets, private, winning, withdrawn_as};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{RefusalKind, SpaceChange};
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
        let space = n("/alice/32=data/docs");
        let path = n("/plan");
        let (alice, bob, carol) = (w.spaces(ALICE), w.spaces(BOB), w.spaces(CAROL));
        alice
            .create(&space, private(&["/bob", "/carol"], &["/bob", "/carol"]))
            .await?;
        let inside = w
            .space_put(BOB, &space, &path, octets("bob: first"))
            .await?;
        w.until("everyone holds Bob's first edit", LIMIT, || async {
            agree(&[&*alice, &*bob, &*carol], &space, &path, &[&inside]).await
        })
        .await?;

        // Alice, on a plane, removes Bob; the cut cannot leave her laptop yet.
        w.net().offline(ALICE);
        alice
            .change(
                &space,
                SpaceChange {
                    remove: vec![n("/bob")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.gesture();

        let mut carols_feed = carol.watch(&space).await?;
        let outside = bob.put(&space, &path, octets("bob: second")).await?;
        w.until(
            "Carol accepts Bob's second edit, not knowing the cut",
            LIMIT,
            || has(&*carol, &space, &outside),
        )
        .await?;

        w.net().online(ALICE);
        let mut seen = Vec::new();
        let took = drain_until(
            &mut *carols_feed,
            &mut seen,
            "Carol withdraws Bob's second edit",
            LIMIT,
            |events| withdrawn_as(events, &outside.key(), RefusalKind::OutsideCut),
        )
        .await?;
        w.converged(took);
        // A version the cut keeps is taken with the bytes its manifest lists (spec §8): while
        // that manifest packet is on its way it waits, asked for again while it does (§17.1),
        // so the state shows it again once the packet arrives, never later than the case limit.
        w.until(
            "the re-check keeps Bob's edit inside the cut",
            LIMIT,
            || has(&*carol, &space, &inside),
        )
        .await?;
        ensure!(
            !has(&*carol, &space, &outside).await?,
            "Carol still holds Bob's edit the cut refuses as applied"
        );
        let got = winning(&*carol, &space, &path, &[&inside]).await?;
        ensure!(
            got.key() != outside.key() && !got.after.iter().any(|a| a.covers(&outside.key())),
            "Carol's register at {path} still rests on Bob's edit the cut refuses"
        );
        ensure!(
            got.bytes == b"bob: first".as_slice(),
            "Carol shows {:?} for Bob's edit after the cut",
            String::from_utf8_lossy(&got.bytes)
        );
        Ok(())
    })
}
