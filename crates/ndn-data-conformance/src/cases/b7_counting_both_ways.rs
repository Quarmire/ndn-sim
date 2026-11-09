//! Slice 6, b7 — counting is a function of the versions applied, so it can stop as well as start:
//! a write and a lock concurrent to it, in either order, give the same counting on every member.
//!
//! Alice owns a paragraph Bob may write. While Bob is offline Alice locks its text, and Bob,
//! unaware, edits it: his write V and her lock L are concurrent. Carol receives L, then V; Dave
//! receives V, then L. Under the rule a write made apart from a lock waits while the lock is in
//! force. Before, a rule could only ever start counting a version (`now_counted`), so Dave, who
//! counted V before L arrived, kept counting it while Carol, holding the same versions, did not:
//! two members, one set of versions, two states. The fix: the rule reports counting changes in
//! both directions (`counting_changed`), the layer tells `Change::NotCounted` as well as
//! `Change::Counted`, and `State::not_counted` follows. Dave stops counting V when L arrives;
//! once Alice unlocks, V counts on every member.

use std::time::Duration;

use ndn_data::Changes;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "b7",
    title: "A write and a lock concurrent to it give the same counting on every member, in \
            either order",
    slice: 6,
    needs: &[Feature::Merge, Feature::AppOps],
    model: &["M12"],
    guards: "A version's counting is a function of the versions applied, never of their arrival \
             order: a member that counted a version stops counting it, telling NotCounted with \
             why, when a version that holds it back arrives, so members receiving the same \
             versions in different orders list the same versions not counted and show the same \
             value; once the lock is lifted the version counts on every member.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const DAVE: Dev = Dev(3);
const DEVICES: [(&str, Dev); 4] = [
    ("Alice", ALICE),
    ("Bob", BOB),
    ("Carol", CAROL),
    ("Dave", DAVE),
];

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p.device("dave", "laptop");
    p
}

/// Whether every device agrees on `c`, holding each of `ids`.
async fn all_agree(w: &World, c: &Name, ids: &[&VersionId]) -> Result<bool, Failure> {
    let layers: Vec<std::sync::Arc<dyn DataLayer>> =
        DEVICES.iter().map(|(_, d)| w.at(*d)).collect();
    let refs: Vec<&dyn DataLayer> = layers.iter().map(|l| &**l).collect();
    agree(&refs, c, ids).await
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let paragraph = n("/alice/32=data/notes/p1");
        let all = [
            person("/alice"),
            person("/bob"),
            person("/carol"),
            person("/dave"),
        ];
        w.at(ALICE)
            .share(
                &paragraph,
                members(element_rule(), &["/alice", "/bob"], &all),
            )
            .await?;
        let made = put_element(w, ALICE, &paragraph, |op| {
            op.then(0, Edit::Create("paragraph".into()))
                .set("text", "draft")
        })
        .await?;
        w.until("every device holds the paragraph", LIMIT, || async {
            hold(w, &[ALICE, BOB, CAROL, DAVE], &paragraph, &[&made]).await
        })
        .await?;

        // Bob and Dave are away while Alice locks the text; Carol receives the lock first.
        w.net().offline(BOB);
        w.net().offline(DAVE);
        let lock = put_element(w, ALICE, &paragraph, |op| {
            op.then(0, Edit::Lock("text".into()))
        })
        .await?;
        w.until("Carol holds the lock", LIMIT, || async {
            hold(w, &[CAROL], &paragraph, &[&lock]).await
        })
        .await?;
        let v = put_element(w, BOB, &paragraph, |op| op.set("text", "bob, unaware")).await?;

        // Alice goes away, nothing of hers stays cached: Dave receives Bob's write first.
        w.net().offline(ALICE);
        w.net().forget_cached(&w.net().spec(ALICE).name()).await;
        w.net().online(BOB);
        w.net().online(DAVE);
        let mut dave_watch: (Changes, Vec<Change>) = (
            w.at(DAVE).watch(&paragraph, &Frontier::new()).await?,
            Vec::new(),
        );
        w.until("Carol and Dave hold Bob's write", LIMIT, || async {
            hold(w, &[CAROL, DAVE], &paragraph, &[&v]).await
        })
        .await?;
        ensure!(
            !has(&*w.at(DAVE), &paragraph, &lock).await?,
            "Dave holds Alice's lock although she was away and nothing of hers was cached: the \
             case could not give him Bob's write first"
        );
        let (s, value) = element_state(&*w.at(DAVE), &paragraph).await?;
        ensure!(
            not_counted_in(&s, &v).is_none() && setting(&value, "text") == Some("bob, unaware"),
            "Dave, holding no lock, does not count Bob's write: {:?}, text {:?}",
            s.not_counted,
            setting(&value, "text")
        );
        let (s, value) = element_state(&*w.at(CAROL), &paragraph).await?;
        ensure!(
            not_counted_in(&s, &v).is_some_and(|why| !why.is_empty())
                && setting(&value, "text") == Some("draft"),
            "Carol, holding the lock Bob's write was made apart from, counts it: {:?}, text {:?}",
            s.not_counted,
            setting(&value, "text")
        );

        // Alice is back: Dave receives the lock after the write, and stops counting it.
        w.net().online(ALICE);
        w.until("Dave holds Alice's lock", LIMIT, || async {
            hold(w, &[DAVE], &paragraph, &[&lock]).await
        })
        .await?;
        drain_until(
            &mut dave_watch.0,
            &mut dave_watch.1,
            "Dave reports Bob's write not counted once the lock arrived",
            LIMIT,
            |seen| reported_not_counted(seen, &v),
        )
        .await?;
        w.until(
            "every device agrees while the lock holds",
            LIMIT,
            || async { all_agree(w, &paragraph, &[&lock, &v]).await },
        )
        .await?;
        for (who, d) in DEVICES {
            let (s, value) = element_state(&*w.at(d), &paragraph).await?;
            ensure!(
                not_counted_in(&s, &v).is_some_and(|why| !why.is_empty()),
                "{who} does not list Bob's write made apart from the lock as not counted, with \
                 why: {:?}",
                s.not_counted
            );
            ensure!(
                setting(&value, "text") == Some("draft"),
                "{who}'s paragraph shows {:?} while the lock holds",
                setting(&value, "text")
            );
        }

        // Alice unlocks: Bob's write counts on every member.
        let mut watches: Vec<(Changes, Vec<Change>)> = Vec::new();
        for (_, d) in DEVICES {
            watches.push((
                w.at(d).watch(&paragraph, &Frontier::new()).await?,
                Vec::new(),
            ));
        }
        let unlocked = put_element(w, ALICE, &paragraph, |op| {
            op.then(0, Edit::Unlock("text".into()))
        })
        .await?;
        let start = tokio::time::Instant::now();
        for ((who, _), (stream, seen)) in DEVICES.iter().zip(watches.iter_mut()) {
            drain_until(
                stream,
                seen,
                &format!("{who} reports Bob's write counted once unlocked"),
                LIMIT,
                |seen| reported_counted(seen, &v),
            )
            .await?;
        }
        w.until(
            "every device agrees on the unlocked paragraph",
            LIMIT,
            || async { all_agree(w, &paragraph, &[&v, &unlocked]).await },
        )
        .await?;
        w.converged(start.elapsed());
        for (who, d) in DEVICES {
            let (s, value) = element_state(&*w.at(d), &paragraph).await?;
            ensure!(
                s.not_counted.is_empty(),
                "{who} still lists versions not counted after the unlock: {:?}",
                s.not_counted
            );
            ensure!(
                setting(&value, "text") == Some("bob, unaware"),
                "{who}'s paragraph shows {:?}, not Bob's write once it counts",
                setting(&value, "text")
            );
        }
        Ok(())
    })
}
