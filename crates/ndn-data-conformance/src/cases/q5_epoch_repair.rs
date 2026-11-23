//! Chain 5 — two owner devices remove two readers at once, and the repair leaves one complete
//! epoch that neither opens.
//!
//! Alice's sealed plans are read by Bob, Carol and Dave, Dave a writer too. Everyone opens a first
//! entry, the draft. Alice's laptop, offline, removes Bob while her phone removes Carol; each
//! signs the epoch it sees short of readers, in an audience that still lists the reader the other
//! removed, so neither epoch fits the readers the two removals leave. The laptop comes back; each
//! owner device repairs what the merged members need, and the writers seal in one epoch that
//! lists exactly Alice and Dave.
//!
//! The guard (the old case `r1`, over the epochs of the new layer): after the repair the owner's
//! devices and Dave hold the same epoch in force and it is complete; what Alice and Dave write
//! then is opened by each other and by nobody removed; Bob's and Carol's devices keep the draft
//! they opened before their removal, and are told nothing was taken back of it.

use std::time::Duration;

use super::chain_kit::{drain_quiet, one_complete_epoch, opens, reads};
use super::kit::{
    LIMIT, LOOK, SETTLE, has, items, known, members_now, n, octets, op_is, people, private,
    withdrawn,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{SpaceChange, SpaceEvent, SpaceMembers, Spaces};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "q5",
    title: "Two owner devices remove two readers at once and the repair leaves one complete epoch",
    slice: 9,
    needs: &[Feature::Chain, Feature::Seal, Feature::RemovalCut],
    model: &[],
    guards: "Two owner devices that remove two different readers of a sealed space at once end \
             with one complete epoch in force on every device, in which the writers seal: the \
             readers that remain open what is written after, neither removed reader does, and \
             the removed readers keep what they opened before without being told it is taken \
             back.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const BOB: Dev = Dev(2);
const CAROL: Dev = Dev(3);
const DAVE: Dev = Dev(4);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("bob", "phone");
    p.device("carol", "phone");
    p.device("dave", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let plans = n("/alice/32=data/plans");
        let (history, later, from_dave) = (n("/history"), n("/later"), n("/dave"));
        let alice = n("/alice");
        let (laptop, phone) = (w.spaces(LAPTOP), w.spaces(PHONE));
        let (bob, carol, dave) = (w.spaces(BOB), w.spaces(CAROL), w.spaces(DAVE));
        let remove = |who: &str| SpaceChange {
            remove: people(&[who]),
            ..SpaceChange::default()
        };

        laptop
            .create(&plans, private(&["/dave"], &["/bob", "/carol", "/dave"]))
            .await?;
        for s in [&phone, &bob, &carol, &dave] {
            s.open(&plans).await?;
        }
        w.until("every device holds the record", LIMIT, || async {
            for s in [&phone, &bob, &carol, &dave] {
                if !known(&**s, &plans).await? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await?;

        // Everyone opens the draft; Bob and Carol watch while they still may.
        let draft = w
            .space_put(LAPTOP, &plans, &history, octets("the draft"))
            .await?;
        let mut bob_feed = w.retry_later(|| bob.watch(&plans)).await?;
        let mut carol_feed = w.retry_later(|| carol.watch(&plans)).await?;
        w.until("every device opens the draft", LIMIT, || async {
            for s in [&laptop, &phone, &bob, &carol, &dave] {
                if !reads(&**s, &plans, &history, "the draft").await? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await?;
        let mut bob_seen = drain_quiet(&mut *bob_feed, LOOK).await;
        let mut carol_seen = drain_quiet(&mut *carol_feed, LOOK).await;
        for (who, seen) in [("Bob", &bob_seen), ("Carol", &carol_seen)] {
            ensure!(
                items(seen).any(|i| i.path == history && op_is(i, "the draft")),
                "{who}'s watch does not report the draft they opened"
            );
        }

        // The laptop, offline, removes Bob; the phone, at the same time, removes Carol.
        w.net().offline(LAPTOP);
        laptop.change(&plans, remove("/bob")).await?;
        phone.change(&plans, remove("/carol")).await?;
        w.gesture();
        w.net().online(LAPTOP);

        // Each owner device repairs; the two removals leave Alice and Dave, and one epoch for
        // exactly them is in force everywhere, complete.
        let end = SpaceMembers::new(&alice, people(&["/dave"]), people(&["/dave"]), false);
        let owners_and_dave: [&dyn Spaces; 3] = [&*laptop, &*phone, &*dave];
        w.converge(
            "the owner's devices and Dave hold the members both removals leave and one complete \
             epoch",
            LIMIT,
            || async {
                for s in &owners_and_dave {
                    if members_now(*s, &plans).await?.as_ref() != Some(&end) {
                        return Ok(false);
                    }
                }
                one_complete_epoch(&owners_and_dave, &plans).await
            },
        )
        .await?;

        // The writers seal in it: what the owner and Dave write, they and nobody removed open.
        let after = w
            .space_put(LAPTOP, &plans, &later, octets("after the repair"))
            .await?;
        let theirs = w
            .space_put(DAVE, &plans, &from_dave, octets("dave's note"))
            .await?;
        w.until("the owner's devices and Dave open both", LIMIT, || async {
            for s in &owners_and_dave {
                if !reads(*s, &plans, &later, "after the repair").await?
                    || !reads(*s, &plans, &from_dave, "dave's note").await?
                {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await?;
        w.sleep(SETTLE).await;

        bob_seen.extend(drain_quiet(&mut *bob_feed, LOOK).await);
        carol_seen.extend(drain_quiet(&mut *carol_feed, LOOK).await);
        for (who, spaces, seen) in [("Bob", &bob, &bob_seen), ("Carol", &carol, &carol_seen)] {
            for (what, path) in [("Alice's", &later), ("Dave's", &from_dave)] {
                ensure!(
                    opens(&**spaces, &plans, path).await?.is_none(),
                    "{who}, removed, opens {what} entry written after the repair, at {path}"
                );
            }
            for (what, entry) in [("Alice's", &after), ("Dave's", &theirs)] {
                ensure!(
                    !has(&**spaces, &plans, entry).await?,
                    "{who}, removed, holds {what} entry written after the repair as applied"
                );
            }
            ensure!(
                !items(seen).any(|i| i.path == later || i.path == from_dave),
                "{who}'s watch reports an entry written after the repair"
            );
            ensure!(
                has(&**spaces, &plans, &draft).await?,
                "{who}'s device no longer holds the draft it opened before its removal"
            );
            ensure!(
                !withdrawn(seen, &draft.key()),
                "{who}'s watch reports the draft withdrawn: a removal takes back nothing a \
                 reader already opened"
            );
            ensure!(
                !seen.iter().any(|e| matches!(e, SpaceEvent::Removed(_))),
                "{who}'s watch reports a path removed after their removal"
            );
        }
        Ok(())
    })
}
