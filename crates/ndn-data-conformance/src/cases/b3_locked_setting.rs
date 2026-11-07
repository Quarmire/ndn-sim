//! Slice 6, b3 — an edit of a locked setting is kept, shown, and counts once unlocked.
//!
//! Alice locks the card's title while she rewrites it. Bob, who holds her lock, sets the title
//! anyway. His version is properly signed and made over what he held, so nothing may drop it;
//! but the app's rule says it does not count while the lock holds. Before slice 6 a rule could
//! only apply or refuse, so the version was either merged against the lock or lost. The fix: the
//! rule answers NotCounted with why; the version is applied, stored and readable by name, shown
//! as `Change::NotCounted` and in `State::not_counted`, kept out of the value — and when Alice
//! unlocks, it counts (`Change::Counted`), on every device alike.

use std::time::Duration;

use ndn_data::Changes;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "b3",
    title: "An edit of a locked setting is kept, shown, and counts once unlocked",
    slice: 6,
    needs: &[Feature::Merge, Feature::AppOps],
    model: &[],
    guards: "A version the rule does not count is stored, readable by name, reported \
             NotCounted with why and listed in the state's not_counted, outside the value, on \
             every device; once the lock is lifted it is reported Counted and in the value, the \
             same on every device.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const DEVICES: [(&str, Dev); 3] = [("Alice", ALICE), ("Bob", BOB), ("Carol", CAROL)];

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let card = n("/alice/32=data/board/card");
        let all = [person("/alice"), person("/bob"), person("/carol")];
        let layers = DEVICES.map(|(_, d)| w.at(d));
        layers[0]
            .share(&card, members(element_rule(), &["/alice", "/bob"], &all))
            .await?;
        let locked = put_element(w, ALICE, &card, |op| {
            op.then(0, Edit::Create("card".into()))
                .set("title", "draft")
                .then(500, Edit::Lock("title".into()))
        })
        .await?;
        w.until("every device holds Alice's lock", LIMIT, || async {
            for layer in &layers {
                if !has(&**layer, &card, &locked).await? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await?;
        let mut watches: Vec<(Changes, Vec<Change>)> = Vec::new();
        for layer in &layers {
            watches.push((layer.watch(&card, &Frontier::new()).await?, Vec::new()));
        }

        let bobs = put_element(w, BOB, &card, |op| op.set("title", "bob's title")).await?;
        let name = log_entry(w, BOB, &card, &bobs);
        for ((who, _), (stream, seen)) in DEVICES.iter().zip(watches.iter_mut()) {
            drain_until(
                stream,
                seen,
                &format!("{who} reports Bob's version not counted"),
                LIMIT,
                |seen| reported_not_counted(seen, &bobs),
            )
            .await?;
        }
        for ((who, _), layer) in DEVICES.iter().zip(&layers) {
            let (s, v) = element_state(&**layer, &card).await?;
            ensure!(
                not_counted_in(&s, &bobs).is_some_and(|why| !why.is_empty()),
                "{who}'s state does not list Bob's version among those not counted, with why: \
                 {:?}",
                s.not_counted
            );
            ensure!(
                setting(&v, "title") == Some("draft"),
                "{who}'s card shows the title {:?} while Alice's lock holds",
                setting(&v, "title")
            );
            match layer.get(&name).await?.got {
                Got::Version(v) => ensure!(
                    v.id == bobs,
                    "{who} answered Bob's version's name with {:?}",
                    v.id
                ),
                other => {
                    return Err(Failure::new(format!(
                        "{who} answered Bob's version's name with {other:?}, not the version"
                    )));
                }
            }
        }

        // Alice lifts her lock: Bob's version counts everywhere.
        let unlocked = put_element(w, ALICE, &card, |op| {
            op.then(0, Edit::Unlock("title".into()))
        })
        .await?;
        let start = tokio::time::Instant::now();
        for ((who, _), (stream, seen)) in DEVICES.iter().zip(watches.iter_mut()) {
            drain_until(
                stream,
                seen,
                &format!("{who} reports Bob's version counted"),
                LIMIT,
                |seen| reported_counted(seen, &bobs),
            )
            .await?;
        }
        w.until("every device agrees on the unlocked card", LIMIT, || {
            let refs: Vec<&dyn DataLayer> = layers.iter().map(|l| &**l).collect();
            let (card, ids) = (&card, [&bobs, &unlocked]);
            async move { agree(&refs, card, &ids).await }
        })
        .await?;
        w.converged(start.elapsed());
        for ((who, _), layer) in DEVICES.iter().zip(&layers) {
            let (s, v) = element_state(&**layer, &card).await?;
            ensure!(
                not_counted_in(&s, &bobs).is_none(),
                "{who} still lists Bob's version as not counted after the unlock"
            );
            ensure!(
                setting(&v, "title") == Some("bob's title"),
                "{who}'s card shows the title {:?}, not Bob's once it counts",
                setting(&v, "title")
            );
        }
        Ok(())
    })
}
