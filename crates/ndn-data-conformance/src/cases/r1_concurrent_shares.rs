//! Review 1 — two of Alice's devices change the readers at once.
//!
//! Alice's laptop, offline, removes Bob from a sealed document while her phone removes Carol.
//! Both sign the next revision of the members record. Under the draft rule a reader kept the
//! record whose signer's key name sorts highest, so one removal silently undid the other: the
//! removed reader kept the epoch key and read every later version. The fix (spec §6): records of
//! one revision merge — readers and writers by intersection, cuts by union — and a merge with
//! fewer readers than the epoch it would keep is resolved by a new record in a new epoch.
//! Removals win.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "r1",
    title: "Two of the owner's devices remove readers at once",
    slice: 2,
    needs: &[Feature::Merge, Feature::Seal],
    model: &["M2", "M4"],
    guards: "Concurrent members records of one revision merge and removals win: a reader that \
             either record removed reads nothing written after both are known, while the readers \
             both kept still do.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const BOB: Dev = Dev(2);
const CAROL: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("bob", "phone");
    p.device("carol", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let doc = n("/alice/32=data/docs/budget");
        let (laptop, phone, bob, carol) = (w.at(LAPTOP), w.at(PHONE), w.at(BOB), w.at(CAROL));
        let readers = |names: &[&str]| names.iter().map(|p| person(p)).collect::<Vec<_>>();
        phone
            .share(
                &doc,
                members(
                    merge(),
                    &["/alice"],
                    &readers(&["/alice", "/bob", "/carol"]),
                ),
            )
            .await?;
        let first = phone.put(&doc, text("draft"), note(1)).await?;
        w.until("every reader opens the draft", LIMIT, || async {
            for layer in [&laptop, &bob, &carol] {
                let seen = look(&**layer, &doc, &Frontier::new(), LOOK).await?;
                if version(&seen, &first).is_none() {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await?;

        // The laptop, offline, removes Bob; the phone, at the same time, removes Carol.
        w.net().offline(LAPTOP);
        laptop
            .share(
                &doc,
                members(merge(), &["/alice"], &readers(&["/alice", "/carol"])),
            )
            .await?;
        phone
            .share(
                &doc,
                members(merge(), &["/alice"], &readers(&["/alice", "/bob"])),
            )
            .await?;
        w.gesture();
        w.net().online(LAPTOP);
        w.sleep(SETTLE).await;

        let later = phone.put(&doc, text("final figures"), note(1)).await?;
        w.until(
            "the laptop opens the phone's later version",
            LIMIT,
            || async {
                let seen = look(&*laptop, &doc, &Frontier::new(), LOOK).await?;
                Ok(version(&seen, &later).is_some())
            },
        )
        .await?;
        w.sleep(SETTLE).await;
        for (who, layer) in [("Bob", &bob), ("Carol", &carol)] {
            let seen = look(&**layer, &doc, &Frontier::new(), LOOK).await?;
            ensure!(
                version(&seen, &later).is_none(),
                "{who}, removed by one of Alice's devices while the other changed the readers \
                 too, opened a version written after both records were known"
            );
        }
        Ok(())
    })
}
