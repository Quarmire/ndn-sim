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

use super::kit::{LIMIT, LOOK, SETTLE, agree, item_of, look, n, octets, private, reads_entry};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::SpaceChange;
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
        let doc = n("/alice/32=data/docs");
        let budget = n("/budget");
        let (laptop, phone, bob, carol) = (
            w.spaces(LAPTOP),
            w.spaces(PHONE),
            w.spaces(BOB),
            w.spaces(CAROL),
        );
        phone
            .create(&doc, private(&[], &["/bob", "/carol"]))
            .await?;
        for device in [&laptop, &bob, &carol] {
            w.retry_later(|| device.open(&doc)).await?;
        }
        let first = w.space_put(PHONE, &doc, &budget, octets("draft")).await?;
        w.until("every reader opens the draft", LIMIT, || async {
            agree(&[&*laptop, &*bob, &*carol], &doc, &budget, &[&first]).await
        })
        .await?;

        // The laptop, offline, removes Bob; the phone, at the same time, removes Carol.
        w.net().offline(LAPTOP);
        laptop
            .change(
                &doc,
                SpaceChange {
                    remove: vec![n("/bob")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        phone
            .change(
                &doc,
                SpaceChange {
                    remove: vec![n("/carol")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.gesture();
        w.net().online(LAPTOP);
        w.sleep(SETTLE).await;

        // The epoch in force may be the laptop's: the phone asks it for the key, and on a faulty
        // network may answer RetryLater first (spec §9, §17.1) — a host puts again.
        let later = w
            .space_put(PHONE, &doc, &budget, octets("final figures"))
            .await?;
        w.until(
            "the laptop opens the phone's later version",
            LIMIT,
            || async { agree(&[&*laptop, &*phone], &doc, &budget, &[&later]).await },
        )
        .await?;
        w.sleep(SETTLE).await;
        for (who, spaces) in [("Bob", &bob), ("Carol", &carol)] {
            let seen = look(&**spaces, &doc, LOOK).await?;
            ensure!(
                item_of(&seen, &later.key()).is_none(),
                "{who}, removed by one of Alice's devices while the other changed the readers \
                 too, opened a version written after both records were known"
            );
            ensure!(
                !reads_entry(&**spaces, &doc, &budget, &later).await?,
                "{who}, removed by one of Alice's devices while the other changed the readers \
                 too, reads the register as a version written after both records were known"
            );
        }
        Ok(())
    })
}
