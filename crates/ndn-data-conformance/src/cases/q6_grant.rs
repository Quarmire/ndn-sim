//! Chain 6 — a new device of an admitted person gets the epoch key by a grant; a removed person's
//! new device is refused.
//!
//! Alice's sealed notes are read by Bob and Carol. Alice writes a history; Bob's laptop and
//! Carol's laptop open it. Bob's phone, a device that did not exist when the epoch's entry was
//! signed and so is in no wrap of it, joins afterwards: it asks the devices of the space for the
//! epoch's key and reads the history. Alice then removes Carol and writes on in a new epoch, which
//! Bob's phone opens as well. Carol's phone, as new to the space, asks the same way after her
//! removal and is told no: it reads neither the history nor what came after, and is refused as a
//! device whose owner must be asked.
//!
//! The guard: an epoch key is given to the new device of a person the epoch is for and who still
//! reads (it opens the history and what follows), never to the device of a person who was
//! removed, whatever epoch it asks for; Carol's first device keeps what it opened before.

use std::time::Duration;

use super::chain_kit::{opens, reads, refuses_the_reader};
use super::kit::{LIMIT, SETTLE, has, members_now, n, octets, people, private};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::SpaceChange;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "q6",
    title: "A new device of an admitted person gets the epoch key by grant; a removed person's \
            new device is refused",
    slice: 9,
    needs: &[Feature::Chain, Feature::Seal],
    model: &[],
    guards: "The key of an epoch reaches a reader's new device by a grant, which opens that \
             epoch's history and the epochs after; a person removed is granted nothing, so its \
             new device reads nothing, is told Sealed or NotAllowed with the owner to ask, and \
             its first device keeps what it opened before.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOBS_LAPTOP: Dev = Dev(1);
const BOBS_PHONE: Dev = Dev(2);
const CAROLS_LAPTOP: Dev = Dev(3);
const CAROLS_PHONE: Dev = Dev(4);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p.device("bob", "phone");
    p.device("carol", "laptop");
    p.device("carol", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let notes = n("/alice/32=data/notes");
        let (history, next, after) = (n("/history"), n("/next"), n("/after"));
        let (bob, carol) = (n("/bob"), n("/carol"));
        let alice = w.spaces(ALICE);
        let (bobs_laptop, bobs_phone) = (w.spaces(BOBS_LAPTOP), w.spaces(BOBS_PHONE));
        let (carols_laptop, carols_phone) = (w.spaces(CAROLS_LAPTOP), w.spaces(CAROLS_PHONE));
        w.net().offline(BOBS_PHONE);
        w.net().offline(CAROLS_PHONE);

        alice
            .create(&notes, private(&[], &["/bob", "/carol"]))
            .await?;
        let written = w
            .space_put(ALICE, &notes, &history, octets("sealed history"))
            .await?;
        for s in [&bobs_laptop, &carols_laptop] {
            s.open(&notes).await?;
        }
        w.until(
            "the first devices of Bob and Carol open the history",
            LIMIT,
            || async {
                Ok(
                    reads(&*bobs_laptop, &notes, &history, "sealed history").await?
                        && reads(&*carols_laptop, &notes, &history, "sealed history").await?,
                )
            },
        )
        .await?;

        // Bob's phone, new to the space, is in no wrap of the epoch: it gets the key by a grant
        // and reads the history, and what is written after it.
        w.net().online(BOBS_PHONE);
        bobs_phone.open(&notes).await?;
        w.until("Bob's new phone opens the history", LIMIT, || {
            reads(&*bobs_phone, &notes, &history, "sealed history")
        })
        .await?;
        ensure!(
            has(&*bobs_phone, &notes, &written).await?,
            "Bob's new phone opens the history but does not hold its entry as applied"
        );
        w.space_put(ALICE, &notes, &next, octets("written in the same epoch"))
            .await?;
        w.until("Bob's new phone opens the next entry", LIMIT, || {
            reads(&*bobs_phone, &notes, &next, "written in the same epoch")
        })
        .await?;

        // Alice removes Carol, and writes on in the epoch the removal forces. Carol's laptop and
        // Bob's devices learn of it before Carol's phone starts.
        alice
            .change(
                &notes,
                SpaceChange {
                    remove: people(&["/carol"]),
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.space_put(ALICE, &notes, &after, octets("written after the removal"))
            .await?;
        w.until(
            "Bob's devices open what is written after the removal",
            LIMIT,
            || async {
                Ok(
                    reads(&*bobs_laptop, &notes, &after, "written after the removal").await?
                        && reads(&*bobs_phone, &notes, &after, "written after the removal").await?,
                )
            },
        )
        .await?;
        w.until(
            "Carol's laptop holds the record without Carol",
            LIMIT,
            || async {
                Ok(members_now(&*carols_laptop, &notes)
                    .await?
                    .is_some_and(|m| !m.readers.contains(&carol)))
            },
        )
        .await?;
        ensure!(
            members_now(&*bobs_phone, &notes)
                .await?
                .is_some_and(|m| m.readers.contains(&bob) && !m.readers.contains(&carol)),
            "Bob's phone does not hold the record that removed Carol and kept Bob"
        );

        // Carol's phone, new to the space, asks after her removal and is refused.
        w.net().online(CAROLS_PHONE);
        carols_phone.open(&notes).await?;
        for path in [&history, &after] {
            w.until(
                &format!("Carol's new phone is refused the reader at {path}"),
                LIMIT,
                || refuses_the_reader(&*carols_phone, &notes, path),
            )
            .await?;
        }
        w.sleep(SETTLE).await;
        for path in [&history, &next, &after] {
            ensure!(
                opens(&*carols_phone, &notes, path).await?.is_none(),
                "Carol's new phone opens {path}, though Carol was removed before it asked"
            );
            ensure!(
                refuses_the_reader(&*carols_phone, &notes, path).await?,
                "Carol's new phone is no longer refused the reader at {path}"
            );
        }
        ensure!(
            !has(&*carols_phone, &notes, &written).await?,
            "Carol's new phone applies the history entry, whose epoch key it was never granted"
        );

        // Her first device keeps what it opened before the removal.
        ensure!(
            has(&*carols_laptop, &notes, &written).await?,
            "Carol's first device no longer holds the history it opened before her removal"
        );
        Ok(())
    })
}
