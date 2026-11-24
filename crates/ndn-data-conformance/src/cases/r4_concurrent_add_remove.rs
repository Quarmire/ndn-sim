//! Review 4 — one of Alice's devices adds Carol while another removes Bob.
//!
//! Alice's laptop adds Carol to a shared document while her phone, offline, removes Bob; both
//! sign the next revision of the members record from the same one. Merging the two by
//! intersection (the fix for r1) keeps the removal but drops the addition: a key is a writer, and
//! a reader reads, only if every record lists it, so Carol, whom only the laptop's record lists,
//! is neither once the phone's record is known. The fix (spec §6): each record names the record it
//! was signed from, and records of one revision that share that parent merge three ways against
//! it — every addition and every removal either side made is kept, a removal beating an
//! addition — and a merge that removed a reader is resolved by a record in a new epoch.

use std::time::Duration;

use super::kit::{
    LIMIT, LOOK, RELAYED, SETTLE, agree_admitted, has, item_of, look, n, octets, private,
    reads_entry, winning, wrote,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::SpaceChange;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "r4",
    title: "The owner adds a member on one device while removing another on a second",
    slice: 2,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::RemovalCut,
        Feature::Seal,
    ],
    model: &["M2", "M3", "M4"],
    guards: "Concurrent members records of one revision signed from one parent merge against \
             it: the member one record added writes and reads at every device, and the member \
             the other removed stays removed — his later versions refused, and nothing written \
             after both records are known opened by him.",
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
        let plan = n("/plan");
        let (laptop, phone, bob, carol) = (
            w.spaces(LAPTOP),
            w.spaces(PHONE),
            w.spaces(BOB),
            w.spaces(CAROL),
        );
        laptop.create(&doc, private(&["/bob"], &["/bob"])).await?;
        let seen = w.space_put(BOB, &doc, &plan, octets("bob: edit 1")).await?;
        w.until("both of Alice's devices hold Bob's edit", LIMIT, || async {
            Ok(has(&*laptop, &doc, &seen).await? && has(&*phone, &doc, &seen).await?)
        })
        .await?;

        // The phone, offline, removes Bob; the laptop, at the same time, adds Carol. Bob, still a
        // writer as far as the laptop knows, edits again meanwhile.
        w.net().offline(PHONE);
        phone
            .change(
                &doc,
                SpaceChange {
                    remove: vec![n("/bob")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        laptop
            .change(
                &doc,
                SpaceChange {
                    add_writers: vec![n("/carol")],
                    add_readers: vec![n("/carol")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.gesture();
        let late = bob
            .put(&doc, &plan, octets("bob: edit 2, after his removal"))
            .await?;
        w.net().online(PHONE);
        w.sleep(SETTLE).await;

        // The phone's first put once both records are known needs the key of the epoch in force,
        // which may still be on its way: refused Unavailable (RetryLater), put again as the
        // refusal says (data-layer §17.1, §18.1).
        let later = w
            .space_put(PHONE, &doc, &plan, octets("phone: after both"))
            .await?;
        w.until(
            "Carol, added by the laptop, opens the phone's later version",
            RELAYED,
            || async {
                // Carol, told of nothing, follows the document by watching it.
                let seen = look(&*carol, &doc, LOOK).await?;
                Ok(item_of(&seen, &later.key()).is_some())
            },
        )
        .await?;
        let carols = w
            .space_put(CAROL, &doc, &plan, octets("carol: her first edit"))
            .await?;
        w.until(
            "both of Alice's devices take Carol's edit",
            RELAYED,
            || async {
                Ok(has(&*laptop, &doc, &carols).await? && has(&*phone, &doc, &carols).await?)
            },
        )
        .await?;
        // Bob may still try; his device may refuse to sign, and every other device must refuse
        // what it signs.
        let after = bob.put(&doc, &plan, octets("bob: edit 3")).await.ok();
        w.sleep(SETTLE).await;
        w.until("all devices agree on the document", RELAYED, || async {
            agree_admitted(&[&*laptop, &*phone, &*carol], &doc, &plan, &[&carols]).await
        })
        .await?;

        for (who, spaces) in [("laptop", &laptop), ("phone", &phone), ("Carol", &carol)] {
            let read = winning(&**spaces, &doc, &plan, &[&carols]).await?;
            ensure!(
                has(&**spaces, &doc, &seen).await?,
                "Bob's edit from before his removal left the document at the {who}"
            );
            for entry in std::iter::once(&late).chain(after.as_ref()) {
                ensure!(
                    !has(&**spaces, &doc, entry).await?,
                    "the document at the {who} includes Bob's edit {entry:?}, signed after his \
                     removal"
                );
            }
            ensure!(
                !wrote(&read, "bob: edit 2") && !wrote(&read, "bob: edit 3"),
                "the document at the {who} shows an edit Bob signed after his removal"
            );
        }
        let at_bob = look(&*bob, &doc, LOOK).await?;
        ensure!(
            item_of(&at_bob, &later.key()).is_none(),
            "Bob, removed by the phone while the laptop added Carol, opened a version written \
             after both records were known"
        );
        ensure!(
            !reads_entry(&*bob, &doc, &plan, &later).await?,
            "Bob, removed by the phone while the laptop added Carol, reads the register as a \
             version written after both records were known"
        );
        Ok(())
    })
}
