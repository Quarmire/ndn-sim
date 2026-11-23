//! Round 3 review M5 — a removal must win across revisions.
//!
//! Alice's laptop removes Carol from a shared document: revision 2, with a removal cut and a new
//! epoch. Her phone, offline, admits Dave at revision 2 from the record before (as an
//! introduction's admission signs it, with no gesture; the case signs that record with `share`),
//! then Eve at revision 3 on top of its own revision 2 — a record that still lists Carol and
//! carries no cut. Carol writes again meanwhile. A reader that merged the two records of
//! revision 2 (Carol removed) then took revision 3 as the record in force: Carol was a writer and
//! a reader again, and nothing owed a record to undo it. The fix (spec §6): a record signed from
//! a view without a sibling record of the revision below is taken onto what that revision stands
//! for — merged three ways against its own parent — so the laptop's removal and cut still apply
//! and the phone's additions stand, at every reader whatever order the records reach it in.

use std::time::Duration;

use super::kit::{
    LIMIT, LOOK, SETTLE, agree, has, item_of, look, members_now, n, octets, private, reads_entry,
    winning, wrote,
};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{SpaceChange, SpaceMembers};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "r7",
    title: "A removal on one device outlasts a later revision another signed without it",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::RemovalCut,
        Feature::Seal,
    ],
    model: &["M2", "M3", "M4"],
    guards: "A writer removed in one record of a revision stays removed when a device that had \
             not seen that record signs the next revision listing it: every device ends with one \
             record in force — Carol neither writer nor reader, her later versions refused, \
             Dave and Eve, whom the other device admitted, writing and reading.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const DAVE: Dev = Dev(3);
const EVE: Dev = Dev(4);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("carol", "phone");
    p.device("dave", "phone");
    p.device("eve", "phone");
    p
}

/// Whether `m` lists the person `who` as a writer or a reader.
fn lists(m: &SpaceMembers, who: &str) -> bool {
    m.writers.contains(&n(who)) || m.readers.contains(&n(who))
}

/// `persons` added to both roles.
fn admit(persons: &[&str]) -> SpaceChange {
    SpaceChange {
        add_writers: persons.iter().map(|p| n(p)).collect(),
        add_readers: persons.iter().map(|p| n(p)).collect(),
        ..SpaceChange::default()
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let doc = n("/alice/32=data/docs");
        let plan = n("/plan");
        let (laptop, phone, carol, dave, eve) = (
            w.spaces(LAPTOP),
            w.spaces(PHONE),
            w.spaces(CAROL),
            w.spaces(DAVE),
            w.spaces(EVE),
        );
        laptop
            .create(&doc, private(&["/carol"], &["/carol"]))
            .await?;
        for device in [&phone, &carol] {
            w.retry_later(|| device.open(&doc)).await?;
        }
        let seen = w
            .space_put(CAROL, &doc, &plan, octets("carol: edit 1"))
            .await?;
        w.until(
            "both of Alice's devices hold Carol's edit",
            LIMIT,
            || async { Ok(has(&*laptop, &doc, &seen).await? && has(&*phone, &doc, &seen).await?) },
        )
        .await?;

        // The laptop removes Carol; the phone, offline, admits Dave from the record before, then
        // Eve on top of its own record. Carol, still a writer as far as the phone knows, edits
        // again meanwhile.
        w.net().offline(PHONE);
        laptop
            .change(
                &doc,
                SpaceChange {
                    remove: vec![n("/carol")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.gesture();
        phone.change(&doc, admit(&["/dave"])).await?;
        phone.change(&doc, admit(&["/eve"])).await?;
        w.gesture();
        let late = carol
            .put(&doc, &plan, octets("carol: edit 2, after her removal"))
            .await?;
        w.net().online(PHONE);
        w.sleep(SETTLE).await;

        // One record in force everywhere: Carol out, Dave and Eve in. What each device held at
        // the last ask is reported if they never agree.
        let all = [
            ("laptop", &laptop),
            ("phone", &phone),
            ("Dave", &dave),
            ("Eve", &eve),
        ];
        let last = std::cell::RefCell::new(String::new());
        w.until(
            "every device holds one record in force without Carol, with Dave and Eve",
            LIMIT,
            || async {
                let mut held = Vec::with_capacity(all.len());
                for (who, spaces) in all {
                    let m = members_now(&**spaces, &doc).await?;
                    if m.is_none() {
                        // Dave and Eve, told of nothing, follow the document by watching it.
                        look(&**spaces, &doc, LOOK).await?;
                    }
                    held.push((who, m));
                }
                *last.borrow_mut() = format!("{held:?}");
                let mut first: Option<&SpaceMembers> = None;
                for (_, m) in &held {
                    let Some(m) = m else {
                        return Ok(false);
                    };
                    if lists(m, "/carol") || !lists(m, "/dave") || !lists(m, "/eve") {
                        return Ok(false);
                    }
                    match first {
                        Some(f) if f != m => return Ok(false),
                        Some(_) => {}
                        None => first = Some(m),
                    }
                }
                Ok(true)
            },
        )
        .await
        .map_err(|e| Failure::new(format!("{e}; at the last ask: {}", last.borrow())))?;

        // Dave and Eve write; every device of the document takes both. Their first put may need
        // the key of the epoch in force, still on its way: refused Unavailable (RetryLater), put
        // again as the refusal says (data-layer §17.1, §18.1).
        let daves = w
            .space_put(DAVE, &doc, &plan, octets("dave: his first edit"))
            .await?;
        let eves = w
            .space_put(EVE, &doc, &plan, octets("eve: her first edit"))
            .await?;
        w.until(
            "every device takes Dave's and Eve's edits",
            LIMIT,
            || async {
                for (_, spaces) in all {
                    if !(has(&**spaces, &doc, &daves).await? && has(&**spaces, &doc, &eves).await?)
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;
        let later = w
            .space_put(PHONE, &doc, &plan, octets("phone: after every record"))
            .await?;
        w.until(
            "Dave and Eve open the phone's later version",
            LIMIT,
            || async { agree(&[&*dave, &*eve], &doc, &plan, &[&later]).await },
        )
        .await?;
        // Carol may still try; her device may refuse to sign, and every other device must refuse
        // what it signs.
        let after = carol.put(&doc, &plan, octets("carol: edit 3")).await.ok();
        w.sleep(SETTLE).await;

        w.until(
            "every device holds the phone's later version",
            LIMIT,
            || async {
                for (_, spaces) in all {
                    if !has(&**spaces, &doc, &later).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;
        for (who, spaces) in all {
            let read = winning(&**spaces, &doc, &plan, &[&later]).await?;
            ensure!(
                has(&**spaces, &doc, &seen).await?,
                "Carol's edit from before her removal left the document at the {who}"
            );
            for entry in std::iter::once(&late).chain(after.as_ref()) {
                ensure!(
                    !has(&**spaces, &doc, entry).await?,
                    "the document at the {who} includes Carol's edit {entry:?}, signed after the \
                     laptop removed her (a later revision the phone signed without that record \
                     listed her again)"
                );
            }
            ensure!(
                !wrote(&read, "carol: edit 2") && !wrote(&read, "carol: edit 3"),
                "the document at the {who} shows an edit Carol signed after the laptop removed her"
            );
        }
        let at_carol = look(&*carol, &doc, LOOK).await?;
        ensure!(
            item_of(&at_carol, &later.key()).is_none(),
            "Carol, removed by the laptop at revision 2, opened a version written after the \
             phone's revision 3 listed her again"
        );
        ensure!(
            !reads_entry(&*carol, &doc, &plan, &later).await?,
            "Carol, removed by the laptop at revision 2, reads the register as a version \
             written after the phone's revision 3 listed her again"
        );
        Ok(())
    })
}
