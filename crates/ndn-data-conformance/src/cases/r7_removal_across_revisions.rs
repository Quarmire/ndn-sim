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

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
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

/// Whether `s` lists the writer or reader prefix `who`.
fn lists(s: &Share, who: &str) -> bool {
    s.writers.contains(&n(who)) || s.readers.contains(&person(who))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let doc = n("/alice/32=data/docs/plan");
        let (laptop, phone, carol, dave, eve) = (
            w.at(LAPTOP),
            w.at(PHONE),
            w.at(CAROL),
            w.at(DAVE),
            w.at(EVE),
        );
        laptop
            .share(
                &doc,
                members(
                    merge(),
                    &["/alice", "/carol"],
                    &[person("/alice"), person("/carol")],
                ),
            )
            .await?;
        let seen = w
            .put(CAROL, &doc, content(&[("carol", "edit 1")]), note(1))
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
            .share(&doc, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.gesture();
        phone
            .share(
                &doc,
                members(
                    merge(),
                    &["/alice", "/carol", "/dave"],
                    &[person("/alice"), person("/carol"), person("/dave")],
                ),
            )
            .await?;
        phone
            .share(
                &doc,
                members(
                    merge(),
                    &["/alice", "/carol", "/dave", "/eve"],
                    &[
                        person("/alice"),
                        person("/carol"),
                        person("/dave"),
                        person("/eve"),
                    ],
                ),
            )
            .await?;
        w.gesture();
        let late = carol
            .put(
                &doc,
                content(&[("carol", "edit 2, after her removal")]),
                note(1),
            )
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
                for (who, layer) in all {
                    let m = layer.members(&doc).await;
                    if matches!(m, Err(DataError::NotReady { .. })) {
                        // Dave and Eve, told of nothing, follow the document by watching it.
                        look(&**layer, &doc, &Frontier::new(), LOOK).await?;
                    }
                    held.push((who, m));
                }
                *last.borrow_mut() = format!("{held:?}");
                let mut first: Option<&Share> = None;
                for (_, m) in &held {
                    let m = match m {
                        Ok(m) => m,
                        Err(DataError::NotReady { .. }) => return Ok(false),
                        Err(e) => return Err(e.clone().into()),
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
            .put(DAVE, &doc, content(&[("dave", "his first edit")]), note(1))
            .await?;
        let eves = w
            .put(EVE, &doc, content(&[("eve", "her first edit")]), note(1))
            .await?;
        w.until(
            "every device takes Dave's and Eve's edits",
            LIMIT,
            || async {
                for (_, layer) in all {
                    if !(has(&**layer, &doc, &daves).await? && has(&**layer, &doc, &eves).await?) {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;
        let later = w
            .put(PHONE, &doc, text("after every record"), note(1))
            .await?;
        w.until(
            "Dave and Eve open the phone's later version",
            LIMIT,
            || async {
                for layer in [&dave, &eve] {
                    let seen = look(&**layer, &doc, &Frontier::new(), LOOK).await?;
                    if version(&seen, &later).is_none() {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;
        // Carol may still try; her device may refuse to sign, and every other device must refuse
        // what it signs.
        let after = carol
            .put(&doc, content(&[("carol", "edit 3")]), note(1))
            .await
            .ok();
        w.sleep(SETTLE).await;

        for (who, layer) in all {
            let s = state(&**layer, &doc).await?;
            ensure!(
                s.at.contains(&seen),
                "Carol's edit from before her removal left the document at the {who}"
            );
            for id in std::iter::once(&late).chain(after.as_ref()) {
                ensure!(
                    !s.at.contains(id),
                    "the document at the {who} includes Carol's edit {id:?}, signed after the \
                     laptop removed her (a later revision the phone signed without that record \
                     listed her again)"
                );
            }
        }
        let at_carol = look(&*carol, &doc, &Frontier::new(), LOOK).await?;
        ensure!(
            version(&at_carol, &later).is_none(),
            "Carol, removed by the laptop at revision 2, opened a version written after the \
             phone's revision 3 listed her again"
        );
        Ok(())
    })
}
