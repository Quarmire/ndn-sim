//! Open item 2 — a cut can drop honest work.
//!
//! Alice's phone writes a note entry offline, which nobody sees; then the phone is taken and its
//! key revoked at what the laptop had seen. The honest offline entry falls outside the cut and is
//! refused — the price of not trusting clocks. The thief also signs with the key. The candidate
//! fix: the owner may re-admit specific versions by signing them into the collection.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "o2",
    title: "Owner re-admits honest work",
    slice: 5,
    needs: &[Feature::Merge, Feature::Revocation, Feature::Readmit],
    model: &["M3"],
    guards: "Versions outside a revocation cut are refused until the owner signs specific ones \
             back in; exactly those return, and the thief's versions stay out.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const THIEF: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    let phone = p.device("alice", "phone");
    p.device("alice", "laptop");
    p.thief(phone);
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let notes = n("/alice/notes/garden");
        let (phone, laptop, thief) = (w.at(PHONE), w.at(LAPTOP), w.at(THIEF));
        laptop
            .share(&notes, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        let seen = phone
            .put(&notes, content(&[("phone", "planted beans")]), note(1))
            .await?;
        w.until("the laptop holds the phone's entry", LIMIT, || {
            has(&*laptop, &notes, &seen)
        })
        .await?;

        w.net().offline(PHONE);
        let honest = phone
            .put(&notes, content(&[("phone", "watered, offline")]), note(1))
            .await?;
        w.revoke(LAPTOP, PHONE).await?;
        w.gesture();
        let forged = thief
            .put(&notes, content(&[("thief", "forged")]), note(1))
            .await?;
        // The phone turns up again and syncs its offline entry.
        w.net().online(PHONE);
        w.sleep(SETTLE).await;
        ensure!(
            !has(&*laptop, &notes, &honest).await?,
            "precondition: the honest offline entry outside the cut should be refused before \
             re-admission"
        );

        // Alice signs the honest entry back in.
        w.gesture();
        let mut readmit = members(merge(), &["/alice"], &[person("/alice")]);
        readmit.readmit = vec![honest.clone()];
        laptop.share(&notes, readmit).await?;
        w.converge("the laptop holds the re-admitted entry", LIMIT, || {
            has(&*laptop, &notes, &honest)
        })
        .await?;
        w.sleep(SETTLE).await;

        let s = state(&*laptop, &notes).await?;
        ensure!(
            s.at.contains(&seen) && s.at.contains(&honest),
            "the journal lacks the entry inside the cut or the re-admitted one"
        );
        ensure!(
            field(&s.value, "thief").is_none(),
            "re-admitting one entry let the thief's version ({forged:?}) in"
        );
        ensure!(
            field(&s.value, "phone") == Some("watered, offline"),
            "the re-admitted entry does not show: {:?}",
            field(&s.value, "phone")
        );
        Ok(())
    })
}
