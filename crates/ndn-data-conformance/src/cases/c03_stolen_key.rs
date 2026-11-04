//! Case 3 — phone stolen, key extracted.
//!
//! The thief has the phone — its key and everything it stores — and signs data with the key on a
//! clock set to last week, writing on from the phone's own log. Signing-time validity rested on a
//! timestamp the key holder writes. The fix (M3): revocation is a causal cut — the phone's
//! versions up to what others had seen stay valid, anything else is refused, and no clock is
//! trusted.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c3",
    title: "Phone stolen, key extracted",
    slice: 5,
    needs: &[Feature::Merge, Feature::Revocation],
    model: &["M3"],
    guards: "Revocation is a causal cut: what others had seen from the key stays valid; nothing \
             the thief signs with it afterwards is accepted, whatever date it claims.",
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
        let journal = n("/alice/32=data/journal");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        laptop
            .share(&journal, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the phone knows the shared journal", LIMIT, || {
            known(&*phone, &journal)
        })
        .await?;
        let seen = phone
            .put(
                &journal,
                content(&[("phone", "last honest entry")]),
                note(1),
            )
            .await?;
        w.until("the laptop holds the phone's entry", LIMIT, || {
            has(&*laptop, &journal, &seen)
        })
        .await?;

        // Stolen: the phone leaves the network; the thief has it, and a clock a week slow.
        let thief = stolen(w, THIEF, &journal, &seen).await?;
        w.net().offline(PHONE);
        w.net().set_clock(THIEF, ClockSkew::behind(7 * DAY));
        w.revoke(LAPTOP, PHONE).await?;
        w.gesture();
        let revoked_at = w.net().true_date();

        let forged = thief
            .put(&journal, content(&[("thief", "dated last week")]), note(1))
            .await?;
        ensure!(
            forged.writer == seen.writer && forged.seq > seen.seq,
            "precondition: the thief signs as the phone ({:?}) past its last seen entry ({:?}), \
             got {forged:?}",
            seen.writer,
            seen.seq
        );
        let own = look(&*thief, &journal, &Frontier::new(), LOOK).await?;
        if let Some(v) = version(&own, &forged) {
            ensure!(
                v.dated < revoked_at,
                "precondition: the forged entry should claim a date before the revocation"
            );
        }
        w.sleep(SETTLE).await;

        let at_laptop = look(&*laptop, &journal, &Frontier::new(), LOOK).await?;
        ensure!(
            !versions(&at_laptop).any(|v| field_of(v, "thief").is_some()),
            "the laptop accepted a version the thief signed with the revoked key"
        );
        let s = state(&*laptop, &journal).await?;
        ensure!(
            s.at.contains(&seen),
            "the phone's entry from before the revocation was dropped"
        );
        ensure!(
            field(&s.value, "thief").is_none(),
            "the journal shows the thief's entry"
        );
        Ok(())
    })
}
