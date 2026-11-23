//! Case 3 — phone stolen, key extracted.
//!
//! The thief has the phone — its key and everything it stores — and signs data with the key on a
//! clock set to last week, writing on from the phone's own log. Signing-time validity rested on a
//! timestamp the key holder writes. The fix (M3): revocation is a causal cut — the phone's
//! versions up to what others had seen stay valid, anything else is refused, and no clock is
//! trusted. The journal is the path `/today` of Alice's space `/alice/32=data/journal`.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::kit::{
    DAY, LIMIT, LOOK, SETTLE, contains, has, item_of, known, look, loss_time, n, octets, private,
    stolen, winning,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
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
        let space = n("/alice/32=data/journal");
        let page = n("/today");
        let (phone, laptop) = (w.spaces(PHONE), w.spaces(LAPTOP));
        laptop.create(&space, private(&[], &[])).await?;
        w.retry_later(|| phone.open(&space)).await?;
        w.until("the phone knows the shared journal", LIMIT, || {
            known(&*phone, &space)
        })
        .await?;
        let seen = w
            .space_put(PHONE, &space, &page, octets("last honest entry"))
            .await?;
        w.until("the laptop holds the phone's entry", LIMIT, || {
            has(&*laptop, &space, &seen)
        })
        .await?;

        // Stolen: the phone leaves the network; the thief has it, and a clock a week slow. Alice
        // says when she lost it, and revokes the key with a cut at what her laptop held by then.
        let lost = loss_time(w, LAPTOP).await;
        stolen(w, THIEF, &space, &seen).await?;
        w.net().offline(PHONE);
        w.net().set_clock(THIEF, ClockSkew::behind(7 * DAY));
        w.revoke(LAPTOP, PHONE, lost).await?;
        w.gesture();
        let revoked_at = w.net().true_date();

        let forged = w
            .space_put(THIEF, &space, &page, octets("dated last week"))
            .await?;
        ensure!(
            forged.writer == seen.writer && forged.seq > seen.seq,
            "precondition: the thief signs as the phone ({:?}) past its last seen entry ({:?}), \
             got {forged:?}",
            seen.writer,
            seen.seq
        );
        let dated = w.net().date(THIEF);
        ensure!(
            dated < revoked_at,
            "precondition: the forged entry should claim a date before the revocation ({dated:?} \
             vs {revoked_at:?})"
        );
        w.sleep(SETTLE).await;

        let at_laptop = look(&*laptop, &space, LOOK).await?;
        ensure!(
            item_of(&at_laptop, &forged.key()).is_none() && !has(&*laptop, &space, &forged).await?,
            "the laptop accepted an entry the thief signed with the revoked key"
        );
        let s = winning(&*laptop, &space, &page, &[&seen]).await?;
        ensure!(
            has(&*laptop, &space, &seen).await?,
            "the phone's entry from before the revocation was dropped"
        );
        ensure!(
            s.key() != forged.key() && !contains(&s.bytes, b"dated last week"),
            "the journal shows the thief's entry"
        );
        Ok(())
    })
}
