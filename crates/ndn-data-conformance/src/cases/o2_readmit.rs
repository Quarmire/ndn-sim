//! Open item 2 — a cut can drop honest work.
//!
//! Alice's phone writes a note entry offline, which nobody sees; meanwhile its key was copied
//! with its storage, and Alice revokes it at what the laptop had seen. The honest offline entry
//! falls outside the cut and is refused — the price of not trusting clocks. The thief signs with
//! the key too, at the very name of the honest entry. The fix (M3): the owner re-admits exact
//! versions — the namespace root signs the honest entry's name and digest into the cut, so it
//! returns and nothing else does, not even the thief's version at the same name.

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
             back in by name and digest; exactly those return, and the thief's versions stay \
             out, even one at the same name.",
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
        let notes = n("/alice/32=data/notes/garden");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        laptop
            .share(&notes, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the phone knows the shared notes", LIMIT, || {
            known(&*phone, &notes)
        })
        .await?;
        // The phone's first put races the epoch key's grant (spec §17.1): put again on RetryLater.
        let seen = w
            .put(
                PHONE,
                &notes,
                content(&[("phone", "planted beans")]),
                note(1),
            )
            .await?;
        w.until("the laptop holds the phone's entry", LIMIT, || {
            has(&*laptop, &notes, &seen)
        })
        .await?;

        // The key leaks with a copy of the phone's storage; the phone goes offline and writes on.
        let lost = loss_time(w, LAPTOP).await;
        let thief = stolen(w, THIEF, &notes, &seen).await?;
        w.net().offline(PHONE);
        let honest = phone
            .put(&notes, content(&[("phone", "watered, offline")]), note(1))
            .await?;
        w.revoke(LAPTOP, PHONE, lost).await?;
        w.gesture();
        let forged = thief
            .put(&notes, content(&[("thief", "forged")]), note(1))
            .await?;
        ensure!(
            forged.writer == honest.writer && forged.seq == honest.seq,
            "precondition: the thief writes at the honest entry's name ({honest:?}), got \
             {forged:?}"
        );
        // The phone turns up again and syncs its offline entry.
        w.net().online(PHONE);
        w.sleep(SETTLE).await;
        ensure!(
            !has(&*laptop, &notes, &honest).await?,
            "precondition: the honest offline entry outside the cut should be refused before \
             re-admission"
        );

        // Alice signs the honest entry back in, as her phone shows it refused.
        w.gesture();
        w.readmit(LAPTOP, PHONE, &notes, &honest).await?;
        w.converge("the laptop holds the re-admitted entry", LIMIT, || {
            has(&*laptop, &notes, &honest)
        })
        .await?;
        w.sleep(SETTLE).await;

        let s = state(&*laptop, &notes).await?;
        ensure!(
            s.at.contains(&seen) && s.at.contains(&honest),
            "the notes lack the entry inside the cut or the re-admitted one"
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
