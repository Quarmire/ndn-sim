//! Keys over time 3 — re-admission is exact.
//!
//! Alice's phone writes two garden notes offline after its key leaked with a copy of its
//! storage; she revokes the key at what the laptop held. She re-admits the first offline note
//! only. The thief, meanwhile, writes a kitchen note at the very sequence number of the
//! re-admitted one. A re-admission by sequence number, or by a range, would bring back the
//! neighbouring note or the thief's — the fix (M3, slice 5) names the one version by its full name
//! and digest, per collection.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k3",
    title: "Re-admission is exact",
    slice: 5,
    needs: &[Feature::Merge, Feature::Revocation, Feature::Readmit],
    model: &["M3"],
    guards: "Re-admitting a version outside a cut brings back that version only: not the next \
             version of the same key, nor a version at the same sequence number in another \
             collection.",
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
        let garden = n("/alice/32=data/notes/garden");
        let kitchen = n("/alice/32=data/notes/kitchen");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        for c in [&garden, &kitchen] {
            laptop
                .share(c, members(merge(), &["/alice"], &[person("/alice")]))
                .await?;
        }
        w.until("the phone knows both shared collections", LIMIT, || async {
            Ok(known(&*phone, &garden).await? && known(&*phone, &kitchen).await?)
        })
        .await?;
        let seen = phone
            .put(&garden, content(&[("phone", "planted beans")]), note(1))
            .await?;
        w.until("the laptop holds the phone's note", LIMIT, || {
            has(&*laptop, &garden, &seen)
        })
        .await?;

        // The key leaks with the phone's storage; the phone, offline, writes two more notes.
        let lost = loss_time(w, LAPTOP).await;
        let thief = stolen(w, THIEF, &garden, &seen).await?;
        w.net().offline(PHONE);
        let wanted = phone
            .put(&garden, content(&[("watered", "tuesday")]), note(1))
            .await?;
        let neighbour = phone
            .put(&garden, content(&[("weeded", "wednesday")]), note(1))
            .await?;
        ensure!(
            neighbour.seq.0 == wanted.seq.0 + 1,
            "precondition: the two offline notes are neighbours in the phone's log, got \
             {wanted:?} and {neighbour:?}"
        );
        w.revoke(LAPTOP, PHONE, lost).await?;
        w.gesture();
        w.until("the stolen device knows the shared kitchen", LIMIT, || {
            known(&*thief, &kitchen)
        })
        .await?;
        let forged = thief
            .put(
                &kitchen,
                content(&[("thief", "same seq, other collection")]),
                note(1),
            )
            .await?;
        ensure!(
            forged.writer == wanted.writer && forged.seq == wanted.seq,
            "precondition: the thief writes the kitchen at the re-admitted note's seq \
             ({wanted:?}), got {forged:?}"
        );
        w.net().online(PHONE);
        w.sleep(SETTLE).await;
        ensure!(
            !has(&*laptop, &garden, &wanted).await?,
            "precondition: the offline notes outside the cut should be refused before \
             re-admission"
        );

        w.gesture();
        w.readmit(LAPTOP, PHONE, &garden, &wanted).await?;
        w.converge("the laptop holds the re-admitted note", LIMIT, || {
            has(&*laptop, &garden, &wanted)
        })
        .await?;
        w.sleep(SETTLE).await;

        let s = state(&*laptop, &garden).await?;
        ensure!(
            s.at.contains(&seen) && s.at.contains(&wanted),
            "the garden lacks the note inside the cut or the re-admitted one"
        );
        ensure!(
            !s.at.contains(&neighbour) && field(&s.value, "weeded").is_none(),
            "re-admitting one note brought back its neighbour {neighbour:?}"
        );
        let kitchen_seen = look(&*laptop, &kitchen, &Frontier::new(), LOOK).await?;
        ensure!(
            version(&kitchen_seen, &forged).is_none()
                && !versions(&kitchen_seen).any(|v| field_of(v, "thief").is_some()),
            "re-admitting the garden note let the thief's kitchen version at its seq in"
        );
        ensure!(
            !has(&*laptop, &kitchen, &forged).await?,
            "the kitchen shows the thief's version at the re-admitted note's seq"
        );
        Ok(())
    })
}
