//! Keys over time 5 — a renewed key continues its log.
//!
//! Alice's phone writes a note, then renews its certificate (the same key, certified again), and
//! writes on; later the old certificate expires, and the phone writes once more. Alice's tablet,
//! offline all along, reads the notes for the first time after that. Renewal must not cut a
//! device's log in two, and the old certificate's expiry must not take the versions signed
//! under it along (M3, slice 5): the key's authority continues under its newer certificate.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::Certs;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k5",
    title: "Renewed key continues its log",
    slice: 5,
    needs: &[Feature::Merge, Feature::KeyLifetime],
    model: &["M3"],
    guards: "A renewed certificate continues the key's log: versions signed before and after the \
             renewal stay valid at every reader, also once the old certificate expired.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const TABLET: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "laptop");
    p.device("alice", "tablet");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let notes = n("/alice/32=data/notes/garden");
        let (phone, laptop, tablet) = (w.at(PHONE), w.at(LAPTOP), w.at(TABLET));
        w.net().offline(TABLET);
        laptop
            .share(&notes, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the phone knows the shared notes", LIMIT, || {
            known(&*phone, &notes)
        })
        .await?;
        let before = phone
            .put(&notes, content(&[("sown", "beans")]), note(1))
            .await?;
        w.until("the laptop holds the first note", LIMIT, || {
            has(&*laptop, &notes, &before)
        })
        .await?;

        w.renew(PHONE).await?;
        let renewed = phone
            .put(&notes, content(&[("watered", "tuesday")]), note(1))
            .await?;
        w.until("the laptop holds the note after the renewal", LIMIT, || {
            has(&*laptop, &notes, &renewed)
        })
        .await?;

        // The certificate the renewal superseded runs out.
        w.expire(PHONE, Certs::Superseded).await?;
        let after = phone
            .put(&notes, content(&[("picked", "friday")]), note(1))
            .await?;
        ensure!(
            before.writer == renewed.writer && renewed.writer == after.writer,
            "precondition: the phone signs every note with its one key, got {before:?}, \
             {renewed:?} and {after:?}"
        );

        w.net().online(TABLET);
        w.converge("every reader holds the whole log", LIMIT, || async {
            agree(
                &[&*phone, &*laptop, &*tablet],
                &notes,
                &[&before, &renewed, &after],
            )
            .await
        })
        .await?;
        w.sleep(SETTLE).await;

        for (who, layer) in [("laptop", &laptop), ("tablet", &tablet)] {
            let s = state(&**layer, &notes).await?;
            ensure!(
                s.at.contains(&before) && s.at.contains(&renewed) && s.at.contains(&after),
                "the {who} dropped a note of the renewed key's log"
            );
        }
        Ok(())
    })
}
