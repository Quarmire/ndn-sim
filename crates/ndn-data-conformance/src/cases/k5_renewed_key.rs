//! Keys over time 5 — a renewed key continues its log.
//!
//! Alice's phone writes a note, then renews its certificate (the same key, certified again), and
//! writes on; later the old certificate expires, and the phone writes once more. Alice's tablet,
//! offline all along, reads the notes for the first time after that. Renewal must not cut a
//! device's log in two, and the old certificate's expiry must not take the versions signed
//! under it along (M3, slice 5): the key's authority continues under its newer certificate.

use std::time::Duration;

use super::kit::{LIMIT, SETTLE, agree, has, known, n, octets, op_is, private, winning};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
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
        let space = n("/alice/32=data/notes");
        let path = n("/garden");
        let (phone, laptop, tablet) = (w.spaces(PHONE), w.spaces(LAPTOP), w.spaces(TABLET));
        w.net().offline(TABLET);
        laptop.create(&space, private(&[], &[])).await?;
        w.retry_later(|| phone.open(&space)).await?;
        w.until("the phone knows the shared notes", LIMIT, || {
            known(&*phone, &space)
        })
        .await?;
        let before = w
            .space_put(PHONE, &space, &path, octets("sown beans"))
            .await?;
        w.until("the laptop holds the first note", LIMIT, || {
            has(&*laptop, &space, &before)
        })
        .await?;

        w.renew(PHONE).await?;
        let renewed = w
            .space_put(PHONE, &space, &path, octets("watered tuesday"))
            .await?;
        w.until("the laptop holds the note after the renewal", LIMIT, || {
            has(&*laptop, &space, &renewed)
        })
        .await?;

        // The certificate the renewal superseded runs out.
        w.expire(PHONE, Certs::Superseded).await?;
        let after = w
            .space_put(PHONE, &space, &path, octets("picked friday"))
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
                &space,
                &path,
                &[&before, &renewed, &after],
            )
            .await
        })
        .await?;
        w.sleep(SETTLE).await;

        for (who, spaces) in [("laptop", &laptop), ("tablet", &tablet)] {
            let s = winning(&**spaces, &space, &path, &[&after]).await?;
            ensure!(
                has(&**spaces, &space, &before).await?
                    && has(&**spaces, &space, &renewed).await?
                    && has(&**spaces, &space, &after).await?,
                "the {who} dropped a note of the renewed key's log"
            );
            ensure!(
                op_is(&s, "picked friday"),
                "the {who} reads {:?}; the renewed key's newest note is the register's value",
                String::from_utf8_lossy(&s.bytes)
            );
        }
        Ok(())
    })
}
