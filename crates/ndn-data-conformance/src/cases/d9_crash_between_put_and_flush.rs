//! Durability, d9 — a crash between a put and its flush never re-signs a seq a peer saw.
//!
//! Alice's laptop creates a space and her phone follows it and writes, so the laptop has heard a
//! peer: its puts return as soon as they are applied, ahead of the flush. The laptop's flush is
//! held (a slow disk). It puts three entries, each of which the phone receives and applies at
//! once; then the power is cut: the laptop restarts on the disk as the last flush left it,
//! without those entries, and the phone is out of reach, so nothing can tell it what it signed.
//! The laptop's next entry takes a seq above every seq the phone holds of the laptop. When the
//! phone is back it holds the three entries it was shown, unchanged, and the new one beside them.
//!
//! The guard: a seq a peer saw is never signed again, whatever the disk lost; no device is shown
//! two entries at one seq, and no device raises an equivocation.
//!
//! Devices: alice's laptop and phone.

use std::time::Duration;

use super::durability::{create, one_entry_per_seq, peers, space, write_ahead};
use super::kit::{LIMIT, SETTLE, drain, equivocation, has, n, octets};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "d9",
    title: "A crash between a put and its flush never re-signs a seq a peer saw",
    slice: 9,
    needs: &[Feature::Crash],
    model: &[],
    guards: "With the flush held, three puts return and reach a peer; after a power cut the \
             device restarts without them and with the peer out of reach, and its next entry \
             takes a seq above every seq the peer holds of it; the peer, back, still holds the \
             three entries and the new one, no device is shown two entries at one seq, and no \
             equivocation is raised.",
    budget: Duration::from_secs(900),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = space();
        create(w, LAPTOP, &space).await?;
        let phone = w.spaces(PHONE);
        peers(w, LAPTOP, PHONE, &space).await?;
        let mut phone_feed = w.retry_later(|| phone.watch(&space)).await?;
        let mut phone_saw = Vec::new();

        // Three entries ahead of the flush; the phone applies each at once.
        w.block_flush(LAPTOP, true).await?;
        let mut shown = Vec::new();
        for i in 0..3 {
            shown.push(
                write_ahead(w, LAPTOP, &space, &format!("/a{i}"), &format!("seen {i}")).await?,
            );
        }
        w.until(
            "the phone applies the laptop's three entries",
            LIMIT,
            || async {
                for e in &shown {
                    if !has(&*phone, &space, e).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;
        let top = shown.iter().map(|e| e.seq).max().expect("three entries");

        // The power is cut; the phone is out of reach of the restarted laptop.
        w.net().offline(PHONE);
        let laptop = w.crash(LAPTOP).await?;
        w.block_flush(LAPTOP, false).await?;
        let mut laptop_feed = w.retry_later(|| laptop.watch(&space)).await?;
        let after = w
            .space_put(LAPTOP, &space, &n("/after"), octets("after"))
            .await?;
        ensure!(
            after.seq > top,
            "after the power cut the laptop signed seq {}, where the phone holds the laptop's \
             entries up to {top}",
            after.seq
        );

        // The phone is back: it holds what it was shown and the new entry.
        w.net().online(PHONE);
        w.until("the phone applies the laptop's new entry", LIMIT, || {
            has(&*phone, &space, &after)
        })
        .await?;
        for e in &shown {
            ensure!(
                has(&*phone, &space, e).await?,
                "the phone no longer holds the laptop's entry {} it was shown",
                e.name
            );
        }

        // Nothing contradicts anything: no seq twice, no equivocation, on either device.
        let mut laptop_saw = Vec::new();
        drain(&mut *phone_feed, SETTLE, &mut phone_saw).await?;
        drain(&mut *laptop_feed, SETTLE, &mut laptop_saw).await?;
        ensure!(
            !equivocation(&phone_saw) && !equivocation(&laptop_saw),
            "an equivocation was raised after a crash that signed nothing twice: phone {:?}, \
             laptop {:?}",
            phone_saw,
            laptop_saw
        );
        one_entry_per_seq("the phone", &phone_saw)?;
        one_entry_per_seq("the laptop", &laptop_saw)?;
        Ok(())
    })
}
