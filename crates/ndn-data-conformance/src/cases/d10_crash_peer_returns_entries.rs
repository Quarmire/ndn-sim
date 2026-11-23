//! Durability, d10 — a crash between a put and its flush, with the peer reachable at the restart,
//! returns the entries whole.
//!
//! As d9: the laptop has heard its phone, its flush is held, and it puts three entries that the
//! phone receives at once. The power is cut and the laptop restarts without them — but this time
//! the phone is there. The laptop asks its peers for the entries of its own log it lacks and
//! adopts them: it reads again, at their paths, what it had put, and applies the very entries it
//! signed. Its next entry takes a seq above them.
//!
//! The guard: a device that lost the tail of its own log recovers it from a peer that holds it,
//! whole (the same entries, not rewritten ones), before it signs on; no equivocation is raised.
//!
//! Devices: alice's laptop and phone.

use std::time::Duration;

use super::durability::{create, holds, one_entry_per_seq, peers, space, write_ahead};
use super::kit::{LIMIT, LOOK, SETTLE, drain, equivocation, has, item_of, look, n, octets};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "d10",
    title: "After a crash between a put and its flush, a reachable peer returns the entries whole",
    slice: 9,
    needs: &[Feature::Crash],
    model: &[],
    guards: "With the flush held, three puts return and reach a peer; after a power cut the \
             device restarts with the peer reachable and recovers its own entries from it: it \
             reads at their paths what it had put, holds the very entries it signed, signs its \
             next entry above them, and no equivocation is raised.",
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

        w.block_flush(LAPTOP, true).await?;
        let mut lost = Vec::new();
        for i in 0..3 {
            let (path, text) = (format!("/a{i}"), format!("unflushed {i}"));
            lost.push((
                write_ahead(w, LAPTOP, &space, &path, &text).await?,
                n(&path),
                text,
            ));
        }
        w.until(
            "the phone applies the laptop's three entries",
            LIMIT,
            || async {
                for (e, _, _) in &lost {
                    if !has(&*phone, &space, e).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;
        let top = lost
            .iter()
            .map(|(e, _, _)| e.seq)
            .max()
            .expect("three entries");

        // The power is cut; the phone is reachable.
        let laptop = w.crash(LAPTOP).await?;
        w.block_flush(LAPTOP, false).await?;
        let mut laptop_feed = w.retry_later(|| laptop.watch(&space)).await?;

        // The laptop has its own entries again, whole, whatever the disk kept.
        w.until(
            "the laptop recovers its three entries from the phone",
            LIMIT,
            || async {
                for (e, path, text) in &lost {
                    if !holds(&*laptop, &space, path, e, text).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;
        let listing = look(&*laptop, &space, LOOK).await?;
        for (e, _, text) in &lost {
            let listed = item_of(&listing, &e.key());
            ensure!(
                listed.is_some_and(|i| i.bytes == octets(text) && i.signed == e.signed),
                "the laptop's listing lacks its entry {} whole after the restart: {:?}",
                e.name,
                listed
            );
        }

        // It signs on above them.
        let next = w
            .space_put(LAPTOP, &space, &n("/next"), octets("next"))
            .await?;
        ensure!(
            next.seq > top,
            "the laptop signed seq {} after recovering its entries up to {top}",
            next.seq
        );
        w.until("the phone applies the laptop's next entry", LIMIT, || {
            has(&*phone, &space, &next)
        })
        .await?;

        let mut laptop_saw = Vec::new();
        drain(&mut *phone_feed, SETTLE, &mut phone_saw).await?;
        drain(&mut *laptop_feed, SETTLE, &mut laptop_saw).await?;
        ensure!(
            !equivocation(&phone_saw) && !equivocation(&laptop_saw),
            "an equivocation was raised although the laptop recovered its entries: phone {:?}, \
             laptop {:?}",
            phone_saw,
            laptop_saw
        );
        one_entry_per_seq("the phone", &phone_saw)?;
        one_entry_per_seq("the laptop", &laptop_saw)?;
        Ok(())
    })
}
