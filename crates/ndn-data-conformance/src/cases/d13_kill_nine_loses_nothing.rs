//! Durability, d13 — `kill -9` loses nothing a returned put promised visible.
//!
//! Alice's laptop has heard her phone, so its puts return when they are applied, ahead of the
//! flush; the flush is held, so none of them has been synced when the process is killed. The
//! phone is out of reach. A killed process is not a power cut: what the store accepted stays (the
//! operating system keeps a killed process's writes). The laptop starts again on that store
//! ([`World::kill`]) and, with no peer to return anything, holds every entry whose put had
//! returned, reads its octets at their paths, and its next entry takes the seq after them. The
//! phone, back, holds the same entries and the new one.
//!
//! The hook: `crash` is the power cut (only what a flush covered stays); `kill` drops the node
//! with no close and starts on the store's live contents. The case needs `kill`, which an
//! implementation without durable storage cannot offer.
//!
//! The guard: a put that returned is in the device's store, and a process kill does not take it
//! back; the log goes on from where the put left it, with no equivocation.
//!
//! Devices: alice's laptop and phone.

use std::time::Duration;

use super::durability::{create, holds, one_entry_per_seq, peers, space, write_ahead};
use super::kit::{LIMIT, SETTLE, drain, equivocation, has, n, octets};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "d13",
    title: "A killed process loses nothing a returned put promised",
    slice: 9,
    needs: &[Feature::Crash],
    model: &[],
    guards: "With the flush held and the peer out of reach, three puts return; the process is \
             killed and starts again on its store: it holds every entry whose put returned and \
             reads its octets, with no peer to return them, signs its next entry above them, and \
             the peer, back, holds all of it with no equivocation.",
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

        // Three puts return ahead of a flush that never ran; the phone cannot be asked.
        w.net().offline(PHONE);
        w.block_flush(LAPTOP, true).await?;
        let mut put = Vec::new();
        for i in 0..3 {
            let (path, text) = (format!("/a{i}"), format!("returned {i}"));
            put.push((
                write_ahead(w, LAPTOP, &space, &path, &text).await?,
                n(&path),
                text,
            ));
        }
        let top = put
            .iter()
            .map(|(e, _, _)| e.seq)
            .max()
            .expect("three entries");

        // The process is killed and starts again on what its store accepted.
        let laptop = w.kill(LAPTOP).await?;
        w.block_flush(LAPTOP, false).await?;
        let mut feed = w.retry_later(|| laptop.watch(&space)).await?;
        w.until(
            "the restarted laptop holds its three entries",
            LIMIT,
            || async {
                for (e, path, text) in &put {
                    if !holds(&*laptop, &space, path, e, text).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;
        let next = w
            .space_put(LAPTOP, &space, &n("/next"), octets("next"))
            .await?;
        ensure!(
            next.seq > top,
            "the laptop signed seq {} after a kill that lost nothing, where its entries run to {top}",
            next.seq
        );

        // The phone is back and holds all of it.
        w.net().online(PHONE);
        w.until("the phone applies the laptop's next entry", LIMIT, || {
            has(&*phone, &space, &next)
        })
        .await?;
        w.until(
            "the phone holds the entries the laptop signed",
            LIMIT,
            || async {
                for (e, _, _) in &put {
                    if !has(&*phone, &space, e).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;
        let mut saw = Vec::new();
        drain(&mut *feed, SETTLE, &mut saw).await?;
        drain(&mut *phone_feed, SETTLE, &mut phone_saw).await?;
        ensure!(
            !equivocation(&phone_saw) && !equivocation(&saw),
            "an equivocation was raised after a kill that signed nothing twice: phone {:?}, \
             laptop {:?}",
            phone_saw,
            saw
        );
        one_entry_per_seq("the phone", &phone_saw)?;
        one_entry_per_seq("the laptop", &saw)?;
        Ok(())
    })
}
