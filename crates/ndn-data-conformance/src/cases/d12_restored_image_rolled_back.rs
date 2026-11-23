//! Durability, d12 — a restored old image, with peers online, raises `RolledBack` and reuses no
//! seq.
//!
//! Alice's laptop and phone share a space; the laptop has heard the phone and has its disk
//! backed up. It then goes on and signs thirty more entries, far past what the backup reserved of
//! its log, and the phone holds all of them. The laptop's disk is replaced by the old backup
//! while the phone is online. The laptop finds the phone holding entries of its own log that its
//! disk knows nothing of, some of them above what the backup reserved: evidence of a rollback.
//! It raises [`AlertKind::RolledBack`], takes its entries back from the phone, and its next entry
//! signs above everything the phone holds of it.
//!
//! The guard: a device restored from an old image detects it from its peers' counters and
//! entries, never signs over a seq a peer holds, and ends up holding its own entries again.
//!
//! Devices: alice's laptop and phone. (The thirty entries exceed the reservation block a provider
//! keeps under test, which `ndn-heap`'s provider sets to 8.)

use std::time::Duration;

use super::durability::{create, holds, one_entry_per_seq, peers, space};
use super::kit::{LIMIT, SETTLE, alerted, drain, drain_until, equivocation, has, n, octets};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::AlertKind;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "d12",
    title: "A restored old image with peers online raises RolledBack and reuses no seq",
    slice: 9,
    needs: &[Feature::Crash],
    model: &[],
    guards: "A device restored from a backup taken before it signed thirty more entries, with \
             its peer online and holding them, raises a RolledBack alert, holds its own entries \
             again, and signs its next entry above every seq the peer holds of it, with no \
             equivocation.",
    budget: Duration::from_secs(1200),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const BEYOND: usize = 30;

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

        // The backup.
        let old = w.image(LAPTOP).await?;

        // The laptop goes on, far past what the backup reserved; the phone holds it all.
        let path = n("/a");
        let mut signed = Vec::new();
        for i in 0..BEYOND {
            signed.push(
                w.space_put(LAPTOP, &space, &path, octets(&format!("v{i}")))
                    .await?,
            );
        }
        let top = signed.last().expect("entries").seq;
        w.until(
            "the phone holds every entry the laptop signed",
            LIMIT,
            || async {
                for e in &signed {
                    if !has(&*phone, &space, e).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;

        // The old backup is put back, with the phone online.
        let laptop = w.restore(LAPTOP, old).await?;
        let mut feed = w.retry_later(|| laptop.watch(&space)).await?;
        let mut saw = Vec::new();
        drain_until(
            &mut *feed,
            &mut saw,
            "the laptop reports a rollback",
            LIMIT,
            |seen| alerted(seen, |k| matches!(k, AlertKind::RolledBack)),
        )
        .await?;
        let newest = signed.last().expect("entries");
        let newest_text = format!("v{}", BEYOND - 1);
        w.until("the laptop holds its own newest entry again", LIMIT, || {
            holds(&*laptop, &space, &path, newest, &newest_text)
        })
        .await?;

        // Nothing the phone holds of the laptop is signed over.
        let next = w
            .space_put(LAPTOP, &space, &n("/z"), octets("after"))
            .await?;
        ensure!(
            next.seq > top,
            "the restored laptop signed seq {}, where the phone holds its entries up to {top}",
            next.seq
        );
        w.until("the phone applies the laptop's next entry", LIMIT, || {
            has(&*phone, &space, &next)
        })
        .await?;
        drain(&mut *feed, SETTLE, &mut saw).await?;
        drain(&mut *phone_feed, SETTLE, &mut phone_saw).await?;
        ensure!(
            !equivocation(&phone_saw) && !equivocation(&saw),
            "an equivocation was raised although no seq was signed twice: phone {:?}, laptop {:?}",
            phone_saw,
            saw
        );
        one_entry_per_seq("the phone", &phone_saw)?;
        one_entry_per_seq("the laptop", &saw)?;
        Ok(())
    })
}
