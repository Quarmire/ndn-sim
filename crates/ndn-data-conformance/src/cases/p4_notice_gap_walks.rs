//! Item p4 — versions written while a reader is away all reach it.
//!
//! The laptop is cut off while the phone writes two versions, announced one after the other. Taking
//! the entry a notice names (spec §12.1) must leave no hole whatever the laptop heard of those
//! notices: it holds both, by a direct take or by the walk a gap causes.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "p4",
    title: "Versions written while a reader was away all reach it",
    slice: 8,
    needs: &[Feature::Merge],
    model: &[],
    guards: "Versions written while a reader was away all reach its watch, whether each notice \
             is taken directly or caught up by a walk: taking an entry by its name never leaves \
             a hole.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.count_names(3);
    p.device("alice", "phone");
    p.device("alice", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let album = n("/alice/32=data/notes/trip");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        phone
            .share(&album, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        phone.put(&album, text("first"), note(1)).await?;
        let mut feed = laptop.watch(&album, &Frontier::new()).await?;
        let mut seen = Vec::new();
        drain_until(
            &mut feed,
            &mut seen,
            "setup: the laptop holds the first version",
            LIMIT,
            |seen| versions(seen).count() >= 1,
        )
        .await?;
        w.skip(Duration::from_secs(30)).await;

        w.net().offline(LAPTOP);
        let missed = phone.put(&album, text("while away"), note(1)).await?;
        // Announced alone, so the second is a second announcement the laptop misses.
        w.skip(Duration::from_secs(5)).await;
        let last = phone.put(&album, text("also while away"), note(1)).await?;
        w.skip(Duration::from_secs(10)).await;
        w.net().online(LAPTOP);
        let start = w.mark();
        w.report_from(start);
        let took = drain_until(
            &mut feed,
            &mut seen,
            "the laptop holds both versions written while it was away",
            LIMIT,
            |seen| versions(seen).any(|v| v.id == last) && versions(seen).any(|v| v.id == missed),
        )
        .await?;
        w.converged(took);
        // What the fabric delivers of the notices sent while a device is away is its own; whether
        // each came directly or by a walk, the laptop holds every version (the gap that forces
        // the walk is a device-level case: `a_missed_notice_is_caught_up_by_a_walk`).
        Ok(())
    })
}
