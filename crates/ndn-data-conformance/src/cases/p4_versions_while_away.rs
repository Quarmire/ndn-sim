//! Item p4 — versions written while a reader is away all reach it, and it is told the summary
//! that lists them.
//!
//! The laptop is cut off while the phone writes two versions, announced one after the other, and
//! comes back. Taking the entry a notice names (spec §12.1) must leave no hole whatever the laptop
//! heard of those notices, and the summary that lists the entries is read next: the laptop holds
//! both versions and its watch is told the phone's summary covering the last.
//!
//! This is not a gap case. On this network a link that is down loses nothing for good: the laptop
//! hears each announcement of the group again when it is back (the writer announces again while no
//! member is heard to take its newest, §17.1), each alone, and takes each entry directly, so what
//! is asserted is convergence, not which way it came; no case here can withhold one notice and
//! deliver the next, so the fall-back to a walk is the device-level case
//! `a_missed_notice_is_caught_up_by_a_walk` (and under `--faulty`, where a notice lost on the
//! laptop's link is a gap, the same assertions hold).

use std::time::Duration;

use ndn_data::Change;

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
             is taken directly or caught up by a walk, and the watch is told the writer's \
             summary that lists them: taking an entry by its name never leaves a hole.",
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
            "the laptop holds both versions written while it was away and is told the summary \
             that lists them",
            LIMIT,
            |seen| {
                versions(seen).any(|v| v.id == last)
                    && versions(seen).any(|v| v.id == missed)
                    && seen.iter().any(|c| {
                        matches!(
                            c,
                            Change::Summary(s) if s.signer == last.writer && s.frontier.contains(&last)
                        )
                    })
            },
        )
        .await?;
        w.converged(took);
        Ok(())
    })
}
