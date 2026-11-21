//! Item p3 — a new version reaches a watcher in one round trip, with the summary that lists it.
//!
//! A sync notice carries the entry it covers (spec §12.1): the laptop that follows the phone's
//! collection asks for that entry by its name and, in the same round trip, for the summary root
//! and the nodes that list it (their names follow from the notice), instead of fetching the root,
//! then each node, then the entry one after the other. Nothing is taken until all are here, so
//! the watch is never told a version before the summary that lists it can be read, and a lost
//! packet costs the re-expression of its ask. The first sync still walks. What is asserted: when
//! the laptop's watch reports a new version, one log entry and the summary packets were fetched
//! and it took about one round trip, not the six sequential asks of a walk; afterwards the walk
//! that follows asks for nothing more and the watch is told the summary — the completeness a
//! `Change::Summary` stands for.

use std::time::Duration;

use ndn_data::Change;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "p3",
    title: "A new version a notice names reaches a watcher in one round trip, with its summary",
    slice: 8,
    needs: &[Feature::Merge],
    model: &[],
    guards: "A watcher told by a sync notice of the entry it covers fetches that entry and the \
             summary that lists it at once: when its watch reports the version the entry and \
             the summary packets are here, the time taken is a round trip, the walk after asks \
             for nothing more, and the watch is told the summary; the first sync is a walk.",
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
        // The walk that brought it has ended.
        w.skip(Duration::from_secs(30)).await;
        ensure!(
            w.net().received(LAPTOP, &n("/alice/phone/32=summary")) > 0,
            "setup: the first sync is a walk, which fetches summary packets"
        );
        let (entries, summaries) = (n("/alice/phone/32=log"), n("/alice/phone/32=summary"));
        let clean = w.net().faults().is_none();
        let mut trips = Vec::new();
        for i in 0..3 {
            let start = w.mark();
            w.report_from(start);
            let (e0, s0) = (
                w.net().received(LAPTOP, &entries),
                w.net().received(LAPTOP, &summaries),
            );
            let id = phone
                .put(&album, text(&format!("version {i}")), note(1))
                .await?;
            // One change at a time, so the counters are read when the version arrives: what the
            // laptop had fetched when its watch was told.
            let begun = tokio::time::Instant::now();
            let deadline = begun + LIMIT;
            loop {
                let change = match tokio::time::timeout_at(deadline, feed.next()).await {
                    Ok(Some(change)) => change?,
                    _ => {
                        return Err(Failure::new(
                            "the laptop's watch did not report the new version",
                        ));
                    }
                };
                let arrived = matches!(&change, Change::Version(v) if v.id == id);
                seen.push(change);
                if arrived {
                    break;
                }
            }
            let took = begun.elapsed();
            w.converged(took);
            let (e, s) = (
                w.net().received(LAPTOP, &entries) - e0,
                w.net().received(LAPTOP, &summaries) - s0,
            );
            // On a faulty network a notice lost is a gap, which the walk catches up, and a packet
            // lost costs a re-expression: the counts and the time are asserted where nothing is
            // lost.
            ensure!(
                !clean || (e == 1 && s > 0),
                "version {i} reached the watcher with {e} log entries and {s} summary packets \
                 fetched: the entry named by its notice, and the summary root and nodes that list \
                 it, are fetched together before it is told"
            );
            ensure!(
                !clean || took < Duration::from_millis(15),
                "version {i} took {took:?} to reach the watcher: the entry and the summary that \
                 lists it are one round trip, not the walk's asks one after the other"
            );
            // The walk that follows asks for nothing more, and no entry again.
            w.skip(Duration::from_secs(30)).await;
            drain(&mut feed, LOOK, &mut seen).await?;
            let (e2, s2) = (
                w.net().received(LAPTOP, &entries) - e0,
                w.net().received(LAPTOP, &summaries) - s0,
            );
            let round_trips = w
                .cost_since(start)
                .round_trips
                .expect("a running world measures round trips");
            trips.push((round_trips, e2, s2));
            ensure!(
                if clean {
                    (e2, s2) == (e, s)
                } else {
                    e2 >= 1 && s2 > 0
                },
                "after version {i} the laptop fetched {e2} log entries and {s2} summary packets \
                 (round trips of the window {round_trips}), {e} and {s} when its watch was told: \
                 the walk after a version taken directly reads what was fetched with it"
            );
            ensure!(
                seen.iter().any(|c| matches!(
                    c,
                    Change::Summary(s) if s.signer == id.writer && s.frontier.contains(&id)
                )),
                "the laptop's watch was not told the phone's summary that lists version {i}"
            );
        }
        ensure!(
            trips.len() == 3,
            "three new versions were measured, (round trips, entries, summaries): {trips:?}"
        );
        Ok(())
    })
}
