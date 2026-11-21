//! Item p3 — one new version reaches a watcher with one fetch, and the summary is read after it.
//!
//! A sync notice carries the entry it covers (spec §12.1): the laptop that follows the phone's
//! collection asks for that entry by its name, verifies it as it verifies anything and takes it,
//! instead of fetching the summary's root, its nodes and then the entry. The first sync still
//! walks. What is asserted: by the time the laptop's watch reports a new version, one log entry
//! and no summary packet were fetched; and afterwards the laptop reads the phone's summary that
//! lists the entry (fetching no entry again), so the watch is told that summary — the
//! completeness a `Change::Summary` stands for — and the laptop can answer a device that missed
//! the notice while the phone is away (h10).

use std::time::Duration;

use ndn_data::Change;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "p3",
    title: "A new version a notice names reaches a watcher with one fetch, the summary is read after",
    slice: 8,
    needs: &[Feature::Merge],
    model: &[],
    guards: "A watcher told by a sync notice of the entry it covers fetches that entry directly: \
             when its watch reports the version, a log entry has been fetched and no summary \
             packet; the summary that lists the entry is read after, fetching no entry held, and \
             the watch is told it; the first sync is a walk.",
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
            w.converged(begun.elapsed());
            let (e, s) = (
                w.net().received(LAPTOP, &entries) - e0,
                w.net().received(LAPTOP, &summaries) - s0,
            );
            // On a faulty network a notice lost is a gap, which the walk catches up: the entry
            // before the summary is asserted where nothing is lost.
            ensure!(
                !clean || (e, s) == (1, 0),
                "version {i} reached the watcher with {e} log entries and {s} summary packets \
                 fetched; the entry named by its notice is one fetch, a walk of the summary a \
                 root, nodes and the entry"
            );
            // The summary that lists it is read next, and no entry again.
            w.skip(Duration::from_secs(30)).await;
            drain(&mut feed, LOOK, &mut seen).await?;
            let (e, s) = (
                w.net().received(LAPTOP, &entries) - e0,
                w.net().received(LAPTOP, &summaries) - s0,
            );
            let round_trips = w
                .cost_since(start)
                .round_trips
                .expect("a running world measures round trips");
            trips.push((round_trips, e, s));
            // Packets lost or duplicated on a faulty network change how often a packet comes.
            ensure!(
                if clean {
                    e == 1 && s > 0
                } else {
                    e >= 1 && s > 0
                },
                "after version {i} the laptop fetched {e} log entries and {s} summary packets \
                 (round trips of the window {round_trips}): the summary that lists a version \
                 taken directly is read once, and fetches no entry held"
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
