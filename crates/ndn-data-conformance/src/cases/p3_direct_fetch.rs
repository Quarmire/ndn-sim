//! Item p3 — one new version reaches a watcher with one fetch, not a walk of the summary.
//!
//! A sync notice carries the entry it covers (spec §12.1): the laptop that follows the phone's
//! collection asks for that entry by its name, verifies it as it verifies anything and takes it,
//! instead of fetching the summary's root, its nodes and then the entry. The first sync still
//! walks. What is asserted is the cost of the next versions, in round trips, and that every one
//! reaches the laptop's watch.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "p3",
    title: "A new version a notice names reaches a watcher with one fetch",
    slice: 8,
    needs: &[Feature::Merge],
    model: &[],
    guards: "A watcher told by a sync notice of the entry it covers fetches that entry directly: \
             a new version costs a round trip or two, not the summary's root, nodes and entry; \
             the first sync is a walk.",
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
            let took = drain_until(
                &mut feed,
                &mut seen,
                "the laptop's watch reports the new version",
                LIMIT,
                |seen| versions(seen).any(|v| v.id == id),
            )
            .await?;
            w.converged(took);
            w.skip(Duration::from_secs(30)).await;
            let round_trips = w
                .cost_since(start)
                .round_trips
                .expect("a running world measures round trips");
            let (e, s) = (
                w.net().received(LAPTOP, &entries) - e0,
                w.net().received(LAPTOP, &summaries) - s0,
            );
            trips.push((round_trips, e, s));
            ensure!(
                (e, s) == (1, 0),
                "version {i} reached the watcher with {e} log entries and {s} summary packets \
                 fetched (round trips of the window {round_trips}); the entry named by its \
                 notice is one fetch, a walk of the summary a root, nodes and the entry"
            );
        }
        ensure!(
            trips.len() == 3,
            "three new versions were measured, (round trips, entries, summaries): {trips:?}"
        );
        Ok(())
    })
}
