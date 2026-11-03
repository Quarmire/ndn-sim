//! Open item 3 — who signs a shared summary.
//!
//! With many writers each signs its own summary; a combined one has no single signer. Completeness
//! is then per writer, gathered by the members record. Eight people write into one shared log
//! collection; one of them keeps writing while offline. Whether this is enough for large shared
//! folders needs measuring, so the case records, besides its cost, what checking completeness
//! costs the reader: a full check of every member's summary with 8 writers and again with 32, and
//! catching one new version.
//!
//! The reader's own key is not among the summaries it checks: a writer's own log is complete to
//! itself (it holds every entry it signed), and a summary exists for the others.

use std::collections::BTreeMap;
use std::time::Duration;

use ndn_data::{Change, Summary, Writer};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "o3",
    title: "Completeness with many writers",
    slice: 2,
    needs: &[Feature::Log, Feature::WritersAcrossPrefixes],
    model: &["M8"],
    guards: "Completeness is per writer: each member signs a summary of its own log, a reader \
             holds exactly what each other member's newest summary covers, and a member offline \
             is a summary that has not moved, not a gap the reader cannot see.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const PEOPLE: [&str; 8] = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
];
/// Members who write once later, to measure a full check with 32 writers.
const MORE: usize = 24;
const EACH: usize = 5;
const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const FRANK: Dev = Dev(5);

fn more(i: usize) -> String {
    format!("member{i:02}")
}

fn plan() -> Plan {
    let mut p = Plan::new();
    for who in PEOPLE {
        p.device(who, "laptop");
    }
    for i in 0..MORE {
        p.device(&more(i), "laptop");
    }
    p
}

/// The newest summary each signer has sent, among `changes`.
fn newest_by_signer(changes: &[Change]) -> BTreeMap<Writer, Summary> {
    let mut out: BTreeMap<Writer, Summary> = BTreeMap::new();
    for c in changes {
        if let Change::Summary(s) = c {
            match out.get(&s.signer) {
                Some(old) if old.frontier.covers(&s.frontier) => {}
                _ => {
                    out.insert(s.signer.clone(), s.clone());
                }
            }
        }
    }
    out
}

/// What a full completeness check costs `reader`, holding `held`: a fresh watch of `folder`
/// looks at every member's newest summary; nothing changed. Records Interests and bytes received,
/// in total and per other writer.
async fn full_check(
    w: &World,
    reader: Dev,
    folder: &Name,
    held: &Frontier,
    writers: usize,
) -> Result<(), Failure> {
    let before = w.net().device_wire(reader);
    let mut stream = w.at(reader).watch(folder, held).await?;
    let mut seen = Vec::new();
    drain(&mut stream, LOOK, &mut seen).await?;
    let spent = w.net().device_wire(reader) - before;
    ensure!(
        versions(&seen).next().is_none(),
        "a check with nothing changed delivered versions"
    );
    let others = writers as u64 - 1;
    w.measure(
        format!("full check, {writers} writers: Interests"),
        spent.interests,
        "round trips",
    );
    w.measure(
        format!("full check, {writers} writers: bytes received"),
        spent.in_bytes,
        "bytes",
    );
    w.measure(
        format!("full check, {writers} writers: bytes received per other writer"),
        spent.in_bytes / others,
        "bytes",
    );
    Ok(())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/32=data/shared/garden-club");
        let alice = w.at(ALICE);
        let writers: Vec<String> = PEOPLE
            .iter()
            .map(|p| format!("/{p}"))
            .chain((0..MORE).map(|i| format!("/{}", more(i))))
            .collect();
        let writer_refs: Vec<&str> = writers.iter().map(String::as_str).collect();
        let readers: Vec<Audience> = writers.iter().map(|p| person(p)).collect();
        alice
            .share(&folder, members(Rule::Log, &writer_refs, &readers))
            .await?;

        let mut by_person: Vec<Vec<VersionId>> = vec![Vec::new(); PEOPLE.len()];
        for round in 0..EACH {
            for (i, who) in PEOPLE.iter().enumerate() {
                let id = w
                    .at(Dev(i))
                    .put(&folder, text(&format!("{who} {round}")), note(1))
                    .await?;
                by_person[i].push(id);
            }
        }
        let mut feed = alice.watch(&folder, &Frontier::new()).await?;
        let mut seen = Vec::new();
        let all: Vec<VersionId> = by_person.iter().flatten().cloned().collect();
        let took = drain_until(
            &mut feed,
            &mut seen,
            "Alice holds every member's log",
            LIMIT,
            |c| all.iter().all(|id| version(c, id).is_some()),
        )
        .await?;
        w.converged(took);

        let summaries = newest_by_signer(&seen);
        for ids in by_person.iter().skip(1) {
            let key = &ids[0].writer;
            let s = summaries
                .get(key)
                .ok_or_else(|| Failure::new(format!("no summary signed by member {key:?}")))?;
            ensure!(
                s.frontier.get(key) == ids.last().map(|id| id.seq),
                "{key:?}'s own summary covers {:?}, not its last version",
                s.frontier.get(key)
            );
        }

        // Frank keeps writing offline: Alice's view of Frank stays complete against his last
        // summary, and catches up when he returns.
        w.net().offline(FRANK);
        let frank = w.at(FRANK);
        let mut later = Vec::new();
        for k in 0..3 {
            later.push(
                frank
                    .put(&folder, text(&format!("frank offline {k}")), note(1))
                    .await?,
            );
        }
        drain(&mut feed, SETTLE, &mut seen).await?;
        let frank_key = later[0].writer.clone();
        let held: Frontier = versions(&seen).map(|v| v.id.clone()).collect();
        let summary = newest_by_signer(&seen)
            .remove(&frank_key)
            .ok_or_else(|| Failure::new("Frank's summary disappeared"))?;
        ensure!(
            summary.frontier.get(&frank_key) == held.get(&frank_key),
            "Alice holds Frank up to {:?} but his newest summary says {:?}",
            held.get(&frank_key),
            summary.frontier.get(&frank_key)
        );

        w.net().online(FRANK);
        drain_until(
            &mut feed,
            &mut seen,
            "Alice catches up with Frank",
            LIMIT,
            |c| {
                later.iter().all(|id| version(c, id).is_some())
                    && newest_by_signer(c)
                        .get(&frank_key)
                        .is_some_and(|s| s.frontier.contains(later.last().expect("three writes")))
            },
        )
        .await?;

        // Measured: what completeness costs the reader.
        w.sleep(SETTLE).await;
        drain(&mut feed, LOOK, &mut seen).await?;
        let held: Frontier = versions(&seen).map(|v| v.id.clone()).collect();
        full_check(w, ALICE, &folder, &held, PEOPLE.len()).await?;

        let before = w.net().device_wire(ALICE);
        let start = tokio::time::Instant::now();
        let one = w
            .at(BOB)
            .put(&folder, text("bob, one more"), note(1))
            .await?;
        // Read the feed one change at a time, so the counters stop when the version arrives.
        let deadline = tokio::time::Instant::now() + LIMIT;
        loop {
            let change = match tokio::time::timeout_at(deadline, feed.next()).await {
                Ok(Some(change)) => change?,
                _ => return Err(Failure::new("Alice did not get Bob's one new version")),
            };
            let arrived = matches!(&change, Change::Version(v) if v.id == one);
            seen.push(change);
            if arrived {
                break;
            }
        }
        let spent = w.net().device_wire(ALICE) - before;
        w.measure(
            "one new version, 8 writers: Interests",
            spent.interests,
            "round trips",
        );
        w.measure(
            "one new version, 8 writers: bytes received",
            spent.in_bytes,
            "bytes",
        );
        w.measure(
            "one new version, 8 writers: time to hold it",
            start.elapsed().as_millis() as u64,
            "ms",
        );

        let mut joined = Vec::new();
        for i in 0..MORE {
            joined.push(
                w.at(Dev(PEOPLE.len() + i))
                    .put(&folder, text(&format!("{} joins", more(i))), note(1))
                    .await?,
            );
        }
        drain_until(
            &mut feed,
            &mut seen,
            "Alice holds the 24 later members' versions",
            LIMIT,
            |c| joined.iter().all(|id| version(c, id).is_some()),
        )
        .await?;
        w.sleep(SETTLE).await;
        drain(&mut feed, LOOK, &mut seen).await?;
        let held: Frontier = versions(&seen).map(|v| v.id.clone()).collect();
        full_check(w, ALICE, &folder, &held, writers.len()).await?;

        // The background cost: with nothing written, the reader still runs one sync group per
        // namespace the members record names (spec §12), each sending its periodic notice.
        let before = w.net().device_wire(ALICE);
        w.sleep(Duration::from_secs(60)).await;
        let idle = w.net().device_wire(ALICE) - before;
        w.measure(
            format!(
                "idle minute, {} writers: sync notices the reader sends",
                writers.len()
            ),
            idle.interests,
            "round trips",
        );
        Ok(())
    })
}
