//! Open item 3 — who signs a shared summary.
//!
//! With many writers each signs its own summary; a combined one has no single signer. Completeness
//! is then per writer, gathered by the members record. Eight people write into one shared folder;
//! one of them keeps writing while offline. Whether this is enough for large shared folders needs
//! measuring, so the case records cost as well as asserting the rule.

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
    model: &["M8"],
    guards: "Completeness is per writer: each member signs a summary of its own log, a reader \
             holds exactly what each member's newest summary covers, and a member offline is a \
             summary that has not moved, not a gap the reader cannot see.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const PEOPLE: [&str; 8] = [
    "alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
];
const EACH: usize = 5;
const FRANK: Dev = Dev(5);

fn plan() -> Plan {
    let mut p = Plan::new();
    for who in PEOPLE {
        p.device(who, "laptop");
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

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/shared/garden-club");
        let alice = w.at(Dev(0));
        let writers: Vec<String> = PEOPLE.iter().map(|p| format!("/{p}")).collect();
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
        for ids in &by_person {
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
        Ok(())
    })
}
