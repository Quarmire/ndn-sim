//! Open item 3 — who vouches for completeness with many writers.
//!
//! With many writers each member's log is its own: completeness is per writer, gathered by the
//! members record. Eight people write into one shared space, each at a path of its own; one of
//! them keeps writing while offline. Whether this is enough for large shared folders needs
//! measuring, so the case records, besides its cost, what checking completeness costs the
//! reader: a full look at every member's state with 8 writers and again with 32, and catching one
//! new entry.
//!
//! The reader's own entries are checked like the others': a writer's own log is complete to
//! itself (it holds every entry it signed).

use std::time::Duration;

use super::kit::{
    LIMIT, LOOK, Role, SETTLE, drain, has, items, joined, look, n, octets, private, required,
};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{SpaceEntry, SpaceEvent, Spaces};
use crate::world::{Dev, Plan, World};
use ndn_data::Name;

pub(super) const CASE: Case = Case {
    id: "o3",
    title: "Completeness with many writers",
    slice: 2,
    needs: &[Feature::WritersAcrossPrefixes],
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

fn path_of(who: &str) -> Name {
    n(&format!("/{who}"))
}

/// What a full completeness check costs `reader`, which holds everything `written`: a fresh look
/// at the space lists what the device holds of every member; nothing changed. Records Interests
/// and bytes received, in total and per other writer.
async fn full_check(
    w: &World,
    reader: Dev,
    space: &Name,
    written: &[SpaceEntry],
    writers: usize,
) -> Result<(), Failure> {
    let before = w.net().device_wire(reader);
    let spaces = w.spaces(reader);
    let seen = look(&*spaces, space, LOOK).await?;
    let spent = w.net().device_wire(reader) - before;
    let strangers: Vec<_> = items(&seen)
        .filter(|i| !written.iter().any(|e| e.key() == i.key()))
        .map(|i| i.key())
        .collect();
    ensure!(
        strangers.is_empty(),
        "a check with nothing changed listed entries nobody wrote: {strangers:?}"
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

/// Whether `reader` has applied every entry of `entries`.
async fn holds_all(
    reader: &dyn Spaces,
    space: &Name,
    entries: &[&SpaceEntry],
) -> Result<bool, Failure> {
    for entry in entries {
        if !has(reader, space, entry).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n("/alice/32=data/shared/garden-club");
        let alice = w.spaces(ALICE);
        let writers: Vec<String> = PEOPLE
            .iter()
            .map(|p| format!("/{p}"))
            .chain((0..MORE).map(|i| format!("/{}", more(i))))
            .collect();
        let writer_refs: Vec<&str> = writers.iter().map(String::as_str).collect();
        alice
            .create(&space, private(&writer_refs, &writer_refs))
            .await?;
        for (i, who) in PEOPLE.iter().enumerate().skip(1) {
            let member = w.spaces(Dev(i));
            w.retry_later(|| member.open(&space)).await?;
            // A member whose device holds only the first of the owner's members entries (the
            // creation lists 32 writers and 32 readers, in more than one) is told it may not
            // write: it writes once the record that lists it as a reader has arrived.
            joined(w, &*member, &space, &path_of(who), Role::Reader).await?;
        }

        // Each member writes its own path five times: its own log, newest last.
        let mut by_person: Vec<Vec<SpaceEntry>> = vec![Vec::new(); PEOPLE.len()];
        for round in 0..EACH {
            for (i, who) in PEOPLE.iter().enumerate() {
                let entry = w
                    .space_put(
                        Dev(i),
                        &space,
                        &path_of(who),
                        octets(&format!("{who} {round}")),
                    )
                    .await?;
                by_person[i].push(entry);
            }
        }
        let mut written: Vec<SpaceEntry> = by_person.iter().flatten().cloned().collect();
        let mut feed = alice.watch(&space).await?;
        let mut seen = Vec::new();
        let newest: Vec<&SpaceEntry> = by_person
            .iter()
            .map(|entries| entries.last().expect("each member wrote"))
            .collect();
        w.converge("Alice holds every member's log", LIMIT, || {
            holds_all(&*alice, &space, &newest)
        })
        .await?;

        // Completeness is per writer: Alice holds every entry of each member's log, and each
        // member's path reads its newest write.
        for (i, entries) in by_person.iter().enumerate() {
            for entry in entries {
                ensure!(
                    has(&*alice, &space, entry).await?,
                    "Alice lacks {} though she holds {}'s newest entry",
                    entry.name,
                    PEOPLE[i]
                );
            }
            let got = required(&*alice, &space, &path_of(PEOPLE[i])).await?;
            ensure!(
                got.entry() == *newest[i],
                "Alice reads {:?} at {}'s path, not the newest write of that member",
                String::from_utf8_lossy(&got.bytes),
                PEOPLE[i]
            );
        }

        // Frank keeps writing offline: Alice's view of Frank stays complete up to what reached
        // her (his newest entry before he went offline, and nothing past it she cannot see), and
        // catches up when he returns.
        w.net().offline(FRANK);
        let frank = w.spaces(FRANK);
        let frank_path = path_of(PEOPLE[FRANK.0]);
        let mut later = Vec::new();
        for k in 0..3 {
            later.push(
                frank
                    .put(&space, &frank_path, octets(&format!("frank offline {k}")))
                    .await?,
            );
        }
        written.extend(later.iter().cloned());
        drain(&mut *feed, SETTLE, &mut seen).await?;
        for entry in &later {
            ensure!(
                !has(&*alice, &space, entry).await?,
                "Alice holds Frank's entry {} though he wrote it offline and nobody else has it",
                entry.name
            );
        }
        ensure!(
            holds_all(
                &*alice,
                &space,
                &by_person[FRANK.0].iter().collect::<Vec<_>>()
            )
            .await?,
            "Alice lost entries of Frank's she held before he went offline"
        );
        let before_return = required(&*alice, &space, &frank_path).await?;
        ensure!(
            before_return.entry() == *newest[FRANK.0],
            "Alice reads {:?} at Frank's path while he is offline, not his newest entry she holds",
            String::from_utf8_lossy(&before_return.bytes)
        );

        w.net().online(FRANK);
        w.until("Alice catches up with Frank", LIMIT, || {
            has(&*alice, &space, later.last().expect("three writes"))
        })
        .await?;
        for entry in &later {
            ensure!(
                has(&*alice, &space, entry).await?,
                "Alice caught up with Frank's newest entry but lacks {}",
                entry.name
            );
        }
        let caught_up = required(&*alice, &space, &frank_path).await?;
        ensure!(
            caught_up.entry() == *later.last().expect("three writes"),
            "Alice reads {:?} at Frank's path after he returned, not his newest entry",
            String::from_utf8_lossy(&caught_up.bytes)
        );

        // Measured: what completeness costs the reader.
        w.sleep(SETTLE).await;
        drain(&mut *feed, LOOK, &mut seen).await?;
        full_check(w, ALICE, &space, &written, PEOPLE.len()).await?;

        let before = w.net().device_wire(ALICE);
        let start = tokio::time::Instant::now();
        let one = w
            .spaces(BOB)
            .put(&space, &path_of("bob"), octets("bob, one more"))
            .await?;
        written.push(one.clone());
        // Read the feed one event at a time, so the counters stop when the entry arrives.
        let deadline = tokio::time::Instant::now() + LIMIT;
        loop {
            let event = match tokio::time::timeout_at(deadline, feed.next()).await {
                Ok(Some(event)) => event?,
                _ => return Err(Failure::new("Alice did not get Bob's one new entry")),
            };
            let arrived = matches!(&event, SpaceEvent::Put(i) if i.key() == one.key());
            seen.push(event);
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
            let member = w.spaces(Dev(PEOPLE.len() + i));
            w.retry_later(|| member.open(&space)).await?;
            joined.push(
                w.space_put(
                    Dev(PEOPLE.len() + i),
                    &space,
                    &path_of(&more(i)),
                    octets(&format!("{} joins", more(i))),
                )
                .await?,
            );
        }
        written.extend(joined.iter().cloned());
        let newest_joined: Vec<&SpaceEntry> = joined.iter().collect();
        w.until("Alice holds the 24 later members' entries", LIMIT, || {
            holds_all(&*alice, &space, &newest_joined)
        })
        .await?;
        w.sleep(SETTLE).await;
        drain(&mut *feed, LOOK, &mut seen).await?;
        full_check(w, ALICE, &space, &written, writers.len()).await?;

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
