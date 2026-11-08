//! Slice 6, b6 — Alice locks a paragraph; Bob's edit made with the lock in view never counts, on
//! every member.
//!
//! Alice shares her notes folder with Bob as a writer. She has two devices of her namespace, a
//! phone and a laptop, and locks a paragraph's text from the phone. A lock is the owner's: any
//! device of the collection's namespace (`owns(collection, writer)`) holds it, so Alice's laptop
//! writes on under it and its edit counts. Before, the rule compared the lock's one key with the
//! writer's, so the phone's lock looked like a stranger's on Alice's own laptop and its edit did
//! not count. Bob is no owner. His edit made with the lock in view — the lock inside what he wrote
//! over, nothing lifting it there — never counts, on Alice's phone, her laptop and his own device,
//! not even once Alice unlocks. His edit made apart from the lock (offline, the lock not in its
//! past) waits while the lock is in force and counts once an owner writes over it.

use std::time::Duration;

use ndn_data::Changes;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "b6",
    title: "Alice locks a paragraph; Bob's edit made with the lock in view never counts, on every \
            member",
    slice: 6,
    needs: &[Feature::Merge, Feature::AppOps, Feature::FolderMembers],
    model: &["M12"],
    guards: "A lock set by one owner device holds for every device of the owner's namespace: \
             another owner device's later write counts. A non-owner's write made with the lock in \
             view is NotCounted with why on every member, and stays so after the lock is lifted. \
             A non-owner's write made apart from the lock is NotCounted while the lock is in \
             force and counts once an owner writes over it, on every member alike.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const BOB: Dev = Dev(2);
const DEVICES: [(&str, Dev); 3] = [
    ("Alice's phone", PHONE),
    ("Alice's laptop", LAPTOP),
    ("Bob", BOB),
];

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p
}

/// Whether every device holds each of `ids` of `c`.
async fn all_hold(w: &World, c: &Name, ids: &[&VersionId]) -> Result<bool, Failure> {
    for (_, d) in DEVICES {
        for id in ids {
            if !has(&*w.at(d), c, id).await? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// Each device's watch drained until it reports `done` of what it saw.
async fn every_reports(
    watches: &mut [(Changes, Vec<Change>)],
    what: &str,
    done: impl Fn(&[Change]) -> bool,
) -> Result<(), Failure> {
    for ((who, _), (stream, seen)) in DEVICES.iter().zip(watches.iter_mut()) {
        drain_until(stream, seen, &format!("{who} reports {what}"), LIMIT, &done).await?;
    }
    Ok(())
}

/// On every device, `id` is listed not counted with why and the text is `text`.
async fn held_back(
    w: &World,
    c: &Name,
    id: &VersionId,
    whose: &str,
    text: &str,
) -> Result<(), Failure> {
    for (who, d) in DEVICES {
        let (s, v) = element_state(&*w.at(d), c).await?;
        ensure!(
            not_counted_in(&s, id).is_some_and(|why| !why.is_empty()),
            "{who} does not list {whose} among the versions not counted, with why: {:?}",
            s.not_counted
        );
        ensure!(
            setting(&v, "text") == Some(text),
            "{who}'s paragraph shows {:?}, not {text:?}, while {whose} does not count",
            setting(&v, "text")
        );
    }
    Ok(())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/32=data/notes");
        let paragraph = n("/alice/32=data/notes/p1");
        w.gesture();
        w.at(LAPTOP)
            .share_folder(
                &folder,
                members(
                    element_rule(),
                    &["/alice", "/bob"],
                    &[person("/alice"), person("/bob")],
                )
                .into(),
            )
            .await?;
        let made = put_element(w, PHONE, &paragraph, |op| {
            op.then(0, Edit::Create("paragraph".into()))
                .set("text", "draft")
        })
        .await?;
        w.until("every device holds the paragraph", LIMIT, || async {
            all_hold(w, &paragraph, &[&made]).await
        })
        .await?;

        // Bob is away while Alice locks the text from her phone; he edits it unaware.
        w.net().offline(BOB);
        let lock = put_element(w, PHONE, &paragraph, |op| {
            op.then(0, Edit::Lock("text".into()))
        })
        .await?;
        let unaware = put_element(w, BOB, &paragraph, |op| op.set("text", "bob, unaware")).await?;
        w.net().online(BOB);
        w.until(
            "every device holds the lock and Bob's edit made apart from it",
            LIMIT,
            || async { all_hold(w, &paragraph, &[&lock, &unaware]).await },
        )
        .await?;
        let mut watches: Vec<(Changes, Vec<Change>)> = Vec::new();
        for (_, d) in DEVICES {
            watches.push((
                w.at(d).watch(&paragraph, &Frontier::new()).await?,
                Vec::new(),
            ));
        }
        // Made apart from the lock in force: it waits.
        every_reports(
            &mut watches,
            "Bob's edit made apart from the lock not counted",
            |seen| reported_not_counted(seen, &unaware),
        )
        .await?;
        held_back(
            w,
            &paragraph,
            &unaware,
            "Bob's edit made apart from the lock",
            "draft",
        )
        .await?;

        // Alice's laptop, an owner device, writes under the phone's lock, over Bob's edit: its
        // edit counts, and Bob's edit, taken in by an owner, counts beneath it.
        let laptops =
            put_element(w, LAPTOP, &paragraph, |op| op.set("text", "laptop edit")).await?;
        w.until("every device holds the laptop's edit", LIMIT, || async {
            all_hold(w, &paragraph, &[&laptops]).await
        })
        .await?;
        every_reports(
            &mut watches,
            "Bob's edit made apart from the lock counted once the laptop wrote over it",
            |seen| reported_counted(seen, &unaware),
        )
        .await?;
        for (who, d) in DEVICES {
            let (s, v) = element_state(&*w.at(d), &paragraph).await?;
            ensure!(
                not_counted_in(&s, &laptops).is_none(),
                "{who} does not count the laptop's edit under the phone's lock: {:?}; a lock is \
                 the owner's, held by every device of the owner's namespace",
                not_counted_in(&s, &laptops)
            );
            ensure!(
                not_counted_in(&s, &unaware).is_none(),
                "{who} still holds back Bob's edit an owner wrote over: {:?}",
                not_counted_in(&s, &unaware)
            );
            ensure!(
                setting(&v, "text") == Some("laptop edit"),
                "{who}'s paragraph shows {:?}, not the laptop's edit",
                setting(&v, "text")
            );
            ensure!(
                v.state.locks.iter().any(|l| l.setting == "text"),
                "{who} shows no lock of the text after the laptop's write: {:?}",
                v.state.locks
            );
        }

        // Bob, holding the lock, edits the text anyway: it never counts.
        let defiant = put_element(w, BOB, &paragraph, |op| {
            op.set("text", "bob, over the lock")
        })
        .await?;
        every_reports(
            &mut watches,
            "Bob's edit made with the lock in view not counted",
            |seen| reported_not_counted(seen, &defiant),
        )
        .await?;
        held_back(
            w,
            &paragraph,
            &defiant,
            "Bob's edit made with the lock in view",
            "laptop edit",
        )
        .await?;
        let name = log_entry(w, BOB, &paragraph, &defiant);
        for (who, d) in DEVICES {
            match w.at(d).get(&name).await?.got {
                Got::Version(v) => ensure!(
                    v.id == defiant,
                    "{who} answered the name of Bob's edit with {:?}",
                    v.id
                ),
                other => {
                    return Err(Failure::new(format!(
                        "{who} answered the name of Bob's edit with {other:?}, not the version"
                    )));
                }
            }
        }

        // Alice unlocks from her phone: Bob's edit made with the lock in view still never counts.
        let unlocked = put_element(w, PHONE, &paragraph, |op| {
            op.then(0, Edit::Unlock("text".into()))
        })
        .await?;
        let start = tokio::time::Instant::now();
        w.until(
            "every device agrees on the unlocked paragraph",
            LIMIT,
            || {
                let layers: Vec<std::sync::Arc<dyn DataLayer>> =
                    DEVICES.iter().map(|(_, d)| w.at(*d)).collect();
                let (paragraph, ids) = (&paragraph, [&defiant, &unlocked]);
                async move {
                    let refs: Vec<&dyn DataLayer> = layers.iter().map(|l| &**l).collect();
                    agree(&refs, paragraph, &ids).await
                }
            },
        )
        .await?;
        w.converged(start.elapsed());
        held_back(
            w,
            &paragraph,
            &defiant,
            "Bob's edit made with the lock in view, after the unlock,",
            "laptop edit",
        )
        .await?;
        for ((who, _), (stream, seen)) in DEVICES.iter().zip(watches.iter_mut()) {
            drain(stream, LOOK, seen).await?;
            ensure!(
                !reported_counted(seen, &defiant),
                "{who} reported Bob's edit made with the lock in view counted"
            );
        }
        Ok(())
    })
}
