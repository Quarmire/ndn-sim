//! Slice 6, g6 — a group with one member under a lock waits whole, then counts whole.
//!
//! Alice's document folder is shared with Bob. While Bob is offline Alice locks the first
//! paragraph's text; Bob, unaware, saves both paragraphs as one group. His first member was made
//! apart from the lock, so the rule does not count it while the lock is in force. Before, a
//! member the rule did not count held nothing else back: half of Bob's save showed. The fix: a
//! group counts only while every member counts. Every other member is held back too, not counted
//! with why — "group waiting on" the member that does not count, and that member's own reason —
//! and kept out of the value on every member device. Once Alice unlocks, the whole save counts
//! everywhere, each member reported counted.

use std::time::Duration;

use ndn_data::Changes;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "g6",
    title: "A group with one member under a lock waits whole, then counts whole",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::AppOps,
        Feature::Groups,
        Feature::FolderMembers,
    ],
    model: &["M14"],
    guards: "While one member of a group is not counted, every other member is not counted \
             either, on every reader: each listed not counted with a reason naming the member it \
             waits on and carrying that member's own reason, and none in the value; once the \
             member counts, every member counts and is reported counted, the same on every \
             reader.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const DEVICES: [(&str, Dev); 3] = [("Alice", ALICE), ("Bob", BOB), ("Carol", CAROL)];

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p
}

/// Whether every device holds each `(collection, id)` of `held`.
async fn all_hold(w: &World, held: &[(&Name, &VersionId)]) -> Result<bool, Failure> {
    for (_, d) in DEVICES {
        for (c, id) in held {
            if !has(&*w.at(d), c, id).await? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/32=data/doc");
        let paragraphs = [n("/alice/32=data/doc/p1"), n("/alice/32=data/doc/p2")];
        w.gesture();
        w.at(ALICE)
            .share_folder(
                &folder,
                members(
                    element_rule(),
                    &["/alice", "/bob"],
                    &[person("/alice"), person("/bob"), person("/carol")],
                ),
            )
            .await?;
        let mut made = Vec::new();
        for p in &paragraphs {
            made.push(
                put_element(w, ALICE, p, |op| {
                    op.then(0, Edit::Create("paragraph".into()))
                        .set("text", "draft")
                })
                .await?,
            );
        }
        w.until("every device holds both paragraphs", LIMIT, || async {
            all_hold(w, &[(&paragraphs[0], &made[0]), (&paragraphs[1], &made[1])]).await
        })
        .await?;

        // Bob is away while Alice locks the first paragraph; he saves both, unaware, as a group.
        w.net().offline(BOB);
        let lock = put_element(w, ALICE, &paragraphs[0], |op| {
            op.then(0, Edit::Lock("text".into()))
        })
        .await?;
        let mut items = Vec::new();
        for (p, text) in paragraphs.iter().zip(["bob 1", "bob 2"]) {
            let op = element_op(w, BOB, p, |op| op.set("text", text)).await?;
            items.push((p.clone(), ndn_data::Edit::Op(op.encode())));
        }
        w.gesture();
        let group = w.at(BOB).put_group(items, element_type()).await?;
        ensure!(
            group.len() == paragraphs.len(),
            "a group of {} versions answered {} ids",
            paragraphs.len(),
            group.len()
        );
        w.net().online(BOB);
        w.until(
            "every device holds the lock and Bob's whole save",
            LIMIT,
            || async {
                all_hold(
                    w,
                    &[
                        (&paragraphs[0], &lock),
                        (&paragraphs[0], &group[0]),
                        (&paragraphs[1], &group[1]),
                    ],
                )
                .await
            },
        )
        .await?;
        let mut watches: Vec<(Changes, Vec<Change>)> = Vec::new();
        for (_, d) in DEVICES {
            watches.push((w.at(d).watch(&folder, &Frontier::new()).await?, Vec::new()));
        }
        for ((who, _), (stream, seen)) in DEVICES.iter().zip(watches.iter_mut()) {
            drain_until(
                stream,
                seen,
                &format!("{who} reports both members of Bob's save not counted"),
                LIMIT,
                |seen| group.iter().all(|id| reported_not_counted(seen, id)),
            )
            .await?;
        }
        let locked_member = log_entry(w, BOB, &paragraphs[0], &group[0]).to_string();
        for (who, d) in DEVICES {
            let layer = w.at(d);
            let (first, first_value) = element_state(&*layer, &paragraphs[0]).await?;
            let (second, second_value) = element_state(&*layer, &paragraphs[1]).await?;
            let own = not_counted_in(&first, &group[0]).ok_or_else(|| {
                Failure::new(format!(
                    "{who} counts Bob's first member, made apart from the lock in force: {:?}",
                    first.not_counted
                ))
            })?;
            ensure!(
                !own.is_empty(),
                "{who} holds Bob's first member back with no reason"
            );
            let waits = not_counted_in(&second, &group[1]).ok_or_else(|| {
                Failure::new(format!(
                    "{who} counts Bob's second member while the first does not count: {:?}",
                    second.not_counted
                ))
            })?;
            ensure!(
                waits.contains(&locked_member) && waits.contains(own),
                "{who}'s reason for holding back the second member, {waits:?}, does not name the \
                 member it waits on ({locked_member}) with that member's reason ({own:?})"
            );
            for (p, v) in [
                (&paragraphs[0], &first_value),
                (&paragraphs[1], &second_value),
            ] {
                ensure!(
                    setting(v, "text") == Some("draft"),
                    "{who} shows {:?} in {p} while Bob's save waits",
                    setting(v, "text")
                );
            }
        }

        // Alice unlocks: Bob's whole save counts everywhere.
        let unlocked = put_element(w, ALICE, &paragraphs[0], |op| {
            op.then(0, Edit::Unlock("text".into()))
        })
        .await?;
        let start = tokio::time::Instant::now();
        for ((who, _), (stream, seen)) in DEVICES.iter().zip(watches.iter_mut()) {
            drain_until(
                stream,
                seen,
                &format!("{who} reports both members of Bob's save counted"),
                LIMIT,
                |seen| group.iter().all(|id| reported_counted(seen, id)),
            )
            .await?;
        }
        w.until("every device holds the unlock", LIMIT, || async {
            all_hold(w, &[(&paragraphs[0], &unlocked)]).await
        })
        .await?;
        w.converged(start.elapsed());
        for (who, d) in DEVICES {
            let layer = w.at(d);
            for ((p, id), text) in paragraphs.iter().zip(&group).zip(["bob 1", "bob 2"]) {
                let (s, v) = element_state(&*layer, p).await?;
                ensure!(
                    not_counted_in(&s, id).is_none(),
                    "{who} still holds back Bob's member in {p} after the unlock: {:?}",
                    s.not_counted
                );
                ensure!(
                    setting(&v, "text") == Some(text),
                    "{who} shows {:?} in {p}, not Bob's save once it counts",
                    setting(&v, "text")
                );
            }
        }
        Ok(())
    })
}
