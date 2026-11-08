//! Slice 6, g1 — a group counts all or none, arriving and withdrawn.
//!
//! Bob moves a task across Alice's board: one change to each of three columns, written as one
//! group. Before slice 6 each version stood alone, so a reader that had two of the three showed a
//! task in two columns, and a removal that cut one of them left the other two standing. The fix:
//! a group's versions count only once all of them are held and opened, on every reader alike —
//! until then each is held, shown not counted ("group incomplete") — and a member refused for
//! good withdraws the whole group everywhere, while a version another writer made over a
//! withdrawn member stays.
//!
//! Alice's laptop has her home repo hold the third column. Bob's device then loses its copy of
//! the group's third member, and the repo, Alice's laptop and Carol — every other device holding
//! it, each of which answers for Bob's versions (spec §13.5) — are away: Dave, coming online,
//! finds the first two members at Bob's but the third nowhere, and counts none of them until the
//! repo is back and serves it. Then Alice's phone, which never saw the group, removes Bob from the
//! third column with a cut at what it had seen of him there — nothing: the group's third member
//! is outside the cut, so every member is withdrawn on every reader, and Carol's edit over the
//! first member stays.

use std::time::Duration;

use ndn_data::{Changes, Refusal};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "g1",
    title: "A group counts all or none, arriving and withdrawn",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::RemovalCut,
        Feature::CutRecheck,
        Feature::Custody,
        Feature::AppOps,
        Feature::Groups,
    ],
    model: &["M14"],
    guards: "A reader holding some members of a group counts none of them (each held, reported \
             not counted with why) until it holds all, then counts all; a member later refused by \
             a cut withdraws every member of the group on every reader, in every collection, \
             while another writer's version made over a withdrawn member stays counted.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const REPO: Dev = Dev(2);
const BOB: Dev = Dev(3);
const CAROL: Dev = Dev(4);
const DAVE: Dev = Dev(5);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.holder("alice", "repo");
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p.device("dave", "phone");
    p
}

/// Whether `layer`'s value of `c` shows Bob's group edit.
async fn shows_bob(layer: &dyn DataLayer, c: &Name) -> Result<bool, Failure> {
    Ok(element_now(layer, c)
        .await?
        .is_some_and(|(_, v)| setting(&v, "task") == Some("moved by bob")))
}

/// Whether `dave` holds the first two members of `group` (in the first two `columns`), each
/// listed not counted; a failure if he counts one.
async fn incomplete(
    dave: &dyn DataLayer,
    columns: &[Name],
    group: &[VersionId],
) -> Result<bool, Failure> {
    for (c, id) in columns.iter().zip(group).take(2) {
        let Some((s, v)) = element_now(dave, c).await? else {
            return Ok(false);
        };
        if not_counted_in(&s, id).is_none() {
            return Ok(false);
        }
        ensure!(
            setting(&v, "task").is_none(),
            "Dave counts a member of Bob's group in {c} while he holds only two of its three"
        );
    }
    Ok(true)
}

/// What `d` holds of each of `columns`: frontier and what it holds without counting.
async fn held(w: &World, d: Dev, columns: &[Name]) -> Result<String, Failure> {
    let mut views = Vec::new();
    for c in columns {
        views.push(
            state_now(&*w.at(d), c)
                .await?
                .map(|s| (s.at, s.not_counted)),
        );
    }
    Ok(format!("{views:?}"))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let columns = [
            n("/alice/32=data/board/todo"),
            n("/alice/32=data/board/doing"),
            n("/alice/32=data/board/done"),
        ];
        let (laptop, phone, bob, carol, dave) = (
            w.at(LAPTOP),
            w.at(PHONE),
            w.at(BOB),
            w.at(CAROL),
            w.at(DAVE),
        );
        let all = [
            person("/alice"),
            person("/bob"),
            person("/carol"),
            person("/dave"),
        ];
        let mut seeds = Vec::new();
        for c in &columns {
            laptop
                .share(
                    c,
                    members(element_rule(), &["/alice", "/bob", "/carol"], &all),
                )
                .await?;
            seeds.push(put_element(w, LAPTOP, c, |op| op.set("column", "made")).await?);
        }
        w.until("everyone holds the three columns", LIMIT, || async {
            for layer in [&phone, &bob, &carol, &dave] {
                for (c, id) in columns.iter().zip(&seeds) {
                    if !has(&**layer, c, id).await? {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })
        .await?;

        // Alice's phone and Dave are away while Bob moves the task, as one group.
        w.net().offline(PHONE);
        w.net().offline(DAVE);
        let mut items = Vec::new();
        for c in &columns {
            let op = element_op(w, BOB, c, |op| op.set("task", "moved by bob")).await?;
            items.push((c.clone(), ndn_data::Edit::Op(op.encode())));
        }
        w.gesture();
        let group = bob.put_group(items, element_type()).await?;
        ensure!(
            group.len() == columns.len(),
            "a group of {} versions answered {} ids",
            columns.len(),
            group.len()
        );
        w.until(
            "Carol and the laptop count Bob's whole group",
            LIMIT,
            || async {
                for layer in [&carol, &laptop] {
                    for c in &columns {
                        if !shows_bob(&**layer, c).await? {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            },
        )
        .await?;
        let over = put_element(w, CAROL, &columns[0], |op| {
            op.set("note", "carol, over bob")
        })
        .await?;

        // The repo holds the third column, then goes away; Bob loses his copy of its member.
        let today = w.net().date(LAPTOP).0;
        let want = Hold {
            copies: 1,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
            holders: vec![w.net().spec(REPO).name()],
        };
        let kept = hold_on(w, LAPTOP, &columns[2], &want, "hold of the third column").await?;
        ensure!(
            kept.leases
                .iter()
                .any(|l| l.audit.kept() && l.holds.contains(&group[2])),
            "the repo holds no kept lease on the group's third member"
        );
        // The repo goes away, and so do Alice's laptop and Carol: each holds the third member too,
        // and a device answers for the versions it holds (spec §13.5).
        w.net().offline(REPO);
        w.net().offline(LAPTOP);
        w.net().offline(CAROL);
        let third = log_entry(w, BOB, &columns[2], &group[2]);
        let lost = w.lose(BOB, &columns[2], 1);
        ensure!(lost > 0, "Bob stored nothing of the third column to lose");
        w.net().forget_cached(&third).await;

        // Dave comes back: Bob serves him two of the three members.
        w.net().online(DAVE);
        let held_two = w
            .until(
                "Dave holds two members of Bob's group, not counted",
                LIMIT,
                || incomplete(&*dave, &columns, &group),
            )
            .await;
        if let Err(f) = held_two {
            return Err(Failure::new(format!(
                "{f} (group {group:?}; Dave holds {})",
                held(w, DAVE, &columns).await?
            )));
        }
        w.sleep(SETTLE).await;
        ensure!(
            incomplete(&*dave, &columns, &group).await?,
            "Dave's two members of Bob's incomplete group no longer show as not counted ({})",
            held(w, DAVE, &columns).await?
        );
        ensure!(
            !shows_bob(&*dave, &columns[2]).await? && !has(&*dave, &columns[0], &over).await?,
            "Dave counts the third member or Carol's edit over the first while the group is \
             incomplete"
        );

        // The repo is back: the third member arrives and all three count.
        w.net().online(REPO);
        let all_three = w
            .until("Dave counts Bob's whole group", LIMIT, || async {
                for c in &columns {
                    if !shows_bob(&*dave, c).await? {
                        return Ok(false);
                    }
                }
                has(&*dave, &columns[0], &over).await
            })
            .await;
        if let Err(f) = all_three {
            return Err(Failure::new(format!(
                "{f} (group {group:?}; Dave holds {})",
                held(w, DAVE, &columns).await?
            )));
        }
        w.net().online(LAPTOP);
        w.net().online(CAROL);
        for (c, id) in columns.iter().zip(&group) {
            let (s, _) = element_state(&*dave, c).await?;
            ensure!(
                not_counted_in(&s, id).is_none(),
                "Dave still lists Bob's member in {c} as not counted once all three count"
            );
        }

        // Alice's phone, which never saw the group, removes Bob from the third column.
        let mut watches: Vec<(&str, &Name, &VersionId, Changes, Vec<Change>)> = Vec::new();
        for (who, d) in [("the laptop", LAPTOP), ("Carol", CAROL), ("Dave", DAVE)] {
            for (c, id) in columns.iter().zip(&group) {
                let stream = w.at(d).watch(c, &Frontier::new()).await?;
                watches.push((who, c, id, stream, Vec::new()));
            }
        }
        w.gesture();
        phone
            .share(
                &columns[2],
                members(element_rule(), &["/alice", "/carol"], &all),
            )
            .await?;
        w.net().online(PHONE);
        let start = tokio::time::Instant::now();
        for (who, c, id, stream, seen) in &mut watches {
            drain_until(
                stream,
                seen,
                &format!("{who} withdraws Bob's member in {c}"),
                LIMIT,
                |seen| withdrawn(seen, id),
            )
            .await?;
            ensure!(
                seen.iter().any(|ch| matches!(ch,
                    Change::Withdrawn { id: x, why: Refusal::Group { .. }, .. } if x == *id)),
                "{who} withdrew Bob's member in {c}, but not because its group was refused"
            );
        }
        let readers = [
            ("the laptop", LAPTOP),
            ("the phone", PHONE),
            ("Carol", CAROL),
            ("Dave", DAVE),
        ];
        let without = w
            .until(
                "every reader shows the board without Bob's group",
                LIMIT,
                || async {
                    for (_, d) in readers {
                        for c in &columns {
                            if shows_bob(&*w.at(d), c).await? {
                                return Ok(false);
                            }
                        }
                        if !has(&*w.at(d), &columns[0], &over).await? {
                            return Ok(false);
                        }
                    }
                    Ok(true)
                },
            )
            .await;
        if let Err(f) = without {
            let mut views = Vec::new();
            for (who, d) in readers {
                let mut shown = Vec::new();
                for c in &columns {
                    shown.push(shows_bob(&*w.at(d), c).await?);
                }
                views.push(format!(
                    "{who}: shows Bob's group per column {shown:?}, Carol's edit counted {}, \
                     holds {}",
                    has(&*w.at(d), &columns[0], &over).await?,
                    held(w, d, &columns).await?
                ));
            }
            return Err(Failure::new(format!(
                "{f} (group {group:?}, Carol's edit {over:?}; {})",
                views.join("; ")
            )));
        }
        w.converged(start.elapsed());
        for (who, d) in readers {
            let (_, v) = element_state(&*w.at(d), &columns[0]).await?;
            ensure!(
                setting(&v, "note") == Some("carol, over bob"),
                "{who} lost Carol's edit made over Bob's withdrawn member"
            );
        }
        Ok(())
    })
}
