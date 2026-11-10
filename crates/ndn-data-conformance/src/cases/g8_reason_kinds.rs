//! Round 4, g8 — a reason a version is not counted says whether it ends.
//!
//! Alice shares a board of two columns with Bob and reads it on Dave's phone. Bob saves one
//! change to each column as a group, and Dave's phone reaches nothing of Bob's second member
//! (its name is cut off at Dave's forwarder) while everything else flows: Dave holds the first
//! member and waits for the second. Before, both that wait and a rule's own exclusion were a bare
//! string, so a program could not tell a spinner from a mark. The fix: a reason is a
//! `NotCounted` — `Waits` for the layer's own wait (the group incomplete: it ends, and the
//! version is then told counted), `Excluded` for a rule's own exclusion (Alice's lock on a
//! setting, with Bob's later write to it: it does not end by waiting).
//!
//! Dave is told the first member `Waits`, in his watch and in the state, with the group's
//! count in the reason; nothing of the group is in his value. Bob's write to the locked setting
//! is `Excluded`, in the change and in the state. Once Dave reaches the second member the group
//! counts, `Counted` follows for the member that waited, and Bob's locked write stays
//! `Excluded`.

use std::time::Duration;

use ndn_data::NotCounted;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit as Op;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "g8",
    title: "A reason a version is not counted says whether it ends",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::AppOps,
        Feature::Groups,
        Feature::FolderMembers,
    ],
    model: &["M14"],
    guards: "A member of a group still arriving is not counted with a reason of kind Waits (in \
             the change a watch is told and in the state's not_counted), and when the wait ends \
             it is told counted; a version a rule does not count, such as a write to a locked \
             setting, is not counted with a reason of kind Excluded, and stays so; on every \
             reader, whatever the faults.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const DAVE: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p.device("dave", "phone");
    p
}

/// The kind of reason `state` holds `id` without counting it, if it does.
fn kind_in<'s>(state: &'s State, id: &VersionId) -> Option<&'s NotCounted> {
    state
        .not_counted
        .iter()
        .find(|(v, _)| v == id)
        .map(|(_, why)| why)
}

/// The reason `changes` last told for `id` not counted, if any.
fn told(changes: &[Change], id: &VersionId) -> Option<NotCounted> {
    changes.iter().rev().find_map(|c| match c {
        Change::NotCounted { id: v, why, .. } if v == id => Some(why.clone()),
        _ => None,
    })
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let columns = [
            n("/alice/32=data/board/todo"),
            n("/alice/32=data/board/done"),
        ];
        let all = [person("/alice"), person("/bob"), person("/dave")];
        let (alice, bob, dave) = (w.at(ALICE), w.at(BOB), w.at(DAVE));
        let mut seeds = Vec::new();
        for c in &columns {
            alice
                .share(c, members(element_rule(), &["/alice", "/bob"], &all))
                .await?;
        }
        // A lock on one setting of the first column, made before Bob writes.
        seeds.push(
            put_element(w, ALICE, &columns[0], |op| {
                op.then(0, Op::Create("card".into()))
                    .set("title", "draft")
                    .then(500, Op::Lock("title".into()))
            })
            .await?,
        );
        seeds.push(put_element(w, ALICE, &columns[1], |op| op.set("column", "made")).await?);
        w.until("Bob and Dave hold both columns", LIMIT, || async {
            for layer in [&bob, &dave] {
                for (c, id) in columns.iter().zip(&seeds) {
                    if !has(&**layer, c, id).await? {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })
        .await?;
        let mut watch = dave.watch(&columns[0], &Frontier::new()).await?;
        let mut seen: Vec<Change> = Vec::new();

        // A rule's own exclusion: Bob writes the title Alice locked.
        let locked = put_element(w, BOB, &columns[0], |op| op.set("title", "bob's title")).await?;
        drain_until(
            &mut watch,
            &mut seen,
            "Dave reports Bob's write to the locked title not counted",
            LIMIT,
            |seen| reported_not_counted(seen, &locked),
        )
        .await?;
        let why = told(&seen, &locked).expect("reported above");
        ensure!(
            matches!(&why, NotCounted::Excluded(r) if !r.is_empty()),
            "Dave is told Bob's write to a locked setting not counted as {why:?}, not as a rule's \
             exclusion with its reason"
        );
        let (s, _) = element_state(&*dave, &columns[0]).await?;
        ensure!(
            matches!(kind_in(&s, &locked), Some(NotCounted::Excluded(_))),
            "Dave's state lists Bob's write to the locked title as {:?}, not as a rule's \
             exclusion: {:?}",
            kind_in(&s, &locked),
            s.not_counted
        );

        // Dave reaches nothing of Bob's second member — not Bob's own packet, nor what Alice's
        // laptop or Bob's answer for it under their own names (spec §13.5) — while Bob saves
        // both as a group.
        let bobs = w.net().spec(BOB).name();
        let log = ndn_data::wire::log_name(&bobs, Some(&columns[1]), 0);
        let held = |d: Dev| {
            w.net()
                .spec(d)
                .name()
                .append_component(ndn_packet::NameComponent::new(
                    32,
                    bytes::Bytes::from_static(b"held"),
                ))
        };
        let away = [
            w.net()
                .cut_off(
                    DAVE,
                    &Name::from_components(log.components()[..log.len() - 1].to_vec()),
                )
                .await,
            w.net().cut_off(DAVE, &held(ALICE)).await,
            w.net().cut_off(DAVE, &held(BOB)).await,
        ];
        let mut items = Vec::new();
        for c in &columns {
            let op = element_op(w, BOB, c, |op| op.set("task", "moved by bob")).await?;
            items.push((c.clone(), ndn_data::Edit::Op(op.encode())));
        }
        w.gesture();
        let group = bob.put_group(items, element_type()).await?;
        let first = group[0].clone();
        drain_until(
            &mut watch,
            &mut seen,
            "Dave reports the first member of Bob's group not counted",
            LIMIT,
            |seen| reported_not_counted(seen, &first),
        )
        .await?;
        w.sleep(SETTLE).await;
        drain(&mut watch, LOOK, &mut seen).await?;
        let why = told(&seen, &first).expect("reported above");
        ensure!(
            matches!(&why, NotCounted::Waits(r) if r.contains("group incomplete")),
            "Dave is told the first member of an incomplete group not counted as {why:?}, not as \
             the layer's own wait (group incomplete)"
        );
        let (s, v) = element_state(&*dave, &columns[0]).await?;
        ensure!(
            matches!(kind_in(&s, &first), Some(NotCounted::Waits(r)) if r.contains("group incomplete")),
            "Dave's state lists the first member as {:?}, not as the layer's own wait: {:?}",
            kind_in(&s, &first),
            s.not_counted
        );
        ensure!(
            setting(&v, "task").is_none(),
            "Dave counts a member of Bob's group while he holds one of its two"
        );
        ensure!(
            !seen
                .iter()
                .any(|c| matches!(c, Change::Counted { id, .. } if *id == first)),
            "Dave is told the first member counted while its group is incomplete"
        );

        // Dave reaches the second member: the wait ends, and the member is told counted.
        drop(away);
        drain_until(
            &mut watch,
            &mut seen,
            "Dave reports the first member counted once its group is whole",
            LIMIT,
            |seen| reported_counted(seen, &first),
        )
        .await?;
        w.until("Dave counts Bob's whole group", LIMIT, || async {
            for c in &columns {
                let Some((_, v)) = element_now(&*dave, c).await? else {
                    return Ok(false);
                };
                if setting(&v, "task") != Some("moved by bob") {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await?;
        let (s, _) = element_state(&*dave, &columns[0]).await?;
        ensure!(
            kind_in(&s, &first).is_none(),
            "Dave still lists the first member not counted once its group is whole: {:?}",
            s.not_counted
        );
        ensure!(
            matches!(kind_in(&s, &locked), Some(NotCounted::Excluded(_))),
            "Bob's write to the locked title is {:?} once the group counts, not still a rule's \
             exclusion",
            kind_in(&s, &locked)
        );
        Ok(())
    })
}
