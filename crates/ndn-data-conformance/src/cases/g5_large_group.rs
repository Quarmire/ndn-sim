//! Slice 6, g5 — a group of 2,000 versions commits whole and is counted whole.
//!
//! Alice's document folder holds 2,000 paragraphs, one element collection each. She saves an edit
//! of every paragraph as one group, so that a reader never shows half of the save. Before, a
//! group held at most 1,024 versions (`GROUP_MAX`): the save was refused, and the app had to split
//! it into groups a reader may count apart. The fix: a group holds up to 65,536 versions (the
//! seqs a summary node lists), and a reader keeps an incomplete group's members in its store
//! rather than in memory. Bob, a reader of the folder, counts none of the save until he holds all
//! of it, then all 2,000 at once.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "g5",
    title: "A group of 2,000 versions commits whole and is counted whole",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::AppOps,
        Feature::Groups,
        Feature::FolderMembers,
    ],
    model: &["M14"],
    guards: "A group larger than 1,024 versions (here 2,000, one per collection of one folder) is \
             written whole by put_group, and another member counts all of its versions once it \
             holds them all, none before: every member in its frontier and none listed not counted \
             at the end.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const PARAGRAPHS: usize = 2_000;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/32=data/doc");
        let paragraphs: Vec<Name> = (0..PARAGRAPHS)
            .map(|i| folder.clone().append(format!("p{i}")))
            .collect();
        w.gesture();
        w.at(ALICE)
            .share_folder(
                &folder,
                members(
                    element_rule(),
                    &["/alice"],
                    &[person("/alice"), person("/bob")],
                ),
            )
            .await?;
        let mut watch = w.at(BOB).watch(&folder, &Frontier::new()).await?;
        let mut items = Vec::with_capacity(PARAGRAPHS);
        for (i, p) in paragraphs.iter().enumerate() {
            let op = element_op(w, ALICE, p, |op| {
                op.then(0, Edit::Create("paragraph".into()))
                    .set("text", format!("paragraph {i}"))
            })
            .await?;
            items.push((p.clone(), ndn_data::Edit::Op(op.encode())));
        }
        let mark = w.mark();
        w.report_from(mark);
        w.gesture();
        let group = w.at(ALICE).put_group(items, element_type()).await?;
        ensure!(
            group.len() == PARAGRAPHS,
            "a group of {PARAGRAPHS} versions answered {} ids",
            group.len()
        );
        // Bob counts none of it until he holds all of it: a version is delivered only as it
        // applies, and a member applies only once its group is whole.
        let start = tokio::time::Instant::now();
        let mut seen = Vec::new();
        drain_until(
            &mut watch,
            &mut seen,
            "Bob holds every version of the save",
            LIMIT * 10,
            |seen| versions(seen).filter(|v| group.contains(&v.id)).count() == PARAGRAPHS,
        )
        .await?;
        let took = start.elapsed();
        w.converged(took);
        for (p, id) in paragraphs.iter().zip(&group) {
            let s = state(&*w.at(BOB), p).await?;
            ensure!(
                s.at.contains(id),
                "Bob does not count Alice's member in {p} though he holds the whole save"
            );
            ensure!(
                s.not_counted.is_empty(),
                "Bob holds back {:?} in {p} though the save is whole",
                s.not_counted
            );
        }
        w.measure("versions in the group", PARAGRAPHS as u64, "versions");
        w.measure(
            "time until the other member counts the whole group",
            took.as_millis() as u64,
            "ms",
        );
        Ok(())
    })
}
