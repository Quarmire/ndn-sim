//! Slice 6, g7 — a group with a member in pieces counts whole, on the reader and on the writer
//! after it reads the folder again.
//!
//! Alice types a long paragraph key by key under a rule that folds nothing, and saves it with two
//! short ones as one group: a 37,847-byte operation beside two small ones. An operation over
//! 6,144 bytes travels in pieces (spec §13.1). Before, the group never counted on Bob, its
//! reader (ndf's REPLY-13 §8): the big member, held pending and not opened yet, was judged
//! missing even once every piece was held, so the group stayed "incomplete: 2 of 3", and only
//! applying a member — which waits for the group — opened it. Alice's own laptop counted the
//! group as she wrote it, but lost it the moment a new members record made it read the folder
//! again: the applied operation in pieces had been let go from memory, so it was missing too.
//! The fix: a pending member whose pieces are all held is waiting, to be opened when it applies,
//! not missing. Bob counts all three; so does Alice after her new record.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "g7",
    title: "A group with a member in pieces counts whole, on the reader and on the writer after \
            it reads the folder again",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::AppOps,
        Feature::MergePieces,
        Feature::Groups,
        Feature::FolderMembers,
    ],
    model: &["M14"],
    guards: "A group of three merge versions, one carrying a 37,847-byte operation in pieces, \
             counts whole on a reader once it holds every member and piece: all three in its \
             frontier, none listed not counted. The writer counts all three as it writes them and \
             still does after a new members record makes it read the folder again.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
/// ndf's operation: a long paragraph typed key by key, nothing folded.
const BIG: usize = 37_847;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p
}

/// Whether `d` counts each of `ids`, its member in the collection beside it.
async fn counts_all(w: &World, d: Dev, members: &[(Name, VersionId)]) -> Result<bool, Failure> {
    for (p, id) in members {
        let s = state(&*w.at(d), p).await?;
        if !s.at.contains(id) || !s.not_counted.is_empty() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/32=data/doc");
        let paragraphs: Vec<Name> = (0..3)
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
                )
                .into(),
            )
            .await?;
        let mut watch = w.at(BOB).watch(&folder, &Frontier::new()).await?;
        let mut items = Vec::with_capacity(3);
        for (i, p) in paragraphs.iter().enumerate() {
            let op = match i {
                1 => {
                    // The text that makes the operation exactly BIG bytes.
                    let mut len = BIG;
                    let mut op = None;
                    for _ in 0..8 {
                        let made = element_op(w, ALICE, p, |op| {
                            op.then(0, Edit::Create("paragraph".into()))
                                .set("text", prose("typed key by key", len))
                        })
                        .await?
                        .encode();
                        if made.len() == BIG {
                            op = Some(made);
                            break;
                        }
                        len = (len + BIG).saturating_sub(made.len());
                    }
                    op.ok_or_else(|| Failure::new(format!("no element operation of {BIG} bytes")))?
                }
                _ => element_op(w, ALICE, p, |op| {
                    op.then(0, Edit::Create("paragraph".into()))
                        .set("text", format!("paragraph {i}"))
                })
                .await?
                .encode(),
            };
            items.push((p.clone(), ndn_data::Edit::Op(op)));
        }
        let group = w.at(ALICE).put_group(items, element_type()).await?;
        ensure!(
            group.len() == 3,
            "a group of 3 versions answered {} ids",
            group.len()
        );
        let saved: Vec<(Name, VersionId)> = paragraphs
            .iter()
            .cloned()
            .zip(group.iter().cloned())
            .collect();
        ensure!(
            counts_all(w, ALICE, &saved).await?,
            "Alice does not count her own group as she writes it"
        );

        // Bob, the reader, holds every member and piece, and counts all three.
        let mut seen = Vec::new();
        drain_until(
            &mut watch,
            &mut seen,
            "Bob counts the whole group",
            LIMIT,
            |seen| versions(seen).filter(|v| group.contains(&v.id)).count() == 3,
        )
        .await?;
        let big = version(&seen, &group[1]).and_then(large);
        ensure!(
            big.is_some(),
            "the {BIG}-byte member reached Bob inline, not in pieces: the case tests nothing"
        );
        ensure!(
            counts_all(w, BOB, &saved).await?,
            "Bob holds the whole group but does not count all three"
        );

        // Alice's laptop reads the folder again under a new members record (Bob becomes a
        // writer): her applied operation in pieces, let go from memory, is opened again.
        w.gesture();
        w.at(ALICE)
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
        w.until(
            "Alice counts all three of her group after reading the folder again",
            LIMIT,
            || async { counts_all(w, ALICE, &saved).await },
        )
        .await?;
        w.measure("bytes of the member in pieces", big.unwrap_or(0), "bytes");
        Ok(())
    })
}
