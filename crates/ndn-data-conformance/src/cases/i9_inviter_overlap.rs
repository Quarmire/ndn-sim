//! Introductions, i9 — a code cannot make the joiner trust a namespace overlapping one it trusts.
//!
//! Bob joins Carol's album by her code, so Bob's device trusts `/carol`. Mallory, a stranger
//! whose namespace is `/carol/m` — under Carol's, where Carol's devices' names live — makes an
//! offer of her own folder and sends Bob its code. Bob's join is refused, before his device
//! adopts anything: the inviter's namespace overlaps one his device trusts, so adopting it would
//! let Mallory speak for names of Carol's. Bob's device holds nothing of Mallory's: it reads
//! nothing she writes, and Carol's album still reads. Guards the round-2 review's C1 (the
//! joiner's side).

use std::time::Duration;

use ndn_data::{IntroRefusal, NextStep, Role};

use super::i1_join_by_code::{joins, reads, refused, shut_out};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "i9",
    title: "A code cannot make the joiner trust a namespace overlapping one it trusts",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A join whose inviter's namespace is under or over a namespace the joiner's device \
             already trusts (or its own) is refused, saying why, and the joiner's device adopts \
             nothing of it and reads nothing under it.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const BOB: Dev = Dev(0);
const CAROL: Dev = Dev(1);
const MALLORY: Dev = Dev(2);

const ALBUM: &str = "/carol/32=data/album";
const LURE: &str = "/carol/m/32=data/lure";

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("bob", "phone");
    p.device("carol", "phone");
    p.device("carol/m", "laptop");
    p.strangers();
    p
}

/// `by` (of namespace `ns`) shares `folder` with itself alone and writes its cover.
async fn keeps(w: &World, by: Dev, ns: &str, folder: &str, cover: &str) -> Result<(), Failure> {
    let layer = w.at(by);
    layer
        .share_folder(&n(folder), members(Rule::Log, &[ns], &[person(ns)]).into())
        .await?;
    layer
        .put(&n(&format!("{folder}/cover")), text(cover), note(1))
        .await?;
    Ok(())
}

/// An offer of `role` by `by`, expiring a day from now by its clock.
fn offer_by(w: &World, by: Dev, role: Role) -> ndn_data::Offer {
    ndn_data::Offer {
        role,
        until: Timestamp(w.net().date(by).0 + DAY.as_millis() as u64),
        tries: 3,
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        keeps(w, CAROL, "/carol", ALBUM, "album by carol").await?;
        let album = w
            .offer(CAROL, &n(ALBUM), offer_by(w, CAROL, Role::Reader))
            .await?;
        joins(w, BOB, &album.link).await?;
        let bob = w.at(BOB);
        let album_cover = n(&format!("{ALBUM}/cover"));
        w.until("bob reads carol's album", LIMIT, || {
            reads(&*bob, &album_cover, "album by carol")
        })
        .await?;

        keeps(w, MALLORY, "/carol/m", LURE, "lure by mallory").await?;
        let lure = w
            .offer(MALLORY, &n(LURE), offer_by(w, MALLORY, Role::Writer))
            .await?;
        for code in [&lure.link, &lure.words] {
            let e = refused(w, BOB, code).await?;
            ensure!(
                matches!(
                    &e,
                    DataError::Introduction {
                        why: IntroRefusal::InviterConflict { .. },
                        ..
                    }
                ) && e.next() == NextStep::AskOwner
                    && !e.retry(),
                "bob's join by mallory's code (/carol/m, under /carol which bob trusts) answered \
                 {e:?}, not 'the inviter's namespace overlaps one you trust'"
            );
        }
        w.sleep(SETTLE).await;
        let lure_cover = n(&format!("{LURE}/cover"));
        ensure!(
            shut_out(&*bob, &lure_cover).await?,
            "bob reads mallory's folder after a refused join"
        );
        ensure!(
            reads(&*bob, &album_cover, "album by carol").await?,
            "bob no longer reads carol's album after mallory's code"
        );
        Ok(())
    })
}
