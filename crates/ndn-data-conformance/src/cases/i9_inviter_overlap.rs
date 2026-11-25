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

use ndn_heap::Name;

use super::i1_join_by_code::{joins, reads, refused, shut_out};
use super::kit::{DAY, LIMIT, SETTLE, n, octets, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{InviteOffer, InviteRefusal, InviteRole};
use crate::world::{Dev, Plan, World};

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

/// `by` shares `space` with itself alone and writes its cover.
async fn keeps(w: &World, by: Dev, space: &Name, cover: &str) -> Result<(), Failure> {
    let spaces = w.spaces(by);
    spaces.create(space, private(&[], &[])).await?;
    spaces.put(space, &n("/cover"), octets(cover)).await?;
    Ok(())
}

/// An offer of `role` by `by`, expiring a day from now by its clock.
fn offer_by(w: &World, by: Dev, role: InviteRole) -> InviteOffer {
    InviteOffer {
        role,
        until: w.net().date(by).0 + DAY.as_millis() as u64,
        tries: 3,
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let (album, lure, cover) = (n(ALBUM), n(LURE), n("/cover"));
        keeps(w, CAROL, &album, "album by carol").await?;
        let code = w
            .offer(CAROL, &album, offer_by(w, CAROL, InviteRole::Reader))
            .await?;
        joins(w, BOB, &code.link).await?;
        let bob = w.spaces(BOB);
        w.until("bob reads carol's album", LIMIT, || {
            reads(&*bob, &album, &cover, "album by carol")
        })
        .await?;

        keeps(w, MALLORY, &lure, "lure by mallory").await?;
        let lured = w
            .offer(MALLORY, &lure, offer_by(w, MALLORY, InviteRole::Writer))
            .await?;
        for code in [&lured.link, &lured.words] {
            let e = refused(w, BOB, code).await?;
            ensure!(
                matches!(&e.refusal, Some(InviteRefusal::InviterConflict { .. }))
                    && e.next_is("AskOwner")
                    && !e.retry,
                "bob's join by mallory's code (/carol/m, under /carol which bob trusts) answered \
                 {e:?}, not 'the inviter's namespace overlaps one you trust'"
            );
        }
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*bob, &lure, &cover).await?,
            "bob reads mallory's folder after a refused join"
        );
        ensure!(
            reads(&*bob, &album, &cover, "album by carol").await?,
            "bob no longer reads carol's album after mallory's code"
        );
        Ok(())
    })
}
