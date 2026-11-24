//! Introductions, i7 — the inviter offline: "retry", and the offer waits.
//!
//! Alice offers her notebook, then her laptop goes offline. Bob's join is refused as not ready:
//! the inviter's device does not answer, retry later. Nothing was used or counted: once Alice's
//! laptop is back, the same code admits Bob, and each reads what the other writes. Mirrors ndf's
//! G10.

use std::time::Duration;

use super::i1_join_by_code::{
    ALICE, BOB, FOLDER, alice_keeps_a_notebook, joins, offer, plan, reads, refused, writes,
};
use super::kit::{LIMIT, n};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::InviteRole;
use crate::world::World;

pub(super) const CASE: Case = Case {
    id: "i7",
    title: "The inviter offline: retry, and the offer waits",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A join while the offering device is unreachable is refused as not ready (next: \
             retry later) and spends nothing; the same code admits its holder once the device \
             is back.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n(FOLDER);
        let cover = n("/cover");
        alice_keeps_a_notebook(w).await?;
        let code = w
            .offer(ALICE, &space, offer(w, InviteRole::Writer, 1))
            .await?;

        w.net().offline(ALICE);
        let e = refused(w, BOB, &code.link).await?;
        ensure!(
            e.kind_is("NotReady") && e.retry && e.next_is("RetryLater"),
            "bob's join while alice's laptop is offline answered {e:?}, not 'not ready: retry'"
        );
        w.net().online(ALICE);

        let joined = joins(w, BOB, &code.link).await?;
        ensure!(joined.space == space, "bob joined {joined:?}");
        let bob = w.spaces(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &space, &cover, "cover by alice")
        })
        .await?;
        let page = n("/page-bob");
        writes(w, BOB, &space, &page, "a page by bob").await?;
        let alice = w.spaces(ALICE);
        w.until("alice reads bob's page", LIMIT, || {
            reads(&*alice, &space, &page, "a page by bob")
        })
        .await?;
        Ok(())
    })
}
