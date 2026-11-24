//! Introductions, i2 — a code once used admits nobody else.
//!
//! Alice offers her notebook to Bob; Bob joins. Carol gets the same code afterwards (a forwarded
//! message, a photo of the QR). Her join is refused as used — ask the inviter for a new code —
//! and she is no member: Alice's folder record names no key of hers, and she cannot read the
//! folder. Bob, asking again with the same code (his answer was lost), is answered again: one
//! use is one key, not one packet. Mirrors ndf's G5.

use std::time::Duration;

use super::i1_join_by_code::{
    ALICE, BOB, CAROL, FOLDER, alice_keeps_a_notebook, joins, offer, plan, reads, refused, shut_out,
};
use super::kit::{LIMIT, SETTLE, n};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{InviteRefusal, InviteRole};
use crate::world::World;

pub(super) const CASE: Case = Case {
    id: "i2",
    title: "A code once used admits nobody else; its user asking again is answered again",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "An offer admits one key: a second key presenting the used code is refused as used \
             (next: ask the inviter) and gets no membership and no reading; the key that used \
             it, asking again, is answered again.",
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
            .offer(ALICE, &space, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, BOB, &code.link).await?;

        let e = refused(w, CAROL, &code.link).await?;
        ensure!(
            e.refusal == Some(InviteRefusal::Used) && e.next_is("AskOwner") && !e.retry,
            "carol's join by the used code answered {e:?}, not 'used: ask the inviter'"
        );
        let e = refused(w, CAROL, &code.words).await?;
        ensure!(
            e.refusal == Some(InviteRefusal::Used),
            "carol's join by the used code's words answered {e:?}, not 'used'"
        );
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*w.spaces(CAROL), &space, &cover).await?,
            "carol reads alice's folder after a refused join"
        );

        let again = joins(w, BOB, &code.link).await?;
        ensure!(
            again.space == space,
            "bob's second ask was answered with {again:?}"
        );
        let bob = w.spaces(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &space, &cover, "cover by alice")
        })
        .await?;
        Ok(())
    })
}
