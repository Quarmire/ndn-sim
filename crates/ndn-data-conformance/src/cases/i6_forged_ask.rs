//! Introductions, i6 — an ask forged without the secret is counted and grants nothing.
//!
//! The offer's name is public (it is a record in Alice's log); its secret is not. Carol knows
//! the offer's name and the anchor fingerprint, not the secret, and asks with a guessed one:
//! refused as a wrong proof, counted — check the code — and she is no member and reads nothing.
//! Bob, holding the real code, still joins afterwards: one wrong try does not close an offer
//! that allows three. Mirrors ndf's G9.

use std::time::Duration;

use super::i1_join_by_code::{
    ALICE, BOB, CAROL, FOLDER, alice_keeps_a_notebook, forged, joins, offer, plan, reads, refused,
    shut_out,
};
use super::kit::{LIMIT, SETTLE, n};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{InviteRefusal, InviteRole};
use crate::world::World;

pub(super) const CASE: Case = Case {
    id: "i6",
    title: "An ask forged without the secret is counted and grants nothing",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "An ask without the offer's secret is refused as a wrong proof (counted; next: check \
             the code) and grants no membership and no reading; the real code, within its tries, \
             still admits its holder.",
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

        let e = refused(w, CAROL, &forged(&code, 0xC4)).await?;
        ensure!(
            e.refusal == Some(InviteRefusal::WrongProof { left: 2 })
                && e.next_is("FixRequest")
                && !e.retry,
            "carol's ask with a guessed secret answered {e:?}, not 'wrong proof, 2 left'"
        );
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*w.spaces(CAROL), &space, &cover).await?,
            "carol reads alice's folder after a forged ask"
        );

        joins(w, BOB, &code.link).await?;
        let bob = w.spaces(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &space, &cover, "cover by alice")
        })
        .await?;
        ensure!(
            shut_out(&*w.spaces(CAROL), &space, &cover).await?,
            "carol reads alice's folder once bob joined"
        );
        Ok(())
    })
}
