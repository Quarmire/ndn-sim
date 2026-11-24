//! Introductions, i5 — a code replayed by a third party admits one key, never two.
//!
//! Carol saw the QR Alice showed Bob. Bob and Carol present the same code at the same moment:
//! exactly one of them becomes a member, the other is refused as used, and only the one admitted
//! reads the folder. Asking again does not change the winner, and a third try by the loser is
//! refused alike. An ask cannot be turned into another key's membership: its proof is bound to
//! the asking key (unit tests and the threat notes, spec §19). Mirrors ndf's G8.

use std::time::Duration;

use super::i1_join_by_code::{
    ALICE, BOB, CAROL, FOLDER, alice_keeps_a_notebook, offer, plan, reads, shut_out,
};
use super::kit::{LIMIT, SETTLE, n};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{InviteFailure, InviteRefusal, InviteRole};
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "i5",
    title: "A code replayed by a third party admits one key, never two",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "Two keys presenting one code at once: exactly one is admitted, the other is \
             refused as used and reads nothing; the loser asking again is refused alike.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

fn used(e: &InviteFailure) -> bool {
    e.refusal == Some(InviteRefusal::Used)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n(FOLDER);
        let cover = n("/cover");
        alice_keeps_a_notebook(w).await?;
        let code = w
            .offer(ALICE, &space, offer(w, InviteRole::Writer, 3))
            .await?;

        // A join that is `NotReady` (the winner's walk of the inviter's summary not done within
        // the join's bound, as on a faulty path) is done again, as a host does what it says.
        let (bob, carol) = futures::join!(
            w.join_again(BOB, &code.link),
            w.join_again(CAROL, &code.link)
        );
        let (winner, loser): (Dev, Dev) = match (bob?, carol?) {
            (Ok(_), Err(e)) if used(&e) => (BOB, CAROL),
            (Err(e), Ok(_)) if used(&e) => (CAROL, BOB),
            other => {
                return Err(Failure::new(format!(
                    "bob and carol presenting one code at once answered {other:?}: exactly one \
                     must be admitted and the other refused as used"
                )));
            }
        };
        // Asking again is a host's: a lost exchange (`NotReady`, retry later) is asked again, so
        // the answer judged is the inviter's own.
        let e = w.join_again(loser, &code.link).await?;
        ensure!(
            matches!(&e, Err(e) if used(e)),
            "the loser asking again answered {e:?}, not 'used'"
        );
        let admitted = w.spaces(winner);
        w.until("the admitted one reads alice's cover", LIMIT, || {
            reads(&*admitted, &space, &cover, "cover by alice")
        })
        .await?;
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*w.spaces(loser), &space, &cover).await?,
            "{} reads alice's folder though refused",
            w.net().spec(loser).name()
        );
        Ok(())
    })
}
