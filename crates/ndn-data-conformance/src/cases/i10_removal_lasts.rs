//! Introductions, i10 — removing a member who joined by a code lasts.
//!
//! Alice offers her notebook; Bob joins by the code (a stolen one, say) and reads it. Alice
//! removes Bob from the folder, as any member is removed, and writes a new cover. Removing him
//! closed the offer he used, which admits no one new but still answers its user: Bob still
//! holds the code and asks again, with a fresh ask, and is answered what he was given — he is
//! no member again, and the new cover stays sealed from him. Alice's laptop then restarts (her
//! kept answers survive in her store) and Bob asks once more: answered alike, still no member.
//! Guards the round-2 review's H2 (and REPLY-15.2: a closed offer keeps answering its user).

use std::time::Duration;

use ndn_data::Role;

use super::i1_join_by_code::{
    ALICE, BOB, FOLDER, alice_keeps_a_notebook, joins, offer, plan, reads,
};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::World;

pub(super) const CASE: Case = Case {
    id: "i10",
    title: "Removing a member who joined by a code lasts",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "Once the owner removes a member who joined by a code, the offer it used admits no \
             one new: asking again with that code — a fresh ask, before or after the inviter's \
             device restarts — is answered what the member was given, never refused as closed, \
             and never makes it a member again: what the owner writes afterwards stays sealed \
             from it.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;
        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        joins(w, BOB, &code.link).await?;
        let bob = w.at(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &cover, "cover by alice")
        })
        .await?;

        // Alice removes Bob.
        let alice = w.at(ALICE);
        alice
            .share_folder(
                &folder,
                members(Rule::Log, &["/alice"], &[person("/alice")]).into(),
            )
            .await?;
        alice
            .put(&cover, text("cover after bob left"), note(1))
            .await?;

        // Bob asks again with the code he holds: a fresh ask.
        let again = w.join(BOB, &code.link).await?;
        ensure!(
            answered(&again),
            "bob, removed, asking again with the code was answered {again:?}, not what he was \
             given"
        );
        alice
            .put(&cover, text("cover after bob asked again"), note(1))
            .await?;
        w.sleep(SETTLE).await;
        ensure!(
            !reads(&*bob, &cover, "cover after bob asked again").await?,
            "bob, removed, asked again with the code and reads alice's folder again"
        );

        // Alice's laptop restarts: what it kept in memory is gone.
        w.stop(ALICE).await?;
        let alice = w.restart(ALICE).await?;
        let again = w.join(BOB, &code.words).await?;
        ensure!(
            answered(&again),
            "bob, removed, asking again after alice's restart was answered {again:?}, not what \
             he was given"
        );
        alice
            .put(&cover, text("cover after alice restarted"), note(1))
            .await?;
        w.sleep(SETTLE).await;
        ensure!(
            !reads(&*bob, &cover, "cover after alice restarted").await?,
            "bob, removed, asked again after alice's restart and reads alice's folder again"
        );
        Ok(())
    })
}

/// Whether a join was answered as the member the offer admitted: it carried on (`Ok`), or its
/// readiness wait ended for want of the records a removed member never gets (`NotReady`) —
/// never a refusal of the introduction: the closed offer still answers its user.
fn answered(join: &Result<ndn_data::Joined, DataError>) -> bool {
    matches!(join, Ok(_) | Err(DataError::NotReady { .. }))
}
