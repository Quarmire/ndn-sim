//! Introductions, i10 — removing a member who joined by a code lasts.
//!
//! Alice offers her notebook; Bob joins by the code (a stolen one, say) and reads it. Alice
//! removes Bob from the folder, as any member is removed, and writes a new cover. Removing him
//! closed the offer he used: Bob still holds the code and asks again, with a fresh ask, and is
//! refused as closed — he is no member again, and the new cover stays sealed from him. Alice's
//! laptop then restarts (her kept answers are gone) and Bob asks once more: refused alike, still
//! no member. Guards the round-2 review's H2.

use std::time::Duration;

use ndn_data::{IntroRefusal, Role};

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
    guards: "Once the owner removes a member who joined by a code, the offer it used is closed: \
             asking again with that code — a fresh ask, before or after the inviter's device \
             restarts — is refused as closed and never makes it a member again: what the owner \
             writes afterwards stays sealed from it.",
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
                members(Rule::Log, &["/alice"], &[person("/alice")]),
            )
            .await?;
        alice
            .put(&cover, text("cover after bob left"), note(1))
            .await?;

        // Bob asks again with the code he holds: a fresh ask.
        let again = w.join(BOB, &code.link).await?;
        ensure!(
            matches!(
                &again,
                Err(DataError::Introduction {
                    why: IntroRefusal::Closed,
                    ..
                })
            ),
            "bob, removed, asking again with the code was answered {again:?}, not 'closed'"
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
            matches!(
                &again,
                Err(DataError::Introduction {
                    why: IntroRefusal::Closed,
                    ..
                })
            ),
            "bob, removed, asking again after alice's restart was answered {again:?}, not 'closed'"
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
