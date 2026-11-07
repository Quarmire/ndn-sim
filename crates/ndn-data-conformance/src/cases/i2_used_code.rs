//! Introductions, i2 — a code once used admits nobody else.
//!
//! Alice offers her notebook to Bob; Bob joins. Carol gets the same code afterwards (a forwarded
//! message, a photo of the QR). Her join is refused as used — ask the inviter for a new code —
//! and she is no member: Alice's folder record names no key of hers, and she cannot read the
//! folder. Bob, asking again with the same code (his answer was lost), is answered again: one
//! use is one key, not one packet. Mirrors ndf's G5.

use ndn_data::{IntroRefusal, NextStep, Role};

use super::i1_join_by_code::{
    ALICE, BOB, CAROL, FOLDER, alice_keeps_a_notebook, joins, offer, plan, reads, refused, shut_out,
};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
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
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;
        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        joins(w, BOB, &code.link).await?;

        let e = refused(w, CAROL, &code.link).await?;
        ensure!(
            matches!(
                &e,
                DataError::Introduction {
                    why: IntroRefusal::Used,
                    ..
                }
            ) && e.next() == NextStep::AskOwner
                && !e.retry(),
            "carol's join by the used code answered {e:?}, not 'used: ask the inviter'"
        );
        let e = refused(w, CAROL, &code.words).await?;
        ensure!(
            matches!(
                &e,
                DataError::Introduction {
                    why: IntroRefusal::Used,
                    ..
                }
            ),
            "carol's join by the used code's words answered {e:?}, not 'used'"
        );
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*w.at(CAROL), &cover).await?,
            "carol reads alice's folder after a refused join"
        );

        let again = joins(w, BOB, &code.link).await?;
        ensure!(
            again.folder == folder,
            "bob's second ask was answered with {again:?}"
        );
        let bob = w.at(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &cover, "cover by alice")
        })
        .await?;
        Ok(())
    })
}
