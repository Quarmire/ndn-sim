//! Introductions, i13 — a closed offer admits no one new, yet still answers the writer it
//! admitted until it expires.
//!
//! Alice offers her notebook to Bob; Bob joins and reads it. Alice's host closes the offer as
//! soon as the new member appears (`close_offer`), as ndf's does — and Bob's host, which lost
//! the answer on the way, asks again with the same code: he is answered what he was given, and
//! is a member as before, not told "closed for good". Carol, presenting the same code after the
//! close, is refused as closed (next: ask the inviter), and reads nothing. Once the offer's
//! expiry has passed, Bob asking once more is refused as expired. Guards REPLY-15.2.

use std::time::Duration;

use ndn_data::{IntroRefusal, NextStep, Role};

use super::i1_join_by_code::{
    ALICE, BOB, CAROL, FOLDER, alice_keeps_a_notebook, joins, plan, reads, refused, shut_out,
};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::World;

pub(super) const CASE: Case = Case {
    id: "i13",
    title: "A closed offer admits no one new, yet answers the writer it admitted until it expires",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "After the owner closes an offer, a retry of the key it admitted is answered again \
             (the acceptance it was given, nothing signed) until the offer expires, then \
             refused as expired; any other key is refused as closed.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

/// How long the offer lasts, by Alice's clock.
const OFFER_FOR: Duration = Duration::from_secs(3600);

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;
        let offer = ndn_data::Offer {
            role: Role::Writer,
            until: Timestamp(w.net().date(ALICE).0 + OFFER_FOR.as_millis() as u64),
            tries: 3,
        };
        let code = w.offer(ALICE, &folder, offer).await?;
        joins(w, BOB, &code.link).await?;
        let bob = w.at(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &cover, "cover by alice")
        })
        .await?;

        // Alice's host sees the new member and closes the offer. Bob's host never saw the
        // answer, and asks again.
        w.close_offer(ALICE, &code.offer).await?;
        let again = joins(w, BOB, &code.link).await?;
        ensure!(
            again.folder == folder && again.role == Role::Writer,
            "bob, asking a closed offer again, was answered {again:?}, not what he was given"
        );
        let again = joins(w, BOB, &code.words).await?;
        ensure!(
            again.folder == folder,
            "bob, asking a closed offer again by its words, was answered {again:?}"
        );

        // Nobody else is admitted by it.
        let e = refused(w, CAROL, &code.link).await?;
        ensure!(
            matches!(
                &e,
                DataError::Introduction {
                    why: IntroRefusal::Closed,
                    ..
                }
            ) && e.next() == NextStep::AskOwner
                && !e.retry(),
            "carol's join by the closed offer answered {e:?}, not 'closed: ask the inviter'"
        );
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*w.at(CAROL), &cover).await?,
            "carol reads alice's folder though the offer was closed to her"
        );

        // The offer answers no one once it expired, its user included.
        w.sleep(OFFER_FOR * 2).await;
        let e = refused(w, BOB, &code.link).await?;
        ensure!(
            matches!(
                &e,
                DataError::Introduction {
                    why: IntroRefusal::Expired,
                    ..
                }
            ),
            "bob's retry after the closed offer expired answered {e:?}, not 'expired'"
        );
        Ok(())
    })
}
