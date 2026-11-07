//! Introductions, i3 — a code past its expiry admits nobody.
//!
//! Alice offers her notebook to Bob for ten minutes. Bob only gets to it after half an hour: by
//! Alice's laptop's clock the offer has expired, and his join is refused as expired — ask the
//! inviter for a new code. He is no member. A new code Alice makes then admits him. Mirrors
//! ndf's G6.

use std::time::Duration;

use ndn_data::{IntroRefusal, NextStep, Offer, Role};

use super::i1_join_by_code::{
    ALICE, BOB, FOLDER, alice_keeps_a_notebook, joins, offer, plan, reads, refused, shut_out,
};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::World;

pub(super) const CASE: Case = Case {
    id: "i3",
    title: "A code past its expiry admits nobody; a new code does",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "An offer is judged against its expiry by the offering device's clock: once past \
             it, a join is refused as expired (next: ask the inviter) and grants nothing.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;
        let short = Offer {
            role: Role::Writer,
            until: Timestamp(w.net().date(ALICE).0 + 10 * 60 * 1000),
            tries: 3,
        };
        let code = w.offer(ALICE, &folder, short).await?;
        w.sleep(Duration::from_secs(30 * 60)).await;

        let e = refused(w, BOB, &code.link).await?;
        ensure!(
            matches!(
                &e,
                DataError::Introduction {
                    why: IntroRefusal::Expired,
                    ..
                }
            ) && e.next() == NextStep::AskOwner,
            "bob's join by an expired code answered {e:?}, not 'expired: ask the inviter'"
        );
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*w.at(BOB), &cover).await?,
            "bob reads alice's folder after a refused join"
        );

        let fresh = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        joins(w, BOB, &fresh.link).await?;
        let bob = w.at(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &cover, "cover by alice")
        })
        .await?;
        Ok(())
    })
}
