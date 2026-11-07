//! Introductions, i4 — wrong tries are counted, durably, then the offer closes for good.
//!
//! Alice offers her notebook allowing two wrong tries. Bob mistypes the code: the first wrong
//! try is refused, saying one is left. Alice's laptop then restarts. Bob's second wrong try is
//! refused as closing the offer — the count survived the restart — and from then on even the
//! right code is refused as closed: ask the inviter for a new code. Bob is no member. Mirrors
//! ndf's G7.

use std::time::Duration;

use ndn_data::{IntroRefusal, NextStep, Role};

use super::i1_join_by_code::{
    ALICE, BOB, FOLDER, alice_keeps_a_notebook, forged, offer, plan, refused, shut_out,
};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::World;

pub(super) const CASE: Case = Case {
    id: "i4",
    title: "Wrong tries are counted across a restart, then the offer closes for good",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "Each ask with a wrong proof of the secret counts, durably on the offering device; \
             once the allowed tries are spent the offer is closed for good, even to the right \
             secret, and nothing was granted.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

fn closed(e: &DataError) -> bool {
    matches!(
        e,
        DataError::Introduction {
            why: IntroRefusal::Closed,
            ..
        }
    ) && e.next() == NextStep::AskOwner
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;
        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 2)).await?;

        let e = refused(w, BOB, &forged(&code, 0x01)).await?;
        ensure!(
            matches!(
                &e,
                DataError::Introduction {
                    why: IntroRefusal::WrongProof { left: 1 },
                    ..
                }
            ) && e.next() == NextStep::FixRequest,
            "bob's first wrong try answered {e:?}, not 'wrong: check the code, 1 left'"
        );

        w.stop(ALICE).await?;
        w.restart(ALICE).await?;

        let e = refused(w, BOB, &forged(&code, 0x02)).await?;
        ensure!(
            closed(&e),
            "bob's second wrong try, after alice's restart, answered {e:?}, not 'closed'"
        );
        let e = refused(w, BOB, &code.link).await?;
        ensure!(
            closed(&e),
            "the right code after the tries were spent answered {e:?}, not 'closed'"
        );
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*w.at(BOB), &cover).await?,
            "bob reads alice's folder after every join was refused"
        );
        Ok(())
    })
}
