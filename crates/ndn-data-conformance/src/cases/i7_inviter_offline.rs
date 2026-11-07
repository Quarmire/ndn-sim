//! Introductions, i7 — the inviter offline: "retry", and the offer waits.
//!
//! Alice offers her notebook, then her laptop goes offline. Bob's join is refused as not ready:
//! the inviter's device does not answer, retry later. Nothing was used or counted: once Alice's
//! laptop is back, the same code admits Bob, and each reads what the other writes. Mirrors ndf's
//! G10.

use std::time::Duration;

use ndn_data::{NextStep, Role};

use super::i1_join_by_code::{
    ALICE, BOB, FOLDER, alice_keeps_a_notebook, joins, offer, plan, reads, refused,
};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
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
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;
        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 1)).await?;

        w.net().offline(ALICE);
        let e = refused(w, BOB, &code.link).await?;
        ensure!(
            matches!(&e, DataError::NotReady { .. })
                && e.retry()
                && e.next() == NextStep::RetryLater,
            "bob's join while alice's laptop is offline answered {e:?}, not 'not ready: retry'"
        );
        w.net().online(ALICE);

        let joined = joins(w, BOB, &code.link).await?;
        ensure!(joined.folder == folder, "bob joined {joined:?}");
        let bob = w.at(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &cover, "cover by alice")
        })
        .await?;
        let page = n(&format!("{FOLDER}/page-bob"));
        w.until("bob writes a page into the folder", LIMIT, || async {
            match bob.put(&page, text("a page by bob"), note(1)).await {
                Ok(_) => Ok(true),
                Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
                Err(e) => Err(e.into()),
            }
        })
        .await?;
        let alice = w.at(ALICE);
        w.until("alice reads bob's page", LIMIT, || {
            reads(&*alice, &page, "a page by bob")
        })
        .await?;
        Ok(())
    })
}
