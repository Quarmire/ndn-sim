//! Introductions, i12 — a member removed from another device of the owner never comes back by
//! its code.
//!
//! Alice's laptop offers her notebook; Bob joins by the code, reads it and writes a page into
//! it. Once Alice's phone — another device of hers, which never made the offer and so closes
//! nothing — reads Bob's page, it removes Bob. Bob asks the laptop again with a fresh ask: he is
//! answered the acceptance he was given, and nothing more — the laptop signs no record adding
//! him back, so he never reads what Alice writes afterwards. (Their nodes hold each other's
//! trust contexts, so Alice's phone can read Bob's page.) Guards the round-2 review's H2 (the
//! offer's user asking again is never admitted again).

use std::time::Duration;

use ndn_data::Role;

use super::i1_join_by_code::{FOLDER, alice_keeps_a_notebook, joins, offer, reads};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "i12",
    title: "A member removed from another device of the owner never comes back by its code",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A used offer's user asking again is answered again but never admitted again: once \
             any device of the owner removed it, what the owner writes afterwards stays sealed \
             from it.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const BOB: Dev = Dev(1);
const PHONE: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("alice", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;
        let code = w.offer(LAPTOP, &folder, offer(w, Role::Writer, 3)).await?;
        joins(w, BOB, &code.link).await?;
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

        // Alice's phone, holding the record that added Bob, removes him.
        let phone = w.at(PHONE);
        let laptop = w.at(LAPTOP);
        w.until("alice's phone reads bob's page", LIMIT, || {
            reads(&*phone, &page, "a page by bob")
        })
        .await?;
        phone
            .share_folder(
                &folder,
                members(Rule::Log, &["/alice"], &[person("/alice")]),
            )
            .await?;
        // The phone writes the cover in the epoch its record started: once the laptop reads it,
        // the laptop holds that record.
        phone
            .put(&cover, text("cover by alice's phone"), note(1))
            .await?;
        w.until("alice's laptop reads the phone's cover", LIMIT, || {
            reads(&*laptop, &cover, "cover by alice's phone")
        })
        .await?;

        // Bob asks the laptop again with the code he holds: a fresh ask.
        let _ = w.join(BOB, &code.link).await?;
        laptop
            .put(&cover, text("cover after bob asked again"), note(1))
            .await?;
        w.sleep(SETTLE).await;
        ensure!(
            !reads(&*bob, &cover, "cover after bob asked again").await?,
            "bob, removed by alice's phone, asked the laptop again with the code and reads \
             alice's folder again"
        );
        Ok(())
    })
}
