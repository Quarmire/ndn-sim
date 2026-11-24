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

use super::i1_join_by_code::{FOLDER, alice_keeps_a_notebook, joins, offer, reads, writes};
use super::kit::{LIMIT, SETTLE, n, octets};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::InviteRole;
use crate::spaces::SpaceChange;
use crate::world::{Dev, Plan, World};

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
        let space = n(FOLDER);
        let cover = n("/cover");
        alice_keeps_a_notebook(w).await?;
        let code = w
            .offer(LAPTOP, &space, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, BOB, &code.link).await?;
        let bob = w.spaces(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &space, &cover, "cover by alice")
        })
        .await?;
        let page = n("/page-bob");
        writes(w, BOB, &space, &page, "a page by bob").await?;

        // Alice's phone, holding the record that added Bob, removes him.
        let phone = w.spaces(PHONE);
        let laptop = w.spaces(LAPTOP);
        w.until("alice's phone reads bob's page", LIMIT, || {
            reads(&*phone, &space, &page, "a page by bob")
        })
        .await?;
        phone
            .change(
                &space,
                SpaceChange {
                    remove: vec![n("/bob")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        // The phone writes the cover in the epoch its record started: once the laptop reads it,
        // the laptop holds that record. It writes over the cover it reads: a version written
        // before the laptop's reached it would be concurrent with the laptop's (data-layer §15:
        // its parents are the state it holds), and the register's winner of two concurrent
        // versions is the head with the greater signed digest.
        w.until("alice's phone reads alice's cover", LIMIT, || {
            reads(&*phone, &space, &cover, "cover by alice")
        })
        .await?;
        phone
            .put(&space, &cover, octets("cover by alice's phone"))
            .await?;
        w.until("alice's laptop reads the phone's cover", LIMIT, || {
            reads(&*laptop, &space, &cover, "cover by alice's phone")
        })
        .await?;

        // Bob asks the laptop again with the code he holds: a fresh ask.
        let _ = w.join(BOB, &code.link).await?;
        laptop
            .put(&space, &cover, octets("cover after bob asked again"))
            .await?;
        w.sleep(SETTLE).await;
        ensure!(
            !reads(&*bob, &space, &cover, "cover after bob asked again").await?,
            "bob, removed by alice's phone, asked the laptop again with the code and reads \
             alice's folder again"
        );
        Ok(())
    })
}
