//! Introductions, i15 — an offer's admission makes one grant to link, for the admitted key only.
//!
//! Alice offers her notebook to two strangers. Bob joins as a writer: Alice's host is told of
//! one grant (`Introducer::grant`) naming Bob's key, his namespace `/bob`, the notebook and the
//! offer's role, with no date (it follows the members record); her layer lists the same grant
//! (`Device::grants`). Bob's host asks again with the same code, as one whose answer was lost
//! does: he is answered what he was given, the host is told nothing more, and the grant has
//! not moved. Carol presenting the used code is refused and granted nothing; so is a code forged
//! without its secret. Carol joins a second offer as a reader: a second grant, naming her key,
//! `/carol` and the reader's role. A host whose policy makes no grants (`grant_for` `Some(ZERO)`) admits
//! Eve all the same and is told nothing.

use std::time::Duration;

use super::i1_join_by_code::{
    ALICE, BOB, CAROL, FOLDER, alice_keeps_a_notebook, forged, joins, offer, refused,
};
use super::kit::{SETTLE, n, octets, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{GrantEvent, InviteRole};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i15",
    title: "An offer's admission makes one grant to link, for the admitted key only",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "Once an offer admits a person, the host is told of one grant naming the asker's \
             key and namespace, the folder and the offer's role, with no date (it follows the \
             members record); Device::grants lists it; a retry of the same key, an ask refused, \
             and a code forged without its secret grant nothing and do not move it; a host with \
             grant_for Some(ZERO) is told nothing; clean or faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const DINA: Dev = Dev(3);
const EVE: Dev = Dev(4);

/// Alice's laptop, Bob's and Carol's phones, Dina's laptop (no grants) and Eve's phone:
/// strangers to each other.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "phone");
    let dina = p.device("dina", "laptop");
    p.device("eve", "phone");
    p.no_link_grants(dina);
    p.strangers();
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n(FOLDER);
        alice_keeps_a_notebook(w).await?;
        let (bob_key, carol_key) = (w.link_key(BOB).await?, w.link_key(CAROL).await?);

        // Bob joins as a writer: one grant, for his key.
        let code = w
            .offer(ALICE, &space, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, BOB, &code.link).await?;
        let log = w.link_grants(ALICE).await?;
        let [GrantEvent::Granted(bobs)] = log.told.as_slice() else {
            return Err(Failure::new(format!(
                "alice's host was told {:?} after bob joined; it must be told of exactly one grant",
                log.told
            )));
        };
        ensure!(
            bobs.key == bob_key,
            "the grant names {:02x?}, not bob's key {bob_key:02x?}",
            bobs.key
        );
        ensure!(
            bobs.namespaces == [n("/bob")],
            "the grant names the namespaces {:?}, not bob's /bob",
            bobs.namespaces
        );
        ensure!(
            bobs.space == space && bobs.role == InviteRole::Writer,
            "the grant names {} as {:?}, not the notebook as a writer",
            bobs.space,
            bobs.role
        );
        ensure!(
            bobs.until.is_none(),
            "the grant ends at {:?}: by default a grant has no date (it follows the members \
             record), whatever the clock says",
            bobs.until
        );
        ensure!(
            log.now == [bobs.clone()],
            "Device::grants is {:?}, not the grant alice's host was told of",
            log.now
        );

        // Bob's host asks again with the code (and with its words): answered as before, and no
        // second grant; the end has not moved however long it was since.
        w.sleep(SETTLE).await;
        joins(w, BOB, &code.link).await?;
        joins(w, BOB, &code.words).await?;
        let again = w.link_grants(ALICE).await?;
        ensure!(
            again == log,
            "after bob asked again alice's host was told {:?} and her layer lists {:?}; a retry \
             must grant nothing and move no end (was {:?}, listing {:?})",
            again.told,
            again.now,
            log.told,
            log.now
        );

        // Carol presents the used code: refused, and granted nothing.
        refused(w, CAROL, &code.link).await?;
        ensure!(
            w.link_grants(ALICE).await? == log,
            "carol, refused by the used code, was granted a link"
        );

        // A code forged without its secret is refused and grants nothing.
        let second = w
            .offer(ALICE, &space, offer(w, InviteRole::Reader, 3))
            .await?;
        refused(w, CAROL, &forged(&second, 9)).await?;
        ensure!(
            w.link_grants(ALICE).await? == log,
            "a code forged without its secret was granted a link"
        );

        // Carol joins the second offer as a reader: a grant of her own.
        joins(w, CAROL, &second.link).await?;
        let both = w.link_grants(ALICE).await?;
        let [first, GrantEvent::Granted(carols)] = both.told.as_slice() else {
            return Err(Failure::new(format!(
                "alice's host was told {:?} after carol joined; it must be told of bob's grant and \
                 then carol's",
                both.told
            )));
        };
        ensure!(
            *first == GrantEvent::Granted(bobs.clone()),
            "carol's join changed bob's grant"
        );
        ensure!(
            carols.key == carol_key
                && carols.namespaces == [n("/carol")]
                && carols.space == space
                && carols.role == InviteRole::Reader,
            "carol's grant is {carols:?}, not her key, /carol, the notebook and the reader's role"
        );
        ensure!(
            both.now.len() == 2 && both.now.contains(bobs) && both.now.contains(carols),
            "Device::grants is {:?}, not bob's grant and carol's",
            both.now
        );

        // A host whose policy makes no grants admits all the same, and is told nothing.
        let dinas = n("/dina/32=data/notebook");
        let dina = w.spaces(DINA);
        dina.create(&dinas, private(&[], &[])).await?;
        dina.put(&dinas, &n("/cover"), octets("cover by dina"))
            .await?;
        let code = w
            .offer(DINA, &dinas, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, EVE, &code.link).await?;
        let none = w.link_grants(DINA).await?;
        ensure!(
            none.told.is_empty() && none.now.is_empty(),
            "a host with grant_for Some(ZERO) was told {:?} and its layer lists {:?} after it \
             admitted eve",
            none.told,
            none.now
        );
        Ok(())
    })
}
