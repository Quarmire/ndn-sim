//! Introductions, i21 — a member let go and invited again joins the sealed folder again.
//!
//! Alice's laptop offers her notebook to Bob; Bob joins and writes a page. Alice's phone then signs
//! a members record that leaves Bob out, and Bob's device takes it (`Device::take_departure`, as
//! i19): it now holds the record that admitted him and the one that left him out. Alice's laptop
//! makes a new offer — what the let-go text tells him to ask for — and Bob joins again. The record
//! that admits him now is signed when the laptop answers and is listed only in the folder's node of
//! the laptop's summary, the node a device let go of the folder does not walk into: the join must
//! still complete (the rule that skips the node is false while an admission is pending, spec §19.8
//! rule 16), Bob writes a page again, and Alice's phone reads it (round 7 review M1).

use std::time::Duration;

use super::i1_join_by_code::{FOLDER, alice_keeps_a_notebook, joins, offer, reads, writes};
use super::kit::{LIMIT, n};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{GrantEvent, InviteRole};
use crate::spaces::SpaceChange;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i21",
    title: "A member let go and invited again joins the sealed folder and writes again",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A person who holds the record that admitted them and the one that let them go, and \
             is invited again to the sealed folder, completes the join: the walk of the inviter's \
             summary descends into the folder's node while the new admission is pending, the \
             record that admits them is fetched, and they write into the folder again and are \
             read; clean or faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const BOB: Dev = Dev(1);
const PHONE: Dev = Dev(2);

/// Not among strangers, as i19: the nodes hold each other's trust contexts.
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
        alice_keeps_a_notebook(w).await?;
        let bobs_key = w.link_key(BOB).await?;
        let code = w
            .offer(LAPTOP, &space, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, BOB, &code.link).await?;
        let bob = w.spaces(BOB);
        let phone = w.spaces(PHONE);
        let page = n("/page-bob");
        writes(w, BOB, &space, &page, "a page by bob").await?;
        w.until("alice's phone reads bob's page", LIMIT, || {
            reads(&*phone, &space, &page, "a page by bob")
        })
        .await?;

        // Alice's phone lets Bob go; his device takes the record that does.
        phone
            .change(
                &space,
                SpaceChange {
                    remove: vec![n("/bob")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.until("alice's laptop is told bob was let go", LIMIT, || async {
            Ok(w.link_grants(LAPTOP).await?.told.iter().any(|e| {
                matches!(e, GrantEvent::Revoked { key, space: s }
                    if *key == bobs_key && *s == space)
            }))
        })
        .await?;
        let told = w.link_grants(LAPTOP).await?;
        let Some(GrantEvent::Departed(left)) = told
            .told
            .iter()
            .find(|e| matches!(e, GrantEvent::Departed(_)))
        else {
            return Err(Failure::new(format!(
                "alice's host was told {:?}; a record that lets bob go must tell it of his \
                 departure, naming the record",
                told.told
            )));
        };
        w.until(
            "bob's device takes the record that lets him go",
            LIMIT,
            || async {
                match w.take_departure(BOB, LAPTOP, &space, &left.record).await? {
                    Ok(()) => Ok(true),
                    Err(e) if e.retry_later() => Ok(false),
                    Err(e) => Err(e.into()),
                }
            },
        )
        .await?;
        let bob_no_more = n("/bob");
        let members = bob.members(&space).await?;
        ensure!(
            !members.writers.contains(&bob_no_more),
            "bob's device took the record that lets him go and still lists him as a writer"
        );

        // Invited again: a new offer, which Bob joins. Bob holds the record that admitted him
        // and the one that let him go; the record that admits him now is still to be fetched.
        let again = w
            .offer(LAPTOP, &space, offer(w, InviteRole::Writer, 3))
            .await?;
        let joined = joins(w, BOB, &again.link).await?;
        ensure!(
            joined.space == space && joined.role == InviteRole::Writer,
            "bob's second join says {joined:?}, not the notebook as a writer"
        );
        let members = bob.members(&space).await?;
        ensure!(
            members.writers.contains(&bob_no_more),
            "bob joined again and his device does not list him among the folder's writers"
        );
        let second = n("/page-bob-again");
        writes(w, BOB, &space, &second, "a page by bob, again").await?;
        w.until("alice's phone reads bob's second page", LIMIT, || {
            reads(&*phone, &space, &second, "a page by bob, again")
        })
        .await?;
        Ok(())
    })
}
