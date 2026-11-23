//! Names by key, n2 — Alice adds Bob and Carol to one space; each writes; all three see
//! everything.
//!
//! Alice, Bob and Carol are each named by their genesis root key alone (`/user/<0xA1: …>`) and
//! are strangers. Alice's device adopts Bob's and Carol's namespaces by name, and each of theirs
//! adopts Alice's; then Alice adds Bob and Carol to her notebook space, each as a writer. So
//! Bob and Carol still hold nothing of each other's namespace. Bob writes a page and Carol
//! writes a page; Alice, Bob and Carol each read both. Bob's device reads Carol's page because
//! Carol is a writer in a members record of the space that Alice's device signed, which Bob
//! holds: it adopts Carol's namespace by name (version 1 fetched and checked as the genesis the
//! name hashes, the newest reached from it) for judging that space's data alone, and Carol's
//! device adopts Bob's the same way (spec §6.3).
//!
//! The guards:
//! - that adoption judges nothing else at Bob: Carol's own diary space, which she opens to
//!   anyone and which Alice (who holds Carol's namespace) reads, stays unreadable at Bob, and
//!   Bob's forwarder (its node's validator) still refuses Carol's page as a person's name it
//!   does not hold;
//! - once Alice's next record drops Carol, Bob refuses a page Carol writes later in the space
//!   (outside the removal cut), while her earlier page, which the cut keeps, still reads.
//!
//! Mirrors ndf's G-series with three members (REPLY-to-ndn-workspace-13 §4).
//!
//! The members are introduced to Alice by the host's `adopt` of an anchor link by name and by the
//! owner's `change` of the members record, not by an invitation code (`offer`/`join`, which the
//! neutral surface does not have until stage 5): what the case guards is the adoption that the
//! record, not the invitation, causes at the other members.

use std::time::Duration;

use super::kit::{LIMIT, SETTLE, members_now, n, octets, private, public};
use super::n1_named_by_key::{adopts, by_name, reads, shut_out, under};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{EntryRead, SpaceChange, SpaceMembers};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "n2",
    title: "Alice invites Bob and Carol to one folder; each writes; all three see everything",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::SelfCertifying,
    ],
    model: &[],
    guards: "Members of one folder named by their keys read each other's writing there with no \
             gesture beyond the owner's invitations: a device adopts by name, for judging that \
             folder's data alone, every self-certifying writer an owner-signed record of the \
             folder lists. That adoption vouches for the namespace nowhere else — not in another \
             folder, not at the device's forwarder — and once a record drops the writer, its new \
             versions in the folder are refused while the removal cut keeps the old ones.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

/// Alice's, Bob's and Carol's genesis root keys (Ed25519 secrets).
const ALICE_KEY: [u8; 32] = [0xa1; 32];
const BOB_KEY: [u8; 32] = [0xb0; 32];
const CAROL_KEY: [u8; 32] = [0xc0; 32];

/// Alice's laptop, Bob's phone and Carol's tablet, each person named by their key: strangers.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.self_certifying(ALICE_KEY, "laptop");
    p.self_certifying(BOB_KEY, "phone");
    p.self_certifying(CAROL_KEY, "tablet");
    p.strangers();
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let alice_ns = w.net().spec(ALICE).person.clone();
        let bob_ns = w.net().spec(BOB).person.clone();
        let carol_ns = w.net().spec(CAROL).person.clone();
        let space = under(&alice_ns, "/32=data/notebook");
        let cover = n("/cover");
        let (alice, bob, carol) = (w.spaces(ALICE), w.spaces(BOB), w.spaces(CAROL));
        // Alice alone writes and reads her notebook.
        alice.create(&space, private(&[], &[])).await?;
        alice.put(&space, &cover, octets("cover by alice")).await?;

        // Alice's device adopts Bob's and Carol's namespaces, and theirs adopt Alice's, each by
        // name alone; Alice adds them as writers (and readers) of the space.
        let start = tokio::time::Instant::now();
        for (d, ns, who) in [(BOB, &bob_ns, "bob"), (CAROL, &carol_ns, "carol")] {
            adopts(
                w,
                ALICE,
                &by_name(ns),
                &format!("{who}'s namespace by its name"),
            )
            .await?;
            adopts(w, d, &by_name(&alice_ns), "alice's namespace by its name").await?;
        }
        alice
            .change(
                &space,
                SpaceChange {
                    add_writers: vec![bob_ns.clone(), carol_ns.clone()],
                    add_readers: vec![bob_ns.clone(), carol_ns.clone()],
                    remove: Vec::new(),
                },
            )
            .await?;
        let members = SpaceMembers::new(
            &alice_ns,
            vec![bob_ns.clone(), carol_ns.clone()],
            vec![bob_ns.clone(), carol_ns.clone()],
            false,
        );
        for (spaces, who) in [(&bob, "bob"), (&carol, "carol")] {
            w.retry_later(|| spaces.open(&space)).await?;
            w.until(
                &format!("{who} holds the record that lists both writers"),
                LIMIT,
                || async { Ok(members_now(&**spaces, &space).await?.as_ref() == Some(&members)) },
            )
            .await?;
        }

        // Each writes; all three read everything.
        let page_b = n("/page-bob");
        let page_c = n("/page-carol");
        w.space_put(BOB, &space, &page_b, octets("a page by bob"))
            .await?;
        let carols = w
            .space_put(CAROL, &space, &page_c, octets("a page by carol"))
            .await?;
        for (d, spaces) in [(ALICE, &alice), (BOB, &bob), (CAROL, &carol)] {
            let who = w.net().spec(d).name();
            for (page, words) in [(&page_b, "a page by bob"), (&page_c, "a page by carol")] {
                w.until(&format!("{who} reads {page}"), LIMIT, || {
                    reads(&**spaces, &space, page, words)
                })
                .await?;
            }
        }
        w.converged(start.elapsed());

        // Bob trusts Carol's namespace for the notebook alone. Carol's diary, open to anyone,
        // reaches Alice, who holds Carol's namespace: Bob, who does not, reads nothing of it.
        let diary = under(&carol_ns, "/32=data/diary");
        let monday = n("/monday");
        carol.create(&diary, public(&[])).await?;
        carol.put(&diary, &monday, octets("diary by carol")).await?;
        w.retry_later(|| alice.open(&diary)).await?;
        w.until("alice reads carol's diary", LIMIT, || {
            reads(&*alice, &diary, &monday, "diary by carol")
        })
        .await?;
        w.retry_later(|| bob.open(&diary)).await?;
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*bob, &diary, &monday).await?,
            "bob reads carol's diary: the notebook's adoption of {carol_ns} judged another space"
        );
        // Nor does it reach Bob's forwarder: its node's validator refuses Carol's page.
        match w.forwarder_verdict(BOB, CAROL, &carols.name).await? {
            Ok(()) => {
                return Err(Failure::new(format!(
                    "bob's forwarder accepts {}: the notebook's adoption of {carol_ns} vouched \
                     for it outside the space",
                    carols.name
                )));
            }
            Err(why) => ensure!(
                why.contains(&carol_ns.to_string()),
                "bob's forwarder refused carol's page, but not as a person's name it does not \
                 hold: {why}"
            ),
        }

        // Alice drops Carol while Carol is away; Carol, not knowing, writes again.
        w.net().offline(CAROL);
        alice
            .change(
                &space,
                SpaceChange {
                    add_writers: Vec::new(),
                    add_readers: Vec::new(),
                    remove: vec![carol_ns.clone()],
                },
            )
            .await?;
        let late = n("/page-carol-late");
        let lates = w
            .space_put(
                CAROL,
                &space,
                &late,
                octets("a page carol wrote once dropped"),
            )
            .await?;
        w.net().online(CAROL);
        w.until(
            "bob refuses carol's page written after her removal",
            LIMIT,
            || async {
                Ok(matches!(
                    bob.entry(&space, &lates.name).await?,
                    EntryRead::Refused { .. }
                ))
            },
        )
        .await?;
        ensure!(
            !reads(&*bob, &space, &late, "a page carol wrote once dropped").await?,
            "bob reads a page carol wrote after alice's record dropped her"
        );
        // Her earlier page is taken with the bytes the removal cut's manifest lists (spec §8):
        // while that manifest packet is on its way the page waits, asked for again while it does
        // (§17.1), so bob reads it again once the packet arrives, within the case limit.
        w.until(
            "bob still reads carol's page from before her removal, which the cut keeps",
            LIMIT,
            || reads(&*bob, &space, &page_c, "a page by carol"),
        )
        .await?;
        Ok(())
    })
}
