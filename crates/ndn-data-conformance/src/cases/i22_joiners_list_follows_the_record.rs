//! Introductions, i22 — the joiner's list of joined folders follows the members record.
//!
//! Alice (a person named by her key) invites Bob and, by a second code, Carol, both as writers of
//! her notebook. Bob's device lists the folder (`Device::joined_folders`): the inviter's key, her
//! namespace as the owner, his own role, and as `writers` the namespaces of the *other* writers
//! the record in force lists, Carol's alone: never his own, never Alice's (the inviter's own
//! names are routed by the link already). Carol writes a page and Bob reads it through Alice
//! (as i20: Bob's and Carol's devices cannot reach each other's logs). The generation of
//! `Device::joined_changes` moves with each change of the list — Bob's join, Carol's — and never
//! repeats. Alice's phone, a device of hers that made no offer, signs a record that leaves Carol
//! out of the writers: Bob's list drops her and the generation moves. A record that adds Dave, a
//! writer of a namespace Bob holds nothing of, adds it; the same record lists a writer under
//! Bob's own namespace, which never appears. Every observation is by signed data (Bob reads
//! the records through Alice's copy) and the Device's own answers, waited for in virtual time
//! (round 9, G11: the Device half of the joiner's routes; the ndn-link half is
//! `a_member_reads_another_member_let_in_by_another_invitation`).

use std::time::Duration;

use ndn_heap::Name;

use super::i1_join_by_code::{joins, offer, reads, writes};
use super::kit::{LIMIT, RELAYED, members_now, n, octets, private};
use super::n1_named_by_key::under;
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{InviteJoinedSpace, InviteRole, JoinedList};
use crate::spaces::SpaceChange;
use crate::world::{Dev, Plan, World, self_certifying_person};

pub(super) const CASE: Case = Case {
    id: "i22",
    title: "The joiner's list of joined folders follows the members record",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
        Feature::SelfCertifying,
    ],
    model: &[],
    guards: "A device that joined a folder lists it with the inviter's key, her namespace, its \
             own role and the other writers' namespaces from the record in force — never its own \
             namespace or one under it, never the inviter's — and the list's generation moves \
             at a join, when a record removes a writer and when one adds a writer, and never \
             repeats; clean or faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const PHONE: Dev = Dev(3);

/// Alice's, Bob's, Carol's and Dave's genesis root keys (Ed25519 secrets). Dave has no device.
const ALICE_KEY: [u8; 32] = [0xa4; 32];
const BOB_KEY: [u8; 32] = [0xb4; 32];
const CAROL_KEY: [u8; 32] = [0xc4; 32];
const DAVE_KEY: [u8; 32] = [0xd4; 32];

/// Alice's laptop and phone, Bob's phone and Carol's tablet, each person named by their key:
/// strangers.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.self_certifying(ALICE_KEY, "laptop");
    p.self_certifying(BOB_KEY, "phone");
    p.self_certifying(CAROL_KEY, "tablet");
    p.self_certifying(ALICE_KEY, "phone");
    p.strangers();
    p
}

/// What Bob's device must list for the folder, who and what it is the joiner of.
struct Expected {
    inviter: [u8; 32],
    owner: Name,
    space: Name,
}

impl Expected {
    /// The one folder Bob lists, as a writer, with `writers`: `list` must be exactly that, and
    /// its generation not one it had before.
    fn check(
        &self,
        list: &JoinedList,
        writers: &[Name],
        seen: &mut Vec<u64>,
        when: &str,
    ) -> Result<(), Failure> {
        let mut sorted = writers.to_vec();
        sorted.sort();
        let wanted = InviteJoinedSpace {
            inviter: self.inviter,
            owner: self.owner.clone(),
            space: self.space.clone(),
            role: InviteRole::Writer,
            writers: sorted,
        };
        ensure!(
            list.spaces == [wanted.clone()],
            "{when}: bob's device lists {:?}; it must list the notebook once, with alice's key \
             as inviter, her namespace as owner, bob as a writer and as writers {:?} (never \
             bob's own namespace nor alice's)",
            list.spaces,
            wanted.writers
        );
        ensure!(
            !seen.contains(&list.generation),
            "{when}: the list changed and its generation is {}, which it already had (had {seen:?})",
            list.generation
        );
        seen.push(list.generation);
        Ok(())
    }
}

/// Wait until Bob's list names exactly `writers` for the folder, and return it.
async fn lists(w: &World, what: &str, writers: &[Name]) -> Result<JoinedList, Failure> {
    let mut sorted = writers.to_vec();
    sorted.sort();
    let waited = w
        .until(what, LIMIT, || async {
            let now = w.joined_folders(BOB).await?;
            Ok(now.spaces.len() == 1 && now.spaces[0].writers == sorted)
        })
        .await;
    let last = w.joined_folders(BOB).await?;
    waited.map_err(|e| Failure::new(format!("{e}; bob's device lists {:?}", last.spaces)))?;
    Ok(last)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let alice_ns = w.net().spec(ALICE).person.clone();
        let bob_ns = w.net().spec(BOB).person.clone();
        let carol_ns = w.net().spec(CAROL).person.clone();
        let dave_ns = self_certifying_person(&DAVE_KEY);
        let space = under(&alice_ns, "/32=data/notebook");
        let (alice, phone) = (w.spaces(ALICE), w.spaces(PHONE));
        alice.create(&space, private(&[], &[])).await?;
        alice
            .put(&space, &n("/cover"), octets("cover by alice"))
            .await?;
        let expected = Expected {
            inviter: w.link_key(ALICE).await?,
            owner: alice_ns.clone(),
            space: space.clone(),
        };

        // Before any join Bob's device lists no folder.
        let before = w.joined_folders(BOB).await?;
        ensure!(
            before.spaces.is_empty(),
            "bob's device lists {:?} before it joined anything",
            before.spaces
        );
        let mut seen = vec![before.generation];

        // Bob joins: the folder, with no other writer yet.
        let for_bob = w
            .offer(ALICE, &space, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, BOB, &for_bob.link).await?;
        let joined = w.joined_folders(BOB).await?;
        expected.check(&joined, &[], &mut seen, "after bob joined")?;

        // Carol joins by a second code of her own: the record that lists her reaches Bob, and
        // his list names her namespace alone.
        let for_carol = w
            .offer(ALICE, &space, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, CAROL, &for_carol.link).await?;
        let with_carol = lists(
            w,
            "bob's device lists carol's namespace as a writer of the notebook",
            std::slice::from_ref(&carol_ns),
        )
        .await?;
        expected.check(
            &with_carol,
            std::slice::from_ref(&carol_ns),
            &mut seen,
            "after carol joined",
        )?;

        // Neither reaches the other's logs and summaries: only Alice's copy joins them.
        let bobs_device = w.net().spec(BOB).name();
        let carols_device = w.net().spec(CAROL).name();
        let _cut = [
            w.net()
                .cut_off(BOB, &under(&carols_device, "/32=log"))
                .await,
            w.net()
                .cut_off(BOB, &under(&carols_device, "/32=summary"))
                .await,
            w.net()
                .cut_off(CAROL, &under(&bobs_device, "/32=log"))
                .await,
            w.net()
                .cut_off(CAROL, &under(&bobs_device, "/32=summary"))
                .await,
        ];
        let (by_bob, by_carol) = (n("/page-bob"), n("/page-carol"));
        writes(w, BOB, &space, &by_bob, "a page by bob").await?;
        writes(w, CAROL, &space, &by_carol, "a page by carol").await?;
        let bob = w.spaces(BOB);
        w.until("bob reads carol's page through alice", RELAYED, || {
            reads(&*bob, &space, &by_carol, "a page by carol")
        })
        .await?;
        // Alice's phone reads both pages: it holds the records that admit them.
        for (at, words) in [(&by_bob, "a page by bob"), (&by_carol, "a page by carol")] {
            w.until("alice's phone reads the page", LIMIT, || {
                reads(&*phone, &space, at, words)
            })
            .await?;
        }
        // Reading and writing changed nothing of the list.
        let steady = w.joined_folders(BOB).await?;
        ensure!(
            steady == with_carol,
            "bob's device lists {steady:?} after pages were written and read; the list and its \
             generation must stay as they were ({with_carol:?})"
        );

        // A record from Alice's phone, which made no offer, leaves Carol out of the writers.
        phone
            .change(
                &space,
                SpaceChange {
                    remove: vec![carol_ns.clone()],
                    ..SpaceChange::default()
                },
            )
            .await?;
        let without_carol = lists(
            w,
            "bob's device drops carol from the writers of the notebook",
            &[],
        )
        .await?;
        expected.check(&without_carol, &[], &mut seen, "after carol was left out")?;

        // A record that adds Dave, whose namespace Bob holds nothing of, adds it; the same
        // record lists a writer under Bob's own namespace, which never appears.
        let bobs_team = under(&bob_ns, "/team");
        phone
            .change(
                &space,
                SpaceChange {
                    add_writers: vec![bobs_team.clone(), dave_ns.clone()],
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.until(
            "bob's device takes the record that adds dave",
            LIMIT,
            || async {
                Ok(members_now(&*bob, &space)
                    .await?
                    .is_some_and(|m| m.writers.contains(&dave_ns)))
            },
        )
        .await?;
        let with_dave = lists(
            w,
            "bob's device lists dave's namespace as a writer of the notebook",
            std::slice::from_ref(&dave_ns),
        )
        .await?;
        expected.check(
            &with_dave,
            std::slice::from_ref(&dave_ns),
            &mut seen,
            "after dave was added",
        )?;
        let held = bob.members(&space).await?;
        ensure!(
            held.writers.contains(&bobs_team),
            "bob's device took the record that adds dave, and does not hold the writer {bobs_team} \
             it lists ({:?}); the case would not show that his own names are left out",
            held.writers
        );
        Ok(())
    })
}
