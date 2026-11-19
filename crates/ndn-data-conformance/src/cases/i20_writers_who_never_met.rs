//! Introductions, i20 — writers invited by separate invitations read each other through the
//! inviter.
//!
//! Alice (named by a key, a stranger to the others) invites Bob and, by a second code, Carol to
//! one folder, each as a writer; each join adopts Alice's namespace and the joiner's at Alice, so
//! Bob and Carol hold nothing of each other's. Bob's and Carol's devices cannot reach each
//! other's logs and summaries directly (the case cuts them off from each other's device names
//! under `32=log` and `32=summary`, as a grant link that joins them to Alice alone leaves them):
//! the only road between them is Alice's copy, by the walk her members record lists the other
//! writer for. Carol writes a page and Bob reads it; Bob writes a page and Carol reads it
//! (REPLY-17 item 2, ndf's G11: three people in one note, each writes, all see everything). The
//! ndn-link half — Alice's grant link carrying the summary root of each other writer the record
//! lists — is `a_member_reads_another_member_let_in_by_another_invitation`.

use std::time::Duration;

use ndn_data::Role;

use super::i1_join_by_code::{joins, offer, reads};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i20",
    title: "Writers invited by separate invitations read each other through the inviter",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
        Feature::SelfCertifying,
    ],
    model: &[],
    guards: "Two writers of one folder invited by invitations of their own, who cannot reach \
             each other's logs and summaries, still read what the other writes there: the walk \
             to another writer's devices is made through the inviter's copy, from the members \
             record that lists them both; clean or faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

/// Alice's, Bob's and Carol's genesis root keys (Ed25519 secrets).
const ALICE_KEY: [u8; 32] = [0xa2; 32];
const BOB_KEY: [u8; 32] = [0xb2; 32];
const CAROL_KEY: [u8; 32] = [0xc2; 32];

/// Alice's laptop, Bob's phone and Carol's tablet, each person named by their key: strangers.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.self_certifying(ALICE_KEY, "laptop");
    p.self_certifying(BOB_KEY, "phone");
    p.self_certifying(CAROL_KEY, "tablet");
    p.strangers();
    p
}

/// `ns` followed by the components of `rest`.
pub(super) fn under(ns: &Name, rest: &str) -> Name {
    Name::from_components(
        ns.components()
            .iter()
            .chain(n(rest).components().iter())
            .cloned(),
    )
}

/// `d` writes `words` as a note into `page`, once its device can (it may first wait for the
/// folder's record and epoch key).
pub(super) async fn writes(w: &World, d: Dev, page: &Name, words: &str) -> Result<(), Failure> {
    let layer = w.at(d);
    w.until(
        &format!("{} writes {page}", w.net().spec(d).name()),
        LIMIT,
        || async {
            match layer.put(page, text(words), note(1)).await {
                Ok(_) => Ok(true),
                Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
                Err(e) => Err(e.into()),
            }
        },
    )
    .await
    .map(|_| ())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let alice_ns = w.net().spec(ALICE).person.clone();
        let folder = under(&alice_ns, "/32=data/notebook");
        let cover = under(&folder, "/cover");
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        alice
            .share_folder(
                &folder,
                Share {
                    rule: Rule::Log,
                    writers: vec![alice_ns.clone()],
                    readers: vec![Audience::Person(alice_ns.clone())],
                }
                .into(),
            )
            .await?;
        alice.put(&cover, text("cover by alice"), note(1)).await?;

        // Alice invites Bob, then Carol, each by a code of their own.
        let offer_for = |w: &World| offer(w, Role::Writer, 3);
        let for_bob = w.offer(ALICE, &folder, offer_for(w)).await?;
        joins(w, BOB, &for_bob.link).await?;
        let for_carol = w.offer(ALICE, &folder, offer_for(w)).await?;
        joins(w, CAROL, &for_carol.link).await?;

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

        let (by_bob, by_carol) = (under(&folder, "/page-bob"), under(&folder, "/page-carol"));
        writes(w, BOB, &by_bob, "a page by bob").await?;
        writes(w, CAROL, &by_carol, "a page by carol").await?;
        for (reader, name, at, expected) in [
            (&alice, "alice", &by_bob, "a page by bob"),
            (&alice, "alice", &by_carol, "a page by carol"),
            (&bob, "bob", &by_carol, "a page by carol"),
            (&carol, "carol", &by_bob, "a page by bob"),
        ] {
            w.until(&format!("{name} reads {at}"), LIMIT, || {
                reads(&**reader, at, expected)
            })
            .await?;
        }
        ensure!(
            reads(&*bob, &by_carol, "a page by carol").await?
                && reads(&*carol, &by_bob, "a page by bob").await?,
            "bob and carol, invited apart and cut off from each other, do not read each other's \
             pages through alice's copy"
        );
        Ok(())
    })
}
