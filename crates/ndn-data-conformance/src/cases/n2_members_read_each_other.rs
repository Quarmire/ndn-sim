//! Names by key, n2 — Alice invites Bob and Carol to one folder; each writes; all three see
//! everything.
//!
//! Alice, Bob and Carol are each named by their genesis root key alone (`/user/<0xA1: …>`) and
//! are strangers. Alice offers her notebook folder to Bob and, by a second code, to Carol, each
//! as a writer. Each join adopts Alice's namespace at the joiner and the joiner's at Alice: so
//! Bob and Carol still hold nothing of each other's namespace. Bob writes a page and Carol
//! writes a page; Alice, Bob and Carol each read both. Bob's device reads Carol's page because
//! Carol is a writer in a members record of the folder that Alice's device signed, which Bob
//! holds: it adopts Carol's namespace by name (version 1 fetched and checked as the genesis the
//! name hashes, the newest reached from it) for judging that folder's data alone, and Carol's
//! device adopts Bob's the same way (spec §6.3).
//!
//! The guards:
//! - that adoption judges nothing else at Bob: Carol's own diary folder, which she opens to
//!   anyone and which Alice (who holds Carol's namespace) reads, stays unreadable at Bob, and
//!   Bob's forwarder (its node's validator) still refuses Carol's page as a person's name it
//!   does not hold;
//! - once Alice's next record drops Carol, Bob refuses a page Carol writes later in the folder
//!   (outside the removal cut), while her earlier page, which the cut keeps, still reads.
//!
//! Mirrors ndf's G-series with three members (REPLY-to-ndn-workspace-13 §4).

use std::time::Duration;

use ndn_data::Role;
use ndn_data::wire::{device_of, log_name};

use super::i1_join_by_code::{joins, offer, reads, shut_out};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "n2",
    title: "Alice invites Bob and Carol to one folder; each writes; all three see everything",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
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

/// `ns` followed by the components of `rest`.
fn under(ns: &Name, rest: &str) -> Name {
    Name::from_components(
        ns.components()
            .iter()
            .chain(n(rest).components().iter())
            .cloned(),
    )
}

/// `d` writes `text` as a note into `page`, once its device can (it may first wait for the
/// folder's record and epoch key): the version written.
async fn writes(w: &World, d: Dev, page: &Name, words: &str) -> Result<VersionId, Failure> {
    let layer = w.at(d);
    let written = std::sync::Mutex::new(None);
    w.until(
        &format!("{} writes {page}", w.net().spec(d).name()),
        LIMIT,
        || async {
            match layer.put(page, text(words), note(1)).await {
                Ok(id) => {
                    *written.lock().expect("the case's lock") = Some(id);
                    Ok(true)
                }
                Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
                Err(e) => Err(e.into()),
            }
        },
    )
    .await?;
    let id = written.lock().expect("the case's lock").take();
    id.ok_or_else(|| Failure::new(format!("{page} was not written")))
}

/// The log entry name of version `id` of collection `c`.
fn entry_of(c: &Name, id: &VersionId) -> Result<Name, Failure> {
    let device = device_of(id.writer.key())
        .ok_or_else(|| Failure::new(format!("{:?} names no device's key", id.writer)))?;
    Ok(log_name(&device, Some(c), id.seq.0))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let alice_ns = w.net().spec(ALICE).person.clone();
        let bob_ns = w.net().spec(BOB).person.clone();
        let carol_ns = w.net().spec(CAROL).person.clone();
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
        let start = tokio::time::Instant::now();
        for (d, who) in [(BOB, "bob"), (CAROL, "carol")] {
            let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
            let joined = joins(w, d, &code.link).await?;
            ensure!(
                joined.folder == folder
                    && joined.role == Role::Writer
                    && joined.inviter == alice_ns,
                "{who}'s join says {joined:?}, not alice's notebook as a writer"
            );
        }

        // Each writes; all three read everything.
        let page_b = under(&folder, "/page-bob");
        let page_c = under(&folder, "/page-carol");
        writes(w, BOB, &page_b, "a page by bob").await?;
        let carols = writes(w, CAROL, &page_c, "a page by carol").await?;
        for (d, layer) in [(ALICE, &alice), (BOB, &bob), (CAROL, &carol)] {
            let who = w.net().spec(d).name();
            for (page, words) in [(&page_b, "a page by bob"), (&page_c, "a page by carol")] {
                w.until(&format!("{who} reads {page}"), LIMIT, || {
                    reads(&**layer, page, words)
                })
                .await?;
            }
        }
        w.converged(start.elapsed());

        // Bob trusts Carol's namespace for the notebook alone. Carol's diary, open to anyone,
        // reaches Alice, who holds Carol's namespace: Bob, who does not, reads nothing of it.
        let diary = under(&carol_ns, "/32=data/diary");
        let note_c = under(&diary, "/monday");
        carol
            .share_folder(
                &diary,
                Share {
                    rule: Rule::Log,
                    writers: vec![carol_ns.clone()],
                    readers: Vec::new(),
                }
                .into(),
            )
            .await?;
        carol.put(&note_c, text("diary by carol"), note(1)).await?;
        w.until("alice reads carol's diary", LIMIT, || {
            reads(&*alice, &note_c, "diary by carol")
        })
        .await?;
        ensure!(
            shut_out(&*bob, &note_c).await?,
            "bob reads carol's diary: the notebook's adoption of {carol_ns} judged another folder"
        );
        // Nor does it reach Bob's forwarder: its node's validator refuses Carol's page.
        let page_c_entry = entry_of(&page_c, &carols)?;
        match w.forwarder_verdict(BOB, CAROL, &page_c_entry).await? {
            Ok(()) => {
                return Err(Failure::new(format!(
                    "bob's forwarder accepts {page_c_entry}: the notebook's adoption of \
                     {carol_ns} vouched for it outside the folder"
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
            .share_folder(
                &folder,
                Share {
                    rule: Rule::Log,
                    writers: vec![alice_ns.clone(), bob_ns.clone()],
                    readers: vec![
                        Audience::Person(alice_ns.clone()),
                        Audience::Person(bob_ns.clone()),
                    ],
                }
                .into(),
            )
            .await?;
        let late = under(&folder, "/page-carol-late");
        let lates = writes(w, CAROL, &late, "a page carol wrote once dropped").await?;
        let late_entry = entry_of(&late, &lates)?;
        w.net().online(CAROL);
        w.until(
            "bob refuses carol's page written after her removal",
            LIMIT,
            || async {
                Ok(matches!(
                    bob.get(&late_entry).await,
                    Err(DataError::Refused { .. })
                ))
            },
        )
        .await?;
        ensure!(
            !reads(&*bob, &late, "a page carol wrote once dropped").await?,
            "bob reads a page carol wrote after alice's record dropped her"
        );
        ensure!(
            reads(&*bob, &page_c, "a page by carol").await?,
            "bob no longer reads carol's page from before her removal, which the cut keeps"
        );
        Ok(())
    })
}
