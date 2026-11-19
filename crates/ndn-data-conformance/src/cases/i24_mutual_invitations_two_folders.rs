//! Introductions, i24 — mutual invitations: two folders, each device the other's inviter and
//! joiner.
//!
//! Alice's laptop invites Bob to her notebook, and Bob's phone invites Alice's laptop to his
//! diary: each is the other's inviter of one folder and the other's joiner of the other, for the
//! one peer key. Each device then holds two entries for that key — an inviter's entry of the
//! folder it owns, a mirror entry of the folder it joined — and they replace one another no way:
//! each host was told of both, `Device::grants` lists both, and `Device::joined_folders` lists
//! the folder joined alone. A record from Alice's phone that leaves Bob out of the notebook ends
//! Bob's mirror entry of the notebook and Alice's inviter entry of it, and only those: the diary's
//! entries stand on both devices. Alice invites Bob again, so each device holds both once more.
//! The host's `end_grant_in` of one folder leaves the other folder's entry, whichever kind it is,
//! and `end_grant` of the key ends every entry of that device for the peer; neither tells the
//! host, nor makes a departure, nor touches the other device (round 9: mirror entries and
//! round 7's per-entry ends, spec data-layer §19.8).

use std::time::Duration;

use ndn_data::{Grant, Role};

use super::i1_join_by_code::{FOLDER, alice_keeps_a_notebook, joins, offer, reads};
use super::i23_joiner_holds_a_grant_for_the_inviter::{no_departure, same_set};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::GrantEvent;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i24",
    title: "Mutual invitations make an inviter's entry and a mirror entry that end one by one",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "Two persons who invite each other to a folder each hold, for the one peer key, an \
             inviter's entry of one folder and a mirror entry of the other, and neither \
             replaces the other; a record that leaves one out of one folder ends that folder's \
             entries on both devices and the other folder's stand; the host's end_grant_in of \
             one folder leaves the other and end_grant of the key ends them all; clean or \
             faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const BOB: Dev = Dev(1);
const PHONE: Dev = Dev(2);

/// Bob's folder.
const DIARY: &str = "/bob/32=data/diary";

/// Not among strangers, as i16: the nodes hold each other's trust contexts, so Alice's phone
/// reads what Bob writes.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("alice", "phone");
    p
}

/// A grant of `folder` to `key`, in the namespace `ns`, as a writer, with no date.
fn grant(key: [u8; 32], ns: &str, folder: &Name) -> Grant {
    Grant {
        key,
        namespaces: vec![n(ns)],
        folder: folder.clone(),
        role: Role::Writer,
        until: None,
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let (notebook, diary) = (n(FOLDER), n(DIARY));
        alice_keeps_a_notebook(w).await?;
        let bob = w.at(BOB);
        bob.share_folder(
            &diary,
            members(Rule::Log, &["/bob"], &[person("/bob")]).into(),
        )
        .await?;
        bob.put(&n(&format!("{DIARY}/cover")), text("cover by bob"), note(1))
            .await?;
        let (alices_key, bobs_key) = (w.link_key(LAPTOP).await?, w.link_key(BOB).await?);

        // Alice's inviter entry of the notebook, her mirror entry of the diary; Bob's mirror
        // entry of the notebook, his inviter entry of the diary: the grant of one key each.
        let alice_inviter = grant(bobs_key, "/bob", &notebook);
        let alice_mirror = grant(bobs_key, "/bob", &diary);
        let bob_mirror = grant(alices_key, "/alice", &notebook);
        let bob_inviter = grant(alices_key, "/alice", &diary);

        // Alice invites Bob to the notebook; Bob invites Alice to the diary.
        let for_bob = w
            .offer(LAPTOP, &notebook, offer(w, Role::Writer, 3))
            .await?;
        joins(w, BOB, &for_bob.link).await?;
        let for_alice = w.offer(BOB, &diary, offer(w, Role::Writer, 3)).await?;
        joins(w, LAPTOP, &for_alice.link).await?;
        both_entries(w, &alice_inviter, &alice_mirror, &bob_mirror, &bob_inviter).await?;

        // Bob writes into the notebook; Alice's phone reads it, so it holds the records that
        // admit him and may sign the one that lets him go.
        let page = notebook.clone().append("page");
        w.until("bob writes a page into the notebook", LIMIT, || async {
            match bob.put(&page, text("a page by bob"), note(1)).await {
                Ok(_) => Ok(true),
                Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
                Err(e) => Err(e.into()),
            }
        })
        .await?;
        let phone = w.at(PHONE);
        w.until("alice's phone reads bob's page", LIMIT, || {
            reads(&*phone, &page, "a page by bob")
        })
        .await?;

        // Alice's phone leaves Bob out of the notebook: Alice's laptop is told he was let go,
        // and his device takes the record that lets him go.
        phone
            .share_folder(
                &notebook,
                members(Rule::Log, &["/alice"], &[person("/alice")]).into(),
            )
            .await?;
        w.until("alice's laptop ends bob's grant", LIMIT, || async {
            Ok(w.link_grants(LAPTOP).await?.told.iter().any(|e| {
                matches!(e, GrantEvent::Revoked { key, folder }
                    if *key == bobs_key && *folder == notebook)
            }))
        })
        .await?;
        let laptop = w.link_grants(LAPTOP).await?;
        let Some(GrantEvent::Departed(left)) = laptop
            .told
            .iter()
            .find(|e| matches!(e, GrantEvent::Departed(_)))
        else {
            return Err(Failure::new(format!(
                "alice's host was told {:?}; a record that lets bob go must tell it of his \
                 departure, naming the record",
                laptop.told
            )));
        };
        w.until(
            "bob's device takes the record that lets him go",
            LIMIT,
            || async {
                match w
                    .take_departure(BOB, LAPTOP, &notebook, &left.record)
                    .await?
                {
                    Ok(()) => Ok(true),
                    Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
                    Err(e) => Err(e.into()),
                }
            },
        )
        .await?;
        w.until(
            "bob's host is told alice's grant of the notebook ended",
            LIMIT,
            || async {
                Ok(w.link_grants(BOB).await?.told.iter().any(|e| {
                    matches!(e, GrantEvent::Revoked { key, folder }
                        if *key == alices_key && *folder == notebook)
                }))
            },
        )
        .await?;
        w.sleep(SETTLE).await;

        // The notebook's two entries ended, once each; the diary's stand.
        let alice_ended = w.link_grants(LAPTOP).await?;
        ensure!(
            alice_ended.told
                == [
                    GrantEvent::Granted(alice_inviter.clone()),
                    GrantEvent::Granted(alice_mirror.clone()),
                    GrantEvent::Departed(left.clone()),
                    GrantEvent::Revoked {
                        key: bobs_key,
                        folder: notebook.clone(),
                    },
                ]
                && alice_ended.now == [alice_mirror.clone()],
            "after the record that leaves bob out of the notebook alice's host was told {:?} and \
             her layer lists {:?}; expected her two grants, the departure and the end of the \
             notebook's grant, and her mirror entry of bob's diary alone",
            alice_ended.told,
            alice_ended.now
        );
        let bob_ended = w.link_grants(BOB).await?;
        ensure!(
            bob_ended.told
                == [
                    GrantEvent::Granted(bob_mirror.clone()),
                    GrantEvent::Granted(bob_inviter.clone()),
                    GrantEvent::Revoked {
                        key: alices_key,
                        folder: notebook.clone(),
                    },
                ]
                && bob_ended.now == [bob_inviter.clone()],
            "after the record that leaves bob out of the notebook his host was told {:?} and his \
             layer lists {:?}; expected his two grants, then once that his mirror entry of \
             the notebook ended, and his inviter's entry of the diary alone",
            bob_ended.told,
            bob_ended.now
        );
        no_departure(&bob_ended, "after the record that leaves bob out")?;
        let alice_joined = w.joined_folders(LAPTOP).await?;
        ensure!(
            alice_joined.folders.len() == 1 && alice_joined.folders[0].folder == diary,
            "alice's device lists {:?} as joined after the record that leaves bob out of the \
             notebook; the diary stands",
            alice_joined.folders
        );
        let bob_joined = w.joined_folders(BOB).await?;
        ensure!(
            bob_joined.folders.is_empty(),
            "bob's device lists {:?} as joined after the record that leaves him out of the \
             notebook; he joined nothing else",
            bob_joined.folders
        );

        // Invited again, each device holds both once more.
        let again = w
            .offer(LAPTOP, &notebook, offer(w, Role::Writer, 3))
            .await?;
        joins(w, BOB, &again.link).await?;
        let alice_back = w.link_grants(LAPTOP).await?;
        let bob_back = w.link_grants(BOB).await?;
        ensure!(
            same_set(
                &alice_back.now,
                &[alice_inviter.clone(), alice_mirror.clone()]
            ) && same_set(&bob_back.now, &[bob_mirror.clone(), bob_inviter.clone()]),
            "after bob joined the notebook again alice's layer lists {:?} and bob's {:?}; each \
             must hold both entries of the other's key again",
            alice_back.now,
            bob_back.now
        );

        // The host's ends tell nothing and touch the other device alone not at all. Alice's
        // `end_grant_in` of the notebook ends her inviter's entry and leaves the mirror's.
        let alice = w.gate(LAPTOP)?;
        ensure!(
            alice.end_grant_in(&bobs_key, &notebook).await?,
            "alice's host ended bob's grants of the notebook and her layer says there was none"
        );
        let after_one = w.link_grants(LAPTOP).await?;
        ensure!(
            after_one.now == [alice_mirror.clone()] && after_one.told == alice_back.told,
            "after alice's host ended bob's grant of the notebook her layer lists {:?} and her \
             host was told {:?}; her mirror entry of the diary must stand and her host be told \
             nothing more ({:?})",
            after_one.now,
            after_one.told,
            alice_back.told
        );
        let joined = w.joined_folders(LAPTOP).await?;
        ensure!(
            joined.folders.len() == 1 && joined.folders[0].folder == diary,
            "alice's device lists {:?} as joined after her host ended the notebook's grant; the \
             diary stands",
            joined.folders
        );
        ensure!(
            !alice.end_grant_in(&bobs_key, &notebook).await?,
            "alice's host ended bob's grant of the notebook twice"
        );
        ensure!(
            w.link_grants(BOB).await? == bob_back,
            "alice's host ended her entry and bob's device changed"
        );
        // `end_grant` of the key ends what is left of it, mirror entries too.
        ensure!(
            alice.end_grant(&bobs_key).await?,
            "alice's host ended bob's key and her layer says there was no grant of it"
        );
        let alice_none = w.link_grants(LAPTOP).await?;
        ensure!(
            alice_none.now.is_empty() && alice_none.told == alice_back.told,
            "after alice's host ended bob's key her layer lists {:?} and her host was told {:?}; \
             no entry may stand and nothing is told",
            alice_none.now,
            alice_none.told
        );
        ensure!(
            w.joined_folders(LAPTOP).await?.folders.is_empty(),
            "alice's device lists a joined folder after her host ended bob's key"
        );
        ensure!(
            !alice.end_grant(&bobs_key).await?,
            "alice's host ended bob's key twice"
        );

        // Bob's host ends alice's key with both entries standing: the inviter's and the
        // mirror's end together.
        let bob_device = w.gate(BOB)?;
        ensure!(
            bob_device.end_grant(&alices_key).await?,
            "bob's host ended alice's key and his layer says there was no grant of it"
        );
        let bob_none = w.link_grants(BOB).await?;
        ensure!(
            bob_none.now.is_empty() && bob_none.told == bob_back.told,
            "after bob's host ended alice's key his layer lists {:?} and his host was told {:?}; \
             no entry of either kind may stand and nothing is told",
            bob_none.now,
            bob_none.told
        );
        ensure!(
            w.joined_folders(BOB).await?.folders.is_empty(),
            "bob's device lists a joined folder after his host ended alice's key"
        );
        no_departure(&bob_none, "after bob's host ended alice's key")?;
        Ok(())
    })
}

/// Each device holds both entries for the peer's key, told and listed, and lists the folder it
/// joined alone as joined.
async fn both_entries(
    w: &World,
    alice_inviter: &Grant,
    alice_mirror: &Grant,
    bob_mirror: &Grant,
    bob_inviter: &Grant,
) -> Result<(), Failure> {
    let alice = w.link_grants(LAPTOP).await?;
    ensure!(
        alice.told
            == [
                GrantEvent::Granted(alice_inviter.clone()),
                GrantEvent::Granted(alice_mirror.clone()),
            ]
            && same_set(&alice.now, &[alice_inviter.clone(), alice_mirror.clone()]),
        "alice's host was told {:?} and her layer lists {:?}; she is bob's inviter of the notebook \
         and his joiner of the diary: expected both grants of bob's key, the notebook's then the \
         diary's, neither replacing the other",
        alice.told,
        alice.now
    );
    let bob = w.link_grants(BOB).await?;
    ensure!(
        bob.told
            == [
                GrantEvent::Granted(bob_mirror.clone()),
                GrantEvent::Granted(bob_inviter.clone()),
            ]
            && same_set(&bob.now, &[bob_mirror.clone(), bob_inviter.clone()]),
        "bob's host was told {:?} and his layer lists {:?}; he is alice's joiner of the notebook \
         and her inviter of the diary: expected both grants of alice's key, the notebook's then \
         the diary's, neither replacing the other",
        bob.told,
        bob.now
    );
    no_departure(&bob, "after the invitations")?;
    for (d, who, folder, owner, inviter) in [
        (
            LAPTOP,
            "alice",
            &alice_mirror.folder,
            "/bob",
            alice_mirror.key,
        ),
        (BOB, "bob", &bob_mirror.folder, "/alice", bob_mirror.key),
    ] {
        let listed = w.joined_folders(d).await?;
        ensure!(
            listed.folders.len() == 1
                && listed.folders[0].folder == *folder
                && listed.folders[0].owner == n(owner)
                && listed.folders[0].inviter == inviter
                && listed.folders[0].role == Role::Writer
                && listed.folders[0].writers.is_empty(),
            "{who}'s device lists {:?} as joined; expected the one folder she or he joined, {folder}, \
             owned by {owner}, as a writer, with no other writer (the folder she or he invited \
             the other to is no joined folder)",
            listed.folders
        );
    }
    Ok(())
}
