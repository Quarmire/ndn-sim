//! Introductions, i18 — two offers to one person are two grants, and a record that lets the
//! person go of one folder ends that folder's grant alone.
//!
//! Alice's laptop offers her notebook to Bob, and, by a second code, her diary to the same Bob
//! (one phone, one key); both are joined, Bob writes a page into each and Alice's host holds
//! two grants of one key, a folder each. Alice's phone — another device of hers, which made no
//! offer — reads both pages and signs a members record that leaves Bob out of the notebook
//! alone. Once the laptop holds it, its host is told Bob was let go of the notebook
//! (`Introducer::departure`) and that his grant *of the notebook* has ended
//! (`Introducer::revoke_grant`, naming the key and the notebook): once, and never for the diary,
//! whose grant `Device::grants` still lists. A record that then lets him go of the diary tells
//! the host of that one, naming the diary. A restart keeps the marks and tells the host nothing
//! more (REPLY-17 item 3, G9: a second folder for the same person must not end the first).

use std::time::Duration;

use super::i1_join_by_code::{FOLDER, alice_keeps_a_notebook, joins, offer, reads, writes};
use super::kit::{LIMIT, SETTLE, n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{GrantEvent, InviteRole};
use crate::spaces::SpaceChange;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i18",
    title: "Two offers to one person are two grants, and a record ends one folder's alone",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A second offer of another folder to a person already granted adds a grant of the \
             same key for that folder; a members record held that leaves the person out of one \
             folder tells the host of that folder's end alone (the key and the folder), once, \
             after the departure it makes, and the person's grant of the other folder stands; \
             clean or faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const BOB: Dev = Dev(1);
const PHONE: Dev = Dev(2);

/// Alice's second folder.
const DIARY: &str = "/alice/32=data/diary";

/// Not among strangers, as i16: the nodes hold each other's trust contexts, so Alice's phone
/// reads what Bob writes.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("alice", "phone");
    p
}

/// A change that leaves Bob out of a space.
fn leaves_bob_out() -> SpaceChange {
    SpaceChange {
        remove: vec![n("/bob")],
        ..SpaceChange::default()
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let notebook = n(FOLDER);
        let diary = n(DIARY);
        alice_keeps_a_notebook(w).await?;
        w.spaces(LAPTOP).create(&diary, private(&[], &[])).await?;
        let bobs_key = w.link_key(BOB).await?;
        let for_notebook = w
            .offer(LAPTOP, &notebook, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, BOB, &for_notebook.link).await?;
        let for_diary = w
            .offer(LAPTOP, &diary, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, BOB, &for_diary.link).await?;

        // Bob writes a page into each; Alice's phone reads both, so it holds the records that
        // admit him to each.
        let phone = w.spaces(PHONE);
        let at = n("/page");
        for (space, who) in [(&notebook, "notebook"), (&diary, "diary")] {
            let words = format!("a page by bob in the {who}");
            writes(w, BOB, space, &at, &words).await?;
            w.until(
                &format!("alice's phone reads bob's page of the {who}"),
                LIMIT,
                || reads(&*phone, space, &at, &words),
            )
            .await?;
        }
        let granted = w.link_grants(LAPTOP).await?;
        let [
            GrantEvent::Granted(of_notebook),
            GrantEvent::Granted(of_diary),
        ] = granted.told.as_slice()
        else {
            return Err(Failure::new(format!(
                "alice's host was told {:?} after bob joined two folders; it must be told of two \
                 grants",
                granted.told
            )));
        };
        ensure!(
            of_notebook.key == bobs_key
                && of_diary.key == bobs_key
                && of_notebook.space == notebook
                && of_diary.space == diary
                && granted.now.len() == 2
                && granted.now.contains(of_notebook)
                && granted.now.contains(of_diary),
            "the two grants of one key are {:?}, listing {:?}: one for the notebook and one for \
             the diary, both bob's key",
            granted.told,
            granted.now
        );

        // Alice's phone lets Bob go of the notebook alone: the diary's record still lists him.
        phone.change(&notebook, leaves_bob_out()).await?;
        w.until(
            "alice's laptop ends bob's grant of the notebook",
            LIMIT,
            || async {
                Ok(w.link_grants(LAPTOP).await?.told.iter().any(|e| {
                    matches!(e, GrantEvent::Revoked { key, space }
                    if *key == bobs_key && *space == notebook)
                }))
            },
        )
        .await?;
        // Whatever settles after it ends nothing twice, and never the diary's grant.
        w.sleep(SETTLE).await;
        let first = w.link_grants(LAPTOP).await?;
        let [
            _,
            _,
            GrantEvent::Departed(left_notebook),
            GrantEvent::Revoked {
                key,
                space: revoked,
            },
        ] = first.told.as_slice()
        else {
            return Err(Failure::new(format!(
                "alice's host was told {:?}; after a record that lets bob go of the notebook it \
                 must be told of his two grants, then once that he was let go of the notebook \
                 and once that his grant of the notebook ended",
                first.told
            )));
        };
        ensure!(
            left_notebook.key == bobs_key
                && left_notebook.space == notebook
                && *key == bobs_key
                && *revoked == notebook,
            "the departure and the end after the notebook's record are {:?}; both must name \
             bob's key and the notebook",
            first.told
        );
        ensure!(
            first.now == [of_diary.clone()],
            "after the record that lets bob go of the notebook Device::grants lists {:?}, not \
             his grant of the diary alone",
            first.now
        );
        ensure!(
            first.departures == [left_notebook.clone()],
            "Device::departures lists {:?}, not the departure of the notebook",
            first.departures
        );

        // The diary next: one more end, naming the diary.
        phone.change(&diary, leaves_bob_out()).await?;
        w.until(
            "alice's laptop ends bob's grant of the diary",
            LIMIT,
            || async {
                Ok(w.link_grants(LAPTOP).await?.told.iter().any(|e| {
                    matches!(e, GrantEvent::Revoked { key, space }
                    if *key == bobs_key && *space == diary)
                }))
            },
        )
        .await?;
        w.sleep(SETTLE).await;
        let ended = w.link_grants(LAPTOP).await?;
        let [
            _,
            _,
            _,
            _,
            GrantEvent::Departed(left_diary),
            GrantEvent::Revoked {
                key: last_key,
                space: last_space,
            },
        ] = ended.told.as_slice()
        else {
            return Err(Failure::new(format!(
                "alice's host was told {:?}; after the diary's record it must be told once more \
                 that bob was let go and that his grant ended, naming the diary",
                ended.told
            )));
        };
        ensure!(
            left_diary.space == diary
                && left_diary.key == bobs_key
                && *last_key == bobs_key
                && *last_space == diary
                && ended.told[..4] == first.told[..],
            "the last two told, {:?}, must name bob's key and the diary after the four before \
             them: {:?}",
            &ended.told[4..],
            first.told
        );
        ensure!(
            ended.now.is_empty()
                && ended.departures.len() == 2
                && ended.departures.contains(left_notebook)
                && ended.departures.contains(left_diary),
            "after both records Device::grants lists {:?} and Device::departures {:?}; expected \
             none and the two departures",
            ended.now,
            ended.departures
        );

        // A restart: the same departures and nothing told again.
        w.stop(LAPTOP).await?;
        w.restart(LAPTOP).await?;
        let restarted = w.link_grants(LAPTOP).await?;
        ensure!(
            restarted == ended,
            "after alice's laptop restarted its host was told {:?} and its layer lists {:?}, \
             departures {:?}; expected {:?}, {:?}, {:?}",
            restarted.told,
            restarted.now,
            restarted.departures,
            ended.told,
            ended.now,
            ended.departures
        );
        Ok(())
    })
}
