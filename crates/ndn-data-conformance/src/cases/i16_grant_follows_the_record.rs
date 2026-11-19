//! Introductions, i16 — a held members record that leaves the person out ends the grant, whoever
//! of the inviter's person signed it, and a restart keeps the rest.
//!
//! Alice's laptop offers her notebook to Bob and to Carol, both as writers; both join, write a
//! page, and Alice's host holds a grant for each. Alice's phone — another device of hers, which
//! made no offer — reads both pages and signs a members record that leaves Bob out. Once the
//! laptop holds it, its host is told Bob was let go (`Introducer::departure`) and that his grant of
//! the folder has ended (`Introducer::revoke_grant`, with his key and the folder), once, and
//! `Device::grants` lists Carol's alone. The laptop stops and starts again on
//! what it stored: its host is told nothing more, and the grants its layer lists are the same
//! set, less the ended: Carol's, with the end it had.

use std::time::Duration;

use ndn_data::Role;

use super::i1_join_by_code::{FOLDER, alice_keeps_a_notebook, joins, offer, reads};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::GrantEvent;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i16",
    title: "A held record that leaves the person out ends the grant, and a restart keeps the rest",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A members record held that leaves a granted person out — signed by another device of \
             the inviter's person too — ends the grant: the host is told once, Device::grants \
             drops it; after a restart the layer lists the same grants less the ended, and tells \
             the host nothing again; clean or faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const PHONE: Dev = Dev(3);

/// Not among strangers, as i12: the nodes hold each other's trust contexts, so Alice's phone
/// reads what Bob and Carol write.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "phone");
    p.device("alice", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        alice_keeps_a_notebook(w).await?;
        let bobs_key = w.link_key(BOB).await?;
        let for_bob = w.offer(LAPTOP, &folder, offer(w, Role::Writer, 3)).await?;
        joins(w, BOB, &for_bob.link).await?;
        let for_carol = w.offer(LAPTOP, &folder, offer(w, Role::Writer, 3)).await?;
        joins(w, CAROL, &for_carol.link).await?;

        // Both write a page; Alice's phone reads them, so it holds the records that admit them.
        let page = |who: &str| n(&format!("{FOLDER}/page-{who}"));
        for (d, who) in [(BOB, "bob"), (CAROL, "carol")] {
            let layer = w.at(d);
            let at = page(who);
            w.until("a joiner writes a page into the folder", LIMIT, || async {
                match layer
                    .put(&at, text(&format!("a page by {who}")), note(1))
                    .await
                {
                    Ok(_) => Ok(true),
                    Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
                    Err(e) => Err(e.into()),
                }
            })
            .await?;
        }
        let phone = w.at(PHONE);
        for who in ["bob", "carol"] {
            let at = page(who);
            let expected = format!("a page by {who}");
            w.until("alice's phone reads the page", LIMIT, || {
                reads(&*phone, &at, &expected)
            })
            .await?;
        }
        let granted = w.link_grants(LAPTOP).await?;
        let [GrantEvent::Granted(bobs), GrantEvent::Granted(carols)] = granted.told.as_slice()
        else {
            return Err(Failure::new(format!(
                "alice's host was told {:?} after bob and carol joined; it must be told of their \
                 two grants",
                granted.told
            )));
        };
        ensure!(
            bobs.key == bobs_key && granted.now.len() == 2,
            "the grants before the removal are {:?}, listing {:?}",
            granted.told,
            granted.now
        );

        // Alice's phone removes Bob. The laptop signs nothing for it: it holds the phone's record.
        phone
            .share_folder(
                &folder,
                members(
                    Rule::Log,
                    &["/alice", "/carol"],
                    &[person("/alice"), person("/carol")],
                )
                .into(),
            )
            .await?;
        w.until("alice's laptop ends bob's grant", LIMIT, || async {
            Ok(w.link_grants(LAPTOP)
                .await?
                .told
                .iter()
                .any(|e| matches!(e, GrantEvent::Revoked { key, .. } if *key == bobs_key)))
        })
        .await?;
        // Whatever settles after it ends nothing twice, and leaves Carol's grant be. The host
        // is told, as the grant ends, that a record let Bob go (the departure), then of the end
        // of his grant of the folder.
        w.sleep(SETTLE).await;
        let ended = w.link_grants(LAPTOP).await?;
        let [
            first,
            second,
            GrantEvent::Departed(left),
            GrantEvent::Revoked {
                key: revoked,
                folder: revoked_in,
            },
        ] = ended.told.as_slice()
        else {
            return Err(Failure::new(format!(
                "alice's host was told {:?}; it must be told of bob's grant, carol's, and once \
                 that a record let bob go and that bob's grant of the folder has ended",
                ended.told
            )));
        };
        ensure!(
            *first == GrantEvent::Granted(bobs.clone())
                && *second == GrantEvent::Granted(carols.clone())
                && left.key == bobs_key
                && left.folder == folder
                && left.namespaces == [n("/bob")]
                && *revoked == bobs_key
                && *revoked_in == folder,
            "alice's host was told {:?}; the departure and the end must name bob's key, /bob and \
             the notebook",
            ended.told
        );
        ensure!(
            ended.now == [carols.clone()],
            "after the record that leaves bob out Device::grants lists {:?}, not carol's grant \
             alone",
            ended.now
        );
        ensure!(
            ended.departures == [left.clone()],
            "after the record that leaves bob out Device::departures lists {:?}, not the \
             departure the host was told of",
            ended.departures
        );

        // A restart: the same grants less the ended, and the host told nothing more.
        w.stop(LAPTOP).await?;
        w.restart(LAPTOP).await?;
        let restarted = w.link_grants(LAPTOP).await?;
        ensure!(
            restarted == ended,
            "after alice's laptop restarted its host was told {:?} and its layer lists {:?}; \
             expected {:?} and {:?}: the same grants less the ended, nothing told again",
            restarted.told,
            restarted.now,
            ended.told,
            ended.now
        );
        Ok(())
    })
}
