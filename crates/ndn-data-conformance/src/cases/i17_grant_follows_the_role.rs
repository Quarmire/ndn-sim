//! Introductions, i17 — a held members record that changes a granted person's role changes the
//! grant, whoever of the inviter's person signed it, and a restart keeps it.
//!
//! Alice's laptop offers her notebook to Carol as a writer; she joins, writes a page, and Alice's
//! host holds her grant as a writer. Alice's phone — another device of hers, which made no
//! offer — reads the page and signs a members record that demotes Carol to a reader. Once the
//! laptop holds it, `Device::grants` lists Carol's grant as a reader's, and its host is told the
//! grant again, with the reader's role and nothing else changed — never that it has ended. The
//! laptop stops and starts again on what it stored: its host is told nothing more, and the
//! grant its layer lists is the reader's.

use std::time::Duration;

use ndn_data::Role;

use super::i1_join_by_code::{FOLDER, alice_keeps_a_notebook, joins, offer, reads};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::GrantEvent;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i17",
    title: "A held record that demotes the person changes the grant's role, and a restart keeps it",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A members record held that changes a granted person's role — signed by another \
             device of the inviter's person too — changes the grant: Device::grants lists it in \
             the role the record in force gives, and the host is told the grant again with that \
             role (never revoked); after a restart the layer lists the same grant and tells the \
             host nothing again; clean or faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const CAROL: Dev = Dev(1);
const PHONE: Dev = Dev(2);

/// Not among strangers, as i16: the nodes hold each other's trust contexts, so Alice's phone
/// reads what Carol writes.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("carol", "phone");
    p.device("alice", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        alice_keeps_a_notebook(w).await?;
        let carols_key = w.link_key(CAROL).await?;
        let code = w.offer(LAPTOP, &folder, offer(w, Role::Writer, 3)).await?;
        joins(w, CAROL, &code.link).await?;

        // Carol writes a page; Alice's phone reads it, so it holds the record that admits her.
        let at = n(&format!("{FOLDER}/page-carol"));
        let layer = w.at(CAROL);
        w.until("carol writes a page into the folder", LIMIT, || async {
            match layer.put(&at, text("a page by carol"), note(1)).await {
                Ok(_) => Ok(true),
                Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
                Err(e) => Err(e.into()),
            }
        })
        .await?;
        let phone = w.at(PHONE);
        w.until("alice's phone reads the page", LIMIT, || {
            reads(&*phone, &at, "a page by carol")
        })
        .await?;
        let before = w.link_grants(LAPTOP).await?;
        let [GrantEvent::Granted(writers)] = before.told.as_slice() else {
            return Err(Failure::new(format!(
                "alice's host was told {:?} after carol joined; it must be told of exactly one \
                 grant",
                before.told
            )));
        };
        ensure!(
            writers.key == carols_key && writers.role == Role::Writer,
            "the grant before the demotion is {writers:?}, not carol's key as a writer"
        );

        // Alice's phone demotes Carol to a reader. The laptop signs nothing for it.
        phone
            .share_folder(
                &folder,
                members(
                    Rule::Log,
                    &["/alice"],
                    &[person("/alice"), person("/carol")],
                )
                .into(),
            )
            .await?;
        let mut reader = writers.clone();
        reader.role = Role::Reader;
        w.until(
            "alice's laptop tells its host the new role",
            LIMIT,
            || async {
                Ok(w.link_grants(LAPTOP)
                    .await?
                    .told
                    .contains(&GrantEvent::Granted(reader.clone())))
            },
        )
        .await?;
        // Whatever settles after it tells nothing twice, and ends nothing.
        w.sleep(SETTLE).await;
        let demoted = w.link_grants(LAPTOP).await?;
        ensure!(
            demoted.told
                == [
                    GrantEvent::Granted(writers.clone()),
                    GrantEvent::Granted(reader.clone()),
                ],
            "alice's host was told {:?}; it must be told of carol's grant as a writer and then, \
             once, as a reader — never that it ended",
            demoted.told
        );
        ensure!(
            demoted.now == [reader.clone()],
            "after the record that demotes carol Device::grants lists {:?}, not her grant as a \
             reader",
            demoted.now
        );

        // A restart: the same grant, in the role the record gives, and the host told nothing more.
        w.stop(LAPTOP).await?;
        w.restart(LAPTOP).await?;
        let restarted = w.link_grants(LAPTOP).await?;
        ensure!(
            restarted == demoted,
            "after alice's laptop restarted its host was told {:?} and its layer lists {:?}; \
             expected {:?} and {:?}: the reader's grant, nothing told again",
            restarted.told,
            restarted.now,
            demoted.told,
            demoted.now
        );
        Ok(())
    })
}
