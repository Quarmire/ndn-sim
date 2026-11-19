//! Introductions, i19 — a person let go takes the record that lets them go, and knows it.
//!
//! Alice's laptop offers her notebook to Bob; Bob joins, writes a page, and Alice's phone reads
//! it. Bob's phone goes offline. Alice's phone then signs a members record that leaves Bob out,
//! and once Alice's laptop holds it its host is told Bob was let go (`Introducer::departure`,
//! naming the record). Bob, offline, still lists himself among the folder's members. Back
//! online, his host — told by the link layer which record to fetch, as the case hands it the
//! name the laptop's host was told — has his device take it (`Device::take_departure`): fetched
//! by name and taken as any held record, so at once the folder's members at his device no longer
//! list him, and it takes no more writing into the folder (REPLY-17 item 1, ndf's `let_go`
//! cases: a person let go is told, and their device says so).

use std::time::Duration;

use ndn_data::Role;

use super::i1_join_by_code::{FOLDER, alice_keeps_a_notebook, joins, offer, reads};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::GrantEvent;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i19",
    title: "A person let go takes the record that lets them go, and says so",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A person's device that is told which members record let it go takes it \
             (Device::take_departure: fetched by its name, validated, merged as any record): its \
             folder's members then no longer list it and it takes no more writing there; a \
             record that is no members record of a folder it is a member of is refused; clean \
             or faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const BOB: Dev = Dev(1);
const PHONE: Dev = Dev(2);

/// Not among strangers, as i16: the nodes hold each other's trust contexts.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("alice", "phone");
    p
}

/// Whether the folder's members at `d`'s device list Bob's namespace as a writer or a reader.
async fn lists_bob(w: &World, d: Dev, folder: &Name) -> Result<bool, Failure> {
    let bob = n("/bob");
    let share = w.at(d).members(folder).await?;
    Ok(share.writers.contains(&bob) || share.readers.contains(&person("/bob")))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        alice_keeps_a_notebook(w).await?;
        let bobs_key = w.link_key(BOB).await?;
        let code = w.offer(LAPTOP, &folder, offer(w, Role::Writer, 3)).await?;
        joins(w, BOB, &code.link).await?;
        let bob = w.at(BOB);
        let page = n(&format!("{FOLDER}/page-bob"));
        w.until("bob writes a page into the folder", LIMIT, || async {
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
        ensure!(
            lists_bob(w, BOB, &folder).await?,
            "the folder's members at bob's device do not list him before he is let go"
        );

        // Bob's phone is away while Alice's phone lets him go.
        w.net().offline(BOB);
        phone
            .share_folder(
                &folder,
                members(Rule::Log, &["/alice"], &[person("/alice")]).into(),
            )
            .await?;
        w.until("alice's laptop is told bob was let go", LIMIT, || async {
            Ok(w.link_grants(LAPTOP).await?.told.iter().any(|e| {
                matches!(e, GrantEvent::Revoked { key, folder: f }
                    if *key == bobs_key && *f == folder)
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
        ensure!(
            left.key == bobs_key && left.folder == folder && told.departures == [left.clone()],
            "the departure {left:?} (listed: {:?}) does not name bob's key and the notebook",
            told.departures
        );
        ensure!(
            ndn_data::departure_carries(&left.record, &left.record),
            "the departure's record {} is no log entry of a collection",
            left.record
        );
        ensure!(
            lists_bob(w, BOB, &folder).await?,
            "bob's device, away, already lists him no more: it cannot have heard of the record"
        );

        // Back online, bob's host is told which record to take, and his device takes it.
        w.net().online(BOB);
        w.until(
            "bob's device takes the record that lets him go",
            LIMIT,
            || async {
                match w.take_departure(BOB, &folder, &left.record).await? {
                    Ok(()) => Ok(true),
                    Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
                    Err(e) => Err(e.into()),
                }
            },
        )
        .await?;
        // At once: the record is held, so the members it names are the ones bob's device lists.
        ensure!(
            !lists_bob(w, BOB, &folder).await?,
            "bob's device took the record that lets him go and still lists him among the \
             folder's members"
        );
        // His writing is refused: a put into a collection new under the folder is "not ready"
        // while his device walks the devices of Alice's namespace (asked again), and then it
        // says it is no member — never that it takes the write.
        let after = n(&format!("{FOLDER}/page-after"));
        w.until("bob's device refuses his writing", LIMIT, || async {
            match bob.put(&after, text("a page after the cut"), note(1)).await {
                Err(DataError::NotAllowed { .. } | DataError::Sealed { .. }) => Ok(true),
                Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
                Ok(_) => Err(Failure::new(
                    "bob's device took the record that lets him go and still takes his writing",
                )),
                Err(e) => Err(e.into()),
            }
        })
        .await?;

        // A name that is no members record of the folder is no departure.
        let other =
            ndn_data::wire::log_name(&n("/alice/laptop"), Some(&n("/alice/32=data/diary")), 1);
        let not_a_record = w.take_departure(BOB, &folder, &other).await?;
        ensure!(
            matches!(not_a_record, Err(DataError::BadRequest { .. })),
            "a hint naming another folder's entry was answered {not_a_record:?}, not refused"
        );
        Ok(())
    })
}
