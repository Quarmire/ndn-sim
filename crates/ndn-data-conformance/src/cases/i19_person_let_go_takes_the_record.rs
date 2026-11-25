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

use ndn_heap::Name;
use ndn_heap::wire::{log_name, parse_log_name};

use super::i1_join_by_code::{FOLDER, alice_keeps_a_notebook, joins, offer, reads, writes};
use super::kit::{LIMIT, n, octets};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{GrantEvent, InviteRole};
use crate::spaces::SpaceChange;
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

/// Whether the space's members at `d`'s device list Bob's namespace as a writer or a reader.
async fn lists_bob(w: &World, d: Dev, space: &Name) -> Result<bool, Failure> {
    let bob = n("/bob");
    let members = w.spaces(d).members(space).await?;
    Ok(members.writers.contains(&bob) || members.readers.contains(&bob))
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
        let page = n("/page-bob");
        writes(w, BOB, &space, &page, "a page by bob").await?;
        let phone = w.spaces(PHONE);
        w.until("alice's phone reads bob's page", LIMIT, || {
            reads(&*phone, &space, &page, "a page by bob")
        })
        .await?;
        ensure!(
            lists_bob(w, BOB, &space).await?,
            "the folder's members at bob's device do not list him before he is let go"
        );

        // Bob's phone is away while Alice's phone lets him go.
        w.net().offline(BOB);
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
        ensure!(
            left.key == bobs_key && left.space == space && told.departures == [left.clone()],
            "the departure {left:?} (listed: {:?}) does not name bob's key and the notebook",
            told.departures
        );
        ensure!(
            parse_log_name(&left.record).is_some(),
            "the departure's record {} is no log entry",
            left.record
        );
        ensure!(
            lists_bob(w, BOB, &space).await?,
            "bob's device, away, already lists him no more: it cannot have heard of the record"
        );

        // Back online, bob's host is told which record to take, and his device takes it.
        w.net().online(BOB);
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
        // At once: the record is held, so the members it names are the ones bob's device lists.
        ensure!(
            !lists_bob(w, BOB, &space).await?,
            "bob's device took the record that lets him go and still lists him among the \
             folder's members"
        );
        // His writing is refused: a put into a collection new under the folder is "not ready"
        // while his device walks the devices of Alice's namespace (asked again), and then it
        // says it is no member — never that it takes the write.
        let after = n("/page-after");
        w.until("bob's device refuses his writing", LIMIT, || async {
            match bob
                .put(&space, &after, octets("a page after the cut"))
                .await
            {
                Err(e) if e.kind_is("NotAllowed") || e.kind_is("Sealed") => Ok(true),
                Err(e) if e.retry_later() => Ok(false),
                Ok(_) => Err(Failure::new(
                    "bob's device took the record that lets him go and still takes his writing",
                )),
                Err(e) => Err(e),
            }
        })
        .await?;

        // A name that is no members record of the folder is no departure.
        let other = log_name(&n("/alice/laptop"), &n("/alice/32=data/diary"), 1);
        let not_a_record = w.take_departure(BOB, LAPTOP, &space, &other).await?;
        ensure!(
            matches!(&not_a_record, Err(e) if e.kind_is("BadRequest")),
            "a hint naming another folder's entry was answered {not_a_record:?}, not refused"
        );
        // A notice from a device that is not under the folder's namespace (Bob's own phone
        // naming Alice's folder) is refused, whatever it names.
        let stranger = w.take_departure(BOB, BOB, &space, &left.record).await?;
        ensure!(
            matches!(&stranger, Err(e) if e.kind_is("BadRequest") && e.why.contains("lies under no namespace")),
            "a departure told by a device outside the folder's namespace was answered \
             {stranger:?}, not refused saying so"
        );
        Ok(())
    })
}
