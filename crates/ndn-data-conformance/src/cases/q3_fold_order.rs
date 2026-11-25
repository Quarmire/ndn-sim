//! Chain 3 — the membership fold depends on the entries held, not on the order they arrived in.
//!
//! Alice owns a sealed roster read by Bob and Carol and has three devices, a laptop, a phone and a
//! tablet. All three go offline and each signs one change of the members on its own: the laptop
//! makes Bob a writer, the phone adds Dave as a reader, the tablet removes Carol (a removal
//! forces a new epoch the tablet signs, and the others' additions leave it short of readers).
//! They come back in two steps, the laptop and the phone first, the tablet last, so the laptop
//! applies its own change then the phone's then the tablet's, the phone its own then the laptop's
//! then the tablet's, and the tablet its own change before the other two: three devices, three
//! arrival orders of the same three entries.
//!
//! The guard: a device's members, and the epoch its writers seal in, are a function of the owner's
//! entries it holds and of nothing else: the three end holding the same members, one epoch in
//! force that is complete (every reader is to be given its key, nobody else), and they stay there;
//! each writes into the roster and every device opens what the others wrote.

use std::time::Duration;

use super::chain_kit::{one_complete_epoch, reads};
use super::kit::{LIMIT, SETTLE, members_now, n, octets, people, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{SpaceChange, SpaceMembers, Spaces};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "q3",
    title: "Three devices applying the same members changes in different orders agree",
    slice: 9,
    needs: &[Feature::Chain, Feature::Seal],
    model: &[],
    guards: "The members and the epoch in force are a function of the owner's entries a device \
             holds: three owner devices that apply three concurrent changes in three different \
             arrival orders end with the same members and one complete epoch, which holds, and \
             what each writes the others open.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const TABLET: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("alice", "tablet");
    p
}

/// Whether every device holds exactly `want` over `space`.
async fn hold(
    spaces: &[&dyn Spaces],
    space: &ndn_heap::Name,
    want: &SpaceMembers,
) -> Result<bool, Failure> {
    let mut all = true;
    for s in spaces {
        all &= members_now(*s, space).await?.as_ref() == Some(want);
    }
    Ok(all)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let roster = n("/alice/32=data/roster");
        let alice = n("/alice");
        let (laptop, phone, tablet) = (w.spaces(LAPTOP), w.spaces(PHONE), w.spaces(TABLET));
        let members = |writers: &[&str], readers: &[&str]| {
            SpaceMembers::new(&alice, people(writers), people(readers), false)
        };

        laptop
            .create(&roster, private(&[], &["/bob", "/carol"]))
            .await?;
        phone.open(&roster).await?;
        tablet.open(&roster).await?;
        let start = members(&[], &["/bob", "/carol"]);
        w.until(
            "the three devices hold the roster and one complete epoch",
            LIMIT,
            || async {
                Ok(hold(&[&*laptop, &*phone, &*tablet], &roster, &start).await?
                    && one_complete_epoch(&[&*laptop, &*phone, &*tablet], &roster).await?)
            },
        )
        .await?;

        // Each device, offline, signs its own change.
        for d in [LAPTOP, PHONE, TABLET] {
            w.net().offline(d);
        }
        laptop
            .change(
                &roster,
                SpaceChange {
                    add_writers: people(&["/bob"]),
                    ..SpaceChange::default()
                },
            )
            .await?;
        phone
            .change(
                &roster,
                SpaceChange {
                    add_readers: people(&["/dave"]),
                    ..SpaceChange::default()
                },
            )
            .await?;
        tablet
            .change(
                &roster,
                SpaceChange {
                    remove: people(&["/carol"]),
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.gesture();

        // The laptop and the phone meet; the tablet is still alone with its own change.
        w.net().online(LAPTOP);
        w.net().online(PHONE);
        let pair = members(&["/bob"], &["/bob", "/carol", "/dave"]);
        w.until(
            "the laptop and the phone hold the writer and the reader and still list Carol",
            LIMIT,
            || async { hold(&[&*laptop, &*phone], &roster, &pair).await },
        )
        .await?;
        let alone = members(&[], &["/bob"]);
        ensure!(
            hold(&[&*tablet], &roster, &alone).await?,
            "precondition: the tablet, offline, holds only its own change ({alone:?}), not {:?}",
            members_now(&*tablet, &roster).await?
        );

        // The tablet meets them: three orders of the same three entries.
        w.net().online(TABLET);
        let end = members(&["/bob"], &["/bob", "/dave"]);
        let all: [&dyn Spaces; 3] = [&*laptop, &*phone, &*tablet];
        w.converge(
            "the three devices hold the same members and one complete epoch",
            LIMIT,
            || async {
                Ok(hold(&all, &roster, &end).await? && one_complete_epoch(&all, &roster).await?)
            },
        )
        .await?;
        w.sleep(SETTLE).await;
        ensure!(
            hold(&all, &roster, &end).await? && one_complete_epoch(&all, &roster).await?,
            "the three devices do not stay with the same members and one complete epoch: {:?}, \
             {:?}, {:?}",
            members_now(&*laptop, &roster).await?,
            members_now(&*phone, &roster).await?,
            members_now(&*tablet, &roster).await?
        );

        // The epoch they share is the one they seal in: each writes, every device opens all.
        let notes = [
            (LAPTOP, n("/laptop"), "from the laptop"),
            (PHONE, n("/phone"), "from the phone"),
            (TABLET, n("/tablet"), "from the tablet"),
        ];
        for (d, path, text) in &notes {
            w.space_put(*d, &roster, path, octets(text)).await?;
        }
        w.until("every device opens what the three wrote", LIMIT, || async {
            for s in &all {
                for (_, path, text) in &notes {
                    if !reads(*s, &roster, path, text).await? {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })
        .await?;
        Ok(())
    })
}
