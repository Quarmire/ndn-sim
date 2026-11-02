//! Case 5 — deleting a photo the repo promised to keep.
//!
//! The home repo holds a lease on Alice's photos for a year; the photo's own keep is a month.
//! Alice deletes one photo today. Nothing said whether a lease or a prune wins, or whether a lease
//! may outlive keep. The fix (M5): no lease outlives keep; an authorised prune ends the lease for
//! what it covers, and readers that know the prune report "pruned". Copies a cache already holds
//! are the stated forward-only limit, so the case asserts nothing about them.

use std::time::Duration;

use ndn_data::{DataError, Hold, Timestamp};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c5",
    title: "Deleting a photo the repo promised to keep",
    slice: 3,
    needs: &[Feature::Log, Feature::Custody, Feature::Prune],
    model: &["M5"],
    guards: "No custody lease outlives the data's keep; after the owner prunes a photo, readers \
             that know the prune report it pruned instead of serving it, while photos outside the \
             prune stay readable.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "repo");
    p.device("alice", "laptop");
    p
}

fn photo(keep: Keep) -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/photo"),
            revision: 1,
        },
        keep,
        batch: None,
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let photos = n("/alice/photos");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        phone
            .share(
                &photos,
                members(Rule::Log, &["/alice"], &[person("/alice")]),
            )
            .await?;
        let today = w.net().date(PHONE).0;
        let keep_until = Timestamp(today + 30 * DAY.as_millis() as u64);
        let beach = phone
            .put(
                &photos,
                content(&[("file", "beach.jpg")]),
                photo(Keep::Until(keep_until)),
            )
            .await?;
        let sunset = phone
            .put(
                &photos,
                content(&[("file", "sunset.jpg")]),
                photo(Keep::Until(keep_until)),
            )
            .await?;

        // The host asks the repo for a year; every lease must stop at the photos' keep.
        let custody = phone
            .hold(
                &photos,
                Hold {
                    copies: 1,
                    until: Timestamp(today + 365 * DAY.as_millis() as u64),
                },
            )
            .await?;
        ensure!(!custody.leases.is_empty(), "no holder leased the photos");
        for lease in &custody.leases {
            ensure!(
                lease.until <= keep_until,
                "{:?} leases until {:?}, beyond the photos' keep {:?}",
                lease.holder,
                lease.until,
                keep_until
            );
        }

        let mine = look(&*phone, &photos, &Frontier::new(), LOOK).await?;
        let beach_name = version(&mine, &beach)
            .ok_or_else(|| Failure::new("the phone's watch does not list beach.jpg"))?
            .name
            .clone();
        let sunset_name = version(&mine, &sunset)
            .ok_or_else(|| Failure::new("the phone's watch does not list sunset.jpg"))?
            .name
            .clone();
        w.until("the laptop reads beach.jpg", LIMIT, || async {
            Ok(laptop.get(&beach_name).await.is_ok())
        })
        .await?;

        // Alice throws the beach photo away.
        w.gesture();
        let upto: Frontier = [beach.clone()].into_iter().collect();
        phone.prune(&beach_name, &upto).await?;
        w.converge("the laptop reports beach.jpg pruned", LIMIT, || async {
            Ok(matches!(
                laptop.get(&beach_name).await,
                Err(DataError::Pruned { .. })
            ))
        })
        .await?;
        w.sleep(SETTLE).await;
        ensure!(
            matches!(laptop.get(&beach_name).await, Err(DataError::Pruned { .. })),
            "after reporting beach.jpg pruned, the laptop served it again"
        );
        ensure!(
            laptop.get(&sunset_name).await.is_ok(),
            "pruning beach.jpg made sunset.jpg unreadable"
        );
        Ok(())
    })
}
