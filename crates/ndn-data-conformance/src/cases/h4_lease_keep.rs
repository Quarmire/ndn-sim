//! Slice 3, h4 — no lease outlives keep.
//!
//! Alice keeps two photos for a month and asks her repo to hold her photos for a year. A lease is
//! a promise to keep what it holds, and keep is the writer's choice: custody never extends it
//! (model invariant 7). So every lease on month-kept photos ends with their keep, however long the
//! owner asked for, and once the month has passed no live lease holds them; a photo kept forever,
//! put afterwards, is leased for as long as asked and no longer.

use std::time::Duration;

use ndn_data::Timestamp;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "h4",
    title: "No lease outlives keep",
    slice: 3,
    needs: &[Feature::Log, Feature::Custody],
    model: &["M5"],
    guards: "A lease on versions kept until a date ends no later than that date, whatever the \
             owner asked for; after the date no live lease holds them, and a lease on data kept \
             forever ends no later than asked.",
    budget: Duration::from_secs(32 * 24 * 3600),
    plan: custody_plan,
    run,
};

const PHONE: Dev = Dev(0);

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let photos = n("/alice/32=data/photos");
        let phone = w.at(PHONE);
        phone
            .share(
                &photos,
                members(Rule::Log, &["/alice"], &[person("/alice")]),
            )
            .await?;
        let today = w.net().date(PHONE).0;
        let keep = Timestamp(today + 30 * DAY.as_millis() as u64);
        let month = [
            phone
                .put(
                    &photos,
                    content(&[("file", "beach.jpg")]),
                    photo(Keep::Until(keep)),
                )
                .await?,
            phone
                .put(
                    &photos,
                    content(&[("file", "sunset.jpg")]),
                    photo(Keep::Until(keep)),
                )
                .await?,
        ];

        // A year asked for; the month's keep is the most any lease may promise.
        w.gesture();
        let want = Hold {
            copies: 1,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
            holders: custody_holders(w),
        };
        let custody = phone.hold(&photos, want.clone()).await?;
        ensure!(!custody.leases.is_empty(), "no holder leased the photos");
        w.measure("copies: live leases", custody.leases.len() as u64, "leases");
        for lease in &custody.leases {
            ensure!(
                lease.until <= keep,
                "{:?} leases the month-kept photos until {:?}, beyond their keep {:?}",
                lease.holder,
                lease.until,
                keep
            );
        }

        // The month passes. A lease that holds the month-kept photos (and nothing kept longer)
        // still ends at their keep, so none is live.
        w.skip(31 * DAY).await;
        let after = phone.hold(&photos, want.clone()).await?;
        let now = w.net().date(PHONE);
        for lease in &after.leases {
            if month.iter().any(|id| lease.holds.contains(id)) {
                ensure!(
                    lease.until <= keep,
                    "after the photos' keep {:?} passed, {:?} leases them until {:?}",
                    keep,
                    lease.holder,
                    lease.until
                );
            }
            ensure!(
                lease.until > now,
                "hold listed {:?}'s lease ending {:?} as live at {:?}",
                lease.holder,
                lease.until,
                now
            );
        }
        w.measure(
            "live leases once the keep passed",
            after.leases.len() as u64,
            "leases",
        );

        // A photo kept forever is leased for as long as asked, and no longer.
        let forever = phone
            .put(
                &photos,
                content(&[("file", "harbour.jpg")]),
                photo(Keep::Forever),
            )
            .await?;
        let custody = phone.hold(&photos, want.clone()).await?;
        let holding: Vec<_> = custody
            .leases
            .iter()
            .filter(|l| l.holds.contains(&forever))
            .collect();
        ensure!(
            !holding.is_empty(),
            "no live lease holds the photo kept forever"
        );
        for lease in holding {
            ensure!(
                lease.until <= want.until,
                "{:?} leases the photo kept forever until {:?}, beyond the {:?} asked",
                lease.holder,
                lease.until,
                want.until
            );
        }
        Ok(())
    })
}
