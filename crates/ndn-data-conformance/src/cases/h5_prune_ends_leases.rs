//! Slice 3, h5 — prune ends leases.
//!
//! The repo holds a large beach photo and a small sunset photo under one lease. Alice throws the
//! beach photo away. Her prune spreads like data: the repo deletes every piece of it (its lease
//! ends for what the prune covers), readers report it pruned, the sunset stays readable, and the
//! next audit asks only for what the lease still promises, so the repo, honest, passes it.

use std::time::Duration;

use ndn_data::Timestamp;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "h5",
    title: "Prune ends leases",
    slice: 3,
    needs: &[
        Feature::Log,
        Feature::LargePayloads,
        Feature::Custody,
        Feature::Prune,
    ],
    model: &["M5"],
    guards: "An authorised prune ends every lease for what it covers: holders delete its pieces, \
             readers report it pruned, versions outside it stay readable, and audits never ask \
             for a pruned piece.",
    budget: Duration::from_secs(1800),
    plan: custody_plan,
    run,
};

const PHONE: Dev = Dev(0);
const REPO: Dev = Dev(1);
const LAPTOP: Dev = Dev(2);

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let photos = n("/alice/32=data/photos");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        let repo = w.net().spec(REPO).name();
        phone
            .share(
                &photos,
                members(Rule::Log, &["/alice"], &[person("/alice")]),
            )
            .await?;
        let beach = phone
            .put(&photos, picture("beach.jpg", IMAGE), photo(Keep::Forever))
            .await?;
        let sunset = phone
            .put(
                &photos,
                content(&[("file", "sunset.jpg")]),
                photo(Keep::Forever),
            )
            .await?;
        let beach_name = listed(&*phone, &photos, &beach).await?.name;
        let sunset_name = listed(&*phone, &photos, &sunset).await?.name;

        let today = w.net().date(PHONE).0;
        let want = Hold {
            copies: 1,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
        };
        let custody = phone.hold(&photos, want).await?;
        ensure!(
            custody
                .leases
                .iter()
                .any(|l| leased_by(l, &repo) && l.audit.kept() && l.holds.contains(&beach)),
            "the repo, a holder for Alice, holds no kept lease on the beach photo"
        );
        let held = w.stored(REPO, &beach_name);
        ensure!(
            held > 0,
            "the repo's lease holds the beach photo, but it stores none of it"
        );
        w.measure(
            "beach photo stored at the repo before the prune",
            held,
            "bytes",
        );

        // Alice throws the beach photo away.
        w.gesture();
        let upto: Frontier = [beach.clone()].into_iter().collect();
        phone.prune(&beach_name, &upto).await?;
        w.converge(
            "the repo deletes the beach photo and the laptop reports it pruned",
            LIMIT,
            || async {
                Ok(w.stored(REPO, &beach_name) == 0
                    && matches!(laptop.get(&beach_name).await, Err(DataError::Pruned { .. })))
            },
        )
        .await?;
        ensure!(
            laptop.get(&sunset_name).await.is_ok(),
            "pruning the beach photo made the sunset unreadable"
        );

        // The lease still promises the sunset; its audit asks for nothing pruned.
        let after = hold_on(w, PHONE, &photos, want, "audit after the prune").await?;
        ensure!(
            after.broken.is_empty(),
            "after the prune, the audit reported {:?} broken: it asked for pruned pieces",
            after
                .broken
                .iter()
                .map(|l| (&l.holder, &l.audit))
                .collect::<Vec<_>>()
        );
        let lease = after
            .leases
            .iter()
            .find(|l| leased_by(l, &repo))
            .ok_or_else(|| Failure::new("after the prune, the repo holds no live lease"))?;
        ensure!(
            lease.audit.kept() && lease.holds.contains(&sunset),
            "after the prune, the repo's lease holds the sunset: {}; audited {:?}",
            lease.holds.contains(&sunset),
            lease.audit
        );
        Ok(())
    })
}
