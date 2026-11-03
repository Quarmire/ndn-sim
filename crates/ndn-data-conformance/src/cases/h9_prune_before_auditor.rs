//! Slice 3, h9 — a prune the holder heard before the auditor does not frame the holder.
//!
//! The laptop puts a large photo into Alice's photos and the home repo keeps it under a lease the
//! phone asked for. While the phone is away, the laptop prunes its photo: the repo hears the
//! prune and, as it must, drops every piece (spec §14). Then the laptop goes away too, and the
//! phone comes back without having heard the prune. Its next audit asks the repo for pieces of
//! the photo, which the repo no longer has. An honest holder must not be judged broken for
//! following a prune: its answer names the prune record, the phone verifies and takes it, and the
//! pruned piece leaves the audit. Only what the auditor's own view proves should be there makes
//! signed evidence.

use std::time::Duration;

use ndn_data::{Audit, Timestamp};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "h9",
    title: "A prune the holder heard first does not frame it",
    slice: 3,
    needs: &[
        Feature::Log,
        Feature::LargePayloads,
        Feature::Custody,
        Feature::Prune,
    ],
    model: &["M5"],
    guards: "A holder that dropped what a prune covers, before its auditor heard the prune, is \
             not judged broken: its answer names the prune, which the auditor verifies and takes; \
             a holder's signed answer is evidence only where the auditor's view proves the piece \
             should be there.",
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
        // A caption from the phone; once the laptop reads it, it holds the phone's record too.
        phone
            .put(
                &photos,
                content(&[("file", "caption.txt")]),
                photo(Keep::Forever),
            )
            .await?;
        w.until("the laptop reads Alice's photos", LIMIT, || async {
            Ok(laptop.get(&photos).await.is_ok())
        })
        .await?;
        let beach = picture("beach.jpg", IMAGE);
        let id = laptop
            .put(&photos, beach.clone(), photo(Keep::Forever))
            .await?;
        let v = listed(&*laptop, &photos, &id).await?;
        large(&v)
            .ok_or_else(|| Failure::new("the laptop lists its photo inline, not in pieces"))?;
        // The phone reads the laptop's photo, so it knows every piece an audit may ask for.
        read_whole(w, PHONE, &v.name, &beach, "phone reads the laptop's photo").await?;

        w.gesture();
        let today = w.net().date(PHONE).0;
        let want = Hold {
            copies: 1,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
            holders: custody_holders(w),
        };
        let kept = hold_on(w, PHONE, &photos, &want, "first hold").await?;
        ensure!(
            kept.leases
                .iter()
                .any(|l| leased_by(l, &repo) && l.audit.kept() && l.holds.contains(&id)),
            "the repo, a holder for Alice, holds no kept lease on the laptop's photo"
        );

        // The phone is away; the laptop prunes its photo, and the repo drops it.
        w.net().offline(PHONE);
        w.gesture();
        let upto: Frontier = [id.clone()].into_iter().collect();
        laptop.prune(&v.name, &upto).await?;
        w.until("the repo drops the pruned photo", LIMIT, || async {
            Ok(w.stored(REPO, &v.name) == 0)
        })
        .await?;
        // The laptop goes away before the phone comes back: the phone has not heard the prune.
        w.net().offline(LAPTOP);
        w.net().online(PHONE);
        ensure!(
            !matches!(phone.get(&v.name).await, Err(DataError::Pruned { .. })),
            "the phone heard the prune already; the case needs it not to"
        );

        let after = hold_on(w, PHONE, &photos, &want, "audit before hearing the prune").await?;
        ensure!(
            !after
                .broken
                .iter()
                .any(|l| leased_by(l, &repo) && matches!(l.audit, Audit::Broken { .. })),
            "the repo dropped the photo because its writer pruned it, and the phone, not having \
             heard the prune, judged the repo's lease broken: {:?}",
            after
                .broken
                .iter()
                .map(|l| (&l.holder, &l.audit))
                .collect::<Vec<_>>()
        );
        ensure!(
            matches!(phone.get(&v.name).await, Err(DataError::Pruned { .. })),
            "the repo's answer named the prune, and the phone still does not report the photo \
             pruned"
        );
        Ok(())
    })
}
