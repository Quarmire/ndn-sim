//! Slice 3, h2 — a holder that silently drops data is caught and repaired.
//!
//! Alice's home repo leases her photos for a year. Its disk then loses them, and it says nothing.
//! A promise nobody checks is worth nothing, so the phone's next `hold` audits the lease: it asks
//! the repo for random pieces with fresh nonces, and the repo cannot answer with what it no longer
//! has. The phone reports the lease broken and repairs custody (the repo is asked again and
//! fetches back what it lost), and only once a lease is audited kept may the phone drop its own
//! copy of the photo; the laptop then reads the photo whole from the repo, the only place left
//! that has it.

use std::time::Duration;

use ndn_data::{Audit, Timestamp};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "h2",
    title: "A holder that silently drops data is caught and repaired",
    slice: 3,
    needs: &[Feature::Log, Feature::LargePayloads, Feature::Custody],
    model: &[],
    guards: "An audit catches a holder that lost what its lease promises (its answers are \
             signed evidence, or it does not answer); the owner device reports the lease broken \
             and repairs custody until a lease is audited kept, and data released to the holders \
             stays readable whole from them.",
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
        let phone = w.at(PHONE);
        let repo = w.net().spec(REPO).name();
        phone
            .share(
                &photos,
                members(Rule::Log, &["/alice"], &[person("/alice")]),
            )
            .await?;
        let beach = picture("beach.jpg", IMAGE);
        let id = phone
            .put(&photos, beach.clone(), photo(Keep::Forever))
            .await?;
        let v = listed(&*phone, &photos, &id).await?;
        let size = large(&v)
            .ok_or_else(|| Failure::new("the phone lists its photo inline, not in pieces"))?;

        w.gesture();
        let today = w.net().date(PHONE).0;
        let want = Hold {
            copies: 1,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
            holders: custody_holders(w),
        };
        let kept = hold_on(w, PHONE, &photos, &want, "first hold").await?;
        ensure!(
            kept.leases.len() == 1 && leased_by(&kept.leases[0], &repo),
            "one copy asked of a repo that holds for Alice: {} leases, by {:?}",
            kept.leases.len(),
            kept.leases.iter().map(|l| &l.holder).collect::<Vec<_>>()
        );
        let lease = &kept.leases[0];
        ensure!(
            lease.audit.kept() && lease.holds.contains(&id),
            "the repo's fresh lease {} holds the photo: {}; audited {:?}",
            lease.name,
            lease.holds.contains(&id),
            lease.audit
        );
        w.measure("copies: live leases", kept.leases.len() as u64, "leases");
        w.measure(
            "storage overhead at holders",
            overhead(w, &[REPO], &photos, size),
            "per mille",
        );

        // The repo's disk loses everything of the photos; it does not know.
        let lost = w.lose(REPO, &photos, 1);
        ensure!(lost > 0, "the repo stored nothing of the photos to lose");
        w.measure("pieces the repo lost", lost, "pieces");

        let repaired = hold_on(w, PHONE, &photos, &want, "hold that audits the loss").await?;
        let caught = repaired.broken.iter().find(|l| leased_by(l, &repo));
        ensure!(
            caught.is_some_and(|l| matches!(
                l.audit,
                Audit::Broken { .. } | Audit::Unanswered { .. }
            )),
            "the repo lost every piece of the photos, and the phone's audit did not report its \
             lease broken or unanswered (broken: {:?})",
            repaired
                .broken
                .iter()
                .map(|l| (&l.holder, &l.audit))
                .collect::<Vec<_>>()
        );
        let live_kept = repaired.leases.iter().filter(|l| l.audit.kept()).count();
        ensure!(
            live_kept == 1 && repaired.leases.len() == 1,
            "after repair, {} live leases, {live_kept} audited kept; one copy was asked for",
            repaired.leases.len()
        );
        ensure!(
            repaired.leases[0].holds.contains(&id),
            "the repaired lease does not hold the photo"
        );

        // Only a kept lease lets the phone drop its own copy.
        let released = w.release(PHONE, &v.name).await?;
        ensure!(
            released > 0,
            "the phone released none of the photo's pieces"
        );
        w.measure("pieces the phone released", released, "pieces");

        let start = tokio::time::Instant::now();
        read_whole(
            w,
            LAPTOP,
            &v.name,
            &beach,
            "the laptop reads the released photo from the repo",
        )
        .await?;
        w.converged(start.elapsed());
        Ok(())
    })
}
