//! Slice 3, h7 — with one copy, a lost holder loses the photo, and hold says so.
//!
//! Alice asks for one copy of her photos. The home repo leases them and the phone's audit finds
//! the lease kept, so the phone releases its own copy of the photo's pieces: from now on the repo
//! is the only place that has them. Then the repo's disk loses everything of the photos. The
//! phone's next `hold` audits the lease and reports it broken (signed `Missing`, or unanswered),
//! and asks the repo again; but the repo can fetch back nothing (the writer released its pieces,
//! and there is no other holder), and no other device holds for Alice. Custody must not pretend:
//! no lease audited kept holds the photo, and the custody names the photo `unkept` — lost unless
//! a copy turns up; the next step is to put it again from wherever a copy is left.

use std::time::Duration;

use ndn_data::{Audit, Timestamp};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "h7",
    title: "With one copy, a lost holder loses the photo, and hold says so",
    slice: 3,
    needs: &[Feature::Log, Feature::LargePayloads, Feature::Custody],
    model: &[],
    guards: "`hold` never claims a copy that does not exist: once the only holder of a released \
             photo lost it, no lease audited kept holds the photo, and what is kept nowhere is \
             reported unkept (next step: put it again from a copy).",
    budget: Duration::from_secs(1800),
    plan: custody_plan,
    run,
};

const PHONE: Dev = Dev(0);
const REPO: Dev = Dev(1);

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
        let id = phone
            .put(&photos, picture("beach.jpg", IMAGE), photo(Keep::Forever))
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
        ensure!(
            kept.unkept.is_empty(),
            "a kept lease holds the photo, yet the custody names {:?} unkept",
            kept.unkept
        );
        w.measure("copies: live leases", kept.leases.len() as u64, "leases");
        w.measure(
            "storage overhead at holders",
            overhead(w, &[REPO], &photos, size),
            "per mille",
        );

        // The repo's kept lease lets the phone drop its own copy: the repo is the only one left.
        let released = w.release(PHONE, &v.name).await?;
        ensure!(
            released > 0,
            "the phone released none of the photo's pieces"
        );
        w.measure("pieces the phone released", released, "pieces");

        // The repo's disk loses everything of the photos; it does not know.
        let lost = w.lose(REPO, &photos, 1);
        ensure!(lost > 0, "the repo stored nothing of the photos to lose");
        w.measure("pieces the repo lost", lost, "pieces");

        let after = hold_on(w, PHONE, &photos, &want, "hold that audits the loss").await?;
        let caught = after.broken.iter().find(|l| leased_by(l, &repo));
        ensure!(
            caught.is_some_and(|l| matches!(
                l.audit,
                Audit::Broken { .. } | Audit::Unanswered { .. }
            )),
            "the repo lost every piece of the photos, and the phone's audit did not report its \
             lease broken or unanswered (broken: {:?})",
            after
                .broken
                .iter()
                .map(|l| (&l.holder, &l.audit))
                .collect::<Vec<_>>()
        );
        let claimed: Vec<_> = after
            .leases
            .iter()
            .filter(|l| l.audit.kept() && l.holds.contains(&id))
            .map(|l| (&l.holder, &l.name))
            .collect();
        ensure!(
            claimed.is_empty(),
            "the only copy of the photo is lost, yet leases audited kept hold it: {claimed:?}"
        );
        ensure!(
            after.unkept.contains(&v.name),
            "the photo {} is kept nowhere, and the custody does not name it unkept (unkept: {:?})",
            v.name,
            after.unkept
        );
        // The repo, asked again, signs a lease over what it still holds whole: live, maybe
        // audited kept, but without the photo.
        w.measure(
            "live leases after the loss",
            after.leases.len() as u64,
            "leases",
        );
        w.measure(
            "copies of the photo after the loss: kept leases holding it",
            claimed.len() as u64,
            "leases",
        );
        w.measure(
            "versions reported unkept",
            after.unkept.len() as u64,
            "versions",
        );
        Ok(())
    })
}
