//! Slice 3, h8 — a holder that keeps nothing and relays from the owner cannot make it release.
//!
//! Alice asks her home repo for one copy of her photos; it leases them and keeps them. Then the
//! repo's disk loses everything and, rather than admit it, the repo answers every audit by
//! fetching the asked piece from the network: from the phone, the only device that still has
//! it. Its answers are the pieces, signed by the repo, so an audit of the repo passes: an audit
//! proves a holder can produce what it promised, not that it stores it (spec §13.4). Releasing on
//! that evidence would drop the last copy. Release asks for fresh evidence of its own: while it
//! runs, the phone serves none of the photo's pieces, so a holder that can only relay them from
//! the phone proves nothing, and the phone keeps its copy, saying why.

use ndn_data::Timestamp;
use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "h8",
    title: "A holder that relays from the owner cannot make it release",
    slice: 3,
    needs: &[Feature::Log, Feature::LargePayloads, Feature::Custody],
    model: &[],
    guards: "Release drops the owner's own chunks only on fresh evidence, from enough distinct \
             holders, that they keep exactly those pieces without the owner's help: a holder \
             that stores nothing and answers audits by fetching the pieces from the owner \
             proves nothing, and the owner keeps its copy, saying why.",
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
        large(&v).ok_or_else(|| Failure::new("the phone lists its photo inline, not in pieces"))?;

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
            "the repo, a holder for Alice, holds no kept lease on the photo"
        );

        // The repo loses everything of the photos, and from now on relays every audit ask.
        let lost = w.lose(REPO, &photos, 1);
        ensure!(lost > 0, "the repo stored nothing of the photos to lose");
        ensure!(
            w.stored(REPO, &v.name) == 0,
            "the repo still stores some of the photo after losing everything"
        );
        w.relay_audits(REPO).await?;
        let relayed = hold_on(w, PHONE, &photos, &want, "hold audited through the relay").await?;
        let passed = relayed
            .leases
            .iter()
            .any(|l| leased_by(l, &repo) && l.audit.kept() && l.holds.contains(&id));
        w.measure(
            "the relaying repo's lease audited kept by hold",
            u64::from(passed),
            "leases",
        );

        // The phone is asked to drop its copy of the photo's pieces.
        let stored = w.stored(PHONE, &v.name);
        let released = w.release(PHONE, &v.name).await;
        let refusal = match released {
            Ok(pieces) => {
                return Err(Failure::new(format!(
                    "the phone released the photo ({pieces} pieces) on the word of a repo that \
                     stores none of it and relays every audit from the phone: the last copy is \
                     gone"
                )));
            }
            Err(e) => e,
        };
        ensure!(
            refusal.0.contains("HoldFirst"),
            "the refusal says what to do (hold first, with a holder that keeps it): {refusal}"
        );
        ensure!(
            w.stored(PHONE, &v.name) == stored,
            "the phone's release was refused, yet it dropped some of the photo"
        );
        // Once the release is refused, the phone serves the photo again.
        read_whole(
            w,
            LAPTOP,
            &v.name,
            &beach,
            "laptop reads the photo after the refusal",
        )
        .await?;
        Ok(())
    })
}
