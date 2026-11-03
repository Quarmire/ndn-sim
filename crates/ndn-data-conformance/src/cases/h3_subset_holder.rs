//! Slice 3, h3 — a holder cannot pass audits from a subset.
//!
//! A holder tempted to save space keeps three pieces in four of what it leased and hopes the
//! audits miss the rest. An audit asks for pieces drawn at random over everything the lease
//! promises, each with a fresh nonce, so its answers cannot be prepared or replayed from a
//! subset: with a quarter missing, a few audits find a missing piece.

use std::time::Duration;

use ndn_data::{Audit, Timestamp};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "h3",
    title: "A holder cannot pass audits from a subset",
    slice: 3,
    needs: &[Feature::Log, Feature::LargePayloads, Feature::Custody],
    model: &[],
    guards: "Audits sample pieces at random over everything a lease promises, with fresh nonces: \
             a holder that kept only a subset (three pieces in four) is reported broken or \
             unanswered within a few audits.",
    budget: Duration::from_secs(1800),
    plan: custody_plan,
    run,
};

const PHONE: Dev = Dev(0);
const REPO: Dev = Dev(1);
/// The audits the subset holder may survive before one must catch it.
const AUDITS: u64 = 3;

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
        phone
            .put(&photos, picture("beach.jpg", IMAGE), photo(Keep::Forever))
            .await?;

        w.gesture();
        let today = w.net().date(PHONE).0;
        let want = Hold {
            copies: 1,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
            holders: custody_holders(w),
        };
        let kept = phone.hold(&photos, want.clone()).await?;
        let sample = match kept.leases.iter().find(|l| leased_by(l, &repo)) {
            Some(lease) => match lease.audit {
                Audit::Kept { pieces } => pieces,
                ref other => {
                    return Err(Failure::new(format!(
                        "the repo's fresh lease, holding everything, was audited {other:?}"
                    )));
                }
            },
            None => return Err(Failure::new("the repo, a holder for Alice, leased nothing")),
        };
        w.measure("pieces an audit asks", u64::from(sample), "pieces");

        // The repo keeps three pieces in four.
        let lost = w.lose(REPO, &photos, 4);
        ensure!(
            lost > 0,
            "the repo stored too little of the photos to lose a quarter"
        );

        let mut caught = None;
        for audit in 1..=AUDITS {
            let custody = hold_on(
                w,
                PHONE,
                &photos,
                &want,
                &format!("audit {audit} of the subset"),
            )
            .await?;
            if custody.broken.iter().any(|l| {
                leased_by(l, &repo)
                    && matches!(l.audit, Audit::Broken { .. } | Audit::Unanswered { .. })
            }) {
                caught = Some(audit);
                break;
            }
        }
        let audits = caught.ok_or_else(|| {
            Failure::new(format!(
                "the repo lost {lost} pieces of the photos (one in four), and {AUDITS} audits of \
                 {sample} pieces each did not report its lease broken or unanswered"
            ))
        })?;
        w.measure("audits until the subset was caught", audits, "audits");
        Ok(())
    })
}
