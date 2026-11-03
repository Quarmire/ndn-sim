//! Slice 3, h6 — sealed data held by a non-reader stays unreadable.
//!
//! Alice seals her photos to her phone and her laptop only; her home repo keeps them for her but
//! is no reader. Custody needs no reading: the repo stores and serves the sealed pieces and passes
//! audits on them, yet asking it for the photo answers "sealed". Once the phone drops its own copy,
//! the laptop reads the photo whole from the repo's ciphertext.

use std::time::Duration;

use ndn_data::Timestamp;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "h6",
    title: "Sealed data held by a non-reader stays unreadable",
    slice: 3,
    needs: &[
        Feature::Log,
        Feature::LargePayloads,
        Feature::Custody,
        Feature::Seal,
    ],
    model: &[],
    guards: "A holder outside a collection's audience keeps, serves and passes audits on its \
             sealed pieces without being able to read them; readers in the audience read the \
             data whole from the holder's copy.",
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
        let (phone, repo) = (w.at(PHONE), w.at(REPO));
        let repo_name = w.net().spec(REPO).name();
        let readers = [
            Audience::Device(w.net().spec(PHONE).name()),
            Audience::Device(w.net().spec(LAPTOP).name()),
        ];
        phone
            .share(&photos, members(Rule::Log, &["/alice"], &readers))
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
        };
        let custody = hold_on(w, PHONE, &photos, want, "hold on a non-reader").await?;
        ensure!(
            custody
                .leases
                .iter()
                .any(|l| leased_by(l, &repo_name) && l.audit.kept() && l.holds.contains(&id)),
            "the repo, a holder for Alice outside the photos' audience, holds no lease on the \
             photo audited kept (leases: {:?})",
            custody
                .leases
                .iter()
                .map(|l| (&l.holder, &l.audit))
                .collect::<Vec<_>>()
        );
        let held = w.stored(REPO, &v.name);
        ensure!(held > 0, "the repo leases the photo but stores none of it");
        w.measure(
            "storage overhead at the holder",
            held * 1000 / size,
            "per mille",
        );

        match repo.get(&v.name).await {
            Err(DataError::Sealed { .. }) => {}
            Ok(_) => {
                return Err(Failure::new(
                    "the repo, outside the photos' audience, read the photo it holds",
                ));
            }
            Err(e) => {
                return Err(Failure::new(format!(
                    "the repo holds the photo, and its get answered {e} rather than sealed"
                )));
            }
        }

        let released = w.release(PHONE, &v.name).await?;
        ensure!(
            released > 0,
            "the phone released none of the photo's pieces"
        );
        let start = tokio::time::Instant::now();
        read_whole(
            w,
            LAPTOP,
            &v.name,
            &beach,
            "the laptop reads the photo from the non-reader's copy",
        )
        .await?;
        w.converged(start.elapsed());
        Ok(())
    })
}
