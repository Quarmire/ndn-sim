//! Slice 6, b5 — a merge version's pieces are released only behind a held checkpoint.
//!
//! Alice's phone wrote a 20 KiB edit into her notes element, in pieces, and her home repo holds
//! the collection under an audited lease. Dropping a log version's pieces once a holder proves it
//! keeps them is safe: whoever reads the version fetches it from the holder. A merge version is
//! different: every device computing the element's state needs it, or a checkpoint that covers
//! it. So the phone may drop the edit's pieces only once a checkpoint covering it is held whole
//! by enough audited holders; until then release keeps them, saying why (`NotHeld`). After the
//! phone writes a checkpoint and the repo holds it, the release succeeds.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "b5",
    title: "A merge version's pieces are released only behind a held checkpoint",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::AppOps,
        Feature::MergePieces,
        Feature::Custody,
    ],
    model: &[],
    guards: "Releasing a merge version's pieces is refused (NotHeld, with why) and drops \
             nothing while no checkpoint covering it is proved held by enough audited holders; \
             once one is written and held, the release drops them, and the element's state \
             stays the same on every device.",
    budget: Duration::from_secs(1800),
    plan: custody_plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(2);

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let notes = n("/alice/32=data/notes/long");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        phone
            .share(
                &notes,
                members(element_rule(), &["/alice"], &[person("/alice")]),
            )
            .await?;
        let edit = put_element(w, PHONE, &notes, |op| {
            op.then(0, Edit::Create("note".into()))
                .set("body", prose("body", 20 * 1024))
        })
        .await?;
        let edit_name = log_entry(w, PHONE, &notes, &edit);

        w.gesture();
        let today = w.net().date(PHONE).0;
        let want = Hold {
            copies: 1,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
            holders: custody_holders(w),
        };
        let kept = hold_on(w, PHONE, &notes, &want, "hold of the edit").await?;
        ensure!(
            kept.leases
                .iter()
                .any(|l| l.audit.kept() && l.holds.contains(&edit)),
            "the repo holds no kept lease on the edit"
        );

        let stored = w.stored(PHONE, &edit_name);
        match w.try_release(PHONE, &edit_name).await? {
            Err(DataError::NotHeld { why, .. }) => {
                ensure!(!why.is_empty(), "the refused release says nothing of why")
            }
            Err(e) => {
                return Err(Failure::new(format!(
                    "releasing the edit with no checkpoint covering it answered {e}, not NotHeld"
                )));
            }
            Ok(pieces) => {
                return Err(Failure::new(format!(
                    "the phone released {pieces} pieces of a merge version no held checkpoint \
                     covers: a device computing the element's state may find it nowhere"
                )));
            }
        }
        ensure!(
            w.stored(PHONE, &edit_name) == stored,
            "the refused release dropped some of the edit"
        );

        // A checkpoint covering the edit, held by the repo.
        let (_, v) = element_state(&*phone, &notes).await?;
        let mut whole = v.state.clone();
        whole
            .settings
            .insert("archive".into(), prose("archive", 100 * 1024));
        let cp = put_element(w, PHONE, &notes, |op| op.then(0, Edit::Checkpoint(whole))).await?;
        let held = hold_on(w, PHONE, &notes, &want, "hold of the checkpoint").await?;
        ensure!(
            held.leases
                .iter()
                .any(|l| l.audit.kept() && l.holds.contains(&cp)),
            "the repo holds no kept lease on the checkpoint"
        );
        let released = w.release(PHONE, &edit_name).await?;
        ensure!(released > 0, "the phone released none of the edit's pieces");
        w.measure("pieces of the edit the phone released", released, "pieces");
        w.measure(
            "octets of the edit the phone stores after release",
            w.stored(PHONE, &edit_name),
            "bytes",
        );

        let start = tokio::time::Instant::now();
        w.until("the laptop reaches the phone's note", LIMIT, || async {
            agree(&[&*phone, &*laptop], &notes, &[&cp, &edit]).await
        })
        .await?;
        w.converged(start.elapsed());
        Ok(())
    })
}
