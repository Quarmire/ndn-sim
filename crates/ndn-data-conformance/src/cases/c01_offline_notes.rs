//! Case 1 — notes on laptop and phone, both offline.
//!
//! Alice edits the same note on the plane (laptop) and in the taxi (phone). Under the draft model
//! both edits were "v=18" by one writer — equivocation for an ordinary offline edit. The fix (M1):
//! a writer is a key; the edits are (laptop, n) and (phone, m), each naming the shared version as
//! parent, and the merge rule combines them.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c1",
    title: "Notes on laptop and phone, both offline",
    slice: 1,
    needs: &[Feature::Merge],
    model: &["M1"],
    guards: "A writer is one key: two devices' offline edits are distinct versions (writer, seq), \
             each naming the common parent; they merge into one state on both devices and are \
             never reported as equivocation.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let doc = n("/alice/notes/trip/day1");
        let (laptop, phone) = (w.at(LAPTOP), w.at(PHONE));
        laptop
            .share(&doc, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        let v17 = laptop.put(&doc, text("day 1"), note(1)).await?;
        w.until("the phone holds the shared version", LIMIT, || {
            has(&*phone, &doc, &v17)
        })
        .await?;

        w.net().offline(LAPTOP);
        w.net().offline(PHONE);
        let plane = laptop
            .put(&doc, text("day 1, on the plane"), note(1))
            .await?;
        let taxi = phone.put(&doc, text("day 1, in the taxi"), note(1)).await?;
        ensure!(
            plane.writer != taxi.writer,
            "both offline edits carry writer {:?}: a writer must be the device's key",
            plane.writer
        );
        w.net().online(LAPTOP);
        w.net().online(PHONE);

        w.converge(
            "laptop and phone agree on a state with both edits",
            LIMIT,
            || async { agree(&[&*laptop, &*phone], &doc, &[&plane, &taxi]).await },
        )
        .await?;

        for device in [&laptop, &phone] {
            let changes = look(&**device, &doc, &Frontier::new(), LOOK).await?;
            ensure!(
                !equivocation(&changes),
                "an ordinary offline edit was reported as equivocation"
            );
            for id in [&plane, &taxi] {
                let v = version(&changes, id)
                    .ok_or_else(|| Failure::new(format!("watch does not list {id:?}")))?;
                ensure!(
                    v.parents.contains(&v17),
                    "{id:?} does not name the shared version {v17:?} as a parent"
                );
            }
        }
        Ok(())
    })
}
