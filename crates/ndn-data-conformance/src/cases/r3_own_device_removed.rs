//! Review 3 — Alice locks her own phone out of a collection.
//!
//! Alice keeps a journal she wants only on her laptop from now on. Under the draft every device
//! of the owner's namespace always read, and a master secret per device gave each of them every
//! epoch key the laptop would ever start, so no audience could leave a device of her own out.
//! The fix (spec §9): an audience is exactly the readers listed, plus the device that signed the
//! record starting the epoch; each epoch's key is fresh and granted per epoch.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "r3",
    title: "The owner locks one of her own devices out",
    slice: 2,
    needs: &[Feature::Merge, Feature::Seal],
    model: &["M4"],
    guards: "A device of the owner's own namespace reads only while the audience admits it: \
             after a share that lists another of her devices alone, it opens nothing written \
             later.",
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
        let journal = n("/alice/32=data/journal");
        let (laptop, phone) = (w.at(LAPTOP), w.at(PHONE));
        laptop
            .share(&journal, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        let first = laptop.put(&journal, text("day 1"), note(1)).await?;
        w.until("the phone opens the first entry", LIMIT, || async {
            let seen = look(&*phone, &journal, &Frontier::new(), LOOK).await?;
            Ok(version(&seen, &first).is_some())
        })
        .await?;

        laptop
            .share(
                &journal,
                members(
                    merge(),
                    &["/alice"],
                    &[Audience::Device(n("/alice/laptop"))],
                ),
            )
            .await?;
        w.gesture();
        let later = laptop.put(&journal, text("day 2"), note(1)).await?;
        let own = look(&*laptop, &journal, &Frontier::new(), LOOK).await?;
        ensure!(
            version(&own, &later).is_some(),
            "the laptop, the one reader left, does not list its own later entry"
        );
        w.sleep(SETTLE).await;
        let seen = look(&*phone, &journal, &Frontier::new(), LOOK).await?;
        ensure!(
            version(&seen, &later).is_none(),
            "the phone, left out of the journal's audience, opened an entry written after"
        );
        Ok(())
    })
}
