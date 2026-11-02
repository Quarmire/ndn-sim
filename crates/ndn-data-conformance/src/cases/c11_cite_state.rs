//! Case 11 — citing the plan as it stood on Friday.
//!
//! Carol wants to link the shared plan exactly as it was before the meeting. `get` returned "a
//! version", but a merged document is a state computed from many writers' versions. The fix
//! (M10): for merge collections `get` returns the merged value at a frontier, and `snapshot` names
//! that state, so the link always opens the same plan.

use std::time::Duration;

use ndn_data::Got;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c11",
    title: "Citing the plan as it stood on Friday",
    slice: 1,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::Snapshot,
    ],
    model: &["M10"],
    guards: "get on a merge collection answers the merged state at a frontier; a snapshot pins \
             that state, and opening the pin on any device answers the same frontier and value \
             however the plan grows.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let doc = n("/alice/docs/plan");
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        let all = [person("/alice"), person("/bob"), person("/carol")];
        alice
            .share(&doc, members(merge(), &["/alice", "/bob", "/carol"], &all))
            .await?;
        let a = alice
            .put(&doc, content(&[("goal", "ship by May")]), note(1))
            .await?;
        let b = bob
            .put(&doc, content(&[("risk", "vendor delay")]), note(1))
            .await?;
        w.until("Carol holds both edits", LIMIT, || async {
            has_all(&*carol, &doc, &[&a, &b]).await
        })
        .await?;

        // `state` fails the case if get answers a single version instead of the merged state.
        let friday = state(&*carol, &doc).await?;
        let snap = carol.snapshot(std::slice::from_ref(&doc)).await?;
        ensure!(
            snap.pins.len() == 1,
            "a snapshot of one collection pins {} names",
            snap.pins.len()
        );
        let pin = snap.pins[0].clone();

        let a2 = alice
            .put(&doc, content(&[("goal", "ship by June")]), note(1))
            .await?;
        let b2 = bob.put(&doc, content(&[("risk", "none")]), note(1)).await?;
        w.converge("Alice holds the later edits", LIMIT, || async {
            has_all(&*alice, &doc, &[&a2, &b2]).await
        })
        .await?;

        for (who, layer) in [("Alice", &alice), ("Carol", &carol)] {
            match layer.get(&pin).await?.got {
                Got::State(s) => ensure!(
                    s.at == friday.at && s.value == friday.value,
                    "{who} opened the cited plan at {:?}, not Friday's {:?}",
                    s.at,
                    friday.at
                ),
                other => {
                    return Err(Failure::new(format!(
                        "{who} opened the pin and got {other:?}, not a state"
                    )));
                }
            }
            match layer.get(&snap.name).await?.got {
                Got::Snapshot(s) => ensure!(
                    s.pins == snap.pins,
                    "{who} opened the snapshot and found other pins"
                ),
                other => {
                    return Err(Failure::new(format!(
                        "{who} opened the snapshot and got {other:?}"
                    )));
                }
            }
        }
        let now = state(&*alice, &doc).await?;
        ensure!(
            now.at != friday.at,
            "the plan's current state did not move past Friday's"
        );
        Ok(())
    })
}

async fn has_all(layer: &dyn DataLayer, doc: &Name, ids: &[&VersionId]) -> Result<bool, Failure> {
    Ok(state_now(layer, doc)
        .await?
        .is_some_and(|s| ids.iter().all(|id| s.at.contains(id))))
}
