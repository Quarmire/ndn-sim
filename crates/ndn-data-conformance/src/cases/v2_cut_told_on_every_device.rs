//! Device events, v2 — a cut is told on every device that takes it, and the version it withdraws
//! too, whether or not a folder is watched.
//!
//! Alice, on a plane, removes Bob from her plan; Carol accepts Bob's next edit before the cut
//! reaches her, then receives it when Alice lands (o1's story). Nobody on Carol's device watches
//! the plan: `Change::Withdrawn` goes to watchers, and there are none.
//!
//! The guard: Carol's device reports a cut event (Bob's prefix removed from the plan by Alice's
//! key, the record named, how many versions it keeps) and a withdrawal event (Bob's second edit,
//! by name and digest, by that cut); Bob's device, the second to take the record, reports the cut
//! too; Alice's own device does not report to her the cut she signed herself.

use std::time::Duration;

use ndn_data::{EntryKind, EventDetail, EventKind, EventSubject, Meaning, WithdrawnBy};

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "v2",
    title: "A cut and the version it withdraws are told on every device that takes the cut",
    slice: 7,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::RemovalCut,
        Feature::CutRecheck,
        Feature::DeviceEvents,
    ],
    model: &["M3"],
    guards: "A members record that removes a writer is a cut event on every device that takes it \
             (not the one that signed it), and a version it withdraws is a withdrawal event, \
             though no watcher of the collection exists: evidence by name and digest, what it \
             means, and what to do.",
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
        let doc = n("/alice/32=data/docs/plan");
        let alices = w.net().spec(ALICE).name();
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        let all = [person("/alice"), person("/bob"), person("/carol")];
        alice
            .share(&doc, members(merge(), &["/alice", "/bob", "/carol"], &all))
            .await?;
        let inside = w
            .put(BOB, &doc, content(&[("bob", "first")]), note(1))
            .await?;
        w.until("everyone holds Bob's first edit", LIMIT, || async {
            agree(&[&*alice, &*bob, &*carol], &doc, &[&inside]).await
        })
        .await?;

        // Alice, on a plane, removes Bob; Carol accepts his next edit; Alice lands.
        w.net().offline(ALICE);
        alice
            .share(
                &doc,
                members(
                    merge(),
                    &["/alice", "/carol"],
                    &[person("/alice"), person("/carol")],
                ),
            )
            .await?;
        w.gesture();
        let outside = bob
            .put(&doc, content(&[("bob", "second")]), note(1))
            .await?;
        w.until(
            "Carol accepts Bob's second edit, not knowing the cut",
            LIMIT,
            || has(&*carol, &doc, &outside),
        )
        .await?;
        w.net().online(ALICE);

        let last = std::cell::RefCell::new(String::new());
        w.until(
            "Carol's device reports the cut and the withdrawal, and Bob's the cut",
            LIMIT,
            || async {
                let cuts = events_of(w, CAROL, EventKind::Cut)?;
                let withdrawals = events_of(w, CAROL, EventKind::Withdrawal)?;
                let bobs = events_of(w, BOB, EventKind::Cut)?;
                let ok = !cuts.is_empty() && !withdrawals.is_empty() && !bobs.is_empty();
                if !ok {
                    *last.borrow_mut() = format!(
                        "Carol: cuts {cuts:?}, withdrawals {withdrawals:?}; Bob: cuts {bobs:?}"
                    );
                }
                Ok(ok)
            },
        )
        .await
        .map_err(|e| Failure::new(format!("{e}; at the last look: {}", last.borrow())))?;

        for (who, d) in [("Carol", CAROL), ("Bob", BOB)] {
            let cuts = events_of(w, d, EventKind::Cut)?;
            ensure!(cuts.len() == 1, "{who}: one cut event, got {cuts:?}");
            let EventDetail::Cut {
                subject,
                folder,
                of,
                signer,
                record,
                kept,
                ..
            } = &cuts[0].detail
            else {
                return Err(Failure::new(format!("{who}: not a cut: {:?}", cuts[0])));
            };
            ensure!(
                *subject == doc && !folder && *of == n("/bob") && signer.has_prefix(&alices),
                "{who}: the cut event names Bob's prefix removed from {doc} by Alice's key, got \
                 {:?}",
                cuts[0]
            );
            ensure!(
                record.has_prefix(&alices) && *kept == 1,
                "{who}: the record is Alice's log entry and the cut keeps Bob's first edit, got \
                 {record} keeping {kept}"
            );
            ensure!(
                cuts[0].subject() == EventSubject::Writer(n("/bob"))
                    && cuts[0].meaning() == Meaning::WriterCut,
                "{who}: {:?}",
                cuts[0]
            );
        }
        let withdrawals = events_of(w, CAROL, EventKind::Withdrawal)?;
        ensure!(
            withdrawals.len() == 1,
            "Carol: one withdrawal event, got {withdrawals:?}"
        );
        let EventDetail::Withdrawal {
            writer,
            collection,
            entry,
            by,
        } = &withdrawals[0].detail
        else {
            return Err(Failure::new(format!("{:?}", withdrawals[0])));
        };
        ensure!(
            *writer == outside.writer.key().clone()
                && collection.as_ref() == Some(&doc)
                && entry.name == log_entry(w, BOB, &doc, &outside)
                && entry.kind == Some(EntryKind::Version)
                && entry.digest.is_some()
                && matches!(by, WithdrawnBy::Cut { of, signer } if *of == n("/bob") && signer.has_prefix(&alices)),
            "Carol's withdrawal event names Bob's second edit by name and digest, by Alice's \
             cut: {:?}",
            withdrawals[0]
        );
        ensure!(
            !format!("{:?}", withdrawals[0]).contains("second"),
            "the withdrawal event carries what the edit says: {:?}",
            withdrawals[0]
        );
        // Alice signed the cut herself: her host asked for it.
        ensure!(
            events_of(w, ALICE, EventKind::Cut)?.is_empty(),
            "Alice's device reports the cut she signed: {:?}",
            events_of(w, ALICE, EventKind::Cut)?
        );
        Ok(())
    })
}
