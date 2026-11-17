//! Device events, v4 — an event not acknowledged comes again after a restart; one acknowledged
//! does not.
//!
//! Alice removes Bob from her plan, and Carol's device reports the cut. Its host reads the event
//! from the stream and does nothing with it; Carol's device stops and starts again on what it
//! stored: the same event, with the same id and cursor, is there and the stream delivers it
//! again. The host then acknowledges it, and a second restart leaves nothing to deliver. An
//! acknowledgement of an id the device never had is refused, saying why.
//!
//! The guard: delivery is at least once and idempotent by id; an acknowledgement survives
//! the restart that follows it; the entries the start judges again (Alice's record, Bob's
//! version) do not make the acknowledged event new.

use std::time::Duration;

use ndn_data::{Cursor, DataError, EventId, EventKind};

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "v4",
    title: "An event not acknowledged comes again after a restart, one acknowledged does not",
    slice: 7,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::RemovalCut,
        Feature::DeviceEvents,
    ],
    model: &[],
    guards: "Events are stored behind the durability barrier: one not acknowledged is delivered \
             again after a restart, with its id and cursor, and by every new stream; an \
             acknowledgement is durable (a restart after it delivers nothing) and idempotent, \
             and an id the device never had is refused with a reason.",
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

/// The next event `stream` delivers within `LOOK`, if any.
async fn next_event(stream: &mut ndn_data::DeviceEvents) -> Option<ndn_data::DeviceEvent> {
    tokio::time::timeout(LOOK, stream.next()).await.ok()?
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let doc = n("/alice/32=data/docs/plan");
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
        w.gesture();
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
        w.until("Carol's device reports the cut", LIMIT, || async {
            Ok(!events_of(w, CAROL, EventKind::Cut)?.is_empty())
        })
        .await?;
        let before = w.gate(CAROL)?.pending_events();

        // Delivered on a stream and never acknowledged; the device stops and starts again.
        let mut stream = w.gate(CAROL)?.events(Cursor::default());
        let first = next_event(&mut stream).await;
        ensure!(
            first.as_ref() == before.first(),
            "the stream delivers the first pending event, {:?}; got {first:?}",
            before.first()
        );
        w.stop(CAROL).await?;
        w.restart(CAROL).await?;
        let after = w.gate(CAROL)?.pending_events();
        ensure!(
            after == before,
            "not acknowledged: the same events with the same ids, cursors and counts after the \
             restart; before {before:?}, after {after:?}"
        );
        let mut stream = w.gate(CAROL)?.events(Cursor::default());
        let again = next_event(&mut stream).await;
        ensure!(
            again.as_ref() == before.first(),
            "the stream delivers it again after the restart, got {again:?}"
        );
        let past = before.last().map_or(Cursor::default(), |e| e.cursor);
        ensure!(
            next_event(&mut w.gate(CAROL)?.events(past)).await.is_none(),
            "an event at or below the cursor given is delivered again"
        );

        // An id the device never had is refused, with a reason, and nothing changes.
        let ids: Vec<EventId> = before.iter().map(|e| e.id).collect();
        let unseen = EventId([0x5a; 16]);
        let mut asked = ids.clone();
        asked.push(unseen);
        match w.gate(CAROL)?.acknowledge(&asked).await {
            Err(DataError::BadRequest { why, .. }) if why.contains(&unseen.to_string()) => {}
            other => {
                return Err(Failure::new(format!(
                    "acknowledging an id the device never had is refused naming it, got {other:?}"
                )));
            }
        }
        ensure!(
            w.gate(CAROL)?.pending_events() == before,
            "a refused acknowledgement changed what is pending"
        );

        // Acknowledged: gone, idempotently, and still gone after the next restart.
        w.gate(CAROL)?.acknowledge(&ids).await?;
        w.gate(CAROL)?.acknowledge(&ids).await?;
        ensure!(
            w.gate(CAROL)?.pending_events().is_empty(),
            "acknowledged events are still pending: {:?}",
            w.gate(CAROL)?.pending_events()
        );
        w.stop(CAROL).await?;
        w.restart(CAROL).await?;
        w.sleep(SETTLE).await;
        ensure!(
            w.gate(CAROL)?.pending_events().is_empty(),
            "after the restart the acknowledged events came again: {:?}",
            w.gate(CAROL)?.pending_events()
        );
        Ok(())
    })
}
