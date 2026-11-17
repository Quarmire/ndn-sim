//! Device events, v5 — a flood of one subject is one event, and what was kept first stays.
//!
//! Carol's device reports Alice's cut of Bob. Alice's laptop is then copied, and for thirty
//! seqs the laptop signs a version of one collection while the copy, offline, signs a version of
//! another at the same seq: thirty equivocations of one key, which Carol's device meets one
//! after another when the copy is the only one that answers.
//!
//! The guard: the thirty are one event (the first occurrence kept, the rest coalesced into a
//! count and the last occurrence), the cut event kept before the flood is the same event
//! afterwards (id, cursor, count), no overflow notice is made for what the cap holds, and what
//! the store keeps for events does not grow with the flood.

use std::time::Duration;

use ndn_data::{EventDetail, EventKind, EventSubject};

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "v5",
    title: "A flood of equivocations is one event and the first cut event is kept",
    slice: 7,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::RemovalCut,
        Feature::FolderMembers,
        Feature::DeviceEvents,
    ],
    model: &["M14"],
    guards: "Per (kind, subject) the first event is kept until acknowledged and later ones are \
             coalesced into a count and the last occurrence: thirty equivocations of one key are \
             one event, an event of another kind kept before them is unchanged after them, and \
             what the device stores for events is bounded, not a record per occurrence.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const COPY: Dev = Dev(3);

/// How many seqs the laptop and the copy sign differently.
const SEQS: u64 = 30;

fn plan() -> Plan {
    let mut p = Plan::new();
    let alice = p.device("alice", "laptop");
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p.thief(alice);
    p
}

/// What `d`'s store keeps for events.
fn kept(w: &World, d: Dev) -> Result<usize, Failure> {
    let prefix = n("/localhost/ndn-data/events");
    Ok(w.stored_names(d)?
        .iter()
        .filter(|name| name.has_prefix(&prefix))
        .count())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let trip = n("/alice/32=data/trip");
        let (plan_c, other) = (trip.clone().append("plan"), trip.clone().append("other"));
        let alices = w.net().spec(ALICE).name();
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        let everyone = [person("/alice"), person("/bob"), person("/carol")];
        alice
            .share_folder(
                &trip,
                members(merge(), &["/alice", "/bob", "/carol"], &everyone).into(),
            )
            .await?;
        let seed = alice.put(&plan_c, text("plan"), note(1)).await?;
        let theirs = alice.put(&other, text("other"), note(1)).await?;
        w.until("Bob and Carol hold both", LIMIT, || async {
            Ok(has(&*bob, &plan_c, &seed).await?
                && has(&*carol, &plan_c, &seed).await?
                && has(&*carol, &other, &theirs).await?)
        })
        .await?;

        // The cut: Alice removes Bob; Carol's device reports it first.
        w.gesture();
        alice
            .share_folder(
                &trip,
                members(
                    merge(),
                    &["/alice", "/carol"],
                    &[person("/alice"), person("/carol")],
                )
                .into(),
            )
            .await?;
        w.until("Carol's device reports the cut", LIMIT, || async {
            Ok(!events_of(w, CAROL, EventKind::Cut)?.is_empty())
        })
        .await?;
        let cuts = events_of(w, CAROL, EventKind::Cut)?;

        // The copy, offline, while the laptop writes on.
        w.steal(COPY).await?;
        let copy = w.at(COPY);
        w.until("the copy knows both collections", LIMIT, || async {
            Ok(known(&*copy, &plan_c).await? && known(&*copy, &other).await?)
        })
        .await?;
        w.net().offline(COPY);
        let mut honest = Vec::new();
        for i in 0..SEQS {
            honest.push(
                alice
                    .put(&plan_c, text(&format!("plan {i}")), note(1))
                    .await?,
            );
        }
        w.until("Carol holds the laptop's versions", LIMIT, || {
            has(&*carol, &plan_c, honest.last().expect("some"))
        })
        .await?;
        let mut twins = Vec::new();
        for i in 0..SEQS {
            twins.push(
                copy.put(&other, text(&format!("other {i}")), note(1))
                    .await?,
            );
        }
        ensure!(
            twins[0].seq == honest[0].seq,
            "precondition: the copy signs again the seqs the laptop signed ({:?}, {:?})",
            honest[0].seq,
            twins[0].seq
        );
        let before = kept(w, CAROL)?;

        // Only the copy answers for the key now.
        w.net().offline(ALICE);
        w.net().online(COPY);
        let last = std::cell::RefCell::new(String::new());
        w.until("Carol's device meets the copy's entries", LIMIT, || async {
            let e = events_of(w, CAROL, EventKind::Equivocation)?;
            let count = e.iter().map(|e| e.count).max().unwrap_or(0);
            *last.borrow_mut() = format!("{count} occurrences in {e:?}");
            Ok(count >= SEQS / 2)
        })
        .await
        .map_err(|e| Failure::new(format!("{e}; at the last look: {}", last.borrow())))?;
        w.sleep(SETTLE).await;

        let eq = events_of(w, CAROL, EventKind::Equivocation)?;
        ensure!(
            eq.len() == 1
                && matches!(&eq[0].subject(), EventSubject::Writer(k) if k.has_prefix(&alices)),
            "the equivocations of one key are one event, got {eq:?}"
        );
        ensure!(
            eq[0].count >= SEQS / 2 && eq[0].count <= SEQS && eq[0].last.is_some(),
            "the occurrences are coalesced into a count of the thirty and the last one: {:?}",
            eq[0]
        );
        ensure!(
            matches!(&eq[0].detail, EventDetail::Equivocation { .. }),
            "{:?}",
            eq[0]
        );
        ensure!(
            events_of(w, CAROL, EventKind::Cut)? == cuts,
            "the cut event kept before the flood changed: before {cuts:?}, after {:?}",
            events_of(w, CAROL, EventKind::Cut)?
        );
        ensure!(
            events_of(w, CAROL, EventKind::Overflow)?.is_empty(),
            "an overflow notice for a flood the cap holds: {:?}",
            events_of(w, CAROL, EventKind::Overflow)?
        );
        let after = kept(w, CAROL)?;
        w.measure(
            "records Carol's store keeps for events, after the flood",
            after as u64,
            "records",
        );
        ensure!(
            after <= before + 2,
            "what the store keeps for events grew with the flood: {before} records before, \
             {after} after {SEQS} occurrences"
        );
        Ok(())
    })
}
