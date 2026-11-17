//! Device events, v1 — a members record and a version at one seq of one key are an equivocation
//! no folder's watch can carry, and every device that holds both is told.
//!
//! A key's log is one sequence across its collections and entry kinds. Alice's laptop is copied
//! while it holds her trip folder; the copy, offline, signs a folder members record at the seq
//! Alice's laptop signs a version of the plan at, and writes on. Bob and Carol, who hold Alice's
//! version, take the copy's record once it is the only one of the two that answers. `Change`'s
//! equivocation tells watchers of versions in two collections; here one entry is a members
//! record, so before device events it was kept as evidence and told to no one.
//!
//! The guard: each of the two readers' devices reports one equivocation event for Alice's key,
//! with both entries by name, kind and digest (a version and a members record), what it means (both
//! kept) and what to do (a device with the owner's authority marks the key suspected) — and
//! nothing of what the entries say.

use std::time::Duration;

use ndn_data::{EntryKind, EventDetail, EventKind, EventSubject, Meaning, NextStep, ShareChange};

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "v1",
    title: "A members record and a version at one seq of a key are told on the device",
    slice: 7,
    needs: &[
        Feature::Merge,
        Feature::FolderMembers,
        Feature::DeviceEvents,
    ],
    model: &["M14"],
    guards: "Two different entries of one key at one seq are an equivocation event on every \
             device that holds both, whatever their kinds: here a version and a folder members \
             record. The event carries both entries by name, kind and digest, says both are \
             kept and that a device with the owner's authority should mark the key suspected, \
             and carries nothing of their content.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const COPY: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    let alice = p.device("alice", "laptop");
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p.thief(alice);
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let trip = n("/alice/32=data/trip");
        let notes = trip.clone().append("notes");
        let alices = w.net().spec(ALICE).name();
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        alice
            .share_folder(&trip, members(merge(), &["/alice"], &[]).into())
            .await?;
        let seed = alice.put(&notes, text("a plan"), note(1)).await?;
        w.until("Bob and Carol hold the plan", LIMIT, || async {
            Ok(has(&*bob, &notes, &seed).await? && has(&*carol, &notes, &seed).await?)
        })
        .await?;

        // The copy: Alice's laptop, key and storage, switched on by a thief and then offline.
        w.steal(COPY).await?;
        let copy = w.at(COPY);
        w.until("the copy knows the folder", LIMIT, || known(&*copy, &notes))
            .await?;
        w.net().offline(COPY);

        // Alice's laptop signs a version; the copy, unaware, signs a folder record at the same
        // seq and then a version, so that its head is past what Bob and Carol hold of the key.
        w.gesture();
        let honest = alice.put(&notes, text("alice's second"), note(1)).await?;
        w.until("Bob and Carol hold it", LIMIT, || async {
            Ok(has(&*bob, &notes, &honest).await? && has(&*carol, &notes, &honest).await?)
        })
        .await?;
        copy.share_folder(
            &trip,
            ShareChange {
                add_writers: vec![n("/carol")],
                ..ShareChange::default()
            }
            .into(),
        )
        .await?;
        copy.put(&notes, text("the copy's"), note(1)).await?;

        // Now only the copy answers for the key.
        w.net().offline(ALICE);
        w.net().online(COPY);
        let last = std::cell::RefCell::new(String::new());
        w.until(
            "Bob's and Carol's devices each report the equivocation",
            LIMIT,
            || async {
                for (who, d) in [("Bob", BOB), ("Carol", CAROL)] {
                    let events = events_of(w, d, EventKind::Equivocation)?;
                    if !events.iter().any(
                        |e| matches!(e.subject(), EventSubject::Writer(k) if k.has_prefix(&alices)),
                    ) {
                        *last.borrow_mut() =
                            format!("{who}'s device reports {events:?} for Alice's key");
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await
        .map_err(|e| Failure::new(format!("{e}; at the last look: {}", last.borrow())))?;

        for (who, d) in [("Bob", BOB), ("Carol", CAROL)] {
            let events = events_of(w, d, EventKind::Equivocation)?;
            let e = events
                .iter()
                .find(|e| matches!(e.subject(), EventSubject::Writer(k) if k.has_prefix(&alices)))
                .expect("reported above");
            let EventDetail::Equivocation {
                writer,
                seq,
                first,
                second,
            } = &e.detail
            else {
                return Err(Failure::new(format!("{who}: not an equivocation: {e:?}")));
            };
            ensure!(
                *seq == honest.seq.0 && *writer == honest.writer.key().clone(),
                "{who}: the event names seq {seq} of {writer}, not Alice's version at \
                 {:?} of {}",
                honest.seq,
                honest.writer.key()
            );
            let mut kinds = [first.kind, second.kind];
            kinds.sort_by_key(|k| format!("{k:?}"));
            ensure!(
                kinds == [Some(EntryKind::Members), Some(EntryKind::Version)],
                "{who}: the two entries are a members record and a version, got {kinds:?}"
            );
            ensure!(
                first.name != second.name
                    && first.digest.is_some()
                    && second.digest.is_some()
                    && first.name.has_prefix(&alices)
                    && second.name.has_prefix(&alices),
                "{who}: the entries are named with the digests of the packets verified: \
                 {first:?}, {second:?}"
            );
            ensure!(
                e.meaning() == Meaning::BothKept && e.next_step() == NextStep::UseOwnerDevice,
                "{who}: the event says {:?} and {:?}",
                e.meaning(),
                e.next_step()
            );
            let said = format!("{e:?} {} {}", e.why(), e.what_to_do());
            ensure!(
                !said.contains("alice's second") && !said.contains("the copy's"),
                "{who}: the event carries what an entry says: {said}"
            );
        }
        Ok(())
    })
}
