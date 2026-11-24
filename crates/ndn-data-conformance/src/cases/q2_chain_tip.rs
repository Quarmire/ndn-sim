//! Chain 2 — a removal keeps exactly the chain ancestors of the tip the owner held.
//!
//! Alice's trip space has Bob as a writer. Bob's phone is copied, key and storage, after his first
//! entry. His disk then stops flushing while he signs two more entries, which Alice holds; the
//! phone dies with those two lost, Alice away, and starts again on what its disk held. His next
//! entry, signed with no peer to recover from, states the gap: it chains to his first entry, over
//! the two Alice holds, which become orphans inside the gap it declares. The copy, offline, signed
//! other bytes at the name of Bob's second entry. Alice, back while Bob's phone is away, removes
//! Bob: the cut names the highest of his entries she holds, the third, and the chain from it runs
//! through the orphans back to the first. Carol, a reader who never held any of it, joins while
//! only the copy answers for Bob's phone and a forwarder on the way holds the copy's bytes; Bob's
//! phone then comes back with the entry it signed after the crash.
//!
//! The guard: the cut keeps exactly the chain's ancestors of its tip, whatever the order in which
//! a reader finds things. The orphans the chain passes through are kept, on Alice and on Carol,
//! who never saw them signed; the copy's other bytes at a kept seq are refused (`OutsideCut`) and
//! never read, and Carol reads Bob's honest bytes by the name instead; the entry above the tip,
//! signed after the crash, is refused (`OutsideCut`) by both and not applied. Nothing the cut
//! keeps is ever withdrawn.

use std::time::Duration;

use super::chain_kit::put_ahead;
use super::kit::{
    LIMIT, LOOK, RELAYED, SETTLE, alerted, drain, drain_until, has, known, members_now, n, octets,
    op_is, people, public, stolen, value_now, withdrawn,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{AlertKind, EntryRead, RefusalKind, SpaceChange};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "q2",
    title: "A removal keeps exactly the chain ancestors of its tip",
    slice: 9,
    needs: &[Feature::Chain, Feature::Crash, Feature::RemovalCut],
    model: &[],
    guards: "A removal cut keeps exactly the chain's ancestors of the tip the owner held: an \
             orphan inside a declared gap that the chain passes through is kept (on a reader \
             that never saw it signed too), other bytes at a kept seq are refused as outside \
             the cut and never read, an entry above the tip is refused and not applied, and \
             nothing the cut keeps is withdrawn.",
    budget: Duration::from_secs(2400),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const THIEF: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    let bob = p.device("bob", "phone");
    p.device("carol", "laptop");
    p.thief(bob);
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let trip = n("/alice/32=data/trip");
        let (p1, p2, p3, p4) = (n("/p1"), n("/p2"), n("/p3"), n("/p4"));
        let bob_person = n("/bob");
        let (alice, carol) = (w.spaces(ALICE), w.spaces(CAROL));
        w.net().offline(CAROL);

        alice.create(&trip, public(&["/bob"])).await?;
        let bob = w.spaces(BOB);
        bob.open(&trip).await?;
        w.until("Bob holds the record admitting him", LIMIT, || {
            known(&*bob, &trip)
        })
        .await?;

        // Bob hears Alice (her entry reaches him), so his puts do not wait for his flush.
        let hello = w
            .space_put(ALICE, &trip, &n("/hello"), octets("alice: hello"))
            .await?;
        w.until("Bob holds Alice's entry", LIMIT, || {
            has(&*bob, &trip, &hello)
        })
        .await?;
        let mut alice_feed = alice.watch(&trip).await?;
        let mut alice_seen = Vec::new();

        let one = w.space_put(BOB, &trip, &p1, octets("bob: one")).await?;
        w.until("Alice holds Bob's first entry", LIMIT, || {
            has(&*alice, &trip, &one)
        })
        .await?;

        // The copy of the phone, with the first entry; offline.
        stolen(w, THIEF, &trip, &one).await?;
        w.net().offline(THIEF);

        // Bob's disk stops flushing; he signs two more entries, which Alice holds, and the copy
        // signs other bytes at the name of the second.
        w.block_flush(BOB, true).await?;
        let two = put_ahead(w, BOB, &trip, &p2, "bob: two").await?;
        let three = put_ahead(w, BOB, &trip, &p3, "bob: three").await?;
        w.until(
            "Alice holds Bob's second and third entries",
            LIMIT,
            || async { Ok(has(&*alice, &trip, &two).await? && has(&*alice, &trip, &three).await?) },
        )
        .await?;
        let other = w
            .space_put(THIEF, &trip, &p2, octets("the copy: other bytes"))
            .await?;
        ensure!(
            other.name == two.name && other.signed != two.signed,
            "precondition: the copy signs other bytes at the name of Bob's second entry ({}); it \
             signed {} (same bytes: {})",
            two.name,
            other.name,
            other.signed == two.signed
        );

        // The phone dies with Alice away, and starts again on what its disk held: the first
        // entry only. Its next entry states the gap.
        w.net().offline(ALICE);
        let bob = w.crash(BOB).await?;
        w.block_flush(BOB, false).await?;
        bob.open(&trip).await?;
        w.until("Bob's phone holds what its disk held", LIMIT, || {
            has(&*bob, &trip, &one)
        })
        .await?;
        ensure!(
            !has(&*bob, &trip, &two).await? && !has(&*bob, &trip, &three).await?,
            "precondition: the crash lost the two entries Bob's disk had not flushed, which only \
             Alice holds"
        );
        let late = w
            .space_put(BOB, &trip, &p4, octets("bob: after the crash"))
            .await?;
        ensure!(
            late.seq > three.seq,
            "precondition: Bob's first entry after the crash (seq {}) follows the ones it lost \
             (seq {})",
            late.seq,
            three.seq
        );

        // Alice is back while Bob's phone is away, and removes him: the cut names her highest.
        w.net().offline(BOB);
        w.net().online(ALICE);
        alice
            .change(
                &trip,
                SpaceChange {
                    remove: people(&["/bob"]),
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.until("Alice's record no longer lists Bob", LIMIT, || async {
            Ok(members_now(&*alice, &trip)
                .await?
                .is_some_and(|m| !m.writers.contains(&bob_person)))
        })
        .await?;

        // Caches on the way drop Bob's packets; the copy comes online while Bob's phone is away
        // and a passer-by asks a forwarder for the entry at the kept name: only the copy answers.
        // Carol, who never held any of it, joins now.
        w.net().forget_cached(&w.net().spec(BOB).name()).await;
        w.net().online(THIEF);
        let _ = w.net().ask_at_hub(&two.name).await;
        w.net().online(CAROL);
        carol.open(&trip).await?;
        let mut carol_feed = carol.watch(&trip).await?;
        let mut carol_seen = Vec::new();
        w.until("Carol holds the record that removed Bob", LIMIT, || async {
            Ok(members_now(&*carol, &trip)
                .await?
                .is_some_and(|m| !m.writers.contains(&bob_person)))
        })
        .await?;
        w.until(
            "Carol reads Bob's second entry by its name, and never the copy's bytes",
            RELAYED,
            || async {
                match carol.entry(&trip, &two.name).await? {
                    EntryRead::Read(item) => {
                        ensure!(
                            op_is(&item, "bob: two"),
                            "Carol reads {:?} at {}, a name the removal cut kept: the copy's \
                             other bytes, not Bob's",
                            String::from_utf8_lossy(&item.bytes),
                            two.name
                        );
                        Ok(item.signed == two.signed)
                    }
                    EntryRead::Refused { kind, text } => {
                        ensure!(
                            kind == RefusalKind::OutsideCut,
                            "Carol refuses the copy's bytes at {} as {kind:?} ({text}), not as \
                             outside the removal cut",
                            two.name
                        );
                        Ok(false)
                    }
                    EntryRead::NotHeld => Ok(false),
                }
            },
        )
        .await?;
        w.until(
            "Carol holds the three entries the cut keeps, the orphans among them",
            RELAYED,
            || async {
                Ok(has(&*carol, &trip, &one).await?
                    && has(&*carol, &trip, &two).await?
                    && has(&*carol, &trip, &three).await?)
            },
        )
        .await?;

        // The copy goes away and Bob's phone comes back with the entry it signed after the
        // crash, which lies above the tip. A phone that learned it was removed would refuse its
        // own entry and serve it to no one, so it is cut off from the devices that hold the
        // removal until Alice has been offered the entry: what the case asks is what a reader
        // does with it.
        w.net().offline(THIEF);
        let from_alice = w.net().cut_off(BOB, &w.net().spec(ALICE).name()).await;
        let from_carol = w.net().cut_off(BOB, &w.net().spec(CAROL).name()).await;
        w.net().online(BOB);
        drain_until(
            &mut *alice_feed,
            &mut alice_seen,
            "Alice is told of an entry outside the removal cut (Bob's entry above the tip)",
            RELAYED,
            |events| alerted(events, |kind| matches!(kind, AlertKind::OutsideCut)),
        )
        .await?;
        from_alice.restore();
        from_carol.restore();
        w.sleep(SETTLE).await;

        drain(&mut *alice_feed, LOOK, &mut alice_seen).await?;
        drain(&mut *carol_feed, LOOK, &mut carol_seen).await?;
        for (who, spaces, seen) in [
            ("Alice", &alice, &alice_seen),
            ("Carol", &carol, &carol_seen),
        ] {
            for (what, entry) in [("first", &one), ("second", &two), ("third", &three)] {
                ensure!(
                    has(&**spaces, &trip, entry).await?,
                    "{who} does not hold Bob's {what} entry, which the removal cut keeps"
                );
                ensure!(
                    !withdrawn(seen, &entry.key()),
                    "{who} is told Bob's {what} entry is withdrawn, though the removal cut keeps it"
                );
            }
            for (what, entry) in [
                ("the copy's other bytes at a kept seq", &other),
                ("Bob's entry above the tip", &late),
            ] {
                ensure!(
                    !has(&**spaces, &trip, entry).await?,
                    "{who} applies {what} ({}), outside the removal cut",
                    entry.name
                );
            }
            for (path, want) in [
                (&p1, Some("bob: one")),
                (&p2, Some("bob: two")),
                (&p3, Some("bob: three")),
                (&p4, None),
            ] {
                let got = value_now(&**spaces, &trip, path).await?;
                ensure!(
                    got.as_deref() == want.map(str::as_bytes),
                    "{who} reads {:?} at {path}; the cut keeps {:?}",
                    got.map(|v| String::from_utf8_lossy(&v).into_owned()),
                    want
                );
            }
        }
        Ok(())
    })
}
