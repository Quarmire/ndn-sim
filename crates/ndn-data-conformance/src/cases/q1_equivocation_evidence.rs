//! Chain 1 — two packets at one name from a copied key are evidence, and the key is suspected.
//!
//! Alice's ledger has Bob as a writer. Bob's phone is copied, key and storage, after his first
//! entry; he then signs a second, which Alice holds, while the copy, offline, signs other bytes at
//! that very name (its next seq is the one Bob's second entry has). Bob goes away and the copy
//! comes online: it writes on from its own entry, so its next entry chains to bytes Alice does not
//! hold at the seq before it. A device that read the fork as a gap, or kept one of the two packets
//! without saying so, would let a copy of Bob's key decide what Alice's ledger shows; and one that
//! only noted the fork would go on taking what the copy signs next. The log keeps what it held,
//! raises an equivocation alert naming Bob's device and the seq of the two packets, refuses the
//! entry that forks the chain, and takes nothing more from the key until its revocation.
//!
//! The guard: two different packets at one name are never silent and never a choice: the watcher
//! is told, Alice's ledger keeps what she held before (both entries Bob signed), and what the
//! suspected key signs afterwards is not applied.

use std::time::Duration;

use super::kit::{
    LIMIT, SETTLE, alerted, drain_until, has, known, n, octets, public, stolen, value_now,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::AlertKind;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "q1",
    title: "Two packets at one name from a copied key are evidence and the key is suspected",
    slice: 9,
    needs: &[Feature::Chain],
    model: &[],
    guards: "Two different packets at one entry name are evidence, not a choice: the watcher is \
             told of the equivocation of that device at that seq, what the device held before \
             stays, the entry that forks the chain is not applied, and what the key signs after \
             the alert is not applied either.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const THIEF: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    let bob = p.device("bob", "phone");
    p.thief(bob);
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let ledger = n("/alice/32=data/ledger");
        let entries = n("/entries");
        let (alice, bob) = (w.spaces(ALICE), w.spaces(BOB));

        alice.create(&ledger, public(&["/bob"])).await?;
        bob.open(&ledger).await?;
        w.until("Bob holds the record admitting him", LIMIT, || {
            known(&*bob, &ledger)
        })
        .await?;
        let mut feed = alice.watch(&ledger).await?;
        let mut seen = Vec::new();

        let first = w
            .space_put(BOB, &ledger, &entries, octets("bob: first"))
            .await?;
        w.until("Alice holds Bob's first entry", LIMIT, || {
            has(&*alice, &ledger, &first)
        })
        .await?;

        // The key leaks with a copy of the storage; the thief stays offline for now. Bob signs a
        // second entry, which Alice holds, and the copy signs other bytes at its name.
        stolen(w, THIEF, &ledger, &first).await?;
        w.net().offline(THIEF);
        let second = w
            .space_put(BOB, &ledger, &entries, octets("bob: second"))
            .await?;
        w.until("Alice holds Bob's second entry", LIMIT, || {
            has(&*alice, &ledger, &second)
        })
        .await?;
        let other = w
            .space_put(THIEF, &ledger, &entries, octets("the copy: other bytes"))
            .await?;
        ensure!(
            other.name == second.name && other.signed != second.signed,
            "precondition: the copy signs other bytes at the name of Bob's second entry ({}); it \
             signed {} (same bytes: {})",
            second.name,
            other.name,
            other.signed == second.signed
        );

        // Bob goes away and the copy comes online. Its next entry chains to its own bytes at the
        // seq before it, and the notice of it reaches Alice, who asks the name of Bob's phone.
        w.net().offline(BOB);
        w.net().online(THIEF);
        let fork = w
            .space_put(THIEF, &ledger, &entries, octets("the copy: third"))
            .await?;
        ensure!(
            fork.seq == second.seq + 1,
            "precondition: the copy's next entry follows its other bytes (seq {}), got seq {}",
            second.seq + 1,
            fork.seq
        );
        drain_until(
            &mut *feed,
            &mut seen,
            "Alice is told of an equivocation of Bob's phone at the seq of the two packets",
            LIMIT,
            |events| {
                alerted(events, |kind| {
                    matches!(kind, AlertKind::Equivocation { device, seq }
                        if *device == second.writer && *seq == second.seq)
                })
            },
        )
        .await?;

        // The key is suspected from the alert on: what it signs now is not applied.
        let later = w
            .space_put(
                THIEF,
                &ledger,
                &entries,
                octets("the copy: after the alert"),
            )
            .await?;
        w.sleep(SETTLE).await;
        for (what, entry) in [
            ("the copy's other bytes at the name Alice held", &other),
            ("the copy's entry that forks the chain", &fork),
            ("an entry the suspected key signed after the alert", &later),
        ] {
            ensure!(
                !has(&*alice, &ledger, entry).await?,
                "Alice applies {what} ({}) of a key she was told signed two packets at one \
                 name",
                entry.name
            );
        }

        // What she held before the alert stays, and is what she reads.
        for (what, entry) in [("first", &first), ("second", &second)] {
            ensure!(
                has(&*alice, &ledger, entry).await?,
                "Alice no longer holds Bob's {what} entry after the alert"
            );
        }
        let value = value_now(&*alice, &ledger, &entries).await?;
        ensure!(
            value.as_deref() == Some(b"bob: second".as_slice()),
            "Alice reads {:?} at {entries}; she held Bob's second entry before the alert",
            value.map(|v| String::from_utf8_lossy(&v).into_owned())
        );
        Ok(())
    })
}
