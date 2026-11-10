//! Signals, e18 — a member whose clock stepped back across a restart is heard again.
//!
//! Alice and Bob share Alice's sealed sketch folder, both writers. Both subscribe and open a
//! run, and Bob draws; Alice hears him, and each ends with a last signal the other acknowledged.
//! Bob's device then stops, its clock steps back an hour (a clock set wrong, a machine whose
//! clock restarted before its last signals) and it starts again on what it stored, subscribes
//! and opens a new run. Bob draws again and sends a last signal.
//!
//! The guard: Bob's new signals are dated above everything his device dated before (its
//! durable clock floor, spec signals.md §3.5), so Alice delivers them: his new final reaches
//! her, acknowledged, and is never older than a signal she delivered before it from him. Without
//! the floor Bob's signals are dated an hour behind: their `Expires` is past for Alice, and
//! their sequences are below the run before it.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e18",
    title: "A member whose clock stepped back across a restart is heard again",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "A member that restarts with its clock an hour behind dates its signals above \
             everything its device dated before, so the other members deliver them: its new \
             final per address arrives, and no signal is delivered older than one before it.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// Cursor moves Bob sends in each run: a third of a second at 60 Hz.
const MOVES: usize = 20;
const HOUR: Duration = Duration::from_secs(3600);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

fn folder() -> Name {
    n("/alice/32=data/sketch")
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.at(ALICE)
            .share_folder(&folder(), sealed_to(&["/alice", "/bob"]).into())
            .await?;
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        for i in 0..MOVES {
            bob.send("cursor", &format!("bob:before:{i}")).await?;
            w.sleep(FRAME).await;
        }
        bob.send_final("cursor", "final:bob:before", &[&alice])
            .await?;
        let before = alice
            .latest(&bob, b"cursor")
            .ok_or_else(|| Failure::new("Alice heard none of Bob's first run"))?;

        // Bob's device stops, its clock steps back an hour, and it starts again.
        drop(bob);
        w.stop(BOB).await?;
        w.net().set_clock(BOB, ClockSkew::behind(HOUR));
        w.restart(BOB).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        for i in 0..MOVES {
            bob.send("cursor", &format!("bob:after:{i}")).await?;
            w.sleep(FRAME).await;
        }
        bob.send_final("cursor", "final:bob:after", &[&alice])
            .await?;
        let after = alice
            .latest(&bob, b"cursor")
            .ok_or_else(|| Failure::new("Alice heard none of Bob after his restart"))?;
        ensure!(
            after.payload == "final:bob:after".as_bytes() && after.seq > before.seq,
            "after Bob's restart with his clock an hour behind, Alice's last signal from him is \
             {:?} at seq {} (before it: seq {}), not his new final above it",
            String::from_utf8_lossy(&after.payload),
            after.seq,
            before.seq
        );
        // The moves go out while Alice may still be admitting his new header, and a faulty
        // network may lose them: only the final, sent until acknowledged, is guarded.
        let heard = alice.delivered("bob:after:");
        w.measure(
            "Bob's moves Alice delivered after the restart",
            heard as u64,
            "signals",
        );
        Ok(())
    })
}
