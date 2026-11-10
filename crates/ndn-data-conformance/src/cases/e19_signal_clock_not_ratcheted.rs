//! Signals, e19 — a crash loop and a clock corrected after a forward step leave a member's
//! clock at real time.
//!
//! Alice and Bob share Alice's sealed sketch folder, both writers. Both subscribe and open a
//! run. Bob's device then stops and starts again a dozen times in a row, each start opening a run
//! and sending a cursor move. Then Bob's clock steps two hours forward while his device runs, he
//! sends, and the clock is corrected; then it steps forward again, his device stops, the clock is
//! corrected and it starts again.
//!
//! The guard: nothing Bob's device did leaves its clock ahead of real time. After the crash loop
//! it still delivers what Alice sends (a clock held ahead by the restarts would judge her
//! signals expired) and its own signals are dated by its clock, not seconds ahead of it. After
//! each forward step, once the clock is corrected, his final reaches Alice, acknowledged: his
//! signals are dated by the corrected clock, not by the step. Sequences come from a durable
//! counter, so none of this can lower one (spec signals.md §3.3, §3.5, §13.8).

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e19",
    title: "A crash loop and a corrected clock leave a member's clock at real time",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "A member whose device restarts many times in a row, or whose clock stepped two \
             hours forward and was corrected, dates its signals by its clock as it reads now \
             and still delivers what others send: its clock is not ratcheted ahead of real \
             time, and it judges arriving signals by its own clock.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// Starts of Bob's device in a row: enough that a clock moved five seconds ahead by each is more
/// than the 30 s a receiver allows (and the 90 s a sender may be ahead by at 18).
const RESTARTS: usize = 12;
/// Cursor moves Bob sends while his clock is ahead: a third of a second at 60 Hz.
const MOVES: usize = 20;
const TWO_HOURS: Duration = Duration::from_secs(2 * 3600);
/// The default `Expires` of a signal, in ms: a signal is dated by its `Expires` less this.
const TTL_MS: u64 = 2_000;
/// How far from Bob's clock a signal of his may be dated: the time it took to send and be heard.
const DATED_WITHIN_MS: u64 = 5_000;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

fn folder() -> Name {
    n("/alice/32=data/sketch")
}

/// How far from Bob's own clock the last signal of his that `alice` delivered is dated.
fn dated_off(w: &World, alice: &Peer, bob: &Peer) -> Result<u64, Failure> {
    let heard = alice
        .latest(bob, b"cursor")
        .ok_or_else(|| Failure::new("Alice heard none of Bob"))?;
    Ok((heard.expires - TTL_MS).abs_diff(w.net().date(BOB).0))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.at(ALICE)
            .share_folder(&folder(), sealed_to(&["/alice", "/bob"]).into())
            .await?;
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let mut bob = Peer::join(w, BOB, &folder()).await?;

        // A crash loop: Bob's device starts again and again, each time opening a run and sending.
        for i in 0..RESTARTS {
            bob.send("cursor", &format!("bob:loop:{i}")).await?;
            w.sleep(FRAME).await;
            drop(bob);
            w.stop(BOB).await?;
            w.restart(BOB).await?;
            bob = Peer::join(w, BOB, &folder()).await?;
        }
        // Bob still delivers Alice's signals: his clock was not held ahead by the restarts.
        alice
            .send_final("cursor", "final:alice:after-loop", &[&bob])
            .await?;
        bob.send_final("cursor", "final:bob:after-loop", &[&alice])
            .await?;
        let off = dated_off(w, &alice, &bob)?;
        ensure!(
            off <= DATED_WITHIN_MS,
            "after {RESTARTS} restarts in a row Bob's signals are dated {off} ms from his own \
             clock, not within {DATED_WITHIN_MS} ms: each start held his clock further ahead"
        );
        w.measure(
            "How far from his clock Bob's signals are dated after the crash loop",
            off,
            "ms",
        );

        // A forward step while the device runs, then the clock corrected.
        w.net().set_clock(BOB, ClockSkew::ahead(TWO_HOURS));
        for i in 0..MOVES {
            bob.send("cursor", &format!("bob:ahead:{i}")).await?;
            w.sleep(FRAME).await;
        }
        w.net().set_clock(BOB, ClockSkew::NONE);
        bob.send_final("cursor", "final:bob:corrected", &[&alice])
            .await?;
        let off = dated_off(w, &alice, &bob)?;
        ensure!(
            off <= DATED_WITHIN_MS,
            "after his clock stepped two hours forward and was corrected, Bob's signals are \
             dated {off} ms from his clock, not within {DATED_WITHIN_MS} ms"
        );
        w.measure(
            "How far from his clock Bob's signals are dated after a corrected step",
            off,
            "ms",
        );

        // A forward step, the device stops, the clock is corrected, and the device starts again.
        w.net().set_clock(BOB, ClockSkew::ahead(TWO_HOURS));
        for i in 0..MOVES {
            bob.send("cursor", &format!("bob:again:{i}")).await?;
            w.sleep(FRAME).await;
        }
        drop(bob);
        w.stop(BOB).await?;
        w.net().set_clock(BOB, ClockSkew::NONE);
        w.restart(BOB).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        alice
            .send_final("cursor", "final:alice:restarted", &[&bob])
            .await?;
        bob.send_final("cursor", "final:bob:restarted", &[&alice])
            .await?;
        let off = dated_off(w, &alice, &bob)?;
        ensure!(
            off <= DATED_WITHIN_MS,
            "after a restart on a corrected clock Bob's signals are dated {off} ms from his \
             clock, not within {DATED_WITHIN_MS} ms: the two hours of the step were kept"
        );
        w.measure(
            "How far from his clock Bob's signals are dated after a restart on a corrected clock",
            off,
            "ms",
        );
        Ok(())
    })
}
