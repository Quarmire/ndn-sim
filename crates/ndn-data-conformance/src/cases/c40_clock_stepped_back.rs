//! Channels, c40 — a sender restarts with its clock an hour behind, and needs nothing durable.
//!
//! (A regression case of "no clock, no durable sequence": a channel keeps no clock floor and no
//! counter across a restart, channel.md 3.1, 3.5.)
//!
//! Alice and Bob write Alice's space. Alice asks Bob for his channel and Bob emits, a long
//! while, so that his session's sequences are well on. Bob's device then stops, its clock steps
//! back an hour (a clock set wrong, a machine whose clock restarted before its last emissions)
//! and it starts again on what it stored. Alice asks again.
//!
//! The guard: the one reading of the clock the setup makes is the ask's time, which a sender
//! requires within 120 s of its own: Alice's ask of the restarted sender is refused, closed,
//! while his clock is an hour off. The clock put right, the same ask sets up a session that is
//! new (another channel id, its sequences beginning afresh, below where the old one stood),
//! whose emissions Alice is given: nothing durable, and no clock floor, was needed.

use std::time::Duration;

use ndn_heap::Name;
use ndn_sim::ClockSkew;

use super::channel_kit::{Listener, emit_until_seen, space, until_ready};
use super::kit::{n, private};
use crate::case::{Case, CaseFuture};
use crate::channel::ChannelTrust;
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c40",
    title: "A sender restarted with its clock an hour behind is heard again, afresh",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A sender that restarts with its clock an hour behind is asked in vain while the \
             clock is off by more than the setup allows, and once the clock is right its new \
             session (a new channel id, sequences from the start) is set up and its emissions \
             are given: no durable clock or sequence is needed.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// Emissions of Bob's in the first session: enough that its sequences are well past a new
/// session's.
const MOVES: usize = 40;
const HOUR: Duration = Duration::from_secs(3600);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

fn cursor() -> Name {
    n("/cursor")
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&space(), private(&["/bob"], &["/bob"]))
            .await?;
        let mut alice = Listener::prepare(w, ALICE, ChannelTrust::Prompt).await?;
        let bob = Listener::prepare(w, BOB, ChannelTrust::Prompt).await?;
        alice.establish(w, BOB).await?;
        let first = alice.channel;
        until_ready(w, &[&alice], first, 1).await?;
        for i in 0..MOVES {
            let text = format!("before:{i}");
            bob.ch
                .emit(&space(), &cursor(), text.into_bytes().into())
                .await?;
            w.sleep(Duration::from_millis(20)).await;
        }
        emit_until_seen(w, &bob.ch, &cursor(), "final-before", &mut [&mut alice]).await?;
        // Where the first session stands, as Alice's session of it last heard.
        w.retry_later(|| alice.ask(w, BOB)).await?;
        let before = alice.ch.next_seq(first)?;
        ensure!(
            before > MOVES as u64,
            "Bob's first session stands at sequence {before} after {MOVES} emissions"
        );

        // Bob's device stops, its clock steps back an hour, and it starts again.
        drop(bob);
        w.stop(BOB).await?;
        w.net().set_clock(BOB, ClockSkew::behind(HOUR));
        w.restart(BOB).await?;
        let bob = Listener::prepare(w, BOB, ChannelTrust::Prompt).await?;

        // Alice's ask is refused while his clock is an hour off.
        alice.restart(w).await?;
        alice.events.clear();
        let refused = alice.ask(w, BOB).await;
        ensure!(
            refused.is_err(),
            "Alice was given a session by a sender whose clock is an hour behind hers: {refused:?}"
        );

        // The clock put right, the ask sets up a new session.
        w.net().set_clock(BOB, ClockSkew::NONE);
        w.sleep(Duration::from_secs(1)).await;
        alice.establish(w, BOB).await?;
        let second = alice.channel;
        ensure!(
            second != first,
            "the restarted sender answered with the old channel {first:016x}: it kept a session \
             across a restart"
        );
        until_ready(w, &[&alice], second, 1).await?;
        emit_until_seen(w, &bob.ch, &cursor(), "after", &mut [&mut alice]).await?;
        let now = alice.ch.next_seq(second)?;
        ensure!(
            now < before,
            "the new session's sequences stand at {now}, not afresh below the old session's \
             {before}"
        );
        alice.alive("Alice")?;
        w.measure("sequence the first session stood at", before, "seq");
        w.measure("sequence the new session began at", now, "seq");
        Ok(())
    })
}
