//! Channels, c41 — a crash loop and a clock corrected after a forward step leave nothing behind.
//!
//! (A regression case of "no clock, no durable sequence": nothing a restart or a clock step does
//! is kept, so nothing can be left ratcheted, channel.md 3.1, 3.5.)
//!
//! Alice and Bob write Alice's space; Alice asks Bob for his channel. Bob's device then stops and
//! starts again a dozen times in a row, each start answering Alice's new ask with a new session
//! that she is given emissions of. Then Bob's clock steps two hours forward while his device
//! runs, and is corrected; then it steps forward again, his device stops, the clock is corrected
//! and it starts again.
//!
//! The guard: after the crash loop a new ask is answered at once (no clock was held ahead by the
//! starts: the setup requires an ask's time within 120 s of the sender's clock, and twelve
//! restarts would have moved it by more than that if each kept a little). While the clock is two
//! hours ahead, the session already held goes on delivering (a frame reads no clock, a lifetime
//! is counted by the receiver's own monotonic clock) and a renewing ask is refused, closed,
//! without ending that session; once the clock is corrected the ask is answered. A restart on a
//! corrected clock sets up a session that is given emissions.
//!
//! The network is lossless here: the clock's effect, not the network's, is under test, and a
//! receiver that asks again after a lossy network ended its session would ask under the
//! stepped clock, which the setup refuses by design.

use std::time::Duration;

use ndn_heap::Name;
use ndn_sim::{ClockSkew, Faults};

use super::channel_kit::{Listener, emit_until_seen, space, until_ready};
use super::kit::{n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::ChannelTrust;
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c41",
    title: "A crash loop and a corrected clock leave a sender's setup unaffected",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A sender whose device restarts many times in a row answers the next ask with a \
             session that delivers; a clock two hours ahead refuses a renewing ask without \
             ending the session held and leaves it delivering; the clock corrected, the ask is \
             answered; a restart on a corrected clock gives a session that delivers.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// Starts of Bob's device in a row.
const RESTARTS: usize = 12;
const TWO_HOURS: Duration = Duration::from_secs(2 * 3600);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.faults(Faults::default());
    p
}

fn cursor() -> Name {
    n("/cursor")
}

/// Bob's device has started again: Alice takes the space live afresh and asks him for a new
/// session; returns his new listener.
async fn started_again(w: &World, alice: &mut Listener) -> Result<Listener, Failure> {
    w.restart(BOB).await?;
    let bob = Listener::prepare(w, BOB, ChannelTrust::Prompt).await?;
    alice.restart(w).await?;
    alice.events.clear();
    alice.establish(w, BOB).await?;
    until_ready(w, &[&*alice], alice.channel, 1).await?;
    Ok(bob)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&space(), private(&["/bob"], &["/bob"]))
            .await?;
        let mut alice = Listener::prepare(w, ALICE, ChannelTrust::Prompt).await?;
        let mut bob = Listener::prepare(w, BOB, ChannelTrust::Prompt).await?;
        alice.establish(w, BOB).await?;
        until_ready(w, &[&alice], alice.channel, 1).await?;

        // A crash loop: Bob's device starts again and again, each time answering a new ask and
        // emitting.
        let mut channels = vec![alice.channel];
        for i in 0..RESTARTS {
            emit_until_seen(
                w,
                &bob.ch,
                &cursor(),
                &format!("loop{i}"),
                &mut [&mut alice],
            )
            .await?;
            drop(bob);
            w.stop(BOB).await?;
            bob = started_again(w, &mut alice).await?;
            ensure!(
                !channels.contains(&alice.channel),
                "after restart {} Bob answered with the channel {:016x} of an earlier run",
                i + 1,
                alice.channel
            );
            channels.push(alice.channel);
        }
        emit_until_seen(w, &bob.ch, &cursor(), "after-loop", &mut [&mut alice]).await?;

        // A forward step while the device runs: the session held delivers, a renewing ask is
        // refused, and the session stands; the clock corrected, the ask is answered.
        w.net().set_clock(BOB, ClockSkew::ahead(TWO_HOURS));
        emit_until_seen(w, &bob.ch, &cursor(), "ahead", &mut [&mut alice]).await?;
        let refused = alice.ask(w, BOB).await;
        ensure!(
            refused.is_err(),
            "Bob, two hours ahead, answered Alice's renewing ask: {refused:?}"
        );
        emit_until_seen(w, &bob.ch, &cursor(), "still-ahead", &mut [&mut alice]).await?;
        w.net().set_clock(BOB, ClockSkew::NONE);
        let renewed = w.retry_later(|| alice.ask(w, BOB)).await?;
        ensure!(
            renewed == alice.channel,
            "the corrected sender answered the renewing ask with channel {renewed:016x}, not the \
             session's {:016x}",
            alice.channel
        );
        emit_until_seen(w, &bob.ch, &cursor(), "corrected", &mut [&mut alice]).await?;

        // A forward step, the device stops, the clock is corrected and the device starts again.
        w.net().set_clock(BOB, ClockSkew::ahead(TWO_HOURS));
        emit_until_seen(w, &bob.ch, &cursor(), "again-ahead", &mut [&mut alice]).await?;
        drop(bob);
        w.stop(BOB).await?;
        w.net().set_clock(BOB, ClockSkew::NONE);
        let bob = started_again(w, &mut alice).await?;
        emit_until_seen(w, &bob.ch, &cursor(), "restarted", &mut [&mut alice]).await?;
        alice.alive("Alice")?;
        w.measure(
            "restarts in a row answered with a new session",
            RESTARTS as u64,
            "restarts",
        );
        Ok(())
    })
}
