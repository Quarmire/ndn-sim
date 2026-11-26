//! Channels, c23 — Alice and Bob draw together; each one's live messages reach the other over
//! the network.
//!
//! (Ported from the signal case e1.) Alice creates her sketch space with Bob a writer. Each
//! device asks the other's channel, so each is a sender and a receiver. Alice moves her cursor
//! across the sketch at 60 Hz for half a second and says she is here; Bob does the same. The hub
//! between their devices is the relay every frame crosses. Each ends by emitting its last cursor
//! and its presence until the other has seen them, as a host emits its latest value again until
//! it is seen.
//!
//! The guard: each member's last message per path reaches the other member, attributed to the
//! sender's device; and whatever the network did, every message delivered is one its sender
//! emitted, delivered once, never older than one delivered before it at the same path.

use std::time::Duration;

use ndn_heap::Name;

use super::channel_kit::{Listener, emit_until_seen};
use super::channel_ledger::Ledger;
use super::kit::{n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c23",
    title: "A member's live messages reach the other members",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "The live messages one member emits into a space reach every other member over the \
             network: the last message per path of each sender is delivered, attributed to the \
             sender's device, and every delivery is one its sender emitted, delivered once and \
             never older than one delivered before it at the same path.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// Cursor moves each emits: half a second at 60 Hz.
const MOVES: u64 = 30;

/// One frame at 60 Hz.
const FRAME: Duration = Duration::from_millis(16);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

/// The runs `who` emits, in order: moves and presence, then the last of each.
fn ledger(who: &str) -> Ledger {
    let (move_, here, last_move, last_here) = match who {
        "alice" => (
            "alice:move",
            "alice:here",
            "alice:last-move",
            "alice:last-here",
        ),
        _ => ("bob:move", "bob:here", "bob:last-move", "bob:last-here"),
    };
    Ledger::new()
        .run("/cursor", move_)
        .run("/presence", here)
        .run("/cursor", last_move)
        .run("/presence", last_here)
}

/// The last message `l` was given at `path`.
fn last_at(l: &Listener, path: &Name) -> Option<String> {
    l.events.iter().rev().find_map(|e| match e {
        ChannelEvent::Message { path: p, bytes, .. } if p == path => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
        _ => None,
    })
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&super::channel_kit::space(), private(&["/bob"], &["/bob"]))
            .await?;
        let alice_tx = w.channels(ALICE).await?;
        let bob_tx = w.channels(BOB).await?;
        let mut at_bob = Listener::join(w, BOB, ChannelTrust::Prompt, ALICE).await?;
        let mut at_alice = Listener::join(w, ALICE, ChannelTrust::Prompt, BOB).await?;
        let space = super::channel_kit::space();

        let start = tokio::time::Instant::now();
        for i in 0..MOVES {
            alice_tx
                .emit(&space, &n("/cursor"), Ledger::payload("alice:move", i))
                .await?;
            bob_tx
                .emit(&space, &n("/cursor"), Ledger::payload("bob:move", i))
                .await?;
            if i == 0 {
                alice_tx
                    .emit(&space, &n("/presence"), Ledger::payload("alice:here", 0))
                    .await?;
                bob_tx
                    .emit(&space, &n("/presence"), Ledger::payload("bob:here", 0))
                    .await?;
            }
            w.sleep(FRAME).await;
        }
        for (tx, to, from) in [
            (&alice_tx, &mut at_bob, "alice"),
            (&bob_tx, &mut at_alice, "bob"),
        ] {
            let (last_move, last_here) = (format!("{from}:last-move"), format!("{from}:last-here"));
            emit_until_seen(w, tx, &n("/cursor"), &last_move, &mut [&mut *to]).await?;
            emit_until_seen(w, tx, &n("/presence"), &last_here, &mut [&mut *to]).await?;
        }
        w.converged(start.elapsed());

        let alice = w.net().spec(ALICE).name();
        let bob = w.net().spec(BOB).name();
        for (l, from, who) in [(&mut at_bob, &alice, "alice"), (&mut at_alice, &bob, "bob")] {
            l.pump();
            l.alive(who)?;
            let given = ledger(who).check(l, from)?;
            for (path, stem) in [("/cursor", "last-move"), ("/presence", "last-here")] {
                let last = last_at(l, &n(path));
                ensure!(
                    last.as_ref()
                        .is_some_and(|m| m.starts_with(&format!("{who}:{stem}#"))),
                    "device {}'s last message at {path} from {who} is {last:?}, not {who}'s last \
                     ({who}:{stem})",
                    l.dev.0
                );
            }
            w.measure(
                format!("messages {who} had delivered"),
                given as u64,
                "messages",
            );
        }
        Ok::<(), Failure>(())
    })
}
