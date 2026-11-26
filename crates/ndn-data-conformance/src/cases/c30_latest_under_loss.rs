//! Channels, c30 — the newest per path, over a path that loses and reorders.
//!
//! (Ported from the signal case e8.) Alice and Bob share Alice's space. On the way into each
//! device, one frame in five is lost, one in ten arrives twice, and three in ten are held behind
//! those after them. Alice drags her cursor for three seconds at 60 Hz and says what she is doing
//! every half second; then she emits her last cursor and her last presence again and again until
//! Bob has each, as a host emits its latest value again until it is seen.
//!
//! The guard: Bob's receiver never delivers an older message after a newer one at the same path,
//! never delivers one twice, and ends with Alice's last cursor and her last presence.

use std::time::Duration;

use ndn_sim::Faults;

use super::channel_kit::{Listener, QUIET, emit_until_seen, space};
use super::channel_ledger::Ledger;
use super::kit::{n, private};
use crate::case::{Case, CaseFuture};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c30",
    title: "The newest message per path, under loss and reordering",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "Over a path that drops, duplicates and reorders frames, a receiver delivers per \
             path only messages newer than the last it delivered, each once, and the last value \
             a sender emits again until it is seen is delivered.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// Three seconds of cursor moves at 60 Hz.
const MOVES: u64 = 180;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.faults(Faults {
        drop: 0.2,
        dup: 0.1,
        delay_ms: 400,
        reorder: 0.3,
        seed: 1,
        ..Faults::default()
    });
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = space();
        w.gesture();
        w.spaces(ALICE)
            .create(&space, private(&[], &["/bob"]))
            .await?;
        let alice_tx = w.channels(ALICE).await?;
        let mut bob = Listener::join(w, BOB, ChannelTrust::Prompt, ALICE).await?;
        let start = tokio::time::Instant::now();
        for i in 0..MOVES {
            alice_tx
                .emit(&space, &n("/cursor"), Ledger::payload("alice:move", i))
                .await?;
            if i % 30 == 0 {
                alice_tx
                    .emit(
                        &space,
                        &n("/presence"),
                        Ledger::payload("alice:here", i / 30),
                    )
                    .await?;
            }
            w.sleep(Duration::from_millis(16)).await;
        }
        emit_until_seen(
            w,
            &alice_tx,
            &n("/cursor"),
            "alice:last-move",
            &mut [&mut bob],
        )
        .await?;
        emit_until_seen(
            w,
            &alice_tx,
            &n("/presence"),
            "alice:last-here",
            &mut [&mut bob],
        )
        .await?;
        w.converged(start.elapsed());
        // What the network still holds is delivered or lost by now.
        w.sleep(QUIET).await;
        bob.heal(w).await?;
        bob.pump();
        bob.alive("bob")?;

        for (path, stem) in [
            ("/cursor", "alice:last-move"),
            ("/presence", "alice:last-here"),
        ] {
            let last = bob.events.iter().rev().find_map(|e| match e {
                ChannelEvent::Message { path: p, bytes, .. } if *p == n(path) => {
                    Some(bytes.clone())
                }
                _ => None,
            });
            ensure!(
                last.as_ref()
                    .is_some_and(|b| b.starts_with(stem.as_bytes())),
                "bob's last message at {path} from alice is {last:?}, not her last ({stem})"
            );
        }
        let given = Ledger::new()
            .run("/cursor", "alice:move")
            .run("/presence", "alice:here")
            .run("/cursor", "alice:last-move")
            .run("/presence", "alice:last-here")
            .check(&bob, &w.net().spec(ALICE).name())?;
        w.measure("moves alice emitted", MOVES, "messages");
        w.measure("messages bob was given", given as u64, "messages");
        Ok(())
    })
}
