//! Channels, c29 — live data leaves nothing behind in any store.
//!
//! (Ported from the signal case e7.) Alice and Bob draw together in Alice's space, each emitting
//! cursor moves and presence until the other has seen the last. The relay between their devices
//! forwards the asks, the sessions that answer them and every frame, and its side table counts
//! the frames it fans out.
//!
//! The guard: afterwards no forwarder's content store (the relay's, Alice's node's, Bob's
//! node's) holds a packet named under `32=chan`, so neither a session Data (`NoCache`) nor any
//! other channel packet was kept, and no device's data store holds one; the frames did cross the
//! relay (its side table fanned them out), so the case flowed live data; and asking the network
//! for a session by the name of the ask it answered gets nothing back, as no one serves or
//! caches one.

use std::time::Duration;

use ndn_heap::Name;
use ndn_packet::Interest;

use super::channel_kit::{Listener, QUIET, emit_until_seen, space};
use super::channel_ledger::Ledger;
use super::kit::{n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::ChannelTrust;
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Fwd, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c29",
    title: "No store keeps a channel packet",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "Live data is never stored: after a channel flowed, no forwarder's content store and \
             no device's store holds a packet named under 32=chan, frames crossed the relay on \
             its side table, and no one answers a session's name.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// How many cursor moves each emits.
const MOVES: u64 = 30;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

/// Whether `name` is a channel packet's: an ask or the session that answers it.
fn names_channel(name: &Name) -> bool {
    // `32=chan` as a name prints it.
    name.to_string().contains(&n("/32=chan").to_string())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = space();
        w.gesture();
        w.spaces(ALICE)
            .create(&space, private(&["/bob"], &["/bob"]))
            .await?;
        let taps = [
            w.net().tap(&w.net().spec(ALICE).name()).await,
            w.net().tap(&w.net().spec(BOB).name()).await,
        ];
        let alice_tx = w.channels(ALICE).await?;
        let bob_tx = w.channels(BOB).await?;
        let mut at_bob = Listener::join(w, BOB, ChannelTrust::Prompt, ALICE).await?;
        let mut at_alice = Listener::join(w, ALICE, ChannelTrust::Prompt, BOB).await?;
        let frames_before = w.net().side_counts(Fwd::Hub).frames_in;
        for i in 0..MOVES {
            alice_tx
                .emit(&space, &n("/cursor"), Ledger::payload("alice:move", i))
                .await?;
            bob_tx
                .emit(&space, &n("/cursor"), Ledger::payload("bob:move", i))
                .await?;
            w.sleep(Duration::from_millis(16)).await;
        }
        emit_until_seen(
            w,
            &alice_tx,
            &n("/presence"),
            "alice:here",
            &mut [&mut at_bob],
        )
        .await?;
        emit_until_seen(
            w,
            &bob_tx,
            &n("/presence"),
            "bob:here",
            &mut [&mut at_alice],
        )
        .await?;
        w.sleep(QUIET).await;

        let cached: Vec<Name> = w
            .net()
            .cached()
            .await
            .into_iter()
            .filter(names_channel)
            .collect();
        ensure!(
            cached.is_empty(),
            "a content store holds packets named under 32=chan: {cached:?}"
        );
        for d in [ALICE, BOB] {
            let stored: Vec<Name> = w
                .stored_names(d)?
                .into_iter()
                .filter(names_channel)
                .collect();
            ensure!(
                stored.is_empty(),
                "{}'s data layer stores packets named under 32=chan: {stored:?}",
                w.net().spec(d).name()
            );
        }
        let frames = w.net().side_counts(Fwd::Hub).frames_in - frames_before;
        ensure!(
            frames > 0,
            "no frame crossed the relay's side table: the case flowed no live data"
        );

        // A session rides the ask's name only: no one answers it by that name.
        let mut asked = 0u64;
        for tap in &taps {
            for wire in tap.interests() {
                let Ok(interest) = Interest::decode(wire) else {
                    continue;
                };
                if !names_channel(&interest.name) {
                    continue;
                }
                asked += 1;
                ensure!(
                    !w.net().ask_at_hub(&interest.name).await,
                    "something answered the session by the ask's name {}",
                    interest.name
                );
            }
        }
        ensure!(asked > 0, "the relay carried no ask: no session was made");
        w.measure("frames the relay's side table fanned out", frames, "frames");
        Ok::<(), Failure>(())
    })
}
