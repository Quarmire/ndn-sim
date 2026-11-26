//! Channels, c24 — Carol, no member of Alice's spaces, tries to take part in their live data; Dave,
//! a mere reader, may only receive.
//!
//! (Ported from the signal case e2.) Alice keeps two spaces: a board open to anyone to read, which
//! Alice and Bob write, and a sketch with Bob a writer and Dave a reader. Carol's device follows
//! both, and neither lists her. Alice emits to Dave over the relay.
//!
//! The guards:
//! - Carol's ask of Alice's channel is refused in both spaces, the open board too: a public space
//!   does not make a listed person of her, and channels need one. The refusal says why and what
//!   to do; no session is ever given. She is given nothing of Alice's emissions, and holds no
//!   session to seal a frame under.
//! - A frame made without the channel's key, one a stranger on the path could make from a frame
//!   it saw (the header moved to a sequence the receiver has not seen), reads like Alice's and
//!   cannot open: Dave's receiver counts it unauthentic, and delivers nothing of it.
//! - Dave, a reader, asks and is answered, and receives what Alice emitted; his own emit is
//!   refused: only a writer's device emits.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;

use super::channel_kit::{
    Listener, QUIET, emit_until_seen, inject_until, rx_count, rx_state, space, until_ready,
};
use super::channel_ledger::{Ledger, refused_ask};
use super::frame_tap::{FrameTap, moved};
use super::kit::{n, private, public};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c24",
    title: "A stranger takes no part in a space's live data; a reader only receives",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A device no members record lists is refused when it asks a sender's channel, in an \
             open space too, and says why; a frame made without the channel's key does not \
             open and delivers nothing; a reader's ask is answered and it receives, and its \
             own emit is refused.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
// Device 1 is Bob, a writer of both spaces; he takes no step of his own.
const DAVE: Dev = Dev(2);
const CAROL: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("dave", "watch");
    p.device("carol", "tablet");
    p
}

/// Open to anyone to read; Alice and Bob write it.
fn board() -> Name {
    n("/alice/32=data/board")
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let sketch = space();
        let alice_spaces = w.spaces(ALICE);
        w.gesture();
        alice_spaces
            .create(&sketch, private(&["/bob"], &["/dave"]))
            .await?;
        w.gesture();
        alice_spaces.create(&board(), public(&["/bob"])).await?;
        let alice_tx = w.channels(ALICE).await?;
        let alice = w.net().spec(ALICE).name();

        // Dave, a reader, asks and is answered.
        let mut dave = Listener::join(w, DAVE, ChannelTrust::Prompt, ALICE).await?;
        until_ready(w, &[&dave], dave.channel, 1).await?;
        let tap = FrameTap::on(w, dave.channel)?;
        emit_until_seen(w, &alice_tx, &n("/cursor"), "alice:move", &mut [&mut dave]).await?;

        // His own emit is refused: only a writer's device emits.
        let emitted = dave
            .ch
            .emit(&sketch, &n("/cursor"), Bytes::from_static(b"dave:move#0"))
            .await;
        ensure!(
            matches!(&emitted, Err(e) if e.detail.contains("may not emit")),
            "a reader's emit answered {emitted:?}, not a refusal saying the device is no writer"
        );

        // Carol's ask is refused in both spaces, with a reason.
        let carol_spaces = w.spaces(CAROL);
        let carol = w.channels(CAROL).await?;
        for space in [&sketch, &board()] {
            w.retry_later(|| carol_spaces.open(space)).await?;
            refused_ask(w, &*carol, "carol", space, &alice).await?;
        }
        // She is given nothing of Alice's emissions, and holds no session to seal under.
        let carol_stream = carol.live(&sketch, ChannelTrust::Prompt).await;
        for _ in 0..4 {
            alice_tx
                .emit(&sketch, &n("/cursor"), Ledger::payload("alice:move", 100))
                .await?;
            w.sleep(Duration::from_millis(250)).await;
        }
        if let Ok(mut stream) = carol_stream {
            let given = stream
                .drain()
                .into_iter()
                .filter(|e| matches!(e, ChannelEvent::Message { .. }))
                .count();
            ensure!(
                given == 0,
                "carol's stream was given {given} messages of a channel she was refused"
            );
        }
        ensure!(
            carol
                .forge_data(dave.channel, 9, &n("/cursor"), b"carol:move")
                .is_err(),
            "carol sealed a frame of Alice's channel without ever holding its session"
        );

        // A frame made without the key reads like Alice's and does not open.
        let frame = tap
            .data()
            .pop()
            .ok_or_else(|| Failure::new("the relay forwarded no frame of Alice's channel"))?;
        let junk = moved(&frame, 1_000);
        // What the network still holds of Alice's emissions lands before the count is taken.
        w.sleep(QUIET).await;
        let (given, before) = {
            dave.pump();
            (dave.messages().len(), rx_count(&dave.ch, "unauthentic"))
        };
        inject_until(w, &mut dave, &junk, false, |l| {
            rx_count(&l.ch, "unauthentic") > before
        })
        .await
        .map_err(|e| Failure::new(format!("{e}; Dave's receiver: {}", rx_state(&dave.ch))))?;
        w.sleep(Duration::from_secs(1)).await;
        dave.pump();
        dave.alive("dave")?;
        ensure!(
            dave.messages().len() == given,
            "Dave was given a message from a frame made without the key: {} messages, there were \
             {given}",
            dave.messages().len()
        );
        Ledger::new()
            .run("/cursor", "alice:move")
            .check(&dave, &alice)?;
        w.measure(
            "frames without the key Dave's receiver counted unauthentic",
            rx_count(&dave.ch, "unauthentic") - before,
            "frames",
        );
        Ok(())
    })
}
