//! Channels, c37 — a frame at the largest sequences does not stop a receiver.
//!
//! Alice's laptop sends her pointer to Bob; Carol, a member, holds the channel's key like him. She
//! turns hostile and has a relay on Bob's link send him frames at the far end of the sequence
//! space:
//!
//! 1. **The largest sequence a frame may take, 2^63 − 1,** and **2^62**, each sealed under the
//!    channel's key, so each opens: far above anything the sender has sent, and above the bound
//!    on how far a receiver's window jumps (2^24).
//! 2. **2^63 and 2^64 − 1,** which no sealed frame may carry (the header says so before any
//!    cryptography): the header of one of Carol's frames with its sequence rewritten.
//!
//! The guard: Bob counts the first two as frames too far above his window (refused after they
//! opened, marking nothing) and the others as frames with a sequence no frame may have (refused
//! before they were opened); none is given to him; his window did not move, so Alice's frames go
//! on arriving as hers, his stream does not end, and none of it is evidence or a bar.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;

use super::channel_kit::{
    Listener, QUIET, channel_state, emit_until_seen, inject_until, rx_count, rx_state, space,
    until_ready,
};
use super::kit::{n, private};
use crate::case::{Case, CaseFuture};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Fwd, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c37",
    title: "A frame at the largest sequences does not stop a receiver",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A key holder's frame at the largest sequence a frame may take (or far above the \
             window) is refused after it opens, and a frame whose header names a sequence no \
             frame may have is refused before it is opened: none is given, the receiver's \
             window does not move, and the sender's later frames go on arriving.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "tablet");
    p
}

fn pointer() -> Name {
    n("/pointer")
}

/// `frame` with the first sequence its header names (octets 11 to 18) replaced by `seq0`.
fn resequenced(frame: &Bytes, seq0: u64) -> Bytes {
    let mut octets = frame.to_vec();
    octets[11..19].copy_from_slice(&seq0.to_be_bytes());
    Bytes::from(octets)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&space(), private(&[], &["/bob", "/carol"]))
            .await?;
        let sender = w.channels(ALICE).await?;
        let mut bob = Listener::join(w, BOB, ChannelTrust::Prompt, ALICE).await?;
        let carol = Listener::join(w, CAROL, ChannelTrust::Prompt, ALICE).await?;
        let channel = bob.channel;
        until_ready(w, &[&bob, &carol], channel, 2).await?;
        emit_until_seen(w, &sender, &pointer(), "before", &mut [&mut bob]).await?;

        let sealed = |seq0: u64| carol.ch.forge_data(channel, seq0, &pointer(), b"far");
        let valid = [("2^63 - 1", (1u64 << 63) - 1), ("2^62", 1u64 << 62)];
        let invalid = [("2^63", 1u64 << 63), ("2^64 - 1", u64::MAX)];
        let mut sent = 0u64;
        for (what, seq0, counter, why) in valid
            .iter()
            .map(|(what, seq0)| (*what, *seq0, "too_far", "a frame too far above the window"))
            .chain(invalid.iter().map(|(what, seq0)| {
                (
                    *what,
                    *seq0,
                    "sequence",
                    "a frame with a sequence none may have",
                )
            }))
        {
            // A frame sealed at a sequence a frame may take; the one with a sequence none may
            // take is that frame's header changed.
            let frame = if counter == "too_far" {
                sealed(seq0)?
            } else {
                resequenced(&sealed(1)?, seq0)
            };
            let before = rx_count(&bob.ch, counter);
            inject_until(w, &mut bob, &frame, false, |bob| {
                rx_count(&bob.ch, counter) > before
            })
            .await
            .map_err(|e| {
                crate::Failure::new(format!(
                    "the frame at {what} was not counted as {why} ({counter}): {e}; receiver \
                     [{}]; {}",
                    rx_state(&bob.ch),
                    channel_state(w, channel, &[Fwd::Hub, Fwd::Device(BOB)])
                ))
            })?;
            sent += 1;
        }
        w.sleep(QUIET).await;
        bob.pump();
        ensure!(
            !bob.has_stem(&pointer(), b"far"),
            "Bob was given a frame at a sequence no frame of Alice's could have: {:?}",
            bob.events
        );

        // Alice's frames still arrive: the window did not move.
        bob.heal(w).await?;
        emit_until_seen(w, &sender, &pointer(), "after", &mut [&mut bob]).await?;
        bob.pump();
        bob.alive("Bob")?;
        ensure!(
            bob.ch.evidence().is_empty() && w.net().side_barred(Fwd::Device(BOB)).is_empty(),
            "frames at the largest sequences left evidence {:?} or a bar {:?}",
            bob.ch.evidence(),
            w.net().side_barred(Fwd::Device(BOB))
        );
        let alice = w.net().spec(ALICE).name();
        for e in &bob.events {
            if let ChannelEvent::Message { path, writer, .. } = e {
                ensure!(
                    *writer == alice,
                    "{path} reached Bob from {writer}, not from Alice's device"
                );
            }
        }
        w.measure(
            "frames at the far end of the sequence space sent",
            sent,
            "frames",
        );
        Ok(())
    })
}
