//! Channels, c35 — a flood of frames that fail to authenticate starves none of the genuine ones.
//!
//! Alice's laptop sends her drag to Bob for three seconds at 60 Hz. Carol, a member, holds the
//! channel's key like Bob; a relay on Bob's link turns hostile and, while Alice drags, sends him
//! about four hundred frames a second under Alice's channel id at the sequences Alice's own next
//! frames will take, each one an octet off what Carol sealed, so that none opens: more frames
//! than a receiver is meant to open of one channel, and carrying the very sequences the genuine
//! frames will carry.
//!
//! The network is lossless here: the guard counts every frame. The guard: Bob counts the flood as
//! frames that did not authenticate and gives none of them; a frame that does not authenticate
//! marks no sequence, so Alice's genuine frames at those sequences are all given, in order, as
//! hers; the flood is no evidence and no bar (it proves nothing of anyone), and no stream of
//! Bob's ends.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;
use ndn_sim::Faults;

use super::channel_kit::{
    Listener, QUIET, channel_state, emit_until_seen, rx_count, rx_state, space, until_ready,
};
use super::kit::{n, private};
use crate::case::{Case, CaseFuture};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Fwd, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c35",
    title: "A flood of frames that do not authenticate starves no genuine frame",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "Frames under a channel's id that fail the seal, sent faster than a receiver is \
             meant to open of one channel and at the sequences the genuine frames will take, \
             are counted and given to nobody, mark no sequence, leave no evidence and no bar; \
             every genuine message sent at the sender's normal rate is given, in order, as the \
             sender's.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

/// Alice's drag: three seconds at 60 Hz.
const FRAMES: usize = 180;
/// 60 Hz.
const FRAME: Duration = Duration::from_micros(16_667);
/// Forged frames sent after each of Alice's: about 420 a second.
const FORGED_PER_FRAME: u64 = 7;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "tablet");
    p.faults(Faults::default());
    p
}

fn drag() -> Name {
    n("/drag")
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
        ensure!(
            carol.channel == channel,
            "Bob and Carol asked one sender for one channel and got {channel:016x} and {:016x}",
            carol.channel
        );
        until_ready(w, &[&bob, &carol], channel, 2).await?;
        emit_until_seen(w, &sender, &drag(), "before", &mut [&mut bob]).await?;
        w.sleep(QUIET).await;
        bob.pump();
        let base = carol.ch.next_seq(channel)?;
        let (failed, accepted) = (
            rx_count(&bob.ch, "unauthentic"),
            rx_count(&bob.ch, "accepted"),
        );

        // Alice drags; after each of her messages the relay sends a few frames sealed under the
        // key of the channel at the sequences ahead, each with its last octet changed.
        let mut forged = 0u64;
        for i in 0..FRAMES {
            sender
                .emit(&space(), &drag(), Bytes::from(format!("alice:drag:{i}")))
                .await?;
            for _ in 0..FORGED_PER_FRAME {
                forged += 1;
                let frame = carol.ch.forge_data(
                    channel,
                    base + forged,
                    &drag(),
                    format!("forged:{forged}").as_bytes(),
                )?;
                let mut octets = frame.to_vec();
                if let Some(last) = octets.last_mut() {
                    *last ^= 1;
                }
                w.net()
                    .relay_inject(BOB, Bytes::from(octets), false)
                    .await?;
            }
            w.sleep(FRAME).await;
            bob.pump();
        }
        w.sleep(QUIET).await;
        bob.pump();

        let refused = rx_count(&bob.ch, "unauthentic") - failed;
        ensure!(
            refused > 0,
            "none of the {forged} forged frames was counted as unauthentic by Bob's receiver \
             [{}]: the flood never reached it; {}",
            rx_state(&bob.ch),
            channel_state(w, channel, &[Fwd::Hub, Fwd::Device(BOB)])
        );
        let delivered: Vec<&Bytes> = bob
            .events
            .iter()
            .filter_map(|e| match e {
                ChannelEvent::Message { path, bytes, .. } if *path == drag() => Some(bytes),
                _ => None,
            })
            .collect();
        ensure!(
            !delivered.iter().any(|b| b.starts_with(b"forged:")),
            "Bob was given a frame that does not authenticate"
        );
        let mut next = 0usize;
        for b in &delivered {
            let Some(i) = std::str::from_utf8(b)
                .ok()
                .and_then(|t| t.strip_prefix("alice:drag:"))
                .and_then(|i| i.parse::<usize>().ok())
            else {
                continue;
            };
            ensure!(
                i >= next,
                "Bob was given Alice's drag message {i} after {}: out of order or twice",
                next.saturating_sub(1)
            );
            next = i + 1;
        }
        let got = delivered
            .iter()
            .filter(|b| b.starts_with(b"alice:drag:"))
            .count();
        ensure!(
            got == FRAMES,
            "Bob was given {got} of Alice's {FRAMES} drag messages while {forged} frames that do \
             not authenticate came at her sequences ({refused} counted, accepted \
             {} -> {}; receiver [{}])",
            accepted,
            rx_count(&bob.ch, "accepted"),
            rx_state(&bob.ch)
        );
        ensure!(
            bob.ch.evidence().is_empty() && w.net().side_barred(Fwd::Device(BOB)).is_empty(),
            "frames that fail to authenticate prove nothing of anyone, and left evidence {:?} or \
             a bar {:?}",
            bob.ch.evidence(),
            w.net().side_barred(Fwd::Device(BOB))
        );
        bob.alive("Bob")?;
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
            "frames the relay sent that do not authenticate",
            forged,
            "frames",
        );
        w.measure("of them counted as unauthentic by Bob", refused, "frames");
        Ok(())
    })
}
