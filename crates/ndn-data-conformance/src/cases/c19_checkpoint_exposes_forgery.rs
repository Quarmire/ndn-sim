//! Channels, c19 — a signed checkpoint exposes a forgery by a member holding the channel key,
//! with evidence against its link, and a lost frame is not one.
//!
//! (The design note's gate names it "c19 as checkpoint"; its table numbers the case c20. The id
//! `c19` is the gate's.)
//!
//! Alice's laptop sends her pointer to Bob, Carol and Dave. Every receiver holds the channel's
//! key, so any of them can seal a frame the others will open. Carol turns hostile: she runs the
//! relay on Bob's link and slips him a frame a few sequences above the one Alice sends next, with a pointer
//! Alice never sent. Bob, who takes frames as they come, is shown it. Alice's next checkpoint
//! lists the frames she sent, signed with her key, which Carol does not hold.
//!
//! Before that, Bob's link goes down for half a second while Alice emits, and Bob misses a frame:
//! a frame that never came is nothing a checkpoint exposes.
//!
//! The guard: a frame no checkpoint lists is exposed by the next checkpoint that covers its
//! sequence, with evidence that holds the frame as it came, the checkpoint that contradicts it
//! and the face it came over; the receiver is told what to retract; the face is barred from
//! carrying channel frames, so frames Alice sends later no longer reach Bob over it while Carol
//! and Dave, on their own links, go on receiving them; and a frame that was lost on the way
//! makes none of this: no evidence, no alert, no bar, no retraction.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;

use super::channel_kit::{
    EMIT_EVERY, Listener, Marks, NEAR, QUIET, channel_state, emit_until_seen, forge_ahead,
    rx_state, space, until_ready,
};
use super::kit::{drain, n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{AlertKind, SpaceEvent};
use crate::world::{Dev, Fwd, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c19",
    title: "A checkpoint exposes a key holder's forgery; a lost frame is not one",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A frame a holder of the channel key made and the sender's signed checkpoint does not \
             list is exposed by the next checkpoint that covers its sequence: evidence holds \
             the frame, the checkpoint and the face; the receiver is told to retract it; the \
             face is barred from channel frames and no other face is. A frame that was lost on \
             the way is no forgery.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

/// How many frames Carol forges one after another before the case says none was exposed.
const ATTEMPTS: usize = 6;

/// How long Alice's emissions go on after a forged frame landed before it is taken as one no
/// checkpoint will judge (it landed after the checkpoint that covers it): the sender's period is
/// 20 ms, and a faulty link holds a packet for less than 2 s.
const EXPOSE_WITHIN: Duration = Duration::from_secs(10);

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const DAVE: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "tablet");
    p.device("dave", "watch");
    p
}

/// Alice's pointer: the one path of the channel.
fn pointer() -> Name {
    n("/pointer")
}

/// The alerts of `events` that are about the channel `channel`.
fn about(events: &[SpaceEvent], channel: u64) -> Vec<&str> {
    let id = format!("{channel:016x}");
    events
        .iter()
        .filter_map(|e| match e {
            SpaceEvent::Alert(a)
                if matches!(a.kind, AlertKind::Other) && a.detail.contains(&id) =>
            {
                Some(a.detail.as_str())
            }
            _ => None,
        })
        .collect()
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&space(), private(&[], &["/bob", "/carol", "/dave"]))
            .await?;
        let sender = w.channels(ALICE).await?;
        let mut bob = Listener::join(w, BOB, ChannelTrust::Prompt, ALICE).await?;
        let mut carol = Listener::join(w, CAROL, ChannelTrust::Prompt, ALICE).await?;
        let mut dave = Listener::join(w, DAVE, ChannelTrust::Prompt, ALICE).await?;
        let mut watch = w.spaces(BOB).watch(&space()).await?;
        let mut told = Vec::new();
        let channel = bob.channel;
        ensure!(
            carol.channel == channel && dave.channel == channel,
            "three receivers asked one sender for one channel and got several"
        );
        let alice = w.net().spec(ALICE).name();
        let link = w.net().link_face(BOB);

        let mut marks = Marks::new();
        until_ready(w, &[&bob, &carol, &dave], channel, 3).await?;
        marks.at("ready", &bob.ch);

        // A frame that was lost on the way: Bob's link is down while Alice emits, so only the
        // others get it. Alice goes on; her checkpoints list the frame Bob never had.
        emit_until_seen(
            w,
            &sender,
            &pointer(),
            "honest",
            &mut [&mut bob, &mut carol, &mut dave],
        )
        .await?;
        marks.at("honest seen", &bob.ch);
        w.net().offline(BOB);
        sender
            .emit(&space(), &pointer(), Bytes::from_static(b"lost#0"))
            .await?;
        w.sleep(Duration::from_millis(500)).await;
        w.net().online(BOB);
        marks.at("online", &bob.ch);
        emit_until_seen(
            w,
            &sender,
            &pointer(),
            "after-loss",
            &mut [&mut bob, &mut carol, &mut dave],
        )
        .await?;
        marks.at("after-loss emitted, before QUIET", &bob.ch);
        w.sleep(QUIET).await;
        marks.at("after QUIET", &bob.ch);
        bob.pump();
        ensure!(
            !bob.has(&pointer(), b"lost#0"),
            "Bob was given the frame sent while his link was down: the case lost nothing"
        );
        drain(&mut *watch, Duration::from_millis(100), &mut told).await?;
        ensure!(
            bob.ch.evidence().is_empty()
                && about(&told, channel).is_empty()
                && w.net().side_barred(Fwd::Device(BOB)).is_empty()
                && !bob
                    .events
                    .iter()
                    .any(|e| matches!(e, ChannelEvent::Retracted { .. })),
            "a lost frame was taken for a forgery: evidence {:?}, alerts {:?}, bars {:?}, \
             events {:?}",
            bob.ch.evidence(),
            about(&told, channel),
            w.net().side_barred(Fwd::Device(BOB)),
            bob.events
        );

        // Carol forges, on Bob's link, a frame a few sequences above the one Alice sends next,
        // while Alice is silent; Alice then sends on, and the checkpoint that covers the frame's
        // sequence does not list it. A frame accepted after the checkpoint that covers its
        // sequence is never judged (channel.md 13.12 item 2), and a network that delays
        // datagrams makes that happen: when the exposure does not come within a stated window
        // of Alice's emissions, or Bob's session ended meanwhile (a frame that waited 3 s for a
        // checkpoint that never covered it), Bob asks again and Carol forges anew. Every frame
        // she forged is kept: nothing but those is evidence.
        let forged_path = pointer();
        let mut forgeries: Vec<(u64, Bytes)> = Vec::new();
        let mut tried = 0;
        let mut began: tokio::time::Instant;
        let (seq, forged) = 'attempts: loop {
            tried += 1;
            ensure!(
                tried <= ATTEMPTS,
                "after {ATTEMPTS} frames forged one after another none was exposed by the \
                 checkpoints that cover it; Bob's evidence {:?}, events {:?}; receiver: {}; now \
                 [{}]; {}",
                bob.ch
                    .evidence()
                    .iter()
                    .map(|e| (e.kind, e.seq0))
                    .collect::<Vec<_>>(),
                bob.events
                    .iter()
                    .filter(|e| !matches!(e, ChannelEvent::Message { .. }))
                    .collect::<Vec<_>>(),
                marks.said(),
                rx_state(&bob.ch),
                channel_state(
                    w,
                    channel,
                    &[Fwd::Device(ALICE), Fwd::Hub, Fwd::Device(BOB)]
                )
            );
            bob.heal(w).await?;
            marks.at("before forging", &bob.ch);
            let Some(forgery) = forge_ahead(
                w,
                ALICE,
                &carol,
                &mut bob,
                &forged_path,
                &format!("forged by carol#{tried}"),
                NEAR,
            )
            .await?
            else {
                marks.at("the forged frame did not land", &bob.ch);
                continue;
            };
            marks.at("forged frame given", &bob.ch);
            forgeries.push(forgery);
            began = tokio::time::Instant::now();
            let mut round = 0u64;
            loop {
                sender
                    .emit(
                        &space(),
                        &pointer(),
                        Bytes::from(format!("genuine#{round}")),
                    )
                    .await?;
                round += 1;
                w.sleep(EMIT_EVERY).await;
                bob.pump();
                let evidence = bob.ch.evidence();
                if let Some(hit) = forgeries.iter().find(|(s, _)| {
                    evidence
                        .iter()
                        .any(|e| e.kind == "mismatch" && e.seq0 == *s)
                }) {
                    break 'attempts hit.clone();
                }
                if bob.lapsed() || began.elapsed() >= EXPOSE_WITHIN {
                    marks.at("not exposed", &bob.ch);
                    break;
                }
            }
        };
        w.measure(
            "virtual time from Alice's next frame to the exposure",
            began.elapsed().as_millis() as u64,
            "ms",
        );
        w.sleep(QUIET).await;
        bob.pump();
        drain(&mut *watch, Duration::from_millis(100), &mut told).await?;

        // The evidence: the frame as it came, what contradicts it, the link it came over, and
        // nothing about any other sequence.
        let evidence = bob.ch.evidence();
        let mismatch = evidence
            .iter()
            .find(|e| e.kind == "mismatch" && e.seq0 == seq)
            .expect("the loop ended on it");
        ensure!(
            mismatch.frame == forged
                && mismatch.channel == channel
                && mismatch.sender == alice
                && mismatch.ingress == link
                && !mismatch.proof.is_empty(),
            "the evidence is {mismatch:?}: it must hold the forged frame as it came, channel \
             {channel:016x}, Alice's device, the face {link} it came over and the checkpoint that \
             contradicts it"
        );
        ensure!(
            evidence.iter().all(|e| e.ingress == link
                && e.channel == channel
                && forgeries.iter().any(|(s, _)| *s == e.seq0)),
            "evidence about something other than the forged frame: {evidence:?}"
        );

        // Bob is told what to retract.
        let retracted = bob.events.iter().any(|e| {
            matches!(e, ChannelEvent::Retracted { writer, from, to }
                if *writer == alice && *from <= seq && seq <= *to)
        });
        ensure!(
            retracted,
            "Bob was never told to retract sequence {seq} of Alice's channel: {:?}",
            bob.events
        );

        // The alert says whose frame, over which face, and what to do.
        let alerts = about(&told, channel);
        ensure!(
            alerts
                .iter()
                .any(|a| a.contains(&alice.to_string()) && a.contains(&format!("({link})"))),
            "no alert names Alice's channel and the face {link} the forgery came over: {alerts:?}"
        );

        // The link is barred, and only it.
        ensure!(
            w.net().side_barred(Fwd::Device(BOB)) == vec![link],
            "Bob's forwarder bars {:?}, not exactly the face {link} the forgery came over",
            w.net().side_barred(Fwd::Device(BOB))
        );
        for (who, at) in [
            ("Carol's", Fwd::Device(CAROL)),
            ("Dave's", Fwd::Device(DAVE)),
            ("Alice's", Fwd::Device(ALICE)),
            ("the relay's", Fwd::Hub),
        ] {
            ensure!(
                w.net().side_barred(at).is_empty(),
                "{who} forwarder bars {:?}: only the face the forgery came over is barred",
                w.net().side_barred(at)
            );
        }
        for (who, l) in [("Carol", &carol), ("Dave", &dave)] {
            ensure!(
                l.ch.evidence().is_empty(),
                "{who} holds evidence of a forgery nobody made on her link: {:?}",
                l.ch.evidence()
            );
        }

        // What Alice sends from now on reaches the others and no longer Bob.
        let dropped = w.net().side_counts(Fwd::Device(BOB)).quarantined;
        let routed = w.net().side_sink_faces(Fwd::Hub, channel).len() == 3;
        emit_until_seen(
            w,
            &sender,
            &pointer(),
            "later",
            &mut [&mut carol, &mut dave],
        )
        .await?;
        // What the network still holds of what was sent has come by now (QUIET); the frames
        // that came over the barred face are counted by then.
        w.sleep(QUIET).await;
        bob.pump();
        ensure!(
            !bob.messages()
                .iter()
                .any(|(_, payload)| payload.starts_with(b"later")),
            "Bob was given a frame over the barred face {link}"
        );
        // A frame over the barred face is dropped at Bob's forwarder; unless the relay holds no
        // sink of Bob's any more: a frame accepted over the face before it was barred that no
        // checkpoint covers ends his session (13.12 item 2), and an ended session leaves its
        // route, so that nothing is sent over the face at all.
        ensure!(
            !routed
                || w.net().side_counts(Fwd::Device(BOB)).quarantined > dropped
                || w.net().side_sink_faces(Fwd::Hub, channel).len() < 3,
            "Bob's forwarder dropped no frame for coming over the barred face"
        );
        bob.alive("Bob")?;
        Ok::<(), Failure>(())
    })
}
