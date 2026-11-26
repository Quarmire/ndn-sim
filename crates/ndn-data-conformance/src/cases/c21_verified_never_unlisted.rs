//! Channels, c21 — a receiver that insists on `Verified` is never given a frame no signed
//! checkpoint lists.
//!
//! Alice's laptop sends her pointer to Bob and Dave, who both ask for `Verified`: each is given
//! a frame only once a checkpoint Alice signed lists it. Carol, a receiver like them, holds the
//! channel's key and turns hostile. She runs the relay on Bob's link and slips him a frame with a
//! pointer Alice never sent, at the sequence Alice sends next, which Alice's next checkpoint
//! will not list. On Dave's link she slips a frame far beyond any sequence Alice will reach, which
//! no checkpoint covers for a long time.
//!
//! The guard: Bob and Dave are given what Alice sent and her checkpoints listed, and neither
//! forged frame, ever. Bob's is dropped when the checkpoint that covers its sequence contradicts
//! it, with evidence against his link and the link barred.
//! Dave's is held for as long as a checkpoint may take, and when none lists it the session ends,
//! saying why, so that what cannot be told from a key holder's frames is never given. Nothing
//! either was given needs retracting.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;

use super::channel_kit::{
    EMIT_EVERY, Listener, NEAR, QUIET, channel_state, emit_until_seen, forge_ahead, rx_state,
    space, until_ready,
};
use super::kit::{n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Fwd, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c21",
    title: "Verified never delivers a frame no checkpoint lists",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A receiver that takes a channel Verified is given a frame only when a checkpoint the \
             sender signed lists it: a frame a key holder made is never delivered, whether a \
             checkpoint contradicts it or none covers it in time, and nothing delivered needs \
             retracting.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

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

fn pointer() -> Name {
    n("/pointer")
}

/// How far past the sequence Alice sends next the far frame is: more than a case sends.
const FAR: u64 = 1_000;

/// How many frames Carol forges one after another before the case says none was exposed.
const ATTEMPTS: usize = 6;

/// How long Alice's emissions go on after a forged frame landed before it is taken as one no
/// checkpoint will judge (it landed after the checkpoint that covers it).
const EXPOSE_WITHIN: Duration = Duration::from_secs(10);

/// What a receiver was given that Alice never sent, if anything.
fn foreign(l: &Listener) -> Option<Bytes> {
    l.messages()
        .into_iter()
        .map(|(_, payload)| payload)
        .find(|p| !(p.starts_with(b"honest") || p.starts_with(b"genuine")))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&space(), private(&[], &["/bob", "/carol", "/dave"]))
            .await?;
        let sender = w.channels(ALICE).await?;
        let mut bob = Listener::join(w, BOB, ChannelTrust::Verified, ALICE).await?;
        let mut carol = Listener::join(w, CAROL, ChannelTrust::Prompt, ALICE).await?;
        let mut dave = Listener::join(w, DAVE, ChannelTrust::Verified, ALICE).await?;
        let channel = bob.channel;
        let link = w.net().link_face(BOB);
        until_ready(w, &[&bob, &carol, &dave], channel, 3).await?;

        // What Alice sends and a checkpoint lists, Bob and Dave are given.
        emit_until_seen(
            w,
            &sender,
            &pointer(),
            "honest",
            &mut [&mut bob, &mut carol, &mut dave],
        )
        .await?;

        // What a receiver that takes frames as they come is given tells that a forged frame
        // reached the node of Bob (or Dave), which takes the channel Verified: the same node,
        // the same session, a second stream.
        let mut bob_sees = Listener::prepare(w, BOB, ChannelTrust::Prompt).await?;
        let mut dave_sees = Listener::prepare(w, DAVE, ChannelTrust::Prompt).await?;

        // A frame a few sequences above the one Alice sends next: the checkpoint that covers
        // its sequence contradicts it, and the Verified receiver never has it. A frame accepted
        // after the checkpoint that covers it is never judged (channel.md 13.12 item 2), and a
        // network that delays datagrams makes that happen: when the exposure does not come
        // within a stated window of Alice's emissions, or Bob's session ended meanwhile, Bob
        // asks again and Carol forges anew. Every frame she forged is kept: nothing but those
        // is evidence.
        let mut forgeries: Vec<(u64, Bytes)> = Vec::new();
        let mut tried = 0;
        let (seq, forged) = 'attempts: loop {
            tried += 1;
            ensure!(
                tried <= ATTEMPTS,
                "after {ATTEMPTS} frames forged one after another none was exposed by the \
                 checkpoints that cover it: evidence {:?}, Bob's events {:?}; receiver: {}; {}",
                bob.ch.evidence(),
                bob.events
                    .iter()
                    .filter(|e| !matches!(e, ChannelEvent::Message { .. }))
                    .collect::<Vec<_>>(),
                rx_state(&bob.ch),
                channel_state(
                    w,
                    channel,
                    &[Fwd::Device(ALICE), Fwd::Hub, Fwd::Device(BOB)]
                )
            );
            bob.heal_with(w, &mut [&mut bob_sees]).await?;
            let Some(forgery) = forge_ahead(
                w,
                ALICE,
                &carol,
                &mut bob_sees,
                &pointer(),
                &format!("forged by carol#{tried}"),
                NEAR,
            )
            .await?
            else {
                continue;
            };
            forgeries.push(forgery);
            let began = tokio::time::Instant::now();
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
                bob_sees.pump();
                ensure!(
                    foreign(&bob).is_none(),
                    "Bob was given {:?}, which Alice never sent, before any checkpoint listed it",
                    foreign(&bob)
                );
                let evidence = bob.ch.evidence();
                if let Some(hit) = forgeries.iter().find(|(s, _)| {
                    evidence
                        .iter()
                        .any(|e| e.kind == "mismatch" && e.seq0 == *s)
                }) {
                    break 'attempts hit.clone();
                }
                if bob.lapsed() || bob_sees.lapsed() || began.elapsed() >= EXPOSE_WITHIN {
                    break;
                }
            }
        };
        w.sleep(QUIET).await;
        bob.pump();
        let evidence = bob.ch.evidence();
        let mismatch = evidence
            .iter()
            .find(|e| e.kind == "mismatch" && e.seq0 == seq)
            .expect("the loop ended on it");
        ensure!(
            mismatch.frame == forged && mismatch.ingress == link && !mismatch.proof.is_empty(),
            "the evidence is {mismatch:?}: it must hold the forged frame as it came, the face \
             {link} it came over and the checkpoint that contradicts it"
        );
        ensure!(
            w.net().side_barred(Fwd::Device(BOB)) == vec![link],
            "Bob's forwarder bars {:?}, not exactly the face {link} the forgery came over",
            w.net().side_barred(Fwd::Device(BOB))
        );
        ensure!(
            foreign(&bob).is_none() && bob.has_stem(&pointer(), b"honest"),
            "Bob was given {:?} that Alice never sent, or none of what her checkpoints listed: \
             {:?}",
            foreign(&bob),
            bob.events
        );
        ensure!(
            !bob.events
                .iter()
                .any(|e| matches!(e, ChannelEvent::Retracted { .. })),
            "Bob was told to retract what he was given, though a Verified receiver is given \
             nothing a checkpoint does not list: {:?}",
            bob.events
        );
        bob.alive("Bob")?;

        // A frame no checkpoint covers: far beyond what Alice will send, on Dave's link. It is
        // held; when none lists it in time it is never given, and the session ends saying why.
        let far = 'far: {
            for tried in 1..=ATTEMPTS {
                dave.heal_with(w, &mut [&mut dave_sees]).await?;
                if let Some((far, _)) = forge_ahead(
                    w,
                    ALICE,
                    &carol,
                    &mut dave_sees,
                    &pointer(),
                    &format!("forged far ahead#{tried}"),
                    FAR,
                )
                .await?
                {
                    break 'far far;
                }
            }
            return Err(Failure::new(format!(
                "the frame far ahead did not land on Dave's node in {ATTEMPTS} tries: {:?}; {}",
                dave_sees.events,
                channel_state(
                    w,
                    channel,
                    &[Fwd::Device(ALICE), Fwd::Hub, Fwd::Device(DAVE)]
                )
            )));
        };
        w.sleep(Duration::from_secs(8)).await;
        dave.pump();
        ensure!(
            foreign(&dave).is_none(),
            "Dave was given {:?} at sequence {far}, which no checkpoint lists",
            foreign(&dave)
        );
        ensure!(
            dave.events
                .iter()
                .any(|e| matches!(e, ChannelEvent::Ended { why } if why.contains("Unverifiable"))),
            "the frame at sequence {far}, which no checkpoint lists, ended nothing for Dave: {:?}",
            dave.events
        );
        ensure!(
            !dave
                .events
                .iter()
                .any(|e| matches!(e, ChannelEvent::Retracted { .. })),
            "Dave was told to retract what he was given: {:?}",
            dave.events
        );
        Ok::<(), Failure>(())
    })
}
