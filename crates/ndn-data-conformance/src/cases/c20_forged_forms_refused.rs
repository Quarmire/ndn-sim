//! Channels, c20 — what a member holding the channel key cannot forge: a session, a frame of
//! another session's key under this channel's id, a checkpoint.
//!
//! (The design note's e3 row becomes "c3": members can inject under the key and are detected, and
//! cannot forge a checkpoint or a session Data. The id `c3` is the stolen-key case's; this one
//! is `c20`.)
//!
//! Alice's laptop sends her pointer to Bob; Dave's watch sends his own channel; Carol is a
//! member of the space and receives both, so she holds both channels' keys. She turns hostile
//! and tries, against Bob:
//!
//! 1. **A re-signed session.** Alice's laptop is off when Bob first asks for her channel, and
//!    Carol answers the ask under Alice's name with a Data she signed herself.
//! 2. **A frame of another session's key under this channel's id.** She seals a frame under the
//!    key of Dave's channel and writes Alice's channel id into its header.
//! 3. **A checkpoint.** She seals a checkpoint under Alice's channel key, signed with her own
//!    device key, as if Alice had sent it.
//!
//! The guard: Bob is given none of it. The answer under Alice's name that Alice did not sign is
//! no session. The relabelled frame fails to authenticate: it is no delivery, no evidence and no
//! bar (it proves nothing of anyone, and costs Bob no signature check), and Alice's own frames go
//! on arriving. The checkpoint Alice did not sign ends the session it claims to belong to, with
//! evidence against the link it came over and that link barred (a holder of the key is shown to
//! be making checkpoints), and the session says why.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;
use ndn_packet::Interest;
use ndn_packet::encode::DataBuilder;
use tokio_util::sync::CancellationToken;

use super::channel_kit::{
    Listener, QUIET, channel_state, emit_until_seen, inject_until, rx_count, rx_state, space,
    transient, until_ready,
};
use super::kit::{n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Fwd, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c20",
    title: "A key holder cannot forge a session, another session's frame or a checkpoint",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A member holding a channel's key cannot answer an ask as the sender, cannot pass a \
             frame of another session's key off as this channel's, and cannot make a \
             checkpoint: the first is no session, the second no delivery and no evidence, the \
             third ends the session it claims with evidence against its link and the link barred.",
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

/// Octets 2 to 9 of a frame are its channel id (the side header: marker, class and kind, then
/// the id), which a hostile member rewrites without touching the rest.
fn relabelled(frame: &Bytes, channel: u64) -> Bytes {
    let mut octets = frame.to_vec();
    octets[2..10].copy_from_slice(&channel.to_be_bytes());
    Bytes::from(octets)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&space(), private(&["/dave"], &["/bob", "/carol", "/dave"]))
            .await?;
        let alice = w.net().spec(ALICE).name();
        let link = w.net().link_face(BOB);

        // 1. A re-signed session: Alice's laptop is off, and Carol answers the ask under
        // Alice's name with a Data of her own signature.
        let sender = w.channels(ALICE).await?;
        let mut bob = Listener::prepare(w, BOB, ChannelTrust::Prompt).await?;
        let hostile = CancellationToken::new();
        let rival = w.net().app_face_until(CAROL, hostile.clone());
        rival
            .register_prefix(&ndn_heap::wire::chan_prefix(&alice))
            .await
            .map_err(|e| Failure::new(format!("carol's node routes no ask: {e}")))?;
        let signer = w.signer(CAROL)?;
        let stop = CancellationToken::new();
        let answering = {
            let (rival, stop) = (rival.clone(), stop.clone());
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = stop.cancelled() => return,
                        wire = rival.recv() => {
                            let Some(wire) = wire else { return };
                            let Ok(interest) = Interest::decode(wire) else { continue };
                            let data = DataBuilder::new((*interest.name).clone(), &[7u8; 96])
                                .sign_sync(signer.sig_type(), Some(signer.key_name()), |region| {
                                    signer.sign_sync(region).unwrap_or_default()
                                });
                            let _ = rival.send(data).await;
                        }
                    }
                }
            })
        };
        w.net().offline(ALICE);
        let answered = bob.ask(w, ALICE).await;
        w.net().online(ALICE);
        stop.cancel();
        let _ = answering.await;
        // Carol's rival face goes, and the route it registered with it, so that her own asks
        // reach the network again.
        hostile.cancel();
        w.sleep(Duration::from_secs(1)).await;
        ensure!(
            answered.is_err(),
            "Bob took a session from an answer under Alice's name that Carol signed: {answered:?}"
        );
        ensure!(
            bob.ch.evidence().is_empty() && w.net().side_barred(Fwd::Device(BOB)).is_empty(),
            "a refused answer left evidence or a bar on Bob's device"
        );

        // The real ask: Alice answers. Dave's channel too, which Carol takes to hold its key.
        bob.establish(w, ALICE).await?;
        let channel = bob.channel;
        let mut carol = Listener::join(w, CAROL, ChannelTrust::Prompt, ALICE).await?;
        let dave = w.channels(DAVE).await?;
        // Dave's device holds the space, as a sender of its channel must.
        let _dave_listens = Listener::prepare(w, DAVE, ChannelTrust::Prompt).await?;
        // Carol asks Dave's channel too and takes no stream of it: she needs its key only.
        let dave_channel = w.retry_later(|| carol.ask(w, DAVE)).await?;
        ensure!(
            channel == carol.channel && channel != dave_channel,
            "Alice's channel {channel:016x} was answered to Carol as {:016x}, and Dave's is \
             {dave_channel:016x}",
            carol.channel
        );
        until_ready(w, &[&bob, &carol], channel, 2).await?;
        emit_until_seen(
            w,
            &sender,
            &pointer(),
            "honest",
            &mut [&mut bob, &mut carol],
        )
        .await?;
        dave.emit(&space(), &n("/tool"), Bytes::from_static(b"hammer"))
            .await?;
        w.sleep(QUIET).await;

        // 2. A frame sealed under Dave's channel key, with Alice's channel id written in its
        // header: it opens under neither key.
        let seq = carol.ch.next_seq(dave_channel)?;
        let frame = carol
            .ch
            .forge_data(dave_channel, seq, &pointer(), b"under daves key")?;
        let frame = relabelled(&frame, channel);
        // Bob's session must stand for the frame to be tried against it; it landed when his
        // node counts a frame it could not open: the key's epoch it does not hold, or a key that
        // does not open it.
        bob.heal(w).await?;
        let refused =
            |bob: &Listener| rx_count(&bob.ch, "unauthentic") + rx_count(&bob.ch, "unknown_epoch");
        let failed = refused(&bob);
        inject_until(w, &mut bob, &frame, false, |bob| refused(bob) > failed)
            .await
            .map_err(|e| {
                Failure::new(format!(
                    "the relabelled frame: {e}; Bob's events {:?}; receiver [{}]; {}",
                    bob.events,
                    rx_state(&bob.ch),
                    channel_state(w, channel, &[Fwd::Hub, Fwd::Device(BOB)])
                ))
            })?;
        w.sleep(QUIET).await;
        bob.pump();
        ensure!(
            !bob.has_stem(&pointer(), b"under daves key"),
            "Bob was given a frame sealed under another session's key: {:?}",
            bob.events
        );
        ensure!(
            bob.ch.evidence().is_empty()
                && w.net().side_barred(Fwd::Device(BOB)).is_empty()
                && !bob
                    .events
                    .iter()
                    .any(|e| matches!(e, ChannelEvent::Retracted { .. })
                        || matches!(e, ChannelEvent::Ended { why } if !transient(why))),
            "a frame that fails to authenticate proves nothing of anyone, and it left evidence {:?}, \
             a bar {:?} or an end {:?}",
            bob.ch.evidence(),
            w.net().side_barred(Fwd::Device(BOB)),
            bob.events
        );
        emit_until_seen(w, &sender, &pointer(), "after", &mut [&mut bob, &mut carol]).await?;

        // 3. A checkpoint Carol signed: sealed under Alice's channel key, signed with her own.
        // It landed when Bob's node counts a checkpoint that opened under the key and did not
        // verify under Alice's.
        bob.heal(w).await?;
        let from = w.net().spec(ALICE).name();
        let ch = carol.ch.clone();
        let space = space();
        w.retry_later(|| ch.ask(&space, &from)).await?;
        let seq = carol.ch.next_seq(channel)?;
        let checkpoint = carol.ch.forge_checkpoint(channel, seq, seq, seq + 1, &[])?;
        let bad = rx_count(&bob.ch, "bad_checkpoints");
        inject_until(w, &mut bob, &checkpoint, true, |bob| {
            rx_count(&bob.ch, "bad_checkpoints") > bad
        })
        .await
        .map_err(|e| Failure::new(format!("the checkpoint Carol made: {e}")))?;
        w.sleep(QUIET).await;
        bob.pump();
        let evidence = bob.ch.evidence();
        ensure!(
            evidence.len() == 1
                && evidence[0].kind == "bad-checkpoint"
                && evidence[0].channel == channel
                && evidence[0].ingress == link
                && evidence[0].frame == checkpoint,
            "the evidence of a checkpoint Alice did not sign is {evidence:?}: it must hold that \
             checkpoint, channel {channel:016x} and the face {link} it came over"
        );
        ensure!(
            w.net().side_barred(Fwd::Device(BOB)) == vec![link],
            "Bob's forwarder bars {:?}, not exactly the face {link} the checkpoint came over",
            w.net().side_barred(Fwd::Device(BOB))
        );
        ensure!(
            bob.events
                .iter()
                .any(|e| matches!(e, ChannelEvent::Ended { why } if why.contains("BadCheckpoint"))),
            "Bob's stream was not told the session ended for a checkpoint Alice did not sign: {:?}",
            bob.events
        );
        ensure!(
            !bob.has_stem(&pointer(), b"under daves key"),
            "Bob was given a forged frame"
        );
        Ok::<(), Failure>(())
    })
}
