//! Channels, c20 — what a member holding the channel key cannot forge: a session, a frame of
//! another session's key under this channel's id, a checkpoint.
//!
//! (The signal case e3, "a member cannot forge another member's signals", has no case of its
//! own: this one asserts what it came to, a session Data, a frame and a checkpoint a key holder
//! cannot make.)
//!
//! Alice's laptop sends her pointer to Bob; Dave's watch sends his own channel; Carol is a
//! member of the space and receives both, so she holds both channels' keys. She turns hostile
//! and tries, against Bob:
//!
//! 1. **A re-signed session.** Alice's laptop is off when Bob first asks for her channel, and
//!    Carol answers the ask under Alice's name with the session she holds of Alice's channel,
//!    its key wrapped for Bob and her own signature on the Data. Sent from her own node, the
//!    forwarders on its way drop it (they judge the Data they carry, and Carol's key does not
//!    sign for Alice's name) and Bob's ask goes unanswered; sent by a face of Bob's own node
//!    (which no forwarder stands between), it reaches his channel code, which refuses it
//!    saying the signature is not the sender's. Either way Bob holds no session.
//! 2. **A frame of another session's key under this channel's id.** She seals a frame under the
//!    key of Dave's channel and writes Alice's channel id into its header.
//! 3. **A checkpoint.** She seals a checkpoint under Alice's channel key, signed with her own
//!    device key, as if Alice had sent it.
//!
//! The guard: Bob is given none of it. The answer under Alice's name that Alice did not sign is
//! no session and leaves no evidence or bar (a Data that is not the sender's proves nothing of
//! anyone). The relabelled frame fails to authenticate: it is no delivery, no evidence and no
//! bar (it proves nothing of anyone, and costs Bob no signature check), and Alice's own frames go
//! on arriving. The checkpoint Alice did not sign ends the session it claims to belong to, with
//! evidence against the link it came over and that link barred (a holder of the key is shown to
//! be making checkpoints), and the session says why.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;
use tokio_util::sync::CancellationToken;

use super::channel_kit::{
    EMIT_EVERY, Listener, NEAR, QUIET, channel_state, emit_until_seen, rx_count, rx_state, space,
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

/// What a hostile Carol makes from sessions she holds fresh: she asks each of `senders` again
/// (a renewal that gives her the sequence they take next), and `make` reads what she needs from
/// the sessions. A session of hers that a lossy network ended on the way (she holds none then)
/// is taken again, as a host does, and the attempt repeated.
async fn forged<T>(
    w: &World,
    carol: &mut Listener,
    senders: &[Dev],
    make: impl Fn(&Listener) -> Result<T, Failure>,
) -> Result<T, Failure> {
    let mut last = None;
    for _ in 0..5 {
        carol.heal(w).await?;
        for sender in senders {
            w.retry_later(|| carol.ask(w, *sender)).await?;
        }
        match make(carol) {
            Ok(made) => return Ok(made),
            Err(e) => last = Some(e),
        }
    }
    Err(Failure::new(format!(
        "Carol could not make what she forges from the sessions she holds, in five tries: {}",
        last.map_or_else(String::new, |e| e.to_string())
    )))
}

/// Alice's laptop goes off and `asker` asks it for its channel while a face `rogue` has on `at`'s
/// node answers the ask under Alice's name with the session `rogue` holds of `channel`, signed
/// with `rogue`'s own key. Returns what the ask came to, and how many answers the face sent.
async fn forged_answer(
    w: &World,
    at: Dev,
    rogue: &Listener,
    channel: u64,
    asker: &Listener,
) -> Result<(Result<u64, Failure>, u32), Failure> {
    let alice = w.net().spec(ALICE).name();
    let hostile = CancellationToken::new();
    let face = w.net().app_face_until(at, hostile.clone());
    face.register_prefix(&ndn_heap::wire::chan_prefix(&alice))
        .await
        .map_err(|e| Failure::new(format!("the face routes no ask: {e}")))?;
    let stop = CancellationToken::new();
    let answering = {
        let (face, stop, ch) = (face.clone(), stop.clone(), rogue.ch.clone());
        tokio::spawn(async move {
            let mut sent = 0u32;
            loop {
                tokio::select! {
                    () = stop.cancelled() => return sent,
                    wire = face.recv() => {
                        let Some(wire) = wire else { return sent };
                        let Ok(data) = ch.forge_session(channel, &wire) else { continue };
                        if face.send(data).await.is_ok() {
                            sent += 1;
                        }
                    }
                }
            }
        })
    };
    w.net().offline(ALICE);
    let answered = asker.ask(w, ALICE).await;
    w.net().online(ALICE);
    stop.cancel();
    let sent = answering
        .await
        .map_err(|e| Failure::new(format!("the face's task failed: {e}")))?;
    // The face goes, and the route it registered with it, so that asks reach the network again.
    hostile.cancel();
    w.sleep(Duration::from_secs(1)).await;
    Ok((answered, sent))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&space(), private(&["/dave"], &["/bob", "/carol", "/dave"]))
            .await?;
        let link = w.net().link_face(BOB);

        // Carol takes Alice's channel and so holds its key. Bob has asked no sender yet.
        let sender = w.channels(ALICE).await?;
        let mut bob = Listener::prepare(w, BOB, ChannelTrust::Prompt).await?;
        let mut carol = Listener::join(w, CAROL, ChannelTrust::Prompt, ALICE).await?;
        let channel = carol.channel;

        // 1. A re-signed session. Alice's laptop is off, and Carol answers Bob's first ask under
        // Alice's name with the session she holds, its key wrapped for Bob and her own
        // signature on it.
        //
        // (a) From her own node, as a relay or neighbour would: the Data crosses her forwarder
        // and the hub's, and the forwarders judge every Data they carry, one of Carol's key
        // under Alice's name does not pass, so it never reaches Bob. Bob's ask goes unanswered.
        let (mut asked, mut sent) = (0, 0);
        while sent == 0 {
            asked += 1;
            ensure!(
                asked <= 5,
                "Carol's face on her own node was never asked for the session in {asked} asks \
                 of Bob's"
            );
            carol.heal(w).await?;
            let (answered, answers) = forged_answer(w, CAROL, &carol, channel, &bob).await?;
            sent = answers;
            match answered {
                Err(e) if e.detail.contains("nothing answered the ask") => {}
                other => {
                    return Err(Failure::new(format!(
                        "Carol's answer under Alice's name, sent from her node, was {other:?}: \
                         the forwarders on its way must drop it and leave Bob's ask unanswered"
                    )));
                }
            }
        }
        // (b) Straight to Bob's own forwarder, a face of his node (which no forwarder between
        // can stop): it reaches his channel code, which refuses it as not the sender's.
        carol.heal(w).await?;
        let (answered, sent) = forged_answer(w, BOB, &carol, channel, &bob).await?;
        ensure!(
            sent >= 1,
            "Carol's face on Bob's node was never asked for the session, or could not answer it: \
             Bob's ask ended {answered:?}"
        );
        match &answered {
            Err(e)
                if e.detail.contains("its signature is refused")
                    && e.detail.contains("it is not the sender's") => {}
            other => {
                return Err(Failure::new(format!(
                    "Bob's ask, answered under Alice's name by a Data Carol signed, ended \
                     {other:?}, not as an answer whose signature is refused as not the \
                     sender's"
                )));
            }
        }
        ensure!(
            bob.ch.evidence().is_empty() && w.net().side_barred(Fwd::Device(BOB)).is_empty(),
            "a refused answer left evidence or a bar on Bob's device"
        );

        // The real ask: Alice answers. Dave's channel too, which Carol takes to hold its key.
        bob.establish(w, ALICE).await?;
        ensure!(
            channel == bob.channel,
            "Alice's channel {channel:016x} was answered to Bob as {:016x}",
            bob.channel
        );
        // Carol's stream of Alice's channel went without Alice for a while.
        carol.heal(w).await?;
        let dave = w.channels(DAVE).await?;
        // Dave's device holds the space, as a sender of its channel must.
        let _dave_listens = Listener::prepare(w, DAVE, ChannelTrust::Prompt).await?;
        // Carol asks Dave's channel too and takes no stream of it: she needs its key only.
        let dave_channel = w.retry_later(|| carol.ask(w, DAVE)).await?;
        ensure!(
            channel != dave_channel,
            "Alice's channel and Dave's are both {channel:016x}"
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
        // header: it opens under neither key. Bob's session must stand for the frame to be
        // tried against it, and the frame must take a sequence Bob's window has not seen: just
        // ahead of Alice's, as Carol reads it from a new ask. An idle sender takes a sequence
        // for each checkpoint, so a frame that waits is forged anew at the sequence then.
        // It landed when Bob's node counts a frame it could not open: the key's epoch it does
        // not hold, or a key that does not open it.
        let refused =
            |bob: &Listener| rx_count(&bob.ch, "unauthentic") + rx_count(&bob.ch, "unknown_epoch");
        let failed = refused(&bob);
        let mut sequences = Vec::new();
        'landing: for _ in 0..12 {
            bob.heal(w).await?;
            let (seq, frame) = forged(w, &mut carol, &[DAVE, ALICE], |c| {
                let seq = c.ch.next_seq(channel)? + NEAR;
                let frame =
                    c.ch.forge_data(dave_channel, seq, &pointer(), b"under daves key")?;
                Ok((seq, frame))
            })
            .await?;
            sequences.push(seq);
            let frame = relabelled(&frame, channel);
            for _ in 0..4 {
                w.net().relay_inject(BOB, frame.clone(), false).await?;
                w.sleep(EMIT_EVERY).await;
                bob.pump();
                if refused(&bob) > failed {
                    break 'landing;
                }
            }
        }
        ensure!(
            refused(&bob) > failed,
            "the relabelled frame, forged at sequences {sequences:?}, had no effect on Bob's \
             device; Bob's events {:?}; receiver [{}]; {}",
            bob.events,
            rx_state(&bob.ch),
            channel_state(w, channel, &[Fwd::Hub, Fwd::Device(BOB)])
        );
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
        //
        // Like the frame above it must take a sequence Bob's window has not seen, and the
        // sender takes one for each checkpoint it queues (after a frame, and an idle one every
        // 5 s) at times the case does not choose: a checkpoint of Alice's that takes the
        // sequence Carol read between her ask and the frame's arrival makes the forged one a copy
        // of a sequence Bob has seen, which his window drops unjudged. A checkpoint that waits is
        // forged anew at the sequence then, just ahead of Alice's as Carol reads it.
        let bad = rx_count(&bob.ch, "bad_checkpoints");
        let mut sequences = Vec::new();
        let mut forgery = None;
        'landing: for _ in 0..12 {
            bob.heal(w).await?;
            let (seq, checkpoint) = forged(w, &mut carol, &[ALICE], |c| {
                let seq = c.ch.next_seq(channel)? + NEAR;
                let checkpoint = c.ch.forge_checkpoint(channel, seq, seq, seq + 1, &[])?;
                Ok((seq, checkpoint))
            })
            .await?;
            sequences.push(seq);
            for _ in 0..4 {
                w.net().relay_inject(BOB, checkpoint.clone(), true).await?;
                w.sleep(EMIT_EVERY).await;
                bob.pump();
                if rx_count(&bob.ch, "bad_checkpoints") > bad {
                    forgery = Some(checkpoint);
                    break 'landing;
                }
            }
        }
        let Some(checkpoint) = forgery else {
            return Err(Failure::new(format!(
                "the checkpoint Carol made, forged at sequences {sequences:?}, had no effect on \
                 Bob's device; Bob's events {:?}; receiver [{}]; {}",
                bob.events,
                rx_state(&bob.ch),
                channel_state(w, channel, &[Fwd::Hub, Fwd::Device(BOB)])
            )));
        };
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
