//! Channels, c27 — Alice removes Bob from her space while her laptop sends him live data; later
//! her phone is lost and its key revoked.
//!
//! (Ported from the signal case e5.) Alice's laptop (her namespace's root device) creates her
//! space with her phone, Bob and Carol; Bob and Carol are writers. Bob and Carol take the
//! laptop's channel, and the relay carries a frame the laptop emitted. Alice's laptop removes
//! Bob. It goes on emitting; Carol goes on receiving; Bob, who holds the old key, is given none
//! of it. Once Bob's device holds the record that removes him, his own emit is refused and his
//! ask of the laptop's channel is too.
//!
//! Then Alice reports her phone lost and her laptop revokes its key; the revocation reaches
//! Carol's node but not the phone's (a lost device adopts nothing that would stop it), which
//! goes on emitting on the channel Carol took from it. Carol's session of the phone ends, saying
//! the sender no longer stands, and a new ask of the phone is refused. The phone is also a
//! receiver of the laptop's channel, as Carol is: once the laptop holds the revocation it lets
//! the phone go and re-keys, and the laptop's later emissions reach Carol and never the phone,
//! whose own node knows nothing of the revocation; when the phone can ask again, its ask of the
//! laptop is refused.
//!
//! The guards are on signed data's order, not time: the record held → the removed member is
//! given nothing the channel carries after the re-key; the revocation held → no message of the
//! revoked key is delivered after the session ended, and no new session is made with it; the
//! revocation held by the sender → the revoked receiver is given nothing after.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;

use super::channel_kit::{
    EMIT_EVERY, Listener, QUIET, emit_until_seen, inject_until, rx_count, rx_state, space,
    transient, until_ready,
};
use super::channel_ledger::{Ledger, refused_ask};
use super::frame_tap::FrameTap;
use super::kit::{LIMIT, holds_key, loss_time, n, private, same_epoch};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::SpaceChange;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c27",
    title: "A removed member and a revoked key are stopped",
    slice: 8,
    needs: &[Feature::Channels, Feature::Revocation],
    model: &[],
    guards: "From the moment a sender holds the record that removes a receiver the channel is \
             re-keyed: the removed member is given nothing after it, the others go on \
             receiving, a frame of the old key opens nothing, and the removed member's own emit \
             and ask are refused; from the moment a receiver holds the revocation of a sender's \
             key its session of that sender ends and no new one is made; from the moment a \
             sender holds the revocation of a receiver's key the receiver is given nothing it \
             emits after, the others go on receiving, and the receiver's new ask is refused.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const BOB: Dev = Dev(2);
const CAROL: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("bob", "phone");
    p.device("carol", "tablet");
    p
}

fn cursor() -> Name {
    n("/cursor")
}

/// What the receivers' counters say of a frame the receiver refused for a key it no longer
/// holds, or a sequence it took.
fn refused_frames(ch: &std::sync::Arc<dyn crate::channel::Channels>) -> u64 {
    ["unknown_epoch", "replayed", "unauthentic", "too_old"]
        .iter()
        .map(|c| rx_count(ch, c))
        .sum()
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = space();
        let layer = w.spaces(LAPTOP);
        w.gesture();
        layer
            .create(&space, private(&["/bob", "/carol"], &["/bob", "/carol"]))
            .await?;
        let laptop_tx = w.channels(LAPTOP).await?;
        let laptop = w.net().spec(LAPTOP).name();
        let mut bob = Listener::join(w, BOB, ChannelTrust::Prompt, LAPTOP).await?;
        let mut carol = Listener::join(w, CAROL, ChannelTrust::Prompt, LAPTOP).await?;
        until_ready(w, &[&bob, &carol], bob.channel, 2).await?;
        let tap = FrameTap::on(w, bob.channel)?;
        emit_until_seen(
            w,
            &laptop_tx,
            &cursor(),
            "alice:before",
            &mut [&mut bob, &mut carol],
        )
        .await?;
        let old = tap
            .data()
            .pop()
            .ok_or_else(|| Failure::new("the relay forwarded no frame of the channel"))?;

        // Alice removes Bob.
        w.gesture();
        layer
            .change(
                &space,
                SpaceChange {
                    remove: vec![n("/bob")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        let held = layer.members(&space).await?;
        ensure!(
            !held.writers.contains(&n("/bob")),
            "alice's laptop does not hold the entry it signed removing bob: {held:?}"
        );
        // The sender's maintenance pass drops a receiver that no longer stands and re-keys: it
        // looks at the record every 250 ms of virtual time.
        w.sleep(QUIET).await;

        // The channel goes on for Carol, and Bob is given none of it.
        emit_until_seen(w, &laptop_tx, &cursor(), "alice:after", &mut [&mut carol]).await?;
        w.sleep(QUIET).await;
        bob.pump();
        carol.pump();
        ensure!(
            !bob.has_stem(&cursor(), b"alice:after"),
            "bob was given a message the laptop emitted after it held the record removing him"
        );
        carol.alive("carol")?;

        // A frame of the old key opens nothing at Carol, past the grace the old key has.
        w.sleep(Duration::from_secs(6)).await;
        let given = carol.messages().len();
        let before = refused_frames(&carol.ch);
        inject_until(w, &mut carol, &old, false, |l| {
            refused_frames(&l.ch) > before
        })
        .await
        .map_err(|e| Failure::new(format!("{e}; Carol's receiver: {}", rx_state(&carol.ch))))?;
        w.sleep(QUIET).await;
        carol.pump();
        ensure!(
            carol.messages().len() == given,
            "carol was given a message from a frame of the key before the removal: {} messages, \
             there were {given}",
            carol.messages().len()
        );
        let alice_ledger = Ledger::new()
            .run("/cursor", "alice:before")
            .run("/cursor", "alice:after");
        let to_carol = alice_ledger.check(&carol, &laptop)?;

        // Once Bob's device holds the record removing him, his own emit and ask are refused.
        w.until("bob holding the record removing him", LIMIT, || async {
            Ok(!w
                .spaces(BOB)
                .members(&space)
                .await?
                .writers
                .contains(&n("/bob")))
        })
        .await?;
        let emitted = bob
            .ch
            .emit(&space, &cursor(), Bytes::from_static(b"bob:removed#0"))
            .await;
        ensure!(
            matches!(&emitted, Err(e) if e.detail.contains("may not emit")),
            "bob's emit once his device holds the record removing him answered {emitted:?}, not a \
             refusal saying the device is no writer"
        );
        refused_ask(w, &*bob.ch, "bob", &space, &laptop).await?;
        drop(bob);
        drop(carol);

        // Alice's phone is lost; her laptop revokes its key, and Carol's node adopts the
        // revocation. The phone's node does not. The laptop, the phone and Carol first hold the
        // key of one epoch in force: the phone has nothing to seal its frames with otherwise.
        let (laptop_spaces, phone_spaces, carol_spaces) =
            (w.spaces(LAPTOP), w.spaces(PHONE), w.spaces(CAROL));
        w.until(
            "the laptop, alice's phone and carol holding the key of one epoch in force",
            LIMIT,
            || async {
                Ok(holds_key(&*phone_spaces, &space).await?
                    && holds_key(&*carol_spaces, &space).await?
                    && same_epoch(&*laptop_spaces, &*phone_spaces, &space).await?
                    && same_epoch(&*laptop_spaces, &*carol_spaces, &space).await?)
            },
        )
        .await?;
        let phone_tx = w.channels(PHONE).await?;
        let phone = w.net().spec(PHONE).name();
        let mut at_carol = Listener::prepare(w, CAROL, ChannelTrust::Prompt).await?;
        at_carol.establish(w, PHONE).await?;
        emit_until_seen(
            w,
            &phone_tx,
            &cursor(),
            "phone:before",
            &mut [&mut at_carol],
        )
        .await?;
        // Alice's phone also takes the laptop's channel, as a receiver.
        let mut at_phone = Listener::prepare(w, PHONE, ChannelTrust::Prompt).await?;
        at_phone.establish(w, LAPTOP).await?;
        emit_until_seen(
            w,
            &laptop_tx,
            &cursor(),
            "alice:phoneup",
            &mut [&mut at_phone],
        )
        .await?;
        // The lost phone reaches nothing that would stop it.
        let mut stranded = Vec::new();
        for d in [LAPTOP, BOB, CAROL] {
            stranded.push(w.net().cut_off(PHONE, &w.net().spec(d).name()).await);
        }
        // Cut off, the phone still receives what the laptop emits (the control of what follows).
        emit_until_seen(
            w,
            &laptop_tx,
            &cursor(),
            "alice:cutoff",
            &mut [&mut at_phone],
        )
        .await?;
        let lost = loss_time(w, LAPTOP).await;
        w.revoke_at(LAPTOP, PHONE, lost).await?;
        w.spread(CAROL).await?;

        // The phone goes on emitting; Carol's session of it ends, and says why.
        let start = tokio::time::Instant::now();
        let mut i = 0;
        let ended = loop {
            phone_tx
                .emit(&space, &cursor(), Ledger::payload("phone:revoked", i))
                .await?;
            i += 1;
            w.sleep(EMIT_EVERY).await;
            at_carol.pump();
            // `NotMember` is the end the revocation makes; a lossy network may end the stream
            // first for a cause it makes (`transient`), and a stream that has ended gives
            // nothing more either way.
            let ended = at_carol.events.iter().position(|e| {
                matches!(e, ChannelEvent::Ended { why } if why.contains("NotMember") || transient(why))
            });
            if let Some(at) = ended {
                break at;
            }
            ensure!(
                start.elapsed() < LIMIT,
                "after {i} emissions over {LIMIT:?} of virtual time carol's session of the revoked \
                 phone had not ended: {:?}",
                at_carol.events
            );
        };
        ensure!(
            !at_carol.events[ended..]
                .iter()
                .any(|e| matches!(e, ChannelEvent::Message { writer, .. } if *writer == phone)),
            "carol was given a message of the revoked key after its session ended"
        );
        let to_phone = Ledger::new()
            .run("/cursor", "phone:before")
            .run("/cursor", "phone:revoked")
            .check_of(&at_carol, &phone)?;
        // No new session is made with the revoked key.
        refused_ask(w, &*at_carol.ch, "carol", &space, &phone).await?;

        // The same revocation, held by the laptop, stops the phone as a receiver: the laptop
        // lets it go and re-keys, and goes on emitting to a receiver that stands (Carol, who
        // takes its channel anew: her stream of the phone's is over). The phone, which holds
        // nothing of the revocation, is given nothing the laptop emits from here on.
        // The laptop's maintenance pass drops a receiver whose key no longer stands and re-keys:
        // it looks at the record every 250 ms of virtual time.
        w.sleep(QUIET).await;
        drop(at_carol);
        let mut carol_again = Listener::join(w, CAROL, ChannelTrust::Prompt, LAPTOP).await?;
        emit_until_seen(
            w,
            &laptop_tx,
            &cursor(),
            "alice:revoked",
            &mut [&mut carol_again],
        )
        .await?;
        w.sleep(QUIET).await;
        at_phone.pump();
        ensure!(
            at_phone.has_stem(&cursor(), b"alice:phoneup"),
            "alice's phone, a receiver of the laptop's channel before its key was revoked, was \
             given nothing of it then: {:?}",
            at_phone.events
        );
        ensure!(
            !at_phone.has_stem(&cursor(), b"alice:revoked"),
            "alice's phone, whose key the laptop holds the revocation of, was given a message the \
             laptop emitted after: {:?}",
            at_phone.events
        );
        let to_revoked = Ledger::new()
            .run("/cursor", "alice:phoneup")
            .run("/cursor", "alice:cutoff")
            .check_of(&at_phone, &laptop)?;
        // The laptop's channel went on for Carol.
        let to_carol_after = Ledger::new()
            .run("/cursor", "alice:revoked")
            .check(&carol_again, &laptop)?;
        // And no new session is made for the revoked receiver, once its phone can ask.
        drop(stranded);
        refused_ask(w, &*at_phone.ch, "alice's phone", &space, &laptop).await?;
        w.measure(
            "messages Carol was given of the laptop",
            to_carol as u64,
            "messages",
        );
        w.measure(
            "messages Carol was given of the phone",
            to_phone as u64,
            "messages",
        );
        w.measure(
            "messages Carol was given of the laptop after the phone's revocation",
            to_carol_after as u64,
            "messages",
        );
        w.measure(
            "messages the revoked phone was given of the laptop",
            to_revoked as u64,
            "messages",
        );
        Ok(())
    })
}
