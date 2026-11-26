//! Channels, c28 — what the relay sees of a space's live data.
//!
//! (Replaces the signal case e6.) Alice and Bob plan a trip on a map in Alice's space, Bob a
//! writer. Each moves a pointer over the map and says where they are looking: each emits twelve
//! positions at a path of its own, then its last until the other has it. The hub between their
//! devices is the relay that forwards every ask and every frame; it is tapped twice: the asks as
//! Interests, and the frames of both channels as the side table forwards them.
//!
//! The guard: every frame the relay forwarded is a side frame (it starts with the marker, never
//! an NDN packet) of one of the five kinds that exist, under the channel's id, and nothing of
//! what was emitted appears in it: no path, no payload, no device key name, no device label. The
//! only signed Interests the relay carried under the senders' names are asks, and they hold no
//! path and no payload either.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;
use ndn_packet::Interest;

use super::channel_kit::{Listener, emit_until_seen, space, until_ready};
use super::frame_tap::{FrameTap, MARKER};
use super::kit::{contains, n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::ChannelTrust;
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c28",
    title: "A relay sees only ciphertext of a space's live data",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "Every frame a relay forwards of a space's channel is a side frame under the \
             channel's id whose octets hold none of what was emitted (no path, no payload) and \
             no device's key name; the asks it carries are signed and hold no path or payload \
             either.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// The first octets a frame may have: `DATA` on a datagram and on a stream, `CHECKPOINT`,
/// `CONTROL`.
const KINDS: [u8; 4] = [0x20, 0x30, 0x31, 0x32];

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

/// The path `who` emits its pointer at.
fn pointer(who: &str) -> String {
    format!("/pointer/route-map-{who}")
}

/// Where `who` looks on the map, the `i`th time.
fn look(who: &str, i: u64) -> String {
    format!("{who}:lat=48.85{i:02},lon=2.35{i:02}")
}

/// What must not appear in a frame or an ask: the paths and payloads emitted so far.
struct Secrets {
    parts: Vec<(String, Vec<u8>)>,
}

impl Secrets {
    fn path(&mut self, path: &str) {
        let name = n(path);
        self.parts
            .push((format!("the path {path}"), name.encode_to_tlv().to_vec()));
        if let Some(last) = path.rsplit('/').next() {
            self.parts
                .push((format!("the path's name {last}"), last.as_bytes().to_vec()));
        }
    }

    fn payload(&mut self, payload: &str) {
        self.parts.push((
            format!("the payload {payload}"),
            payload.as_bytes().to_vec(),
        ));
    }

    /// Fails when `wire` shows any of them.
    fn absent(&self, wire: &[u8], what: &str) -> Result<(), Failure> {
        for (name, part) in &self.parts {
            ensure!(!contains(wire, part), "{what} shows {name}");
        }
        Ok(())
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = space();
        w.gesture();
        w.spaces(ALICE)
            .create(&space, private(&["/bob"], &["/bob"]))
            .await?;
        let alice = w.net().spec(ALICE).name();
        let bob = w.net().spec(BOB).name();
        let asks = [w.net().tap(&alice).await, w.net().tap(&bob).await];
        let alice_tx = w.channels(ALICE).await?;
        let bob_tx = w.channels(BOB).await?;
        let mut at_bob = Listener::join(w, BOB, ChannelTrust::Prompt, ALICE).await?;
        let mut at_alice = Listener::join(w, ALICE, ChannelTrust::Prompt, BOB).await?;
        until_ready(w, &[&at_bob], at_bob.channel, 1).await?;
        until_ready(w, &[&at_alice], at_alice.channel, 1).await?;
        let taps = [
            (FrameTap::on(w, at_bob.channel)?, at_bob.channel),
            (FrameTap::on(w, at_alice.channel)?, at_alice.channel),
        ];

        let mut secrets = Secrets { parts: Vec::new() };
        for who in ["alice", "bob"] {
            secrets.path(&pointer(who));
        }
        for i in 0..12 {
            for (tx, who) in [(&alice_tx, "alice"), (&bob_tx, "bob")] {
                let text = look(who, i);
                tx.emit(&space, &n(&pointer(who)), Bytes::from(text.clone()))
                    .await?;
                secrets.payload(&text);
            }
            w.sleep(Duration::from_millis(16)).await;
        }
        let last = [
            "final:alice:lat=48.8566,lon=2.3522",
            "final:bob:lat=48.8606,lon=2.3376",
        ];
        for stem in last {
            secrets.payload(stem);
        }
        emit_until_seen(
            w,
            &alice_tx,
            &n(&pointer("alice")),
            last[0],
            &mut [&mut at_bob],
        )
        .await?;
        emit_until_seen(
            w,
            &bob_tx,
            &n(&pointer("bob")),
            last[1],
            &mut [&mut at_alice],
        )
        .await?;
        // The frames that carry a checkpoint of the last ones.
        w.sleep(Duration::from_secs(1)).await;

        // What of a device must not appear in a frame (an ask names it): its key name and its
        // label.
        let mut devices = Secrets { parts: Vec::new() };
        for (d, label) in [(ALICE, "laptop"), (BOB, "phone")] {
            let key = w.signer(d)?.key_name().clone();
            devices
                .parts
                .push((format!("{label}'s key name"), key.encode_to_tlv().to_vec()));
            devices.parts.push((
                format!("the device label {label}"),
                label.as_bytes().to_vec(),
            ));
        }
        let mut frames = 0u64;
        let mut bytes = 0u64;
        for (tap, channel) in &taps {
            let seen = tap.frames();
            ensure!(
                !seen.is_empty(),
                "the relay forwarded no frame of channel {channel:016x}"
            );
            for frame in seen {
                frames += 1;
                bytes += frame.len() as u64;
                ensure!(
                    frame.len() >= 46 && frame[0] == MARKER && KINDS.contains(&frame[1]),
                    "a frame the relay forwarded of channel {channel:016x} is no sealed frame: \
                     {} octets starting {:02x?}",
                    frame.len(),
                    &frame[..frame.len().min(4)]
                );
                ensure!(
                    frame[2..10] == channel.to_be_bytes(),
                    "a frame the relay forwarded on the route of channel {channel:016x} names \
                     channel {:02x?}",
                    &frame[2..10]
                );
                let what = format!("a frame of channel {channel:016x}");
                secrets.absent(&frame, &what)?;
                devices.absent(&frame, &what)?;
            }
        }

        // The asks the relay carried: signed, and no path, no payload in them.
        let mut seen_asks = 0u64;
        for tap in &asks {
            for wire in tap.interests() {
                let Ok(interest) = Interest::decode(wire.clone()) else {
                    continue;
                };
                if !is_ask(&interest.name) {
                    continue;
                }
                seen_asks += 1;
                ensure!(
                    interest.sig_info().is_some(),
                    "an ask the relay forwarded is not signed: {}",
                    interest.name
                );
                secrets.absent(&wire, &format!("the ask {}", interest.name))?;
            }
        }
        ensure!(seen_asks > 0, "the relay carried no ask of either channel");
        w.measure("frames the relay forwarded", frames, "frames");
        w.measure(
            "octets per frame the relay forwarded",
            bytes / frames.max(1),
            "octets",
        );
        Ok(())
    })
}

/// Whether `name` is an ask: `<device>/32=chan/<digest>`.
fn is_ask(name: &Name) -> bool {
    // `32=chan` as a name prints it.
    name.to_string().contains(&n("/32=chan").to_string())
}
