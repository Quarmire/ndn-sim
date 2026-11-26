//! Channels, c22 — one sender, two receivers behind a relay: the sender's link carries one copy
//! of each frame.
//!
//! Alice's laptop has live data for the members of her space: three values a second device wants
//! to see as they change. Bob and Carol each ask Alice's device for its channel. The hub between
//! the devices is the relay: it holds no key and no identity of theirs, and its forwarder fans a
//! frame out to every device that asked, knowing nothing of what the frame holds. Alice emits
//! until both have each value, and the case reads the forwarders' side tables.
//!
//! (The design's c22 also names an L2 multicast face carrying one frame for every station on a
//! segment: the simulated links are point to point, so that half has no case here; the face
//! tests of `ndn-face` hold it.)
//!
//! The guard: the relay's route for the channel has one sink for each receiver and Alice's own
//! forwarder one (the relay); every frame Alice's forwarder routed is a frame the relay received
//! and fanned out, so the sender's link carried each frame once whatever the number of
//! receivers; each receiver's forwarder holds the route with one sink, its node; and every
//! message either receiver was given is one Alice emitted, attributed to her device, at most once
//! per value, whatever the network did to the frames in between.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;

use super::channel_kit::{Listener, emit_until_seen, space, until_ready};
use super::kit::{n, private};
use crate::case::{Case, CaseFuture};
use crate::channel::ChannelTrust;
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Fwd, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c22",
    title: "Two receivers behind a relay: one copy of each frame on the sender's link",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A channel's frames are fanned out by the relay's side table: the sender's link \
             carries one copy of each frame for any number of receivers behind the relay, each \
             receiver gets what the sender emitted, and the relay holds no more of the channel \
             than a route and its sinks.",
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

/// The values: a path and the stem every payload emitted there begins with.
const VALUES: [(&str, &str); 3] = [("/pointer", "p"), ("/color", "c"), ("/tool", "t")];

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&space(), private(&[], &["/bob", "/carol"]))
            .await?;
        let sender = w.channels(ALICE).await?;
        let mut bob = Listener::join(w, BOB, ChannelTrust::Prompt, ALICE).await?;
        let mut carol = Listener::join(w, CAROL, ChannelTrust::Prompt, ALICE).await?;
        ensure!(
            bob.channel == carol.channel,
            "Bob and Carol asked one sender for one channel and were answered with {:016x} and \
             {:016x}",
            bob.channel,
            carol.channel
        );
        let channel = bob.channel;

        // The route stands at every hop before a frame is sent: the relay holds a sink for each
        // receiver, the sender's forwarder one (the relay), the receivers' one each (their node).
        until_ready(w, &[&bob, &carol], channel, 2).await?;
        for (at, who, sinks) in [
            (Fwd::Device(ALICE), "the sender's forwarder", 1),
            (Fwd::Hub, "the relay", 2),
            (Fwd::Device(BOB), "Bob's forwarder", 1),
            (Fwd::Device(CAROL), "Carol's forwarder", 1),
        ] {
            let held = w.net().side_route(at, channel).map(|(_, s)| s);
            ensure!(
                held == Some(sinks),
                "{who} holds {held:?} sinks for the channel, not {sinks}"
            );
        }

        let before = (
            w.net().side_route(Fwd::Device(ALICE), channel),
            w.net().side_route(Fwd::Hub, channel),
        );
        for (path, stem) in VALUES {
            emit_until_seen(w, &sender, &n(path), stem, &mut [&mut bob, &mut carol]).await?;
        }
        // The checkpoints that follow the last frames are frames of the channel too.
        w.sleep(Duration::from_secs(1)).await;
        let after = (
            w.net().side_route(Fwd::Device(ALICE), channel),
            w.net().side_route(Fwd::Hub, channel),
        );
        let frames = |at: usize| -> Result<u64, crate::Failure> {
            let (b, a) = match at {
                0 => (before.0, after.0),
                _ => (before.1, after.1),
            };
            match (b, a) {
                (Some((b, _)), Some((a, _))) => Ok(a - b),
                _ => Err(crate::Failure::new(
                    "a route of the channel went away while the case ran",
                )),
            }
        };
        let (sent, relayed) = (frames(0)?, frames(1)?);
        ensure!(
            sent >= VALUES.len() as u64,
            "Alice's forwarder routed {sent} frames for {} values",
            VALUES.len()
        );
        ensure!(
            sent == relayed,
            "Alice's forwarder routed {sent} frames onto its one link and the relay received \
             {relayed} on the route: the link carried more or fewer than one copy of each frame"
        );

        // What each receiver was given is what Alice emitted, as hers, once per value.
        let alice = w.net().spec(ALICE).name();
        for l in [&mut bob, &mut carol] {
            l.pump();
            l.alive("a receiver")?;
            let mut seen: Vec<(Name, Bytes)> = Vec::new();
            for e in &l.events {
                if let crate::channel::ChannelEvent::Message {
                    path,
                    bytes,
                    writer,
                } = e
                {
                    ensure!(
                        *writer == alice,
                        "{path} reached device {} from {writer}, not from Alice's device",
                        l.dev.0
                    );
                    let stem = VALUES
                        .iter()
                        .find(|(p, _)| n(p) == *path)
                        .map(|(_, s)| *s)
                        .ok_or_else(|| {
                            crate::Failure::new(format!(
                                "a message at {path}, which Alice never emitted"
                            ))
                        })?;
                    ensure!(
                        bytes.starts_with(stem.as_bytes()),
                        "{path} was given as {bytes:?}, which Alice never emitted there"
                    );
                    ensure!(
                        !seen.iter().any(|(p, b)| p == path && b == bytes),
                        "{path} was delivered twice as {bytes:?}"
                    );
                    seen.push((path.clone(), bytes.clone()));
                }
            }
        }
        w.measure("frames Alice's link carried", sent, "frames");
        Ok(())
    })
}
