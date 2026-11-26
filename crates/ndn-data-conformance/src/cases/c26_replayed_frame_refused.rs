//! Channels, c26 — a frame captured on the way is sent again.
//!
//! (Ported from the signal case e4.) Alice and Bob share Alice's space. Alice marks six spots on
//! the sketch, each at its own path, and emits each until Bob has it. Someone on the path keeps
//! a copy of a frame the relay forwarded and sends it again later: once over the link the frame
//! first came by, and once from an app on Bob's own node, another way in.
//!
//! The guard: the copy sent again over the session's link is refused by the receiver's replay
//! window as a sequence it already took (`replayed`, before any cryptography), and the copy an
//! app of Bob's node puts into his forwarder is no frame of the route: the forwarder refuses it
//! as coming from a face that is not the route's source. The spot it carries is delivered at most
//! once.

use std::time::Duration;

use ndn_heap::Name;
use ndn_transport::SideClass;

use super::channel_kit::{
    Listener, emit_until_seen, inject_until, rx_count, rx_state, space, until_ready,
};
use super::channel_ledger::Ledger;
use super::frame_tap::FrameTap;
use super::kit::{n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::ChannelTrust;
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Fwd, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c26",
    title: "A replayed frame is refused",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A frame captured on the way and sent again over the session's link is refused as a \
             sequence the receiver already took; one an app of the receiver's own node puts into \
             its forwarder is refused as not from the route's source; the message it carries is \
             delivered at most once.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// The spots Alice marks.
const SPOTS: u64 = 6;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

fn spot(i: u64) -> Name {
    n(&format!("/spot/{i}"))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&space(), private(&[], &["/bob"]))
            .await?;
        let alice_tx = w.channels(ALICE).await?;
        let mut bob = Listener::join(w, BOB, ChannelTrust::Prompt, ALICE).await?;
        until_ready(w, &[&bob], bob.channel, 1).await?;
        let tap = FrameTap::on(w, bob.channel)?;
        let mut ledger = Ledger::new();
        for i in 0..SPOTS {
            ledger = ledger.run(&format!("/spot/{i}"), "alice:spot");
            emit_until_seen(w, &alice_tx, &spot(i), "alice:spot", &mut [&mut bob]).await?;
        }

        // A copy of a frame the relay forwarded.
        let frame = tap
            .data()
            .pop()
            .ok_or_else(|| Failure::new("the relay forwarded no frame of Alice's channel"))?;

        // Sent again over the link it came by.
        let mut copies = 0u64;
        let before = rx_count(&bob.ch, "replayed");
        inject_until(w, &mut bob, &frame, false, |l| {
            rx_count(&l.ch, "replayed") > before
        })
        .await
        .map_err(|e| {
            Failure::new(format!(
                "{e}; the copy was not refused as replayed; Bob's receiver: {}",
                rx_state(&bob.ch)
            ))
        })?;
        copies += 1;

        // Put into Bob's forwarder by an app of his own node.
        let bobs_fwd = Fwd::Device(BOB);
        let wrong = w.net().side_counts(bobs_fwd).wrong_source;
        w.net()
            .app_face(BOB)
            .send_side(frame.clone(), SideClass::Datagram)
            .await
            .map_err(|e| {
                Failure::new(format!("an app of Bob's node could not send the copy: {e}"))
            })?;
        copies += 1;
        w.sleep(Duration::from_secs(1)).await;
        let now = w.net().side_counts(bobs_fwd).wrong_source;
        ensure!(
            now > wrong,
            "Bob's forwarder counted {now} frames from a face that is not the route's source, \
             none more than before an app of his own node sent the copy"
        );

        // Whatever the copies did, each spot was delivered at most once.
        w.sleep(Duration::from_secs(1)).await;
        bob.pump();
        bob.alive("bob")?;
        let given = ledger.check(&bob, &w.net().spec(ALICE).name())?;
        w.measure("copies sent again", copies, "frames");
        w.measure("messages Bob was given", given as u64, "messages");
        Ok(())
    })
}
