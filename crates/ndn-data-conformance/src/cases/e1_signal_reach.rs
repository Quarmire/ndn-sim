//! Signals, e1 — Alice and Bob draw together in a sealed folder; each one's live signals reach
//! the other over the network.
//!
//! Alice shares her sketch folder, sealed to her and Bob, both writers. Each device's host starts
//! signals, subscribes to the folder and opens a run. Alice moves her cursor across the sketch at
//! 60 Hz for half a second and says she is here; Bob does the same. The hub between their
//! devices is the relay every packet crosses. Each ends by sending its last cursor and its
//! presence until the other acknowledges them, as a host re-sends its latest value until it is
//! seen.
//!
//! The guard: each member's last signal per address reaches the other member, from the
//! network (no ring: every device is its own host), attributed to the device whose key vouched
//! for the run, in the folder's scope; and whatever the network did, every delivered signal is
//! one its sender sent, delivered once, never older than one delivered before it for the same
//! sender and address.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e1",
    title: "A member's signals reach the other members",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "Signals of a sealed folder pushed by one member reach every other member over the \
             network: the last signal per address of each sender is delivered, attributed to the \
             device whose key vouched for its run, and every delivery is one its sender sent, \
             delivered once and never older than one delivered before it for the same sender \
             and address.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// Cursor moves each sends: half a second at 60 Hz.
const MOVES: usize = 30;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

fn folder() -> Name {
    n("/alice/32=data/sketch")
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.at(ALICE)
            .share_folder(&folder(), sealed_to(&["/alice", "/bob"]).into())
            .await?;
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;

        let start = tokio::time::Instant::now();
        for i in 0..MOVES {
            alice
                .send("cursor", &format!("alice:cursor:{i},{}", 2 * i))
                .await?;
            bob.send("cursor", &format!("bob:cursor:{},{i}", 3 * i))
                .await?;
            if i == 0 {
                alice.send("presence", "alice:presence:drawing").await?;
                bob.send("presence", "bob:presence:drawing").await?;
            }
            w.sleep(FRAME).await;
        }
        let finals = [
            (&alice, &bob, "cursor", "final:alice:cursor:30,60"),
            (&alice, &bob, "presence", "final:alice:presence:here"),
            (&bob, &alice, "cursor", "final:bob:cursor:90,30"),
            (&bob, &alice, "presence", "final:bob:presence:here"),
        ];
        for (from, to, address, payload) in finals {
            from.send_final(address, payload, &[to]).await?;
        }
        w.converged(start.elapsed());

        for (from, to, address, payload) in finals {
            let got = to.latest(from, address.as_bytes());
            ensure!(
                got.as_ref()
                    .is_some_and(|s| s.payload == payload.as_bytes()),
                "{}'s last signal at {address} from {} is {got:?}, not its final {payload:?}",
                to.who,
                from.who
            );
            let got = got.expect("checked above");
            ensure!(
                got.sender.has_prefix(&from.me) && !got.local && got.scope == folder(),
                "{}'s final reached {} as {got:?}: not from the network, of the folder, \
                 attributed to its device",
                from.who,
                to.who
            );
        }
        for p in [&alice, &bob] {
            p.check(&[&alice, &bob])?;
        }
        let sent = stats(w, ALICE).await?.sent_packets;
        w.measure("packets Alice's run pushed", sent, "packets");
        w.measure(
            "signals Bob delivered",
            stats(w, BOB).await?.delivered,
            "signals",
        );
        Ok(())
    })
}
