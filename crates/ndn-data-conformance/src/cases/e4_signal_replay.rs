//! Signals, e4 — a packet captured on the way is pushed again.
//!
//! Alice and Bob share Alice's sealed sketch folder. Alice marks ten spots on the sketch, each
//! at its own address. Someone on the path keeps a copy of one of her packets that reached Bob
//! and pushes it again later, under a fresh Interest nonce (so no forwarder takes it for a
//! looping copy): once into the network from Alice's node, the way it first came, and once from
//! an app on Bob's own node, another way in.
//!
//! The guard: each copy pushed again is refused by Bob's run window as a sequence already seen
//! (`replayed`), and the spot it carries is delivered once.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e4",
    title: "A replayed signal is refused",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "A signal packet captured on the way and pushed again — by the path it came or \
             another — is refused as a sequence its run already delivered, and its signals are \
             delivered once.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// How long a copy waits before it is pushed again: past the 1 s a pushed Interest lives in a
/// PIT, so no forwarder takes it for the one it copies, under the same name, still pending.
const PIT_LIFE: Duration = Duration::from_millis(1_200);

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
        let bob_group = group(&n("/bob"));
        let tap = w
            .net()
            .tap(
                &bob_group
                    .clone()
                    .append_component(ndn_packet::NameComponent::new(
                        32,
                        bytes::Bytes::from_static(b"signal"),
                    )),
            )
            .await;
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        for i in 0..10 {
            alice
                .send(&format!("spot/{i}"), &format!("alice:spot:{i}"))
                .await?;
            w.sleep(FRAME).await;
        }
        alice
            .send_final("cursor", "final:alice:cursor:done", &[&bob])
            .await?;

        // A copy of one of her packets whose signal Bob delivered (the spots' first packets may
        // all have been lost before Bob held her run's header; her final reached him).
        let (_, key) = signal_key(w, BOB, &folder())?;
        let alice_run = alice.run_id().await;
        let delivered = |seq: u64| {
            bob.all()
                .iter()
                .filter(|s| s.run.0 == alice_run && s.seq == seq)
                .count()
        };
        let (wire, seq) = tap
            .interests()
            .into_iter()
            .find_map(|wire| {
                let body = opened(&wire, &key).filter(|b| b.run == alice_run)?;
                let seq = body
                    .signals
                    .iter()
                    .map(|s| s.seq)
                    .find(|&seq| delivered(seq) == 1)?;
                Some((wire, seq))
            })
            .ok_or_else(|| {
                Failure::new(
                    "the relay carried no packet of alice's run whose signal bob delivered",
                )
            })?;
        let (_, packet) = signal::pushed(&wire).expect("a push the tap kept");

        let mut copies = 0u64;
        for (from, way) in [(ALICE, "the way it came"), (BOB, "from bob's own node")] {
            let face = w.net().app_face(from);
            let before = stats(w, BOB).await?.replayed;
            until_counted(
                w,
                BOB,
                &format!("bob refusing the copy pushed again {way} as replayed"),
                |s| s.replayed > before,
                || {
                    copies += 1;
                    let push = signal::push(&bob_group, &packet);
                    let face = &face;
                    async move {
                        tokio::time::sleep(PIT_LIFE).await;
                        face.send(push)
                            .await
                            .map_err(|e| Failure::new(format!("no node took the copy: {e}")))
                    }
                },
            )
            .await?;
        }
        w.sleep(SETTLE).await;
        ensure!(
            delivered(seq) == 1,
            "bob delivered alice's seq {seq} {} times after its packet was pushed again",
            delivered(seq)
        );
        bob.check(&[&alice, &bob])?;
        w.measure("copies pushed again", copies, "packets");
        Ok(())
    })
}
