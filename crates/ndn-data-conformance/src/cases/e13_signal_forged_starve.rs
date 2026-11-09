//! Signals, e13 — forged packets of a held run do not starve its genuine packets.
//!
//! Alice, Bob and Carol share Alice's sealed sketch folder, all three writers, and Carol holds
//! Alice's run. Bob, a member, holds the folder's signal key: he opens one of Alice's packets on
//! the relay and takes her run's id. Then, while Alice drags at 60 Hz for three seconds, he
//! pushes into Carol's group four hundred packets a second sealed under the folder's key, each
//! claiming Alice's run with a sequence no packet of hers carried and signed by a run key of his
//! own — more than a receiver takes of one run (240 a second, spec §5).
//!
//! The network is lossless here: the guard counts every packet. The guards: Carol delivers
//! every one of Alice's drag signals (a forged packet, however many, never uses up what her run
//! may send — a receiver charges a run's and a scope's rates only for packets whose run
//! signature verifies, §8.1); no forged signal is delivered; and Alice's final reaches Carol.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ndn_sim::Faults;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e13",
    title: "Forged packets of a held run do not starve its genuine ones",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "Packets claiming a held run that its key did not sign, pushed faster than a \
             receiver takes of one run, never cost the run's genuine packets their delivery: \
             every genuine signal sent at the sender's normal rate is delivered, no forged one.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

/// Bob's forged packets: one every 2.5 ms, 400 a second.
const FORGE_EVERY: Duration = Duration::from_micros(2_500);
/// Alice's drag: three seconds at 60 Hz.
const FRAMES: u32 = 180;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "tablet");
    p.faults(Faults::default());
    p
}

fn folder() -> Name {
    n("/alice/32=data/sketch")
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.at(ALICE)
            .share_folder(&folder(), sealed_to(&["/alice", "/bob", "/carol"]).into())
            .await?;
        let tap = w.net().tap(&n("/carol/32=sync/32=signal")).await;
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        let carol = Peer::join(w, CAROL, &folder()).await?;
        alice
            .send_final("cursor", "final:alice:cursor:before", &[&bob, &carol])
            .await?;

        let (key_id, key) = signal_key(w, BOB, &folder())?;
        let alice_run = alice.run_id().await;
        let last = tap
            .interests()
            .iter()
            .filter_map(|wire| opened(wire, &key))
            .filter(|b| b.run == alice_run)
            .flat_map(|b| b.signals.into_iter().map(|s| s.seq))
            .max()
            .ok_or_else(|| Failure::new("the relay carried no packet of Alice's run"))?;

        let face = w.net().app_face(BOB);
        let target = group(&n("/carol"));
        let mine = signal::RunKey::from_seed([0xb2; 32]);
        let before = stats(w, CAROL).await?;
        let done = AtomicBool::new(false);
        let mut forged = 0u64;
        let forge = async {
            while !done.load(Ordering::Relaxed) {
                forged += 1;
                let body = signal::body(
                    &folder(),
                    &alice_run,
                    None,
                    &[signal::Signal {
                        seq: last + 1_000_000 + forged,
                        address: bytes::Bytes::from_static(b"drag"),
                        expires: w.net().date(BOB).0 + 10_000,
                        payload: format!("forged:{forged}").into(),
                    }],
                    &mine,
                );
                let mut nonce = [0xb2; 24];
                nonce[..8].copy_from_slice(&forged.to_be_bytes());
                let packet = signal::seal(&key_id, &key, &nonce, &body);
                face.send(signal::push(&target, &packet))
                    .await
                    .map_err(|e| Failure::new(format!("bob's node took no packet: {e}")))?;
                w.sleep(FORGE_EVERY).await;
            }
            Ok::<(), Failure>(())
        };
        let genuine = async {
            let result = async {
                // The forgeries are under way before Alice drags.
                w.sleep(Duration::from_secs(1)).await;
                for i in 0..FRAMES {
                    alice.send("drag", &format!("alice:drag:{i}")).await?;
                    w.sleep(FRAME).await;
                }
                w.sleep(Duration::from_secs(1)).await;
                Ok::<(), Failure>(())
            }
            .await;
            done.store(true, Ordering::Relaxed);
            result
        };
        let (forging, dragged) = futures::join!(forge, genuine);
        forging?;
        dragged?;

        w.sleep(Duration::from_secs(2)).await;
        let now = stats(w, CAROL).await?;
        let delivered = carol.delivered("alice:drag:");
        ensure!(
            delivered == FRAMES as usize,
            "carol delivered {delivered} of alice's {FRAMES} drag signals while bob pushed \
             {forged} forged packets of her run ({} more dropped as flood, {} more \
             bad_signature): forgeries used up her run's rate",
            now.flood - before.flood,
            now.bad_signature - before.bad_signature
        );
        alice
            .send_final("cursor", "final:alice:cursor:after", &[&bob, &carol])
            .await?;
        w.sleep(SETTLE).await;
        for p in [&alice, &bob, &carol] {
            p.check(&[&alice, &bob, &carol])?;
            ensure!(
                p.delivered("forged:") == 0,
                "{} delivered a signal bob forged as alice's",
                p.who
            );
        }
        w.measure("forged packets bob pushed", forged, "packets");
        Ok(())
    })
}
