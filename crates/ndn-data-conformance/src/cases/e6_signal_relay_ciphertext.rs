//! Signals, e6 — what the relay sees of a sealed folder's signals.
//!
//! Alice and Bob plan a trip on a map in Alice's folder `trip-sketch`, sealed to the two of
//! them. Each moves a pointer over the map and says where they are looking. The hub between
//! their devices is the relay that forwards every packet; it is tapped, and every signal packet
//! it forwards is read the way the relay can read it.
//!
//! The guard: every one is an unsigned push Interest named by a member namespace's sync group,
//! `32=signal` and its parameters digest, carrying exactly a SignalSealed — a key id of the
//! folder's signal key, a nonce and a ciphertext — and nothing else: no scope name, no sender's
//! key name or device, no run id, no address and no payload appears anywhere in it.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e6",
    title: "A relay sees only ciphertext of a sealed folder's signals",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "Every signal packet of a sealed scope a relay forwards is an unsigned push into a \
             member namespace's sync group carrying only a SignalSealed: the relay reads the \
             group, a key id, the size and the timing, and no scope name, sender, run, address or \
             payload.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

fn folder() -> Name {
    n("/alice/32=data/trip-sketch")
}

/// Where each looks on the map: (address, payload).
fn looks(who: &str) -> Vec<(String, String)> {
    (0..12)
        .map(|i| {
            (
                format!("pointer/route-map-{who}"),
                format!("{who}:lat=48.85{i:02},lon=2.35{i:02}"),
            )
        })
        .collect()
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.at(ALICE)
            .share_folder(&folder(), sealed_to(&["/alice", "/bob"]).into())
            .await?;
        let signal = |ns: &str| {
            group(&n(ns)).append_component(ndn_packet::NameComponent::new(
                32,
                bytes::Bytes::from_static(b"signal"),
            ))
        };
        let taps = [
            w.net().tap(&signal("/alice")).await,
            w.net().tap(&signal("/bob")).await,
        ];
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        for ((aa, ap), (ba, bp)) in looks("alice").into_iter().zip(looks("bob")) {
            alice.send(&aa, &ap).await?;
            bob.send(&ba, &bp).await?;
            w.sleep(FRAME).await;
        }
        alice
            .send_final(
                "pointer/route-map-alice",
                "final:alice:lat=48.8566,lon=2.3522",
                &[&bob],
            )
            .await?;
        bob.send_final(
            "pointer/route-map-bob",
            "final:bob:lat=48.8606,lon=2.3376",
            &[&alice],
        )
        .await?;

        // What must not appear: the scope, the senders, the runs, every address and payload.
        let mut secret: Vec<(String, Vec<u8>)> = vec![
            ("the scope name".into(), folder().encode_to_tlv().to_vec()),
            ("the scope's label".into(), b"trip-sketch".to_vec()),
            ("alice's run id".into(), alice.run_id().await.to_vec()),
            ("bob's run id".into(), bob.run_id().await.to_vec()),
        ];
        for d in [ALICE, BOB] {
            let device = w.net().spec(d).name();
            let key = w.signer(d)?.key_name().clone();
            secret.push((format!("{device}'s key name"), key.encode_to_tlv().to_vec()));
            secret.push((
                format!("{device}'s label"),
                w.net().spec(d).device.as_bytes().to_vec(),
            ));
        }
        for p in [&alice, &bob] {
            for (address, payload) in p.sent.lock().expect("the ledger's lock").iter() {
                secret.push((format!("{}'s address", p.who), address.clone()));
                secret.push((format!("{}'s payload", p.who), payload.clone()));
            }
        }
        let held: Vec<[u8; 8]> = w
            .gate(ALICE)?
            .signal_scope(&folder())?
            .keys
            .iter()
            .map(|k| k.id)
            .collect();

        let mut seen = 0u64;
        let mut bytes = 0u64;
        for (tap, ns) in taps.iter().zip(["/alice", "/bob"]) {
            let interests = tap.interests();
            ensure!(
                !interests.is_empty(),
                "the relay forwarded no signal packet into {ns}'s group"
            );
            for wire in interests {
                seen += 1;
                bytes += wire.len() as u64;
                let interest = ndn_packet::Interest::decode(wire.clone()).map_err(|e| {
                    Failure::new(format!("the relay forwarded a non-Interest: {e:?}"))
                })?;
                ensure!(
                    interest.sig_info().is_none(),
                    "a signal push the relay forwarded is signed: {}",
                    interest.name
                );
                let (pushed_to, packet) = signal::pushed(&wire)
                    .ok_or_else(|| Failure::new(format!("{} is no signal push", interest.name)))?;
                ensure!(
                    pushed_to == group(&n(ns)) && interest.name.len() == pushed_to.len() + 2,
                    "a signal push named {} is not <{ns}/32=sync>/32=signal/<digest>",
                    interest.name
                );
                let sealed = signal::sealed(&packet).ok_or_else(|| {
                    Failure::new(format!(
                        "the relay forwarded a packet of the sealed folder that is no \
                         SignalSealed alone: {} octets",
                        packet.len()
                    ))
                })?;
                ensure!(
                    held.contains(&sealed.key_id),
                    "a packet the relay forwarded is sealed under key id {:02x?}, no signal key \
                     of the folder",
                    sealed.key_id
                );
                for (what, bytes) in &secret {
                    ensure!(
                        !contains(&wire, bytes),
                        "a signal push the relay forwarded shows {what}: {}",
                        interest.name
                    );
                }
            }
        }
        for p in [&alice, &bob] {
            p.check(&[&alice, &bob])?;
        }
        w.measure("signal packets the relay forwarded", seen, "packets");
        w.measure(
            "bytes per signal push the relay forwarded",
            bytes / seen.max(1),
            "bytes",
        );
        Ok(())
    })
}
