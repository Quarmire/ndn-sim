//! Signals, e3 — Bob, a member, forges signals as Alice's.
//!
//! Alice, Bob and Carol share Alice's sealed sketch folder, all three writers. Alice draws; the
//! relay between the devices carries her packets, and Bob, a member, holds the folder's signal
//! key: he opens one of her packets and takes her run's id and her run header. He then pushes
//! into Carol's and Alice's groups, sealed under the folder's key, packets that claim Alice's
//! run:
//! - signals under her run id, signed by a run key of his own;
//! - her run header re-signed by his device key (it binds her run key), with signals signed by
//!   his run key;
//! - a header his device key signs for her run id that binds his own run key instead.
//!
//! The guards: each is refused (`bad_signature`: a run signature the run's key did not make, or
//! a run id its header's key does not hash to), and no forged signal is ever delivered; Alice's
//! later signals are still delivered as hers — no header Bob signed takes her run over.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e3",
    title: "A member cannot forge another member's signals",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "A member holding the scope's signal key cannot pass signals off as another \
             member's: a packet claiming another's run is refused unless that run's key signed \
             it, a run id is refused under a header whose run key does not hash to it, and a \
             header a member re-signs for another's run never takes that run over; no forged \
             signal is ever delivered.",
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

fn folder() -> Name {
    n("/alice/32=data/sketch")
}

/// One forged signal at `seq`, as Bob's packet claims Alice's run.
fn forged(w: &World, seq: u64, what: &str) -> signal::Signal {
    signal::Signal {
        seq,
        address: bytes::Bytes::from_static(b"cursor"),
        expires: w.net().date(BOB).0 + 10_000,
        payload: format!("forged:{what}").into(),
    }
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
        for i in 0..10 {
            alice.send("cursor", &format!("alice:cursor:{i}")).await?;
            w.sleep(FRAME).await;
        }
        alice
            .send_final("cursor", "final:alice:cursor:before", &[&bob, &carol])
            .await?;

        // Bob opens Alice's packets with the folder's signal key he holds as a member.
        let (key_id, key) = signal_key(w, BOB, &folder())?;
        let alice_run = alice.run_id().await;
        let theirs: Vec<signal::Body> = tap
            .interests()
            .iter()
            .filter_map(|wire| opened(wire, &key))
            .filter(|b| b.run == alice_run)
            .collect();
        let header = theirs
            .iter()
            .find_map(|b| b.header.clone())
            .ok_or_else(|| {
                Failure::new("the relay carried no packet of Alice's run with its header")
            })?;
        let header_data = ndn_packet::Data::decode(header.clone())
            .map_err(|e| Failure::new(format!("alice's run header does not decode: {e:?}")))?;
        let content = header_data.content().cloned().unwrap_or_default();
        let last = theirs
            .iter()
            .flat_map(|b| b.signals.iter().map(|s| s.seq))
            .max()
            .unwrap_or_default();

        let face = w.net().app_face(BOB);
        let groups = [group(&n("/carol")), group(&n("/alice"))];
        let mine = signal::RunKey::from_seed([0xb0; 32]);
        let gate = w.gate(BOB)?;
        let resigned = gate.signal_header(&folder(), &alice_run, &content)?;
        let bound_to_mine = gate.signal_header(
            &folder(),
            &alice_run,
            &signal::header_content(&mine.public(), last + 1, w.net().date(BOB).0 + 3_600_000),
        )?;
        let forgeries: [(&str, Option<&bytes::Bytes>); 3] = [
            ("her run, his run key", None),
            ("her header re-signed by his device", Some(&resigned)),
            ("his header for her run id", Some(&bound_to_mine)),
        ];
        let mut nonce = 0u8;
        let mut pushed = 0u64;
        for (k, (what, header)) in forgeries.iter().enumerate() {
            let before = stats(w, CAROL).await?.bad_signature;
            until_counted(
                w,
                CAROL,
                &format!("carol refusing bob's forgery ({what}) as badly signed"),
                |s| s.bad_signature > before,
                || {
                    nonce = nonce.wrapping_add(1);
                    pushed += 1;
                    let seq = last + 1_000 * (k as u64 + 1) + u64::from(nonce);
                    let body = signal::body(
                        &folder(),
                        &alice_run,
                        header.map(|h| &h[..]),
                        &[forged(w, seq, what)],
                        &mine,
                    );
                    let packet = signal::seal(&key_id, &key, &[nonce; 24], &body);
                    let face = &face;
                    let groups = &groups;
                    async move {
                        for g in groups {
                            face.send(signal::push(g, &packet)).await.map_err(|e| {
                                Failure::new(format!("bob's node took no packet: {e}"))
                            })?;
                        }
                        Ok(())
                    }
                },
            )
            .await?;
        }

        // Alice goes on drawing: still delivered as hers.
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
        for p in [&bob, &carol] {
            let latest = p.latest(&alice, b"cursor");
            ensure!(
                latest
                    .as_ref()
                    .is_some_and(|s| s.payload == "final:alice:cursor:after".as_bytes()),
                "{}'s last cursor from alice is {latest:?}: her run was taken over",
                p.who
            );
        }
        w.measure("forged packets bob pushed", pushed, "packets");
        Ok(())
    })
}
