//! Signals, e11 — Bob, a member, claims Alice's run at a receiver that does not hold it yet.
//!
//! Alice, Bob and Carol share Alice's sealed sketch folder, all three writers. Alice draws while
//! Bob listens; the relay carries her packets, and Bob, a member, holds the folder's signal key:
//! he opens one and reads her run's id and, from her run header, her run's public key. Alice
//! pauses. Only then does Carol's app open the folder, so Carol holds no run of Alice's. Bob
//! pushes into Carol's and Alice's groups, sealed under the folder's key, header-only packets for
//! Alice's run id whose run header his own device key signs, each binding *Alice's* run key (so
//! the run id hashes right) and each signed by a run key of his own, which is not Alice's:
//! - her header's content as it is, re-signed by his device;
//! - a RunStart a million above her sequences;
//! - a LocalRing secret of his choosing.
//!
//! Then Alice draws again. The guards: Carol refuses each of Bob's headers (`bad_signature`: the
//! packet carrying a header must be signed by the run key the header binds, which only the run's
//! owner holds — spec §3.1, §8.1 step 4); every signal of Alice's run Carol and Bob deliver is
//! delivered as Alice's, none as Bob's; and Alice's later signals reach Carol (her final is
//! acknowledged) — no header Bob signed takes her run over or shuts it out.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e11",
    title: "A member cannot claim another member's run",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "A run header is taken only with proof that its signer holds the run key: a \
             member who signs a header binding another member's run key (with any RunStart or \
             LocalRing), in a packet that run key did not sign, is refused bad_signature by a \
             receiver that holds no run of that id yet; the other member's signals are still \
             delivered as hers, never as the claimant's, and reach that receiver.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

/// How many times Bob pushes one forged header while Carol has not counted it, [`RESEND`] apart.
const PUSHES: u32 = 8;

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

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.at(ALICE)
            .share_folder(&folder(), sealed_to(&["/alice", "/bob", "/carol"]).into())
            .await?;
        let tap = w.net().tap(&n("/bob/32=sync/32=signal")).await;
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        for i in 0..10 {
            alice.send("cursor", &format!("alice:cursor:{i}")).await?;
            w.sleep(FRAME).await;
        }
        alice
            .send_final("cursor", "final:alice:cursor:before", &[&bob])
            .await?;

        // Bob opens Alice's packets and reads her run key off her header.
        let (key_id, key) = signal_key(w, BOB, &folder())?;
        let alice_run = alice.run_id().await;
        let header = tap
            .interests()
            .iter()
            .filter_map(|wire| opened(wire, &key))
            .filter(|b| b.run == alice_run)
            .find_map(|b| b.header)
            .ok_or_else(|| {
                Failure::new("the relay carried no packet of Alice's run with its header")
            })?;
        let header_data = ndn_packet::Data::decode(header)
            .map_err(|e| Failure::new(format!("alice's run header does not decode: {e:?}")))?;
        let content = header_data.content().cloned().unwrap_or_default();
        let alice_key = signal::header_run_key(&content)
            .ok_or_else(|| Failure::new("alice's run header binds no run key"))?;

        // Alice has paused (her last push expired a second after it left); Carol opens the
        // folder now, so she holds no run of Alice's.
        w.sleep(Duration::from_secs(2)).await;
        let carol = Peer::join(w, CAROL, &folder()).await?;

        let gate = w.gate(BOB)?;
        let not_after = w.net().date(BOB).0 + 3_600_000;
        let start = w.net().date(BOB).0 * 1000 + 1_000_000_000;
        let claims = [
            (
                "her header re-signed by his device",
                gate.signal_header(&folder(), &alice_run, &content)?,
            ),
            (
                "her run key, a RunStart above her sequences",
                gate.signal_header(
                    &folder(),
                    &alice_run,
                    &signal::header_content(&alice_key, start, not_after),
                )?,
            ),
            (
                "her run key, a LocalRing of his",
                gate.signal_header(
                    &folder(),
                    &alice_run,
                    &signal::header_content_ring(&alice_key, start, not_after, &[0x5a; 32]),
                )?,
            ),
        ];
        let face = w.net().app_face(BOB);
        let groups = [group(&n("/carol")), group(&n("/alice"))];
        let mine = signal::RunKey::from_seed([0xb1; 32]);
        let mut nonce = 0u8;
        let mut pushed = 0u64;
        let mut refused = Vec::new();
        for (what, header) in &claims {
            let before = stats(w, CAROL).await?.bad_signature;
            let mut counted = false;
            for _ in 0..PUSHES {
                nonce = nonce.wrapping_add(1);
                pushed += 1;
                let body = signal::body(&folder(), &alice_run, Some(header), &[], &mine);
                let packet = signal::seal(&key_id, &key, &[nonce; 24], &body);
                for g in &groups {
                    face.send(signal::push(g, &packet))
                        .await
                        .map_err(|e| Failure::new(format!("bob's node took no packet: {e}")))?;
                }
                w.sleep(RESEND).await;
                if stats(w, CAROL).await?.bad_signature > before {
                    counted = true;
                    break;
                }
            }
            refused.push((*what, counted, before));
        }

        // Alice draws again.
        for i in 0..20 {
            alice.send("cursor", &format!("alice:after:{i}")).await?;
            w.sleep(FRAME).await;
        }
        w.sleep(Duration::from_secs(2)).await;
        for p in [&bob, &carol] {
            if let Some(s) = p
                .all()
                .into_iter()
                .find(|s| s.run.0 == alice_run && sender_of(s) != alice.me)
            {
                return Err(Failure::new(format!(
                    "{} delivered {:?} of alice's run as {}'s: bob's header took her run over",
                    p.who,
                    String::from_utf8_lossy(&s.payload),
                    s.sender
                )));
            }
        }
        for (what, counted, before) in &refused {
            ensure!(
                *counted,
                "carol did not refuse bob's header for alice's run ({what}) as badly signed \
                 after {PUSHES} pushes (bad_signature stayed at {before}): she took it"
            );
        }
        alice
            .send_final("cursor", "final:alice:cursor:after", &[&bob, &carol])
            .await?;
        w.sleep(SETTLE).await;
        for p in [&alice, &bob, &carol] {
            p.check(&[&alice, &bob, &carol])?;
        }
        let latest = carol.latest(&alice, b"cursor");
        ensure!(
            latest.as_ref().is_some_and(
                |s| s.payload == "final:alice:cursor:after".as_bytes() && s.run.0 == alice_run
            ),
            "carol's last cursor from alice is {latest:?}: her run did not reach carol"
        );
        w.measure("forged headers bob pushed", pushed, "packets");
        Ok(())
    })
}
