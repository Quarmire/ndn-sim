//! Signals, e15 — a member's genuine packet at the last sequence does not stop a receiver.
//!
//! Alice, Bob and Carol share Alice's sealed sketch folder, all three writers. A program on
//! Alice's laptop opens a run of its own: its device key signs (through the device's gate) the
//! header of a run key the program made, with a RunStart just below 2⁶⁴ − 1, and the run key
//! signs a packet carrying one signal at sequence 2⁶⁴ − 1 — a packet every check passes: a
//! member's header, the run's own signature, a sequence at or above RunStart. It pushes it into
//! Carol's group, sealed under the folder's key.
//!
//! The guards: Carol's signals go on: Bob's later final and Alice's are delivered to her and
//! acknowledged (a receiver must not overflow its replay window at the last sequence, panic
//! holding its lock and stop — spec §8.2), and every delivery is one its sender sent.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e15",
    title: "A packet at the last sequence does not stop a receiver",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "A member's genuine packet whose sequence is the largest a sequence can be (2^64 - \
             1) is taken or refused like any other: the receiver goes on delivering every \
             sender's later signals.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

/// How many times the packet at the last sequence is pushed, [`RESEND`] apart.
const PUSHES: u32 = 4;

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
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        let carol = Peer::join(w, CAROL, &folder()).await?;
        bob.send_final("cursor", "final:bob:cursor:before", &[&carol])
            .await?;

        // The program's own run on Alice's laptop, its header signed by her device key.
        let (key_id, key) = signal_key(w, ALICE, &folder())?;
        let mine = signal::RunKey::from_seed([0xa1; 32]);
        let now = w.net().date(ALICE).0;
        let header = w.gate(ALICE)?.signal_header(
            &folder(),
            &mine.id(),
            &signal::header_content(&mine.public(), u64::MAX - 8, now + 3_600_000),
        )?;
        let body = signal::body(
            &folder(),
            &mine.id(),
            Some(&header),
            &[signal::Signal {
                seq: u64::MAX,
                address: bytes::Bytes::from_static(b"last"),
                expires: now + 10_000,
                payload: bytes::Bytes::from_static(b"alice:last-sequence"),
            }],
            &mine,
        );
        let face = w.net().app_face(ALICE);
        // The program's packet is Alice's device's: a receiver may deliver it as hers.
        alice
            .sent
            .lock()
            .expect("the ledger's lock")
            .insert((b"last".to_vec(), b"alice:last-sequence".to_vec()));
        for k in 0..PUSHES {
            let packet = signal::seal(&key_id, &key, &[0xa1 ^ k as u8; 24], &body);
            face.send(signal::push(&group(&n("/carol")), &packet))
                .await
                .map_err(|e| Failure::new(format!("alice's node took no packet: {e}")))?;
            w.sleep(RESEND).await;
        }

        let stopped = |who: &str, e: Failure| {
            Failure::new(format!(
                "after alice's genuine packet at sequence 2^64 - 1, carol no longer delivers \
                 {who}'s signals: {e}"
            ))
        };
        bob.send_final("cursor", "final:bob:cursor:after", &[&carol])
            .await
            .map_err(|e| stopped("bob", e))?;
        alice
            .send_final("cursor", "final:alice:cursor:after", &[&carol])
            .await
            .map_err(|e| stopped("alice", e))?;
        w.sleep(SETTLE).await;
        for p in [&alice, &bob, &carol] {
            p.check(&[&alice, &bob, &carol])?;
        }
        Ok(())
    })
}
