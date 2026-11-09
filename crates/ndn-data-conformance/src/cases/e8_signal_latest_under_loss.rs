//! Signals, e8 — the newest per address, over a path that loses and reorders.
//!
//! Alice and Bob share Alice's sealed sketch folder. On the way into each device, one packet in
//! five is lost, one in ten arrives twice, and three in ten are held behind those after them.
//! Alice drags her cursor for three seconds at 60 Hz and says what she is doing every half
//! second; then she sends her last cursor and her last presence again and again until Bob has
//! acknowledged each, as a host re-sends its latest value until it is seen.
//!
//! The guard: Bob's subscriber never delivers an older signal after a newer one for the same
//! sender and address, never delivers one twice, and ends with Alice's last cursor and her last
//! presence.

use std::time::Duration;

use ndn_sim::Faults;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e8",
    title: "The newest signal per address, under loss and reordering",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "Over a path that drops, duplicates and reorders packets, a subscriber delivers per \
             sender and address only signals newer than the last it delivered, each once, and \
             the last value a sender sends again until it is acknowledged is delivered.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// Three seconds of cursor moves at 60 Hz.
const MOVES: usize = 180;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.faults(Faults {
        drop: 0.2,
        dup: 0.1,
        delay_ms: 400,
        reorder: 0.3,
        seed: 1,
        ..Faults::default()
    });
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
            alice.send("cursor", &format!("alice:cursor:{i}")).await?;
            if i % 30 == 0 {
                alice
                    .send("presence", &format!("alice:presence:{}", i / 30))
                    .await?;
            }
            w.sleep(FRAME).await;
        }
        let mut sends = 0;
        for (address, last) in [
            ("cursor", "final:alice:cursor:180"),
            ("presence", "final:alice:presence:idle"),
        ] {
            sends += alice.send_final(address, last, &[&bob]).await?;
        }
        w.converged(start.elapsed());
        for (address, last) in [
            ("cursor", "final:alice:cursor:180"),
            ("presence", "final:alice:presence:idle"),
        ] {
            let got = bob.latest(&alice, address.as_bytes());
            ensure!(
                got.as_ref().is_some_and(|s| s.payload == last.as_bytes()),
                "bob's last {address} from alice is {got:?}, not her last {last:?}"
            );
        }
        bob.check(&[&alice, &bob])?;
        // Over the cursor moves themselves, the order of what Bob delivered follows the order
        // Alice sent them in.
        let mut last = None;
        for s in bob.all() {
            let Some(i) = s
                .payload
                .strip_prefix(b"alice:cursor:")
                .and_then(|i| std::str::from_utf8(i).ok()?.parse::<usize>().ok())
            else {
                continue;
            };
            ensure!(
                last.is_none_or(|l| i > l),
                "bob delivered alice's cursor move {i} after move {last:?}"
            );
            last = Some(i);
        }
        let got = stats(w, BOB).await?;
        w.measure("cursor moves alice sent", MOVES as u64, "signals");
        w.measure("signals bob delivered", got.delivered, "signals");
        w.measure("stale signals bob dropped", got.stale, "signals");
        w.measure(
            "finals alice sent until acknowledged",
            u64::from(sends),
            "signals",
        );
        Ok(())
    })
}
