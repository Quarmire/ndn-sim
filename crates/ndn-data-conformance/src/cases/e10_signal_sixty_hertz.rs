//! Signals, e10 — four people draw at 60 Hz in one folder.
//!
//! Alice, Bob, Carol and Dave share Alice's sealed whiteboard folder, all four writers. For five
//! seconds each drags a cursor at 60 Hz and says four times a second what they are doing; then
//! each sends their last cursor and presence until all three others acknowledged them. The
//! relay between the devices is tapped, so the case reports what the push costs per packet.
//!
//! The guard: every receiver ends with each sender's last signal per address, and whatever the
//! network did, every delivery is one its sender sent, once, and never older than one delivered
//! before it for the same sender and address. The report shows the push Interests the relay
//! forwarded, the octets of each and how many each signal took (one per member namespace's
//! group).

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e10",
    title: "Four senders at 60 Hz in one folder",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "With four members each pushing cursor signals at 60 Hz into one sealed folder, \
             every receiver gets each sender's last signal per address, and every delivery is \
             one its sender sent, once, never older than one before it for the same sender and \
             address.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const PEOPLE: [(&str, &str); 4] = [
    ("alice", "laptop"),
    ("bob", "phone"),
    ("carol", "tablet"),
    ("dave", "laptop"),
];

/// Five seconds at 60 Hz.
const FRAMES: usize = 300;
/// Presence every 15 frames: four times a second.
const PRESENCE_EVERY: usize = 15;

fn plan() -> Plan {
    let mut p = Plan::new();
    for (person, device) in PEOPLE {
        p.device(person, device);
    }
    p
}

fn folder() -> Name {
    n("/alice/32=data/whiteboard")
}

/// `peer` draws for [`FRAMES`] frames: its cursor every frame, its presence every
/// [`PRESENCE_EVERY`]. Returns how many signals it sent.
async fn draw(w: &World, peer: &Peer, who: &str) -> Result<u64, Failure> {
    let mut sent = 0;
    for i in 0..FRAMES {
        peer.send("cursor", &format!("{who}:cursor:{i}")).await?;
        sent += 1;
        if i % PRESENCE_EVERY == 0 {
            peer.send(
                "presence",
                &format!("{who}:presence:{}", i / PRESENCE_EVERY),
            )
            .await?;
            sent += 1;
        }
        w.sleep(FRAME).await;
    }
    Ok(sent)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let namespaces: Vec<String> = PEOPLE.iter().map(|(p, _)| format!("/{p}")).collect();
        let people: Vec<&str> = namespaces.iter().map(String::as_str).collect();
        w.gesture();
        w.at(Dev(0))
            .share_folder(&folder(), sealed_to(&people).into())
            .await?;
        let mut taps = Vec::new();
        for ns in &people {
            taps.push(
                w.net()
                    .tap(
                        &group(&n(ns)).append_component(ndn_packet::NameComponent::new(
                            32,
                            bytes::Bytes::from_static(b"signal"),
                        )),
                    )
                    .await,
            );
        }
        let mut peers = Vec::new();
        for i in 0..PEOPLE.len() {
            peers.push(Peer::join(w, Dev(i), &folder()).await?);
        }
        let everyone: Vec<&Peer> = peers.iter().collect();

        let tapped = |taps: &[crate::world::Tap]| -> (u64, u64) {
            taps.iter()
                .flat_map(|t| t.interests())
                .fold((0, 0), |(n, b), wire| (n + 1, b + wire.len() as u64))
        };
        let (before, before_bytes) = tapped(&taps);
        let start = tokio::time::Instant::now();
        let drawn = futures::future::join_all(
            peers
                .iter()
                .zip(PEOPLE)
                .map(|(p, (who, _))| draw(w, p, who)),
        )
        .await;
        let mut signals = 0;
        for d in drawn {
            signals += d?;
        }
        let (pushes, push_bytes) = tapped(&taps);
        let (pushes, push_bytes) = (pushes - before, push_bytes - before_bytes);
        let drawing = start.elapsed();
        ensure!(
            pushes == signals * PEOPLE.len() as u64,
            "the relay forwarded {pushes} push Interests for {signals} signals: not one per member \
             namespace's group ({}) per signal",
            PEOPLE.len()
        );

        for (p, (who, _)) in peers.iter().zip(PEOPLE) {
            let others: Vec<&Peer> = everyone.iter().copied().filter(|o| o.me != p.me).collect();
            p.send_final("cursor", &format!("final:{who}:cursor:done"), &others)
                .await?;
            p.send_final("presence", &format!("final:{who}:presence:away"), &others)
                .await?;
        }
        w.converged(start.elapsed());
        for receiver in &peers {
            receiver.check(&everyone)?;
            for (sender, (who, _)) in peers.iter().zip(PEOPLE) {
                if sender.me == receiver.me {
                    continue;
                }
                for (address, last) in [
                    ("cursor", format!("final:{who}:cursor:done")),
                    ("presence", format!("final:{who}:presence:away")),
                ] {
                    let got = receiver.latest(sender, address.as_bytes());
                    ensure!(
                        got.as_ref().is_some_and(|s| s.payload == last.as_bytes()),
                        "{}'s last {address} from {who} is {got:?}, not {last:?}",
                        receiver.who
                    );
                }
            }
        }
        w.measure("signals the four sent while they drew", signals, "signals");
        w.measure(
            "virtual time the drawing took",
            drawing.as_millis() as u64,
            "ms",
        );
        w.measure(
            "push Interests the relay forwarded while they drew",
            pushes,
            "Interests",
        );
        w.measure(
            "push Interests per signal (one per member namespace's group)",
            pushes / signals.max(1),
            "Interests",
        );
        w.measure(
            "octets per push Interest",
            push_bytes / pushes.max(1),
            "bytes",
        );
        for (i, (who, _)) in PEOPLE.iter().enumerate() {
            let s = stats(w, Dev(i)).await?;
            w.measure(format!("{who}'s signals delivered"), s.delivered, "signals");
        }
        Ok(())
    })
}
