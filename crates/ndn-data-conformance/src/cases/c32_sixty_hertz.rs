//! Channels, c32 — four devices emit at 60 Hz into one space and each receives the other three.
//!
//! Alice, Bob, Carol and Dave write one private space, one device each. Each device is the
//! sender of its own channel and, asking the other three, the receiver of three. For five seconds
//! each emits a cursor at 60 Hz and says four times a second what it is doing (presence); then
//! each emits a last cursor and a last presence until all three others have them. The relay
//! between the devices is the hub: the case reads what its side table carried.
//!
//! The guard: whatever the network did, every message a receiver is given at a path is one the
//! sender emitted there, attributed to the sender's device, given once, and never older than one
//! given before it for the same sender and path; every receiver ends with each sender's last
//! cursor and last presence. The report shows the frames and octets the relay received while they
//! drew and what one message cost.
//!
//! The network is lossless here: twelve sessions (each device asks the other three) on a lossy
//! network are let go and asked again on every transient end, which releases all of a device's
//! sessions at once and does not settle within the case's bound; the case is about what the
//! senders' rate and the receivers' order do, not about loss (c30 is that).

use std::collections::BTreeMap;
use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;
use ndn_sim::Faults;

use super::channel_kit::{EMIT_EVERY, Listener, space};
use super::kit::{LIMIT, n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Fwd, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c32",
    title: "Four senders at 60 Hz in one space",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "With four devices each emitting cursors at 60 Hz into one space, every message a \
             receiver is given is one its sender emitted at that path, attributed to the \
             sender's device, given once and never older than one given before it for the same \
             sender and path, and every receiver ends with each sender's last value of each \
             path.",
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

/// Everyone but the owner: writers and readers beside her.
const OTHERS: [&str; 3] = ["/bob", "/carol", "/dave"];

/// Five seconds at 60 Hz.
const FRAMES: usize = 300;
/// Presence every 15 frames: four times a second.
const PRESENCE_EVERY: usize = 15;
/// 60 Hz.
const FRAME: Duration = Duration::from_micros(16_667);
/// A receiver told of an end a lossy network makes asks again this often while the senders draw.
const HEAL_EVERY: usize = 15;

fn plan() -> Plan {
    let mut p = Plan::new();
    for (person, device) in PEOPLE {
        p.device(person, device);
    }
    p.faults(Faults::default());
    p
}

fn path_of(stem: &str) -> Name {
    n(&format!("/{stem}"))
}

/// How a message of `who` at `stem` ranks among the ones `who` emitted there: a move by its
/// index, a last one after every move by its round. `None` for a payload `who` never emitted
/// at `stem`.
fn rank(payload: &[u8], who: &str, stem: &str) -> Option<(u8, u64)> {
    let text = std::str::from_utf8(payload).ok()?;
    if let Some(i) = text.strip_prefix(&format!("{who}:{stem}:")) {
        let i: u64 = i.parse().ok()?;
        let most = match stem {
            "cursor" => FRAMES,
            _ => FRAMES.div_ceil(PRESENCE_EVERY),
        };
        return (i < most as u64).then_some((0, i));
    }
    let round = text.strip_prefix(&format!("final:{who}:{stem}#"))?;
    Some((1, round.parse().ok()?))
}

/// The rank of the last message given per (sender, path).
type Last = BTreeMap<(usize, &'static str), (u8, u64)>;

/// Fail unless everything `receiver` was given is what the other three emitted: by their
/// devices, at the paths they emit at, once, in order. Returns the last rank held per
/// (sender, path).
fn check(w: &World, receiver: usize, listener: &Listener) -> Result<Last, Failure> {
    let mut last = Last::new();
    for e in &listener.events {
        let ChannelEvent::Message {
            path,
            bytes,
            writer,
        } = e
        else {
            continue;
        };
        let Some(sender) = (0..PEOPLE.len()).find(|j| w.net().spec(Dev(*j)).name() == *writer)
        else {
            return Err(Failure::new(format!(
                "{} was given {path} from {writer}, a device that is none of the four",
                PEOPLE[receiver].0
            )));
        };
        ensure!(
            sender != receiver,
            "{} was given its own message at {path}",
            PEOPLE[receiver].0
        );
        let who = PEOPLE[sender].0;
        let Some(stem) = ["cursor", "presence"]
            .into_iter()
            .find(|s| *path == path_of(s))
        else {
            return Err(Failure::new(format!(
                "{} was given a message at {path}, which nobody emitted",
                PEOPLE[receiver].0
            )));
        };
        let Some(ranked) = rank(bytes, who, stem) else {
            return Err(Failure::new(format!(
                "{} was given {bytes:?} at {path} from {who}, which {who} never emitted there",
                PEOPLE[receiver].0
            )));
        };
        if let Some(before) = last.get(&(sender, stem)) {
            ensure!(
                ranked > *before,
                "{} was given {who}'s {path} message {ranked:?} after {before:?}: given twice or \
                 older than one given before it",
                PEOPLE[receiver].0
            );
        }
        last.insert((sender, stem), ranked);
    }
    Ok(last)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(Dev(0))
            .create(&space(), private(&OTHERS, &OTHERS))
            .await?;
        let mut listeners = Vec::new();
        for i in 0..PEOPLE.len() {
            listeners.push(Listener::prepare(w, Dev(i), ChannelTrust::Prompt).await?);
        }
        for (i, l) in listeners.iter_mut().enumerate() {
            for j in (0..PEOPLE.len()).filter(|j| *j != i) {
                l.establish(w, Dev(j)).await?;
            }
        }
        let senders: Vec<_> = listeners.iter().map(|l| l.ch.clone()).collect();

        // Five seconds of drawing: each frame every sender emits its cursor, and now and then its
        // presence; the receivers read what has arrived each frame, as a host that draws does.
        let before = w.net().side_counts(Fwd::Hub);
        let start = tokio::time::Instant::now();
        let mut emitted = 0u64;
        for i in 0..FRAMES {
            for (j, (who, _)) in PEOPLE.iter().enumerate() {
                senders[j]
                    .emit(
                        &space(),
                        &path_of("cursor"),
                        Bytes::from(format!("{who}:cursor:{i}")),
                    )
                    .await?;
                emitted += 1;
                if i % PRESENCE_EVERY == 0 {
                    senders[j]
                        .emit(
                            &space(),
                            &path_of("presence"),
                            Bytes::from(format!("{who}:presence:{}", i / PRESENCE_EVERY)),
                        )
                        .await?;
                    emitted += 1;
                }
            }
            w.sleep(FRAME).await;
            for l in &mut listeners {
                l.pump();
            }
            if i % HEAL_EVERY == HEAL_EVERY - 1 {
                for l in &mut listeners {
                    l.heal(w).await?;
                }
            }
        }
        let drawing = start.elapsed();
        let after = w.net().side_counts(Fwd::Hub);

        // Each sender's last cursor and presence, again every EMIT_EVERY until the others have
        // them.
        let finals = start.elapsed();
        let mut round = 0u64;
        loop {
            for (j, (who, _)) in PEOPLE.iter().enumerate() {
                for stem in ["cursor", "presence"] {
                    senders[j]
                        .emit(
                            &space(),
                            &path_of(stem),
                            Bytes::from(format!("final:{who}:{stem}#{round}")),
                        )
                        .await?;
                }
            }
            round += 1;
            w.sleep(EMIT_EVERY).await;
            let mut every = true;
            for (r, l) in listeners.iter_mut().enumerate() {
                l.heal(w).await?;
                l.pump();
                let last = check(w, r, l)?;
                for j in (0..PEOPLE.len()).filter(|j| *j != r) {
                    for stem in ["cursor", "presence"] {
                        every &= last.get(&(j, stem)).is_some_and(|(kind, _)| *kind == 1);
                    }
                }
            }
            if every {
                break;
            }
            ensure!(
                start.elapsed() - finals < LIMIT,
                "after {round} rounds of last values over {LIMIT:?} of virtual time, not every \
                 receiver had each sender's last cursor and presence"
            );
        }
        w.converged(start.elapsed());
        for (r, l) in listeners.iter().enumerate() {
            l.alive(PEOPLE[r].0)?;
        }

        let frames = after.frames_in - before.frames_in;
        let octets = after.bytes_in - before.bytes_in;
        w.measure(
            "messages the four emitted while they drew",
            emitted,
            "messages",
        );
        w.measure(
            "virtual time the drawing took",
            drawing.as_millis() as u64,
            "ms",
        );
        w.measure(
            "frames the relay received while they drew",
            frames,
            "frames",
        );
        w.measure("octets the relay received while they drew", octets, "bytes");
        w.measure(
            "octets the relay received per message",
            octets / emitted.max(1),
            "bytes",
        );
        Ok(())
    })
}
