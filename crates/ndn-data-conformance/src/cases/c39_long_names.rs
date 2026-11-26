//! Channels, c39 — a space named in very many words, and a path as long as one may be, still
//! leave a message of 512 octets its room.
//!
//! Alice names two spaces as long as a space may be named (four components after `32=data`, the
//! most a space name has, of a hundred letters each): one sealed to her and Bob, one public, both
//! writers. In each, Alice and Bob ask each other's channel and emit, at a path of exactly 255
//! octets (the longest name a message carries), messages of 512 octets, until the other has one.
//!
//! The guard: every message arrives whole, at the path it was emitted at, attributed to the
//! sender's device, in both spaces (the space's name rides in the ask and the session, never in a
//! frame, so a long name leaves a frame all its room); and a path of 256 octets is refused at
//! `emit` as over the limit, with the limit stated.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;

use super::channel_kit::{EMIT_EVERY, Listener};
use super::kit::{LIMIT, n, private, public};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c39",
    title: "A very long space name and path leave a message of 512 octets its room",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A message of 512 octets at a path of 255 octets is delivered whole, at its path and \
             as its sender's, in a sealed and in a public space named with the most components \
             a space may have, each a hundred letters long; a path of 256 octets is refused as \
             over the limit of 255.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// The octets of a message.
const MESSAGE: usize = 512;
/// The longest name (its components' octets) a message carries.
const NAME_MAX: usize = 255;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

/// Alice's space whose four components after `32=data` are a hundred letters each, the first
/// starting with `tag` (so that two spaces differ).
fn long_space(tag: char) -> Name {
    let labels: Vec<String> = (0..4)
        .map(|i| {
            let letter = if i == 0 { tag } else { 'x' };
            letter.to_string().repeat(100)
        })
        .collect();
    n(&format!("/alice/32=data/{}", labels.join("/")))
}

/// A path whose components take exactly `octets` octets (labels of up to a hundred letters,
/// each with its two octets of type and length).
fn long_path(octets: usize) -> Name {
    let mut left = octets;
    let mut labels = Vec::new();
    while left > 0 {
        let take = if left <= 102 {
            left
        } else if left - 102 < 3 {
            left - 3
        } else {
            102
        };
        labels.push("p".repeat(take - 2));
        left -= take;
    }
    let name = n(&format!("/{}", labels.join("/")));
    let encoded = name.encode_to_tlv();
    // The Name's own TLV header: type and a 1- or 3-octet length.
    let header = if octets < 253 { 2 } else { 4 };
    assert_eq!(encoded.len(), octets + header, "the path is exact");
    name
}

/// `text` padded with dots to `MESSAGE` octets.
fn padded(text: &str) -> Bytes {
    Bytes::from(format!("{text:.<MESSAGE$}"))
}

/// Alice and Bob in `space` ask each other and emit at `path` until each has a message of the
/// other's, whole.
async fn exchange(w: &World, space: &Name, path: &Name) -> Result<(), Failure> {
    let mut alice = Listener::prepare_in(w, ALICE, ChannelTrust::Prompt, space).await?;
    let mut bob = Listener::prepare_in(w, BOB, ChannelTrust::Prompt, space).await?;
    alice.establish(w, BOB).await?;
    bob.establish(w, ALICE).await?;
    let (from_alice, from_bob) = (w.net().spec(ALICE).name(), w.net().spec(BOB).name());
    let start = tokio::time::Instant::now();
    let mut round = 0u64;
    loop {
        alice
            .ch
            .emit(space, path, padded(&format!("alice:{round}:")))
            .await?;
        bob.ch
            .emit(space, path, padded(&format!("bob:{round}:")))
            .await?;
        round += 1;
        w.sleep(EMIT_EVERY).await;
        alice.heal(w).await?;
        bob.heal(w).await?;
        alice.pump();
        bob.pump();
        let whole = |l: &Listener, who: &str, writer: &Name| {
            l.events.iter().any(|e| {
                matches!(
                    e,
                    ChannelEvent::Message { path: p, bytes, writer: wr }
                        if p == path
                            && wr == writer
                            && bytes.len() == MESSAGE
                            && bytes.starts_with(format!("{who}:").as_bytes())
                            && bytes.ends_with(b"..")
                )
            })
        };
        if whole(&alice, "bob", &from_bob) && whole(&bob, "alice", &from_alice) {
            break;
        }
        ensure!(
            start.elapsed() < LIMIT,
            "after {round} emissions over {LIMIT:?} of virtual time, not both of Alice and Bob \
             had a whole message of 512 octets at the path of {} octets from the other, in a \
             space of {} octets",
            NAME_MAX,
            space.encode_to_tlv().len()
        );
    }
    for (l, who) in [(&alice, "Alice"), (&bob, "Bob")] {
        l.alive(who)?;
        for e in &l.events {
            if let ChannelEvent::Message { bytes, .. } = e {
                ensure!(
                    bytes.len() == MESSAGE,
                    "{who} was given a message of {} octets, not {MESSAGE}",
                    bytes.len()
                );
            }
        }
    }
    Ok(())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        let (sealed, open) = (long_space('s'), long_space('o'));
        let path = long_path(NAME_MAX);
        w.spaces(ALICE)
            .create(&sealed, private(&["/bob"], &["/bob"]))
            .await?;
        exchange(w, &sealed, &path).await?;
        w.spaces(ALICE).create(&open, public(&["/bob"])).await?;
        exchange(w, &open, &path).await?;

        // One octet over: refused, saying so.
        let over = long_path(NAME_MAX + 1);
        let sender = w.channels(ALICE).await?;
        let refused = sender.emit(&open, &over, padded("alice:over:")).await;
        match refused {
            Err(e)
                if e.detail
                    .contains(&format!("{} is over the limit of {NAME_MAX}", NAME_MAX + 1)) => {}
            other => {
                return Err(Failure::new(format!(
                    "an emission at a path of {} octets, one over the limit of {NAME_MAX}, \
                     answered {other:?}, not a refusal that states the limit",
                    NAME_MAX + 1
                )));
            }
        }
        w.measure(
            "octets of the space's name",
            open.encode_to_tlv().len() as u64,
            "bytes",
        );
        Ok(())
    })
}
