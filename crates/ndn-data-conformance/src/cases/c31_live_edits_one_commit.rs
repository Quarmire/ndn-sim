//! Channels, c31 — live edits, then one commit.
//!
//! (Ported from the signal case e9.) Alice and Bob share Alice's notes space; Alice's draft, a
//! path in it, holds one value: "Dear Bob,". Alice types the rest of a sentence; each keystroke
//! goes to Bob as a live, unsigned emission carrying the text so far, and Bob watches it grow.
//! When she is done, she emits her final text until Bob has seen it, then commits: one `put` of
//! the final text. Bob takes the live data without the kept entries (`kept: false`), as the
//! harness does.
//!
//! The guard: Bob reads the draft as the final text, no live emission became an entry (Alice's log
//! in the space, at Alice and at Bob, grew by exactly the one entry of the commit), the commit
//! never rode the live stream, and the last live edit Bob delivered is the final text.

use std::collections::BTreeSet;
use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;
use ndn_heap::wire::parse_log_name;

use super::channel_kit::{Listener, emit_until_seen, space};
use super::kit::{LIMIT, SETTLE, n, octets, private, value_now};
use crate::case::{Case, CaseFuture, Failure};
use crate::channel::ChannelEvent;
use crate::channel::ChannelTrust;
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c31",
    title: "Live edits end in one commit",
    slice: 8,
    needs: &[Feature::Channels, Feature::Log],
    model: &[],
    guards: "Live edits emitted on a channel never become versions: after a stream of them ends \
             in one put of the final text, the other member reads the final text, the writer's \
             log gained exactly the one entry of the commit, at the writer and at the reader, \
             and the live stream never carried the commit.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

const FIRST: &str = "Dear Bob,";
const FINAL_TEXT: &str = "Dear Bob, the trip is on for Friday; bring the map.";

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

fn draft() -> Name {
    n("/draft")
}

/// The seqs of Alice's laptop's log in the space that `d`'s store holds an entry of.
fn alices_log(w: &World, d: Dev) -> Result<BTreeSet<u64>, Failure> {
    let alice = w.net().spec(ALICE).name();
    let space = space();
    Ok(w.stored_names(d)?
        .iter()
        .filter_map(parse_log_name)
        .filter(|l| l.device == alice && l.space == space)
        .map(|l| l.seq)
        .collect())
}

/// Whether `d` reads the draft as `text`.
async fn reads(w: &World, d: Dev, text: &str) -> Result<bool, Failure> {
    Ok(value_now(&*w.spaces(d), &space(), &draft())
        .await?
        .is_some_and(|v| v == text.as_bytes()))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = space();
        w.gesture();
        w.spaces(ALICE)
            .create(&space, private(&[], &["/bob"]))
            .await?;
        w.space_put(ALICE, &space, &draft(), octets(FIRST)).await?;
        w.until("bob reading the draft's first value", LIMIT, || {
            reads(w, BOB, FIRST)
        })
        .await?;
        let alice_tx = w.channels(ALICE).await?;
        let mut bob = Listener::join(w, BOB, ChannelTrust::Prompt, ALICE).await?;
        let before = [alices_log(w, ALICE)?, alices_log(w, BOB)?];

        // Each keystroke a live edit: the text so far.
        let mut sent = 0u64;
        for end in FIRST.len() + 1..FINAL_TEXT.len() {
            alice_tx
                .emit(
                    &space,
                    &draft(),
                    Bytes::from(format!("edit:{}", &FINAL_TEXT[..end])),
                )
                .await?;
            sent += 1;
            w.sleep(Duration::from_millis(16)).await;
        }
        // The last edit is emitted until Bob has it.
        let last = format!("final:{FINAL_TEXT}");
        emit_until_seen(w, &alice_tx, &draft(), &last, &mut [&mut bob]).await?;

        // The commit: one put.
        w.gesture();
        let commit = w
            .space_put(ALICE, &space, &draft(), octets(FINAL_TEXT))
            .await?;
        w.until("bob reading the committed value", LIMIT, || {
            reads(w, BOB, FINAL_TEXT)
        })
        .await?;
        w.sleep(SETTLE).await;
        for (d, held) in [ALICE, BOB].into_iter().zip(&before) {
            let now = alices_log(w, d)?;
            let gained: Vec<u64> = now.difference(held).copied().collect();
            ensure!(
                gained == [commit.seq],
                "{}'s store holds alice's log entries {gained:?} that it did not before the live \
                 edits, not the commit's alone ({}): {sent} live edits were emitted",
                w.net().spec(d).name(),
                commit.seq
            );
        }

        // What Bob was given: the edits grow, the last is the final text, and the commit is not
        // among them.
        bob.pump();
        bob.alive("bob")?;
        let mut length = 0;
        let mut given = 0u64;
        for e in &bob.events {
            let ChannelEvent::Message { path, bytes, .. } = e else {
                continue;
            };
            ensure!(
                *path == draft(),
                "bob was given a message at {path}, not the draft"
            );
            ensure!(
                bytes[..] != *FINAL_TEXT.as_bytes(),
                "the commit rode the live stream: bob was given {bytes:?} as a live message"
            );
            let text = std::str::from_utf8(bytes).unwrap_or_default();
            let body = text
                .strip_prefix("edit:")
                .or_else(|| {
                    text.strip_prefix("final:")
                        .and_then(|t| t.rsplit_once('#'))
                        .map(|(t, _)| t)
                })
                .ok_or_else(|| {
                    Failure::new(format!("bob was given {text:?}, no edit alice emitted"))
                })?;
            ensure!(
                FINAL_TEXT.starts_with(body) && body.len() >= length,
                "bob was given the edit {body:?} after one of {length} octets: older, or no text \
                 alice typed"
            );
            length = body.len();
            given += 1;
        }
        ensure!(
            length == FINAL_TEXT.len(),
            "bob's last live edit has {length} octets, not the final text's {}",
            FINAL_TEXT.len()
        );
        w.measure("live edits emitted before the commit", sent, "messages");
        w.measure("live messages bob was given", given, "messages");
        w.measure(
            "entries alice's log gained from them and the commit",
            (alices_log(w, ALICE)?.len() - before[0].len()) as u64,
            "entries",
        );
        Ok(())
    })
}
