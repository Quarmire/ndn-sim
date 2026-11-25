//! Signals, e9 — live edits, then one commit.
//!
//! Alice and Bob share Alice's sealed notes space; Alice's draft, a path in it, holds one
//! value: "Dear Bob,". Alice types the rest of a sentence; each keystroke goes to Bob as a
//! live, unsigned edit — a signal carrying the text so far — and Bob watches it grow. When she
//! is done, she sends her final text until Bob has seen it, then commits: one `put` of the final
//! text.
//!
//! The guard: Bob reads the draft as the final text — no signal became an entry (Alice's log
//! in the space, at Alice and at Bob, grew by exactly the one entry of the commit) — and the
//! last live edit Bob delivered is that same text.

use std::collections::BTreeSet;
use std::time::Duration;

use ndn_heap::Name;
use ndn_heap::wire::parse_log_name;

use super::kit::{LIMIT, SETTLE, n, octets, value_now};
use super::signal_kit::{FINAL, FRAME, Peer, sealed_to};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e9",
    title: "Live edits end in one commit",
    slice: 7,
    needs: &[
        Feature::Seal,
        Feature::Log,
        Feature::FolderMembers,
        Feature::Signals,
    ],
    model: &[],
    guards: "Live edits sent as signals never become versions: after a stream of them ends in \
             one put of the final text, the other member reads the final text, and the writer's \
             log gained exactly the one entry of the commit, at the writer and at the reader.",
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

fn folder() -> Name {
    n("/alice/32=data/notes")
}

fn draft() -> Name {
    n("/draft")
}

/// The seqs of Alice's laptop's log in the space that `d`'s store holds an entry of.
fn alices_log(w: &World, d: Dev) -> Result<BTreeSet<u64>, Failure> {
    let alice = w.net().spec(ALICE).name();
    Ok(w.stored_names(d)?
        .iter()
        .filter_map(parse_log_name)
        .filter(|l| l.device == alice && l.space == folder())
        .map(|l| l.seq)
        .collect())
}

/// Whether `d` reads the draft as `text`.
async fn reads(w: &World, d: Dev, text: &str) -> Result<bool, Failure> {
    Ok(value_now(&*w.spaces(d), &folder(), &draft())
        .await?
        .is_some_and(|v| v == text.as_bytes()))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&folder(), sealed_to(&["/bob"]))
            .await?;
        w.space_put(ALICE, &folder(), &draft(), octets(FIRST))
            .await?;
        w.until("bob reading the draft's first value", LIMIT, || {
            reads(w, BOB, FIRST)
        })
        .await?;
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        let before = [alices_log(w, ALICE)?, alices_log(w, BOB)?];

        // Each keystroke a live edit: the text so far.
        let address = "text/draft";
        let mut sent = 0u64;
        for end in FIRST.len() + 1..FINAL_TEXT.len() {
            alice
                .send(address, &format!("edit:{}", &FINAL_TEXT[..end]))
                .await?;
            sent += 1;
            w.sleep(FRAME).await;
        }
        // The last edit is a final, so Bob acknowledges it.
        let last_edit = format!("{FINAL}{FINAL_TEXT}");
        alice.send_final(address, &last_edit, &[&bob]).await?;

        // The commit: one put.
        w.gesture();
        let commit = w
            .space_put(ALICE, &folder(), &draft(), octets(FINAL_TEXT))
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
                 edits, not the commit's alone ({}): {sent} live edits were sent",
                w.net().spec(d).name(),
                commit.seq
            );
        }
        let edit = bob.latest(&alice, address.as_bytes());
        ensure!(
            edit.as_ref()
                .is_some_and(|s| s.payload == last_edit.as_bytes()),
            "bob's last live edit is {edit:?}, not the final text"
        );
        bob.check(&[&alice, &bob])?;
        w.measure("live edits sent before the commit", sent, "signals");
        w.measure(
            "entries alice's log gained from them and the commit",
            (alices_log(w, ALICE)?.len() - before[0].len()) as u64,
            "entries",
        );
        Ok(())
    })
}
