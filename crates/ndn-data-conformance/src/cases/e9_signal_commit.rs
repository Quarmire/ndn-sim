//! Signals, e9 — live edits, then one commit.
//!
//! Alice and Bob share Alice's sealed notes folder; Alice's draft, a collection in it, holds one
//! version: "Dear Bob,". Alice types the rest of a sentence; each keystroke goes to Bob as a
//! live, unsigned edit — a signal carrying the text so far — and Bob watches it grow. When she
//! is done, she sends her final text until Bob has seen it, then commits: one `put` of the final
//! text.
//!
//! The guard: Bob reads exactly one new version of the draft, whose text is the final text — no
//! signal became a version (the draft's versions grew by one, at Alice and at Bob) — and the
//! last live edit Bob delivered is that same text.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
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
             one put of the final text, the other member reads exactly one new version, whose \
             value is the final text, and the collection's versions grew by one.",
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
    folder().append("draft")
}

/// The versions `d` lists of the draft, oldest first.
async fn draft_versions(w: &World, d: Dev) -> Result<Vec<Version>, Failure> {
    let changes = look(&*w.at(d), &draft(), &Frontier::new(), LOOK).await?;
    Ok(versions(&changes).cloned().collect())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.at(ALICE)
            .share_folder(&folder(), sealed_to(&["/alice", "/bob"]).into())
            .await?;
        let first = w.put(ALICE, &draft(), text(FIRST), note(1)).await?;
        w.until("bob reading the draft's first version", LIMIT, || async {
            Ok(draft_versions(w, BOB).await?.iter().any(|v| v.id == first))
        })
        .await?;
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;

        // Each keystroke a live edit: the text so far.
        let address = format!("text/{}", draft());
        let mut sent = 0u64;
        for end in FIRST.len() + 1..FINAL_TEXT.len() {
            alice
                .send(&address, &format!("edit:{}", &FINAL_TEXT[..end]))
                .await?;
            sent += 1;
            w.sleep(FRAME).await;
        }
        // The last edit is a final, so Bob acknowledges it.
        let last_edit = format!("{FINAL}{FINAL_TEXT}");
        alice.send_final(&address, &last_edit, &[&bob]).await?;

        // The commit: one put.
        w.gesture();
        let commit = w.put(ALICE, &draft(), text(FINAL_TEXT), note(1)).await?;
        w.until("bob reading the committed version", LIMIT, || async {
            Ok(draft_versions(w, BOB).await?.iter().any(|v| v.id == commit))
        })
        .await?;
        w.sleep(SETTLE).await;
        for d in [ALICE, BOB] {
            let listed = draft_versions(w, d).await?;
            let ids: Vec<&VersionId> = listed.iter().map(|v| &v.id).collect();
            ensure!(
                ids.len() == 2 && ids.contains(&&first) && ids.contains(&&commit),
                "{} lists the draft's versions {ids:?}, not its first and the one commit: \
                 {sent} live edits were sent",
                w.net().spec(d).name()
            );
        }
        let committed = draft_versions(w, BOB).await?;
        let text_read = committed
            .iter()
            .find(|v| v.id == commit)
            .and_then(|v| field_of(v, "text"));
        ensure!(
            text_read == Some(FINAL_TEXT),
            "bob reads the commit as {text_read:?}, not the final text"
        );
        let edit = bob.latest(&alice, address.as_bytes());
        ensure!(
            edit.as_ref()
                .is_some_and(|s| s.payload == last_edit.as_bytes()),
            "bob's last live edit is {edit:?}, not the final text"
        );
        bob.check(&[&alice, &bob])?;
        w.measure("live edits sent before the commit", sent, "signals");
        w.measure(
            "versions the draft gained from them and the commit",
            (committed.len() - 1) as u64,
            "versions",
        );
        Ok(())
    })
}
