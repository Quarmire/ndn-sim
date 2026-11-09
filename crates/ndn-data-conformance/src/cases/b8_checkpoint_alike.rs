//! Slice 6, b8 — a rule's state after a checkpoint does not depend on whether the versions it
//! covers were applied before it.
//!
//! Alice owns a paragraph Bob may write. From her phone she writes it (with a long note, so the
//! version travels in pieces), locks its text, gives it a title, and then a checkpoint covering
//! all three. Bob held the first two when he went offline; unaware of the checkpoint he edits the
//! text with the lock in view. Alice's laptop, online throughout, applied the three versions and
//! then the checkpoint (device S). Alice's tablet, away until the checkpoint was written, applies
//! the checkpoint first and never fetches what it covers (device R); it restarts before Bob
//! returns, so it builds its state from the checkpoint whatever order the versions reached it in
//! (on a lossy network the first may come first). Before, the reference rule
//! kept the covered versions in its set and judged Bob's edit against the locks it held: S saw
//! the lock in Bob's past ("never counts") while R, holding only the checkpoint's lock, saw an
//! edit made apart from it ("waits") — and once Alice wrote over Bob's edit, R counted it while S
//! never would. The fix: applying a checkpoint drops every version it covers from the rule's set;
//! a covered version serves only as what a version made apart from the checkpoint was made over,
//! and the device hands the rule those (fetching them when it lacks them, spec §5.2). R and S then
//! count the same versions, with the same reasons, and show the same value.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "b8",
    title: "A checkpoint's state does not depend on whether the versions it covers were applied \
            before it",
    slice: 6,
    needs: &[Feature::Merge, Feature::AppOps, Feature::MergePieces],
    model: &["M12", "M13"],
    guards: "A rule's state after applying a checkpoint is the same on a device that applied the \
             versions it covers before it and on one that applied the checkpoint first and never \
             fetched them: a version written apart from the checkpoint over some of them is \
             counted alike, for the same reason, and the value, the locks and the versions not \
             counted are the same on every member, also after an owner writes over it.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const TABLET: Dev = Dev(2);
const BOB: Dev = Dev(3);
const DEVICES: [(&str, Dev); 4] = [
    ("Alice's phone", PHONE),
    ("Alice's laptop (S)", LAPTOP),
    ("Alice's tablet (R)", TABLET),
    ("Bob", BOB),
];

/// The paragraph's note: 20 KiB, so the first version travels in pieces.
const NOTE: usize = 20 * 1024;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "laptop");
    p.device("alice", "tablet");
    p.device("bob", "laptop");
    p
}

/// Whether every device agrees on `c`, holding each of `ids`, and lists the same versions not
/// counted with the same reasons.
async fn all_agree(w: &World, c: &Name, ids: &[&VersionId]) -> Result<bool, Failure> {
    let layers: Vec<std::sync::Arc<dyn DataLayer>> =
        DEVICES.iter().map(|(_, d)| w.at(*d)).collect();
    let refs: Vec<&dyn DataLayer> = layers.iter().map(|l| &**l).collect();
    if !agree(&refs, c, ids).await? {
        return Ok(false);
    }
    let mut first: Option<Vec<(VersionId, String)>> = None;
    for layer in &refs {
        let Some(s) = state_now(*layer, c).await? else {
            return Ok(false);
        };
        match &first {
            None => first = Some(s.not_counted),
            Some(f) if *f != s.not_counted => return Ok(false),
            Some(_) => {}
        }
    }
    Ok(true)
}

/// On every device: Bob's edit is not counted, as one made with the lock in view, the text is
/// `text`, and the text is locked.
async fn bob_never_counts(
    w: &World,
    c: &Name,
    bobs: &VersionId,
    text: &str,
    when: &str,
) -> Result<(), Failure> {
    let mut reasons: Vec<(&str, Option<String>)> = Vec::new();
    for (who, d) in DEVICES {
        let (s, v) = element_state(&*w.at(d), c).await?;
        let why = not_counted_in(&s, bobs).map(str::to_owned);
        ensure!(
            why.as_deref()
                .is_some_and(|why| why.starts_with("never counts")),
            "{who}, {when}, does not hold Bob's edit made with the lock in view as never \
             counting: {:?}",
            s.not_counted
        );
        ensure!(
            setting(&v, "text") == Some(text),
            "{who}'s paragraph, {when}, shows {:?}, not {text:?}",
            setting(&v, "text")
        );
        ensure!(
            v.state.locks.iter().any(|l| l.setting == "text"),
            "{who}, {when}, shows no lock of the text: {:?}",
            v.state.locks
        );
        reasons.push((who, why));
    }
    let (first, why) = &reasons[0];
    for (who, other) in &reasons[1..] {
        ensure!(
            other == why,
            "{who} and {first} give different reasons for Bob's edit, {when}: {other:?} and \
             {why:?}"
        );
    }
    Ok(())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let paragraph = n("/alice/32=data/notes/p1");
        let all = [person("/alice"), person("/bob")];
        w.net().offline(TABLET);
        w.at(PHONE)
            .share(
                &paragraph,
                members(element_rule(), &["/alice", "/bob"], &all),
            )
            .await?;
        let note = prose("note", NOTE);
        let made = put_element(w, PHONE, &paragraph, |op| {
            op.then(0, Edit::Create("paragraph".into()))
                .set("text", "draft")
                .set("note", note.clone())
        })
        .await?;
        let lock = put_element(w, PHONE, &paragraph, |op| {
            op.then(0, Edit::Lock("text".into()))
        })
        .await?;
        w.until("Bob and Alice's laptop hold the lock", LIMIT, || async {
            hold(w, &[LAPTOP, BOB], &paragraph, &[&made, &lock]).await
        })
        .await?;

        // Bob goes away holding the lock; Alice titles the paragraph and checkpoints it.
        w.net().offline(BOB);
        let titled = put_element(w, PHONE, &paragraph, |op| op.set("title", "Notes")).await?;
        let (_, mine) = element_state(&*w.at(PHONE), &paragraph).await?;
        let whole = mine.state.clone();
        ensure!(
            whole.locks.iter().any(|l| l.setting == "text"),
            "the phone's state before the checkpoint holds no lock of the text: {:?}",
            whole.locks
        );
        let cp = put_element(w, PHONE, &paragraph, |op| {
            op.then(0, Edit::Checkpoint(whole))
        })
        .await?;
        w.until("Alice's laptop holds the checkpoint", LIMIT, || async {
            hold(w, &[LAPTOP], &paragraph, &[&titled, &cp]).await
        })
        .await?;
        // Bob, unaware of the checkpoint, edits the text with the lock in view.
        let bobs = put_element(w, BOB, &paragraph, |op| {
            op.set("text", "bob, over the lock")
        })
        .await?;

        // The tablet comes back after the checkpoint: it applies it first, never fetching what it
        // covers.
        w.net().online(TABLET);
        w.until("the tablet reaches the checkpoint", LIMIT, || async {
            let (phone, tablet) = (w.at(PHONE), w.at(TABLET));
            agree(&[&*phone, &*tablet], &paragraph, &[&cp]).await
        })
        .await?;
        let covered = log_entry(w, PHONE, &paragraph, &made);
        w.measure(
            "pieces of the covered version the tablet fetched before Bob returned",
            w.pieces_stored(TABLET, &covered),
            "pieces",
        );
        // On a lossy network the first version may reach it before the checkpoint does, so it
        // restarts: a restarted device builds the state anew from its newest checkpoint (spec
        // §5.2), so whatever order it received them in, it is R — the checkpoint applied, nothing
        // it covers applied before it.
        w.stop(TABLET).await?;
        w.restart(TABLET).await?;
        w.until(
            "the tablet, restarted, holds the checkpoint",
            LIMIT,
            || async {
                let (phone, tablet) = (w.at(PHONE), w.at(TABLET));
                agree(&[&*phone, &*tablet], &paragraph, &[&cp]).await
            },
        )
        .await?;

        // Bob comes back: his edit reaches R and S.
        w.net().online(BOB);
        let start = tokio::time::Instant::now();
        w.until(
            "every device agrees on Bob's edit made apart from the checkpoint",
            LIMIT,
            || async { all_agree(w, &paragraph, &[&cp, &bobs]).await },
        )
        .await?;
        w.converged(start.elapsed());
        w.measure(
            "pieces of the covered version the tablet fetched as basis",
            w.pieces_stored(TABLET, &covered),
            "pieces",
        );
        bob_never_counts(w, &paragraph, &bobs, "draft", "after Bob returns").await?;

        // Alice writes over Bob's edit: made with the lock in view, it still never counts.
        let over = put_element(w, PHONE, &paragraph, |op| op.set("title", "Notes, kept")).await?;
        w.until(
            "every device agrees once Alice wrote over Bob's edit",
            LIMIT,
            || async { all_agree(w, &paragraph, &[&over, &bobs]).await },
        )
        .await?;
        bob_never_counts(
            w,
            &paragraph,
            &bobs,
            "draft",
            "after Alice wrote over Bob's edit",
        )
        .await?;
        for (who, d) in DEVICES {
            let (_, v) = element_state(&*w.at(d), &paragraph).await?;
            ensure!(
                setting(&v, "title") == Some("Notes, kept")
                    && setting(&v, "note") == Some(note.as_str()),
                "{who}'s paragraph lacks Alice's title or the note whole: title {:?}",
                setting(&v, "title")
            );
        }
        Ok(())
    })
}
