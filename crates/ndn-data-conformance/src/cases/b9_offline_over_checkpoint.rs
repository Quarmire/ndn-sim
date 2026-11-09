//! Slice 6, b9 — a checkpoint written while another member works offline: when they return
//! before any release, their edit merges exactly on every device.
//!
//! Alice writes a trip note from her phone: a title and a long body (so the version travels in
//! pieces). Bob holds it and goes offline. Alice retitles the note and writes a checkpoint. Bob,
//! unaware of the checkpoint, appends a line to the body: his edit is a splice of the text he
//! held, made over Alice's first version. Alice's tablet, away until the checkpoint was written,
//! applies the checkpoint first and never fetches the first version's pieces. Before, a rule saw
//! Bob's edit only beside the checkpoint's state: the checkpoint restates every setting, so Bob's
//! body and the checkpoint's stood as two alternatives — a conflict where two people simply worked
//! at once — and the tablet, lacking the first version, spliced Bob's line into nothing. The fix:
//! when a version made apart from a checkpoint names covered versions in its past, the device
//! hands them to the rule as its basis, fetching their pieces from any holder (Bob's device among
//! them, which applied them), and the rule merges exactly: the checkpoint's statement of the body
//! is what Bob's edit was made over, so his edit replaces it, and the new title stays. Only after
//! a release, when the covered versions are gone everywhere, does the rule fall back to a
//! conflict (spec §5.2).

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::element::{Edit, Splice};
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "b9",
    title: "A checkpoint written while another member works offline: their edit merges exactly \
            on every device",
    slice: 6,
    needs: &[Feature::Merge, Feature::AppOps, Feature::MergePieces],
    model: &["M12", "M13"],
    guards: "A version written apart from a checkpoint over versions it covers merges exactly \
             when those versions are still held somewhere: a device that applied the checkpoint \
             first fetches them and hands them to the rule as the version's basis, and every \
             device shows the same value with no conflict — the edit replaces what the \
             checkpoint restated of its basis, and what the checkpoint changed stays.",
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
    ("Alice's laptop", LAPTOP),
    ("Alice's tablet", TABLET),
    ("Bob", BOB),
];

/// The note's body: 20 KiB, so the first version travels in pieces.
const BODY: usize = 20 * 1024;

/// What Bob appends.
const ADDED: &str = " (Bob: the night train leaves at ten)";

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "laptop");
    p.device("alice", "tablet");
    p.device("bob", "laptop");
    p
}

/// Whether every device agrees on `c`, holding each of `ids`.
async fn all_agree(w: &World, c: &Name, ids: &[&VersionId]) -> Result<bool, Failure> {
    let layers: Vec<std::sync::Arc<dyn DataLayer>> =
        DEVICES.iter().map(|(_, d)| w.at(*d)).collect();
    let refs: Vec<&dyn DataLayer> = layers.iter().map(|l| &**l).collect();
    agree(&refs, c, ids).await
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let trip = n("/alice/32=data/notes/trip");
        let all = [person("/alice"), person("/bob")];
        w.net().offline(TABLET);
        w.at(PHONE)
            .share(&trip, members(element_rule(), &["/alice", "/bob"], &all))
            .await?;
        let body = prose("trip", BODY);
        let first = put_element(w, PHONE, &trip, |op| {
            op.then(0, Edit::Create("note".into()))
                .set("title", "Trip")
                .set("body", body.clone())
        })
        .await?;
        w.until("Bob and Alice's laptop hold the note", LIMIT, || async {
            hold(w, &[LAPTOP, BOB], &trip, &[&first]).await
        })
        .await?;

        // Bob goes away; Alice retitles the note and checkpoints it.
        w.net().offline(BOB);
        let retitled = put_element(w, PHONE, &trip, |op| op.set("title", "Trip to Lyon")).await?;
        let (_, mine) = element_state(&*w.at(PHONE), &trip).await?;
        let cp = put_element(w, PHONE, &trip, |op| {
            op.then(0, Edit::Checkpoint(mine.state.clone()))
        })
        .await?;
        w.until("Alice's laptop holds the checkpoint", LIMIT, || async {
            hold(w, &[LAPTOP], &trip, &[&retitled, &cp]).await
        })
        .await?;
        // Bob, offline, appends a line to the body he holds.
        let appended = put_element(w, BOB, &trip, |op| {
            op.then(
                1000,
                Edit::Change(
                    "body".into(),
                    Splice {
                        at: body.chars().count(),
                        remove: 0,
                        insert: ADDED.into(),
                    },
                ),
            )
        })
        .await?;

        // The tablet comes back after the checkpoint: it applies it first, never fetching what it
        // covers.
        w.net().online(TABLET);
        w.until("the tablet reaches the checkpoint", LIMIT, || async {
            let (phone, tablet) = (w.at(PHONE), w.at(TABLET));
            agree(&[&*phone, &*tablet], &trip, &[&cp]).await
        })
        .await?;
        let covered = log_entry(w, PHONE, &trip, &first);
        // On a clean network none: the checkpoint covers the first version. On a lossy one the
        // first version may reach the tablet before the checkpoint, which then applies it first.
        w.measure(
            "pieces of the covered version the tablet fetched before Bob returned",
            w.pieces_stored(TABLET, &covered),
            "pieces",
        );

        // Bob comes back before any release.
        w.net().online(BOB);
        let start = tokio::time::Instant::now();
        w.until(
            "every device agrees on Bob's edit made apart from the checkpoint",
            LIMIT,
            || async { all_agree(w, &trip, &[&cp, &appended]).await },
        )
        .await?;
        w.converged(start.elapsed());
        w.measure(
            "pieces of the covered version the tablet fetched as basis",
            w.pieces_stored(TABLET, &covered),
            "pieces",
        );
        ensure!(
            w.pieces_stored(TABLET, &covered) > 0,
            "the tablet merged Bob's edit without fetching the covered version it was made over"
        );
        let expected = format!("{body}{ADDED}");
        for (who, d) in DEVICES {
            let (s, v) = element_state(&*w.at(d), &trip).await?;
            ensure!(
                s.not_counted.is_empty(),
                "{who} lists versions not counted: {:?}",
                s.not_counted
            );
            ensure!(
                v.variants.is_empty(),
                "{who} shows a conflict where Bob and Alice simply worked at once: {:?}",
                v.variants
                    .iter()
                    .map(|var| (&var.slot, var.alternatives.len()))
                    .collect::<Vec<_>>()
            );
            ensure!(
                setting(&v, "title") == Some("Trip to Lyon"),
                "{who}'s note is titled {:?}, not Alice's new title",
                setting(&v, "title")
            );
            ensure!(
                setting(&v, "body") == Some(expected.as_str()),
                "{who}'s body is {} characters ending {:?}, not the body with Bob's line appended",
                setting(&v, "body").map_or(0, |b| b.chars().count()),
                setting(&v, "body").map(|b| {
                    let n = b.chars().count();
                    b.chars().skip(n.saturating_sub(40)).collect::<String>()
                })
            );
        }
        Ok(())
    })
}
