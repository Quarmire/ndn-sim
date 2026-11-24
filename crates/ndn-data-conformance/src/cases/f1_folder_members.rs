//! Slice 6, f1 — one members record and one grant per reader for a space of a thousand paths.
//!
//! Alice keeps her recipes as a thousand paths in one space and shares the space with three
//! friends. Slice 2 knew only per-collection records: a thousand records signed, a thousand
//! seal epochs, and each friend asking a grant for every one (N records, N·k grants — "open after
//! slice 2"). The fix: a space's members record governs every path under it, which seals in the
//! space's epoch, so a reader asks one grant per space epoch whatever the number of paths. The
//! case measures both ways side by side — the slice-2 way as a space of its own for every recipe
//! (a members record, an epoch and a grant each), and the one space — and asserts that every
//! friend reads every path with one grant for the whole space.

use std::time::Duration;

use ndn_data::Name;

use super::kit::{LIMIT, n, octets, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::Spaces;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "f1",
    title: "One members record and one grant per reader for a folder of a thousand collections",
    slice: 6,
    needs: &[Feature::Seal, Feature::Log, Feature::FolderMembers],
    model: &["M15"],
    guards: "A folder's members record lets every reader read every collection under it, each \
             reader getting one grant per folder epoch whatever the number of collections; the \
             per-collection way (a record and a grant per collection per reader) is measured \
             beside it.",
    budget: Duration::from_secs(12 * 3600),
    plan,
    run,
};

const OWNER: Dev = Dev(0);
const READERS: [Dev; 3] = [Dev(1), Dev(2), Dev(3)];
/// Paths under the one space.
const FOLDER_N: usize = 1000;
/// Recipes shared a space each, the slice-2 way.
const PER_COLLECTION_N: usize = 1000;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "phone");
    p.device("dave", "phone");
    p
}

/// Whether `spaces` reads recipe `i` at `path` of `space`. A reader that has not yet received the
/// record, or the keys of the epoch the recipe is sealed in, reads nothing yet.
async fn reads(spaces: &dyn Spaces, space: &Name, path: &Name, i: usize) -> Result<bool, Failure> {
    match spaces.get(space, path).await {
        Ok(Some(read)) => Ok(read.bytes == i.to_string().as_bytes()),
        Ok(None) => Ok(false),
        Err(e) if e.retry_later() || e.kind_is("Sealed") => Ok(false),
        Err(e) => Err(e),
    }
}

/// What one way of sharing cost; grants asked per reader, as each reader's layer counts them
/// (a layer that counts none says zero), and the signatures the owner made beyond the share and
/// the recipes, which are its answers to the readers' grant asks (and any record it signs
/// lazily).
struct Spent {
    signatures: u64,
    records: u64,
    asked: Vec<u64>,
    answered: u64,
    grant_signatures: u64,
    interests: u64,
    bytes: u64,
    took: Duration,
}

/// Alice shares `count` recipes under `root` with every reader — as one space of `count` paths,
/// or as a space each (a record per recipe) — writes one recipe into each, and every reader reads
/// every one.
async fn share_and_read(
    w: &World,
    root: &Name,
    count: usize,
    by_folder: bool,
) -> Result<Spent, Failure> {
    let alice = w.spaces(OWNER);
    let share = private(&[], &["/bob", "/carol", "/dave"]);
    // Where each recipe lives: a path of the one space, or the one path of a space of its own.
    let places: Vec<(Name, Name)> = (0..count)
        .map(|i| {
            if by_folder {
                (root.clone(), n(&format!("/r{i:04}")))
            } else {
                (n(&format!("{root}/r{i:04}")), n("/recipe"))
            }
        })
        .collect();
    let spaces: Vec<&Name> = if by_folder {
        vec![root]
    } else {
        places.iter().map(|(space, _)| space).collect()
    };

    // Readers follow the owner's writes as they come: what they spend is counted from the share.
    let asked: Vec<u64> = READERS.iter().map(|r| w.grants(*r).asked).collect();
    let answered = w.grants(OWNER).answered;
    let wire: Vec<_> = READERS.iter().map(|r| w.net().device_wire(*r)).collect();
    let signed = w.signed_by(OWNER);
    w.gesture();
    for space in &spaces {
        alice.create(space, share.clone()).await?;
    }
    let records = spaces.len() as u64;
    let signatures = w.signed_by(OWNER) - signed;
    let start = tokio::time::Instant::now();
    for r in READERS {
        let reader = w.spaces(r);
        for space in &spaces {
            w.retry_later(|| reader.open(space)).await?;
        }
    }
    for (i, (space, path)) in places.iter().enumerate() {
        alice.put(space, path, octets(&i.to_string())).await?;
    }
    // Following a thousand spaces of their own, one group and one epoch each, a reader on a lossy
    // network may wait out a few of the growing pauses before an asked packet arrives, so the
    // per-collection way gets ten limits for each recipe; the folder, one group, keeps one.
    let limit = if by_folder { LIMIT } else { 10 * LIMIT };
    for (i, (space, path)) in places.iter().enumerate() {
        for r in READERS {
            let reader = w.spaces(r);
            w.until(
                &format!("{} reads {space}{path}", w.net().spec(r).name()),
                limit,
                || reads(&*reader, space, path, i),
            )
            .await?;
        }
    }
    let took = start.elapsed();
    // Every signature the owner made, less the share's and one per recipe, answered a grant ask.
    let signed_in_all = w.signed_by(OWNER) - signed;
    let grant_signatures = signed_in_all
        .checked_sub(signatures + count as u64)
        .ok_or_else(|| {
            Failure::new(format!(
                "the owner made {signed_in_all} signatures: fewer than {signatures} to share \
                 and {count} recipes"
            ))
        })?;
    let mut spent = Spent {
        signatures,
        records,
        asked: Vec::new(),
        answered: w.grants(OWNER).answered - answered,
        grant_signatures,
        interests: 0,
        bytes: 0,
        took,
    };
    for (j, r) in READERS.iter().enumerate() {
        spent.asked.push(w.grants(*r).asked - asked[j]);
        let used = w.net().device_wire(*r) - wire[j];
        spent.interests += used.interests;
        spent.bytes += used.in_bytes;
    }
    Ok(spent)
}

/// Record what one way cost, as the Results page reads it.
fn record(w: &World, way: &str, count: usize, spent: &Spent) {
    let what = |metric: &str| {
        format!(
            "{way}, {count} collections × {} readers: {metric}",
            READERS.len()
        )
    };
    w.measure(what("signatures to share"), spent.signatures, "signatures");
    w.measure(what("members records signed"), spent.records, "records");
    w.measure(what("grants asked"), spent.asked.iter().sum(), "grants");
    w.measure(what("grants answered"), spent.answered, "grants");
    w.measure(
        what("signatures beyond the share and the recipes"),
        spent.grant_signatures,
        "signatures",
    );
    w.measure(what("reader Interests"), spent.interests, "round trips");
    w.measure(what("reader bytes received"), spent.bytes, "bytes");
    w.measure(
        what("time until every reader read every collection"),
        spent.took.as_millis() as u64,
        "ms",
    );
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let before = share_and_read(
            w,
            &n("/alice/32=data/recipes-by-one"),
            PER_COLLECTION_N,
            false,
        )
        .await?;
        record(w, "per-collection records", PER_COLLECTION_N, &before);

        let mark = w.mark();
        let after = share_and_read(w, &n("/alice/32=data/recipes"), FOLDER_N, true).await?;
        record(w, "folder record", FOLDER_N, &after);
        w.report_from(mark);
        w.converged(after.took);
        // One grant per reader for the whole folder, as the owner's signatures say it: every
        // reader's ask for the epoch is answered once, not once per collection. Each reader's
        // grant is a signature, so there are at least as many as readers; a layer may sign a
        // record or two besides (the old one signs one lazily), so the bound is twice the
        // readers, against the per-collection way's grant for every collection.
        let readers = READERS.len() as u64;
        ensure!(
            (readers..=2 * readers).contains(&after.grant_signatures),
            "the owner made {} signatures beyond the share and the recipes to answer the {} \
             readers of {FOLDER_N} collections under one folder record: one grant per reader \
             per folder epoch, {readers} to {} of them",
            after.grant_signatures,
            READERS.len(),
            2 * readers
        );
        ensure!(
            before.grant_signatures >= after.grant_signatures * 10,
            "the per-collection way cost the owner {} answers to grant asks, the folder way {}: \
             the folder's one epoch should save the grant of every collection",
            before.grant_signatures,
            after.grant_signatures
        );
        // A layer that counts the grants its readers ask says it per reader.
        if before.asked.iter().sum::<u64>() > 0 {
            for (j, r) in READERS.iter().enumerate() {
                ensure!(
                    after.asked[j] == 1,
                    "{} asked {} grants to read {FOLDER_N} collections under one folder record: \
                     one per reader per folder epoch",
                    w.net().spec(*r).name(),
                    after.asked[j]
                );
            }
        }
        Ok(())
    })
}
