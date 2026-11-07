//! Slice 6, f1 — one members record and one grant per reader for a folder of a thousand
//! collections.
//!
//! Alice keeps her recipes as a thousand collections under one folder and shares the folder with
//! three friends. Slice 2 knew only per-collection records: a thousand records signed, a thousand
//! seal epochs, and each friend asking a grant for every one (N records, N·k grants — "open after
//! slice 2"). The fix: a folder's members record governs every collection under it; collections
//! without their own readers seal in the folder's epoch, so a reader asks one grant per folder
//! epoch whatever the number of collections. The case measures both ways side by side — the
//! slice-2 way over its own folder of per-collection records, and the folder record — and asserts
//! that every friend reads every collection with one grant for the whole folder.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "f1",
    title: "One members record and one grant per reader for a folder of a thousand collections",
    slice: 6,
    needs: &[Feature::Seal, Feature::Log, Feature::FolderMembers],
    model: &[],
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
/// Collections under the folder record.
const FOLDER_N: usize = 1000;
/// Collections shared one by one, the slice-2 way.
const PER_COLLECTION_N: usize = 1000;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "phone");
    p.device("dave", "phone");
    // `<granter>/32=grant`: three components, so grants are counted apart from everything else.
    p.count_names(3);
    p
}

/// The recipe type.
fn recipe() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/recipe"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

/// Whether a counted name group is a granter's grants (`<granter>/32=grant`, however the
/// keyword component is spelled).
fn grants(prefix: &str) -> bool {
    prefix
        .rsplit('/')
        .next()
        .is_some_and(|c| c == "32=grant" || c == "keyword=grant")
}

/// Whether `layer` reads recipe `i` as collection `c`'s newest version.
async fn reads(layer: &dyn DataLayer, c: &Name, i: usize) -> Result<bool, Failure> {
    match layer.get(c).await {
        Ok(Answer {
            got: Got::Version(v),
            ..
        }) => Ok(field_of(&v, "n") == Some(i.to_string().as_str())),
        Ok(a) => Err(Failure::new(format!(
            "get of the log collection {c} answered {:?}, not its newest version",
            a.got
        ))),
        Err(
            DataError::Unavailable { .. } | DataError::NotFound { .. } | DataError::Sealed { .. },
        ) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// What one way of sharing cost, per reader where it is per reader.
struct Spent {
    signatures: u64,
    records: u64,
    asked: Vec<u64>,
    answered: Vec<u64>,
    interests: u64,
    bytes: u64,
    took: Duration,
}

/// Alice shares `count` collections under `folder` with every reader — by one folder record, or
/// by a record per collection — writes one recipe into each, and every reader reads every one.
async fn share_and_read(
    w: &World,
    folder: &Name,
    count: usize,
    by_folder: bool,
) -> Result<Spent, Failure> {
    let alice = w.at(OWNER);
    let readers = [
        person("/alice"),
        person("/bob"),
        person("/carol"),
        person("/dave"),
    ];
    let share = members(Rule::Log, &["/alice"], &readers);
    let collections: Vec<Name> = (0..count)
        .map(|i| n(&format!("{folder}/r{i:04}")))
        .collect();

    // Readers follow the owner's writes as they come: what they spend is counted from the share.
    let counted: Vec<_> = READERS
        .iter()
        .map(|r| w.net().counted_where(*r, grants))
        .collect();
    let wire: Vec<_> = READERS.iter().map(|r| w.net().device_wire(*r)).collect();
    let signed = w.signed_by(OWNER);
    w.gesture();
    let records = if by_folder {
        alice.share_folder(folder, share).await?;
        1
    } else {
        for c in &collections {
            alice.share(c, share.clone()).await?;
        }
        collections.len() as u64
    };
    let signatures = w.signed_by(OWNER) - signed;
    let start = tokio::time::Instant::now();
    for (i, c) in collections.iter().enumerate() {
        alice
            .put(c, content(&[("n", &i.to_string())]), recipe())
            .await?;
    }
    for (i, c) in collections.iter().enumerate() {
        for r in READERS {
            let layer = w.at(r);
            w.until(
                &format!("{} reads {c}", w.net().spec(r).name()),
                LIMIT,
                || reads(&*layer, c, i),
            )
            .await?;
        }
    }
    let took = start.elapsed();
    let mut spent = Spent {
        signatures,
        records,
        asked: Vec::new(),
        answered: Vec::new(),
        interests: 0,
        bytes: 0,
        took,
    };
    for (j, r) in READERS.iter().enumerate() {
        let now = w.net().counted_where(*r, grants);
        spent
            .asked
            .push(now.out_interests - counted[j].out_interests);
        spent.answered.push(now.in_data - counted[j].in_data);
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
    w.measure(
        what("grants answered"),
        spent.answered.iter().sum(),
        "grants",
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
        for (j, r) in READERS.iter().enumerate() {
            ensure!(
                after.answered[j] == 1,
                "{} got {} grants to read {FOLDER_N} collections under one folder record: one \
                 per reader per folder epoch",
                w.net().spec(*r).name(),
                after.answered[j]
            );
        }
        Ok(())
    })
}
