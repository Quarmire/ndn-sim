//! Slice 6, f3 — a collection taking its first own record keeps what its folder admitted.
//!
//! Alice's club folder is a log written by Alice, Bob and Carol, unsealed. Carol writes the
//! minutes and Bob a note, each in a collection with no record of its own: the folder's governs
//! them. Then Alice gives each collection a record of its own — the minutes narrowed to Alice and
//! Bob, the notes sealed to Alice and Bob. A first own record must start from what governed the
//! collection until then, as any revision starts from the record in force: narrowing the writers
//! cuts Carol at what Alice holds of hers, so her earlier minute stays; sealing a collection the
//! folder left unsealed sets `Since`, so Bob's earlier note stays. Computed as if the collection
//! had no record before, Carol's minute would be refused `NotMember` and Bob's note `Unsealed`,
//! and both withdrawn everywhere.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "f3",
    title: "A collection taking its first own record keeps what its folder admitted",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::RemovalCut,
        Feature::FolderMembers,
    ],
    model: &["M15"],
    guards: "A collection's first own record under a folder starts from the folder's: a writer it \
             drops is cut at what the owner holds, so that writer's earlier versions stay \
             admitted on every reader and only later ones are refused; a seal on a collection \
             the folder left unsealed keeps what was written before readable (Since).",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p
}

/// Whether `layer` reads the version `entry` names: admitted and held. `false` while it does not
/// hold it, or refuses it.
async fn reads(layer: &dyn DataLayer, entry: &Name) -> Result<bool, Failure> {
    match layer.get(entry).await {
        Ok(Answer {
            got: Got::Version(_),
            ..
        }) => Ok(true),
        Ok(a) => Err(Failure::new(format!(
            "get of the version {entry} answered {:?}, not the version",
            a.got
        ))),
        Err(
            DataError::Unavailable { .. }
            | DataError::NotFound { .. }
            | DataError::Sealed { .. }
            | DataError::Refused { .. },
        ) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/32=data/club");
        let minutes = n("/alice/32=data/club/minutes");
        let notes = n("/alice/32=data/club/notes");
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));

        alice
            .share_folder(
                &folder,
                members(Rule::Log, &["/alice", "/bob", "/carol"], &[]).into(),
            )
            .await?;
        let minute = w
            .put(CAROL, &minutes, text("carol: we met"), note(1))
            .await?;
        let minute_entry = log_entry(w, CAROL, &minutes, &minute);
        let bobs_note = w
            .put(BOB, &notes, text("bob: bring chairs"), note(1))
            .await?;
        let note_entry = log_entry(w, BOB, &notes, &bobs_note);
        w.until(
            "Alice and Bob read Carol's minute and Bob's note",
            LIMIT,
            || async {
                Ok(reads(&*alice, &minute_entry).await?
                    && reads(&*bob, &minute_entry).await?
                    && reads(&*alice, &note_entry).await?
                    && reads(&*bob, &note_entry).await?)
            },
        )
        .await?;
        let mut watched = bob.watch(&minutes, &Frontier::default()).await?;

        // Each collection gets a record of its own: the minutes without Carol, the notes sealed.
        w.gesture();
        alice
            .share(&minutes, members(Rule::Log, &["/alice", "/bob"], &[]))
            .await?;
        alice
            .share(
                &notes,
                members(Rule::Log, &[], &[person("/alice"), person("/bob")]),
            )
            .await?;
        let later = carol
            .put(&minutes, text("carol: after"), note(1))
            .await
            .ok();
        let after = alice.put(&minutes, text("alice: noted"), note(1)).await?;
        let after_entry = log_entry(w, ALICE, &minutes, &after);
        let alices_note = alice.put(&notes, text("alice: sealed"), note(1)).await?;
        let alices_note_entry = log_entry(w, ALICE, &notes, &alices_note);
        // Bob writes into the notes once he holds the record sealing them:
        // a version written before is refused `Unsealed` (spec §9).
        w.until(
            "Bob reads what Alice wrote after the records",
            LIMIT,
            || async {
                Ok(reads(&*bob, &after_entry).await? && reads(&*bob, &alices_note_entry).await?)
            },
        )
        .await?;
        let sealed = bob.put(&notes, text("bob: sealed now"), note(1)).await?;
        let sealed_entry = log_entry(w, BOB, &notes, &sealed);
        w.until("Alice reads Bob's sealed note", LIMIT, || {
            reads(&*alice, &sealed_entry)
        })
        .await?;
        w.sleep(SETTLE).await;

        for (who, layer) in [("Alice", &alice), ("Bob", &bob)] {
            ensure!(
                reads(&**layer, &minute_entry).await?,
                "{who} no longer reads Carol's minute written before the minutes took a record of \
                 its own: the record dropped her without a cut over what Alice held"
            );
            ensure!(
                reads(&**layer, &note_entry).await?,
                "{who} no longer reads Bob's note written before the notes were sealed: the first \
                 own record set no Since over what the folder admitted unsealed"
            );
            if let Some(id) = &later {
                let entry = log_entry(w, CAROL, &minutes, id);
                ensure!(
                    !reads(&**layer, &entry).await?,
                    "{who} reads Carol's minute written after the record that dropped her"
                );
            }
        }
        let mut changes = Vec::new();
        drain(&mut watched, LOOK, &mut changes).await?;
        ensure!(
            !withdrawn(&changes, &minute),
            "Bob's watch reports Carol's earlier minute withdrawn"
        );
        Ok(())
    })
}
