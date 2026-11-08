//! Folder members, f4 — Alice lets Carol go from a note Bob joined by code; Bob stays.
//!
//! An app such as ndf keeps a scope's members only as the layer tells it. Bob and Carol each
//! joined Alice's notebook by a code: Alice's device signed each admission itself, and the app
//! made no gesture. Once `share_folder` took only a whole list, a let-go signed from the app's
//! own copy of the members dropped every member the app had not heard of. Now the layer answers
//! `members(folder)`, tells a folder watch `Change::Members` whenever the record in force
//! changes — admissions included — and `share_folder` takes a change, applied to the record in
//! force when the device signs it. Alice watches her folder; Carol and then Bob join by codes;
//! her watch and `members` show both, with no gesture of hers. She lets Carol go with a change
//! that names Carol only. Bob stays a member: `members` and her watch show him without Carol,
//! his device holds the same record, and he still writes and reads; Carol no longer reads what
//! Alice writes afterwards. Mirrors ndf's "alice lets carol go from a note bob joined by code".

use std::time::Duration;

use ndn_data::{Role, ShareChange};

use super::i1_join_by_code::{
    ALICE, BOB, CAROL, FOLDER, alice_keeps_a_notebook, joins, offer, plan, reads,
};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "f4",
    title: "Alice lets Carol go from a note Bob joined by code; Bob stays",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A host reads a folder's members record in force (members) and is told every change \
             of it on a folder watch (Change::Members), an introduction's admission included; a \
             let-go signed as a change removes exactly whom it names, so a member who joined by \
             a code and whom the host never listed stays a member, writing and reading.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

/// Whether `share` lists namespace `ns` as a writer and as a reader.
fn lists(share: &Share, ns: &str) -> bool {
    share.writers.contains(&n(ns)) && share.readers.contains(&person(ns))
}

/// Whether `share` names namespace `ns` at all, as a writer or a reader.
fn names(share: &Share, ns: &str) -> bool {
    share.writers.contains(&n(ns)) || share.readers.contains(&person(ns))
}

/// The record the newest `Change::Members` among `seen` tells for `folder`.
fn told<'c>(seen: &'c [Change], folder: &Name) -> Option<&'c Share> {
    seen.iter().rev().find_map(|c| match c {
        Change::Members { collection, share } if collection == folder => Some(share),
        _ => None,
    })
}

/// `d` writes `text_of` into collection `c` of the folder, once its device may.
async fn writes(w: &World, d: Dev, c: &Name, text_of: &str) -> Result<(), Failure> {
    let layer = w.at(d);
    let who = w.net().spec(d).name().to_string();
    w.until(&format!("{who} writes {c}"), LIMIT, || async {
        match layer.put(c, text(text_of), note(1)).await {
            Ok(_) => Ok(true),
            Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
            Err(e) => Err(e.into()),
        }
    })
    .await?;
    Ok(())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;
        let alice = w.at(ALICE);
        let mut feed = alice.watch(&folder, &Frontier::new()).await?;
        let mut seen = Vec::new();

        // The record in force: Alice alone, as `members` answers and her watch lists first.
        let m = alice.members(&folder).await?;
        ensure!(
            m.writers == [n("/alice")] && m.readers == [person("/alice")],
            "members of alice's notebook before anyone joined: {m:?}"
        );
        drain_until(
            &mut feed,
            &mut seen,
            "alice's watch lists the folder's record in force",
            LIMIT,
            |s| told(s, &folder) == Some(&m),
        )
        .await?;

        // Carol, then Bob, join by codes as writers: Alice's device signs each admission.
        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        joins(w, CAROL, &code.link).await?;
        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        joins(w, BOB, &code.link).await?;
        let took = drain_until(
            &mut feed,
            &mut seen,
            "alice's watch tells the record her device signed admitting bob and carol",
            LIMIT,
            |s| told(s, &folder).is_some_and(|m| lists(m, "/bob") && lists(m, "/carol")),
        )
        .await?;
        w.measure(
            "admission to Change::Members",
            took.as_millis() as u64,
            "ms",
        );
        let m = alice.members(&folder).await?;
        ensure!(
            lists(&m, "/alice") && lists(&m, "/bob") && lists(&m, "/carol"),
            "members after bob and carol joined by codes: {m:?}"
        );

        // Both write a page; Alice reads both.
        let carol_page = n(&format!("{FOLDER}/page-carol"));
        let bob_page = n(&format!("{FOLDER}/page-bob"));
        writes(w, CAROL, &carol_page, "a page by carol").await?;
        writes(w, BOB, &bob_page, "a page by bob").await?;
        w.until("alice reads carol's page", LIMIT, || {
            reads(&*alice, &carol_page, "a page by carol")
        })
        .await?;
        w.until("alice reads bob's page", LIMIT, || {
            reads(&*alice, &bob_page, "a page by bob")
        })
        .await?;

        // Alice lets Carol go with a change naming Carol alone.
        alice
            .share_folder(
                &folder,
                ShareChange {
                    remove_writers: vec![n("/carol")],
                    remove_readers: vec![person("/carol")],
                    ..ShareChange::default()
                }
                .into(),
            )
            .await?;
        let m = alice.members(&folder).await?;
        ensure!(
            lists(&m, "/alice") && lists(&m, "/bob") && !names(&m, "/carol"),
            "members after alice let carol go: {m:?} (bob must stay, carol must be gone)"
        );
        drain_until(
            &mut feed,
            &mut seen,
            "alice's watch tells carol let go and bob kept",
            LIMIT,
            |s| told(s, &folder).is_some_and(|t| *t == m),
        )
        .await?;

        // Bob's device holds the same record, and Bob still writes and reads.
        let bob = w.at(BOB);
        w.until(
            "bob's device holds the record without carol",
            LIMIT,
            || async {
                match bob.members(&folder).await {
                    Ok(b) => Ok(b == m),
                    Err(DataError::NotReady { .. }) => Ok(false),
                    Err(e) => Err(e.into()),
                }
            },
        )
        .await?;
        alice
            .put(&cover, text("cover after carol left"), note(1))
            .await?;
        w.until(
            "bob reads the cover alice wrote after carol left",
            LIMIT,
            || reads(&*bob, &cover, "cover after carol left"),
        )
        .await?;
        let again = n(&format!("{FOLDER}/page-bob-2"));
        writes(w, BOB, &again, "bob's page after carol left").await?;
        w.until("alice reads bob's page after carol left", LIMIT, || {
            reads(&*alice, &again, "bob's page after carol left")
        })
        .await?;

        // Carol's page, written while she was a member, stays; what Alice wrote after stays
        // sealed from her.
        ensure!(
            reads(&*alice, &carol_page, "a page by carol").await?,
            "carol's page, written while she was a member, is gone after she was let go"
        );
        w.sleep(SETTLE).await;
        ensure!(
            !reads(&*w.at(CAROL), &cover, "cover after carol left").await?,
            "carol reads what alice wrote after letting her go"
        );
        Ok(())
    })
}
