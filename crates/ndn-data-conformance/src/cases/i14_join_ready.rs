//! Introductions, i14 — `join` returns once the joiner may write, and says what it waits for.
//!
//! Alice offers her sealed notebook to two strangers as a writer. Bob joins and, with no pause
//! and no retry, writes a page: before, `join` returned as soon as the offer answered, and a put
//! right after it was refused for want of the members record that admits the joiner or of the
//! epoch's key, or answered `AskOwner` to a device the owner had just admitted. Now `Ok(Joined)`
//! means the device holds the record that admits it and the epoch's grant, and the put goes
//! through.
//!
//! Carol joins with every route to Alice's grants cut off: the offer answered and the record
//! is held, but not the key. Her join waits its bound (`first_look * 3 + lifetime`) and answers
//! `NotReady` / `RetryLater` naming the key — never `Ok`, never `AskOwner` —, and a put of hers
//! is `NotReady` naming the key as well. The grants reachable again, she joins again with the
//! same code (the offer answers the writer it admitted, never "already used"), and writes at
//! once.

use std::time::Duration;

use ndn_data::{NextStep, Role};

use super::i1_join_by_code::{
    ALICE, BOB, CAROL, FOLDER, alice_keeps_a_notebook, joins, offer, plan,
};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::World;

pub(super) const CASE: Case = Case {
    id: "i14",
    title: "A join returns once the joiner may write, and says what it waits for",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "join answers Ok only once the device holds the members record that admits it and, \
             sealed, the epoch's key, so a put right after it is neither NotReady nor AskOwner; \
             when the bound passes it answers NotReady with next step RetryLater naming what is \
             missing, a put of the half-admitted device answers NotReady the same way, joining \
             again with the same code is answered, and a reader the record does not admit as a \
             writer is still told to ask the owner; clean or faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        alice_keeps_a_notebook(w).await?;

        // Bob joins and writes at once.
        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        let start = tokio::time::Instant::now();
        let joined = joins(w, BOB, &code.link).await?;
        w.measure(
            "join, code to a member that may write",
            start.elapsed().as_millis() as u64,
            "ms",
        );
        ensure!(joined.folder == folder, "bob joined {joined:?}");
        let bob = w.at(BOB);
        let page = n(&format!("{FOLDER}/page-bob"));
        let put = bob.put(&page, text("a page by bob"), note(1)).await;
        ensure!(
            put.is_ok(),
            "bob's first put, right after join returned, was refused: {put:?}"
        );

        // Carol joins with every route to Alice's grants cut off.
        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        let grants = w
            .net()
            .spec(ALICE)
            .name()
            .append_component(ndn_packet::NameComponent::new(
                32,
                bytes::Bytes::from_static(b"grant"),
            ));
        let away = w.net().cut_off(CAROL, &grants).await;
        // A lost exchange is asked again as a host does; the answer judged is the layer's own.
        let begun = tokio::time::Instant::now();
        let (first, took) = loop {
            let attempt = tokio::time::Instant::now();
            match w.join(CAROL, &code.link).await? {
                Err(DataError::NotReady { why, .. })
                    if !why.contains("key") && begun.elapsed() < crate::world::AGAIN_FOR =>
                {
                    w.sleep(crate::world::AGAIN_PAUSE).await;
                }
                answer => break (answer, attempt.elapsed()),
            }
        };
        match &first {
            Err(e @ DataError::NotReady { why, .. }) => {
                ensure!(
                    e.next() == NextStep::RetryLater,
                    "the join says {:?}, not retry later: {e}",
                    e.next()
                );
                ensure!(
                    why.contains("key"),
                    "the join does not name the key it waits for: {e}"
                );
            }
            other => {
                return Err(Failure::new(format!(
                    "carol's join, the epoch's key out of reach, answered {other:?} after \
                     {took:?}, not NotReady naming the key"
                )));
            }
        }
        w.measure(
            "join, the epoch's key out of reach: virtual ms until NotReady",
            took.as_millis() as u64,
            "ms",
        );
        // Admitted, the key not held: a put is NotReady, never AskOwner.
        let carol = w.at(CAROL);
        let mine = n(&format!("{FOLDER}/page-carol"));
        let refused = carol.put(&mine, text("a page by carol"), note(1)).await;
        match &refused {
            Err(e @ DataError::NotReady { why, .. }) => ensure!(
                e.next() == NextStep::RetryLater && why.contains("key"),
                "carol's put says {e} (next {:?}), not retry later naming the key",
                e.next()
            ),
            other => {
                return Err(Failure::new(format!(
                    "carol's put, admitted but without the epoch's key, answered {other:?}, \
                     not NotReady naming the key"
                )));
            }
        }

        // The grants reachable again: the same code, joined again, and a put at once.
        drop(away);
        let joined = joins(w, CAROL, &code.link).await?;
        ensure!(
            joined.folder == folder && joined.role == Role::Writer,
            "carol's second join says {joined:?}, not the notebook as a writer"
        );
        let put = carol.put(&mine, text("a page by carol"), note(1)).await;
        ensure!(
            put.is_ok(),
            "carol's first put, right after her second join returned, was refused: {put:?}"
        );
        Ok(())
    })
}
