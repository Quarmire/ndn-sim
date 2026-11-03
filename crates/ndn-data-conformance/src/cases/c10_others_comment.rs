//! Case 10 — Alice deletes Bob's comment.
//!
//! In the shared plan, Alice removes a comment Bob wrote. Prune assumed authority over everything
//! in a collection, but Bob's comment is signed data under Bob's prefix; Alice cannot sign a prune
//! for it. The fix (M9): prune reaches only the pruner's own writes; in a shared collection removal
//! is an edit every reader applies (Carol stops seeing it), and Bob's own version remains his.

use std::time::Duration;

use ndn_data::{DataError, Got, NextStep};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c10",
    title: "Alice deletes Bob's comment",
    slice: 2,
    needs: &[
        Feature::Merge,
        Feature::WritersAcrossPrefixes,
        Feature::Prune,
    ],
    model: &["M9"],
    guards: "Prune covers only the pruner's own writes and says to edit instead; removing \
             another member's comment is a merge edit every reader applies, and the author's own \
             version stays readable by exact name.",
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

/// The comment's field; an empty value is the merge edit that removes it.
const COMMENT: &str = "comment/bob-1";

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let plan_doc = n("/alice/32=data/docs/plan");
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        let all = [person("/alice"), person("/bob"), person("/carol")];
        alice
            .share(
                &plan_doc,
                members(merge(), &["/alice", "/bob", "/carol"], &all),
            )
            .await?;
        let comment = bob
            .put(
                &plan_doc,
                content(&[(COMMENT, "this date looks wrong")]),
                note(1),
            )
            .await?;
        w.until("everyone holds Bob's comment", LIMIT, || async {
            agree(&[&*alice, &*bob, &*carol], &plan_doc, &[&comment]).await
        })
        .await?;
        let bobs = look(&*bob, &plan_doc, &Frontier::new(), LOOK).await?;
        let comment_name = version(&bobs, &comment)
            .ok_or_else(|| Failure::new("Bob's watch does not list his comment"))?
            .name
            .clone();

        // Alice throws the comment away.
        w.gesture();
        let upto: Frontier = [comment.clone()].into_iter().collect();
        match alice.prune(&comment_name, &upto).await {
            Err(e @ DataError::NotOwnWrites { .. }) => ensure!(
                e.next() == NextStep::EditInstead,
                "refusing to prune another's writes must say to edit instead, said {:?}",
                e.next()
            ),
            Ok(()) => {
                return Err(Failure::new("Alice pruned a version signed by Bob's key"));
            }
            Err(e) => return Err(e.into()),
        }
        let removal = alice
            .put(&plan_doc, content(&[(COMMENT, "")]), note(1))
            .await?;
        w.converge("every reader applies Alice's removal", LIMIT, || async {
            agree(&[&*alice, &*bob, &*carol], &plan_doc, &[&removal]).await
        })
        .await?;
        let at_carol = state(&*carol, &plan_doc).await?;
        ensure!(
            field(&at_carol.value, COMMENT).is_none_or(str::is_empty),
            "Carol still sees Bob's comment: {:?}",
            field(&at_carol.value, COMMENT)
        );
        match bob.get(&comment_name).await?.got {
            Got::Version(v) => ensure!(
                field_of(&v, COMMENT) == Some("this date looks wrong"),
                "Bob's own version changed"
            ),
            other => {
                return Err(Failure::new(format!(
                    "Bob's comment by exact name answered {other:?}, not his version"
                )));
            }
        }
        Ok(())
    })
}
