//! Slice 6, g2 — a group no reader could judge alike is refused before anything is signed.
//!
//! A group's versions count all or none, on every reader alike. So its members must be ones every
//! reader judges by the same rules: collections of one folder, sealed to one audience. A group
//! across two folders, or over a collection whose readers were narrowed (its versions sealed in
//! an epoch the others' readers may not hold), could count on one reader and not another.
//! `put_group` refuses such a group with why (`BadRequest`) and writes nothing: no signature, no
//! seq taken — the next group of the writer starts right after its last version.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "g2",
    title: "A group no reader could judge alike is refused before anything is signed",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::Seal,
        Feature::AppOps,
        Feature::Groups,
    ],
    model: &[],
    guards: "put_group refuses a group across two folders, or over collections whose records in \
             force have different readers, with why (BadRequest) and signs nothing: the \
             writer's signatures and seqs are unchanged, and its next group follows its last \
             version.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let alice = w.at(ALICE);
        let both = [person("/alice"), person("/bob")];
        let shared = members(element_rule(), &["/alice"], &both);
        let (x, y) = (n("/alice/32=data/x/card"), n("/alice/32=data/y/card"));
        let (a, b, c) = (
            n("/alice/32=data/board/a"),
            n("/alice/32=data/board/b"),
            n("/alice/32=data/board/c"),
        );
        for coll in [&x, &y, &a, &b, &c] {
            alice.share(coll, shared.clone()).await?;
        }
        // The board's b narrows to Alice alone: a new epoch, other readers than a's.
        alice
            .share(
                &b,
                members(element_rule(), &["/alice"], &[person("/alice")]),
            )
            .await?;
        let mut last = None;
        for coll in [&x, &y, &a, &b, &c] {
            last = Some(put_element(w, ALICE, coll, |op| op.set("title", "first")).await?);
        }
        let last = last.expect("five collections written");

        let op = |coll: &Name| {
            let coll = coll.clone();
            async move {
                let op = element_op(w, ALICE, &coll, |op| op.set("title", "grouped")).await?;
                Ok::<_, Failure>((coll, ndn_data::Edit::Op(op.encode())))
            }
        };
        for (what, items) in [
            (
                "collections of two folders",
                vec![op(&x).await?, op(&y).await?],
            ),
            (
                "collections whose readers differ after a narrowing",
                vec![op(&a).await?, op(&b).await?],
            ),
        ] {
            let signed = w.signed_by(ALICE);
            match alice.put_group(items, element_type()).await {
                Err(DataError::BadRequest { why, .. }) => {
                    ensure!(
                        !why.is_empty(),
                        "the refused group of {what} says nothing of why"
                    );
                }
                Err(e) => {
                    return Err(Failure::new(format!(
                        "a group of {what} answered {e}, not BadRequest"
                    )));
                }
                Ok(ids) => {
                    return Err(Failure::new(format!(
                        "a group of {what} was signed as {ids:?}: its readers cannot judge it \
                         alike"
                    )));
                }
            }
            ensure!(
                w.signed_by(ALICE) == signed,
                "the refused group of {what} cost {} signatures; nothing may be signed",
                w.signed_by(ALICE) - signed
            );
        }

        // A possible group follows the last version written.
        let ids = alice
            .put_group(vec![op(&a).await?, op(&c).await?], element_type())
            .await?;
        let seqs: Vec<u64> = ids.iter().map(|id| id.seq.0).collect();
        ensure!(
            seqs == [last.seq.0 + 1, last.seq.0 + 2],
            "the group after the refused ones took seqs {seqs:?}, not the two after {}: a refused \
             group took a place in the log",
            last.seq.0
        );
        let bob = w.at(BOB);
        let start = tokio::time::Instant::now();
        let took = w
            .until("Bob takes the group", LIMIT, || async {
                Ok(has(&*bob, &a, &ids[0]).await? && has(&*bob, &c, &ids[1]).await?)
            })
            .await;
        if let Err(f) = took {
            let mut held = Vec::new();
            for coll in [&a, &c] {
                held.push(state_now(&*bob, coll).await?.map(|s| (s.at, s.not_counted)));
            }
            return Err(Failure::new(format!(
                "{f} (Bob holds {held:?}; the group is {ids:?})"
            )));
        }
        w.converged(start.elapsed());
        Ok(())
    })
}
