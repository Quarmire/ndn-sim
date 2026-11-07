//! Slice 6, f2 — a collection narrows its folder's members, and never widens them.
//!
//! Alice's club folder is shared with Bob and Carol: one folder record governs every collection
//! under it. One collection, the treasurer's notes, narrows that to Alice and Bob: Carol may no
//! longer write it, nor read what is written after. A collection may narrow its folder but never
//! widen it, or a collection's record would let in someone the folder's owner never admitted:
//! `share` refuses a writer or reader the folder does not admit (`BadRequest`, share the folder
//! instead), and a record that does widen — one signed before the folder record existed — has
//! no effect on readers, who intersect every level.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "f2",
    title: "A collection narrows its folder's members, and never widens them",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::Seal,
        Feature::AppOps,
        Feature::FolderMembers,
    ],
    model: &["M15"],
    guards: "A collection's own record narrows its folder's on every reader: a writer it drops is \
             refused and a reader it drops opens nothing written after. share refuses a record \
             that would widen the folder's (BadRequest) and changes nothing, and a record that \
             widens it has no effect on readers.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const DAVE: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p.device("dave", "laptop");
    p
}

/// Whether `e` refuses a share that would widen the folder.
fn widening_refused(r: Result<(), DataError>) -> Result<(), Failure> {
    match r {
        Err(DataError::BadRequest { why, .. }) => {
            ensure!(!why.is_empty(), "the refused share says nothing of why");
            Ok(())
        }
        Err(e) => Err(Failure::new(format!(
            "a share widening the folder's members answered {e}, not BadRequest"
        ))),
        Ok(()) => Err(Failure::new(
            "a collection's share widening its folder's members was signed",
        )),
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/32=data/club");
        let treasury = n("/alice/32=data/club/treasury");
        let old = n("/alice/32=data/club/old-list");
        let (alice, bob, carol, dave) = (w.at(ALICE), w.at(BOB), w.at(CAROL), w.at(DAVE));

        // A record signed before the folder had one, letting Dave in.
        alice
            .share(
                &old,
                members(
                    element_rule(),
                    &["/alice", "/dave"],
                    &[person("/alice"), person("/bob"), person("/dave")],
                ),
            )
            .await?;
        let first = put_element(w, DAVE, &old, |op| op.set("dave", "first")).await?;
        w.until("Alice holds Dave's first entry", LIMIT, || {
            has(&*alice, &old, &first)
        })
        .await?;
        w.net().offline(DAVE);

        w.gesture();
        alice
            .share_folder(
                &folder,
                members(
                    element_rule(),
                    &["/alice", "/bob", "/carol"],
                    &[person("/alice"), person("/bob"), person("/carol")],
                ),
            )
            .await?;
        // Dave, offline, knows only the old record.
        let late = dave
            .put_op(
                &old,
                element_op(w, DAVE, &old, |op| op.set("dave", "after the folder"))
                    .await?
                    .encode(),
                element_type(),
            )
            .await?;
        w.net().online(DAVE);

        let opened = put_element(w, ALICE, &treasury, |op| {
            op.then(0, Edit::Create("ledger".into()))
                .set("balance", "100")
        })
        .await?;
        w.until("Bob and Carol read the treasury", LIMIT, || async {
            Ok(has(&*bob, &treasury, &opened).await? && has(&*carol, &treasury, &opened).await?)
        })
        .await?;

        // The treasury narrows to Alice and Bob.
        w.gesture();
        alice
            .share(
                &treasury,
                members(
                    element_rule(),
                    &["/alice", "/bob"],
                    &[person("/alice"), person("/bob")],
                ),
            )
            .await?;
        let carols = put_element(w, CAROL, &treasury, |op| op.set("balance", "1000"))
            .await
            .ok();
        let after = put_element(w, ALICE, &treasury, |op| op.set("balance", "90")).await?;
        w.until("Bob reads the treasury after the narrowing", LIMIT, || {
            has(&*bob, &treasury, &after)
        })
        .await?;

        // Widening is refused and changes nothing.
        widening_refused(
            alice
                .share(
                    &treasury,
                    members(
                        element_rule(),
                        &["/alice", "/bob", "/dave"],
                        &[person("/alice"), person("/bob")],
                    ),
                )
                .await,
        )?;
        widening_refused(
            alice
                .share(
                    &treasury,
                    members(
                        element_rule(),
                        &["/alice", "/bob"],
                        &[person("/alice"), person("/bob"), person("/dave")],
                    ),
                )
                .await,
        )?;
        let daves = put_element(w, DAVE, &treasury, |op| op.set("balance", "0"))
            .await
            .ok();
        let in_old = put_element(w, ALICE, &old, |op| op.set("alice", "still here")).await?;
        w.until("Bob reads the old list", LIMIT, || {
            has(&*bob, &old, &in_old)
        })
        .await?;
        w.sleep(SETTLE).await;

        for (who, layer) in [("Alice", &alice), ("Bob", &bob)] {
            let (s, v) = element_state(&**layer, &treasury).await?;
            ensure!(
                setting(&v, "balance") == Some("90") && s.at.contains(&after),
                "{who}'s treasury shows the balance {:?}, not Alice's last",
                setting(&v, "balance")
            );
            for (whose, id) in [("Carol", &carols), ("Dave", &daves)] {
                ensure!(
                    id.as_ref().is_none_or(|id| !s.at.contains(id)),
                    "{who}'s treasury counts {whose}'s version {id:?}, which its narrowed (or \
                     refused widened) record does not admit"
                );
            }
            let (s, v) = element_state(&**layer, &old).await?;
            ensure!(
                !s.at.contains(&late) && setting(&v, "dave") != Some("after the folder"),
                "{who}'s old list counts Dave's version {late:?}, which only a record the folder \
                 does not admit lets in"
            );
            ensure!(
                setting(&v, "alice") == Some("still here"),
                "{who}'s old list lacks Alice's entry"
            );
        }
        // Carol either cannot open the treasury now (sealed) or holds it without Alice's version
        // written after the narrowing.
        let opened_after = match carol.get(&treasury).await {
            Ok(Answer {
                got: Got::State(s), ..
            }) => s.at.contains(&after),
            Ok(a) => {
                return Err(Failure::new(format!(
                    "Carol's get of the treasury answered {:?}, not a state",
                    a.got
                )));
            }
            Err(DataError::Sealed { .. } | DataError::Unavailable { .. }) => false,
            Err(e) => return Err(e.into()),
        };
        ensure!(
            !opened_after,
            "Carol, whom the treasury dropped as a reader, opened Alice's version written after"
        );
        if let Ok(Answer {
            got: Got::Version(_),
            ..
        }) = carol.get(&log_entry(w, ALICE, &treasury, &after)).await
        {
            return Err(Failure::new(
                "Carol, whom the treasury dropped as a reader, read Alice's version written after \
                 by its name",
            ));
        }
        Ok(())
    })
}
