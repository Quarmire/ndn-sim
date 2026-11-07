//! Slice 6, b1 — a merge rule named by the app, and a device whose program lacks it.
//!
//! Alice's board app merges its cards with its own rule, `/conformance/merge/element/v=1`, named
//! in the card's members record by its full, versioned name. Her laptop and Bob's laptop run the
//! app: their writes merge into one value, the same on both. Carol's laptop runs an older program
//! that knows only the standard rules. Before slice 6 a device knew one rule, and a collection
//! naming another was either refused or merged under the one it knew — a state no one wrote. The
//! fix: names match exactly, and a device that does not know the named rule holds the versions
//! (verified, stored) but reads none of them: `get` of the collection or of a state, `put` and
//! `put_op` answer `RuleUnknown`, naming the rule, and the next step is to update the program.

use std::time::Duration;

use ndn_data::NextStep;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::provider::Program;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "b1",
    title: "A merge rule named by the app, and a device whose program lacks it",
    slice: 6,
    needs: &[Feature::Merge, Feature::RuleByName, Feature::AppOps],
    model: &[],
    guards: "Devices whose program knows the rule a members record names converge on one value \
             under it; a device that does not know it holds the versions but answers get, put \
             and put_op with RuleUnknown naming that rule (update the program), never a state \
             under another rule.",
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
    let carol = p.device("carol", "laptop");
    p.program(carol, Program::Standard);
    p
}

/// Whether `e` is the refusal of a device that does not know the element rule, for `c`.
fn rule_unknown(e: &DataError, c: &Name) -> bool {
    matches!(e, DataError::RuleUnknown { collection, rule }
        if collection == c && *rule == element::name())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let card = n("/alice/32=data/board/card");
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        let all = [person("/alice"), person("/bob"), person("/carol")];
        alice
            .share(
                &card,
                members(element_rule(), &["/alice", "/bob", "/carol"], &all),
            )
            .await?;
        let a = put_element(w, ALICE, &card, |op| {
            op.then(0, Edit::Create("card".into()))
                .set("title", "plan the trip")
        })
        .await?;
        w.until("Bob holds Alice's card", LIMIT, || has(&*bob, &card, &a))
            .await?;
        let b = put_element(w, BOB, &card, |op| op.set("owner", "bob")).await?;

        let start = w.net().wire();
        w.converge(
            "Alice and Bob agree on the card under its rule",
            LIMIT,
            || async { agree(&[&*alice, &*bob], &card, &[&a, &b]).await },
        )
        .await?;
        let spent = w.net().wire();
        w.measure(
            "two writers converge: Interests",
            spent.device_interests - start.device_interests,
            "round trips",
        );
        w.measure(
            "two writers converge: bytes",
            spent.bytes - start.bytes,
            "bytes",
        );
        for (who, layer) in [("Alice", &alice), ("Bob", &bob)] {
            let (_, v) = element_state(&**layer, &card).await?;
            ensure!(
                v.state.kind.as_deref() == Some("card")
                    && setting(&v, "title") == Some("plan the trip")
                    && setting(&v, "owner") == Some("bob"),
                "{who}'s card under the element rule is {:?}, not both writes",
                v.state
            );
        }
        let (named, _) = element_state(&*alice, &card).await?;

        // Carol's program does not know the rule. She asks for the card until she holds both
        // versions; she must never answer a state.
        let entries = [log_entry(w, ALICE, &card, &a), log_entry(w, BOB, &card, &b)];
        w.until(
            "Carol holds both versions of the card, unreadable",
            LIMIT,
            || async {
                match carol.get(&card).await {
                    Ok(answer) => Err(Failure::new(format!(
                        "Carol, whose program does not know {}, answered {:?} for the card",
                        element::NAME,
                        answer.got
                    ))),
                    Err(e) if rule_unknown(&e, &card) => {
                        Ok(entries.iter().all(|e| w.stored(CAROL, e) > 0))
                    }
                    Err(DataError::Unavailable { .. } | DataError::NotFound { .. }) => Ok(false),
                    Err(e) => Err(Failure::new(format!(
                        "Carol answered get of the card with {e}, not RuleUnknown naming {}",
                        element::NAME
                    ))),
                }
            },
        )
        .await?;
        w.measure(
            "octets Carol holds of the card, unreadable",
            entries.iter().map(|e| w.stored(CAROL, e)).sum(),
            "bytes",
        );

        let state_get = carol.get(&named.name).await;
        let op = Operation::by(&w.net().spec(CAROL).name()).set("title", "carol's title");
        let put_op = carol.put_op(&card, op.encode(), element_type()).await;
        let put = carol.put(&card, text("carol"), note(1)).await;
        for (verb, outcome) in [
            (
                "get of Alice's state by name",
                state_get.map(|a| format!("{:?}", a.got)),
            ),
            ("put_op", put_op.map(|id| format!("version {id:?}"))),
            ("put", put.map(|id| format!("version {id:?}"))),
        ] {
            match outcome {
                Err(e) if rule_unknown(&e, &card) => ensure!(
                    e.next() == NextStep::UpdateProgram,
                    "Carol's {verb} refused with RuleUnknown, but says to {:?}, not to update \
                     the program",
                    e.next()
                ),
                Err(e) => {
                    return Err(Failure::new(format!(
                        "Carol's {verb} answered {e}, not RuleUnknown naming {}",
                        element::NAME
                    )));
                }
                Ok(got) => {
                    return Err(Failure::new(format!(
                        "Carol's {verb} answered {got} on a card whose rule her program does not \
                         know"
                    )));
                }
            }
        }
        Ok(())
    })
}
