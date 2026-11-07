//! Slice 6, b2 — an operation made over a version its writer never held.
//!
//! An app builds its own operations: each names its basis, the versions of the element it was
//! made over, by their content addresses (implicit digests). A basis is a claim about the
//! writer's past, so the rule checks it against the past the layer computes from the version's
//! parents: a basis naming a version outside it is refused for good. Before slice 6 the layer
//! handed the rule only an operation and its writer, so no rule could check such a claim.
//!
//! Alice, offline, holds only the card's first version when she names Bob's newer version in
//! her basis: her own device refuses the operation and signs nothing into her log. Bob's device
//! runs a faulty copy of the rule (named alike, its check refusing nothing — how this provider
//! injects a crafted version): it signs an operation naming Alice's offline version, which Bob
//! never held, and then a valid one over it. Alice and Carol refuse the crafted version as the
//! rule's (`Refusal::Rule`), and take Bob's later version without waiting for it.

use std::time::Duration;

use ndn_data::Refusal;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::provider::Program;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "b2",
    title: "An operation made over a version its writer never held",
    slice: 6,
    needs: &[Feature::Merge, Feature::AppOps],
    model: &[],
    guards: "A rule checks an operation's basis against the past its parents give: put_op of an \
             operation naming a version outside it is refused at the writer (BadRequest, nothing \
             signed into its log), and a signed version naming one is refused by every honest \
             reader (Refusal::Rule) while later versions over it still apply.",
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
    let bob = p.device("bob", "laptop");
    p.device("carol", "laptop");
    p.program(bob, Program::LaxElement);
    p
}

/// The digest of `id` among the heads `d` holds of `c`.
async fn head_digest(w: &World, d: Dev, c: &Name, id: &VersionId) -> Result<[u8; 32], Failure> {
    let (_, v) = element_state(&*w.at(d), c).await?;
    v.heads
        .iter()
        .find(|h| h.seq == id.seq.0 && h.writer == id.writer.key().to_string())
        .and_then(|h| h.digest())
        .ok_or_else(|| {
            Failure::new(format!(
                "the writer's own value of {c} lists no head for its version {}",
                id.seq.0
            ))
        })
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let card = n("/alice/32=data/board/card");
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        let all = [person("/alice"), person("/bob"), person("/carol")];
        alice
            .share(&card, members(element_rule(), &["/alice", "/bob"], &all))
            .await?;
        let first = put_element(w, ALICE, &card, |op| {
            op.then(0, Edit::Create("card".into()))
                .set("colour", "white")
        })
        .await?;
        w.until("Bob and Carol hold the first version", LIMIT, || async {
            Ok(has(&*bob, &card, &first).await? && has(&*carol, &card, &first).await?)
        })
        .await?;

        // Alice, offline, names a version she never held.
        w.net().offline(ALICE);
        let bobs = put_element(w, BOB, &card, |op| op.set("colour", "red")).await?;
        let unseen = head_digest(w, BOB, &card, &bobs).await?;
        let (before, _) = element_state(&*alice, &card).await?;
        let op = element_op(w, ALICE, &card, |op| op.set("colour", "blue"))
            .await?
            .over([&unseen]);
        match alice.put_op(&card, op.encode(), element_type()).await {
            Err(DataError::BadRequest { why, .. }) => ensure!(
                !why.is_empty(),
                "Alice's refused operation says nothing of why"
            ),
            Err(e) => {
                return Err(Failure::new(format!(
                    "Alice's put_op naming a version outside her past answered {e}, not \
                     BadRequest"
                )));
            }
            Ok(id) => {
                return Err(Failure::new(format!(
                    "Alice's put_op naming a version outside her past was signed as {id:?}"
                )));
            }
        }
        let (after, _) = element_state(&*alice, &card).await?;
        ensure!(
            after.at == before.at,
            "the refused operation moved Alice's state from {:?} to {:?}",
            before.at,
            after.at
        );
        let blue = put_element(w, ALICE, &card, |op| op.set("colour", "blue")).await?;
        ensure!(
            blue.seq.0 == first.seq.0 + 1,
            "Alice's next version has seq {}, not {}: the refused operation took a place in her \
             log",
            blue.seq.0,
            first.seq.0 + 1
        );

        // Bob's faulty program signs an operation over Alice's offline version, then one over it.
        let unheld = head_digest(w, ALICE, &card, &blue).await?;
        let crafted = element_op(w, BOB, &card, |op| op.set("shape", "square"))
            .await?
            .over([&unheld]);
        let crafted = bob.put_op(&card, crafted.encode(), element_type()).await?;
        // Bob's next version is made over the crafted one (its parent), but names in its basis
        // only versions an honest reader holds.
        let crafted_digest = element::hex(&head_digest(w, BOB, &card, &crafted).await?);
        let mut later = element_op(w, BOB, &card, |op| op.set("size", "large")).await?;
        later.basis.retain(|d| *d != crafted_digest);
        let later = bob.put_op(&card, later.encode(), element_type()).await?;
        w.net().online(ALICE);

        let bad = log_entry(w, BOB, &card, &crafted);
        w.converge(
            "Alice and Carol take Bob's later version and agree",
            LIMIT,
            || async {
                Ok(agree(&[&*alice, &*carol], &card, &[&later, &blue]).await?
                    && has(&*alice, &card, &bobs).await?)
            },
        )
        .await?;
        for (who, layer) in [("Alice", &alice), ("Carol", &carol)] {
            let (_, v) = element_state(&**layer, &card).await?;
            ensure!(
                setting(&v, "shape").is_none(),
                "{who}'s card shows the crafted version's shape {:?}",
                setting(&v, "shape")
            );
            ensure!(
                setting(&v, "size") == Some("large"),
                "{who}'s card lacks Bob's later version over the crafted one"
            );
            match layer.get(&bad).await {
                Err(DataError::Refused {
                    why: Refusal::Rule { .. },
                    ..
                }) => {}
                other => {
                    return Err(Failure::new(format!(
                        "{who} answered get of the crafted version with {other:?}, not refused \
                         by the rule"
                    )));
                }
            }
        }
        Ok(())
    })
}
