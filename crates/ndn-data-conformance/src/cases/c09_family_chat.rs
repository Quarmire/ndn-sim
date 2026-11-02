//! Case 9 — a family chat across three people.
//!
//! Alice starts a chat, invites Bob, later adds Carol; each writes from their own device. Nothing
//! said which writers make up "the chat", so a reader could not tell a member from a stranger
//! posting under the same name. The fix (M1, M2): the chat's members record, signed by Alice,
//! lists its writers; the log rule unions exactly those keys. Mallory, who is not a member, posts
//! into the same collection name.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c9",
    title: "A family chat across three people",
    slice: 2,
    needs: &[Feature::Log, Feature::WritersAcrossPrefixes],
    model: &["M1", "M2"],
    guards: "A log collection is the union of exactly its members' logs: every member's message \
             reaches the other members, and a non-member's post under the same name reaches no \
             one.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);
const MALLORY: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("bob", "phone");
    p.device("carol", "phone");
    p.device("mallory", "phone");
    p
}

fn message() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/chat-message"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let chat = n("/alice/chat/family");
        let (alice, bob, carol, mallory) = (w.at(ALICE), w.at(BOB), w.at(CAROL), w.at(MALLORY));
        let readers = |names: &[&str]| names.iter().map(|p| person(p)).collect::<Vec<_>>();

        alice
            .share(
                &chat,
                members(Rule::Log, &["/alice"], &readers(&["/alice"])),
            )
            .await?;
        let start = alice.put(&chat, text("start"), message()).await?;
        alice
            .share(
                &chat,
                members(
                    Rule::Log,
                    &["/alice", "/bob"],
                    &readers(&["/alice", "/bob"]),
                ),
            )
            .await?;
        w.gesture();
        let hi = bob.put(&chat, text("hi"), message()).await?;
        alice
            .share(
                &chat,
                members(
                    Rule::Log,
                    &["/alice", "/bob", "/carol"],
                    &readers(&["/alice", "/bob", "/carol"]),
                ),
            )
            .await?;
        w.gesture();
        let hello = carol.put(&chat, text("hello"), message()).await?;
        // Mallory is no member: her layer may refuse locally, or sign a version readers refuse.
        let spam = mallory.put(&chat, text("spam"), message()).await.ok();

        let everyone = [&start, &hi, &hello];
        w.converge(
            "Alice's chat holds every member's message",
            LIMIT,
            || async {
                let seen = look(&*alice, &chat, &Frontier::new(), LOOK).await?;
                Ok(everyone.iter().all(|id| version(&seen, id).is_some()))
            },
        )
        .await?;
        w.until("Bob and Carol hold Carol's message", LIMIT, || async {
            for layer in [&bob, &carol] {
                let seen = look(&**layer, &chat, &Frontier::new(), LOOK).await?;
                if version(&seen, &hello).is_none() {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await?;
        w.sleep(SETTLE).await;

        let member_keys = [&start.writer, &hi.writer, &hello.writer];
        for (who, layer) in [("Alice", &alice), ("Bob", &bob), ("Carol", &carol)] {
            let seen = look(&**layer, &chat, &Frontier::new(), LOOK).await?;
            for v in versions(&seen) {
                ensure!(
                    member_keys.contains(&&v.id.writer),
                    "{who}'s chat holds {:?}, by a key that is not a member",
                    v.id
                );
            }
            if let Some(spam) = &spam {
                ensure!(
                    version(&seen, spam).is_none(),
                    "{who}'s chat holds Mallory's post"
                );
            }
        }
        Ok(())
    })
}
