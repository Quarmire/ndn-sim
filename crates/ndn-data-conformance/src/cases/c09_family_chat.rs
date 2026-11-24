//! Case 9 — a family chat across three people.
//!
//! Alice starts a chat, invites Bob, later adds Carol; each writes from their own device. Nothing
//! said which writers make up "the chat", so a reader could not tell a member from a stranger
//! posting under the same name. The fix (M1, M2): the chat's members record, signed by Alice,
//! lists its writers; the space rule unions exactly those keys. Mallory, who is not a member,
//! posts into the same space. The chat is the space `/alice/32=data/chat/family`, a message a
//! path of its own (`/start`, `/hi`, `/hello`, and Mallory's `/spam`).

use std::time::Duration;

use super::kit::{
    LIMIT, LOOK, Role, SETTLE, has, item, items, joined, look, n, octets, people, private,
    value_now,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::SpaceChange;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c9",
    title: "A family chat across three people",
    slice: 2,
    needs: &[Feature::Merge, Feature::WritersAcrossPrefixes],
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

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let chat = n("/alice/32=data/chat/family");
        let (start_at, hi_at, hello_at, spam_at) = (n("/start"), n("/hi"), n("/hello"), n("/spam"));
        let (alice, bob, carol, mallory) = (
            w.spaces(ALICE),
            w.spaces(BOB),
            w.spaces(CAROL),
            w.spaces(MALLORY),
        );
        let adding = |who: &str| SpaceChange {
            add_writers: people(&[who]),
            add_readers: people(&[who]),
            ..SpaceChange::default()
        };

        alice.create(&chat, private(&[], &[])).await?;
        let start = alice.put(&chat, &start_at, octets("start")).await?;
        alice.change(&chat, adding("/bob")).await?;
        w.gesture();
        w.retry_later(|| bob.open(&chat)).await?;
        joined(w, &*bob, &chat, &n("/bob"), Role::Writer).await?;
        let hi = w.space_put(BOB, &chat, &hi_at, octets("hi")).await?;
        alice.change(&chat, adding("/carol")).await?;
        w.gesture();
        w.retry_later(|| carol.open(&chat)).await?;
        joined(w, &*carol, &chat, &n("/carol"), Role::Writer).await?;
        let hello = w
            .space_put(CAROL, &chat, &hello_at, octets("hello"))
            .await?;
        // Mallory is no member: her device may refuse locally, or sign an entry readers refuse.
        let spam = mallory.put(&chat, &spam_at, octets("spam")).await.ok();

        let everyone = [&start, &hi, &hello];
        w.converge(
            "every member's chat holds every member's message",
            LIMIT,
            || async {
                for device in [&alice, &bob, &carol] {
                    for entry in everyone {
                        if !has(&**device, &chat, entry).await? {
                            return Ok(false);
                        }
                    }
                }
                Ok(true)
            },
        )
        .await?;
        w.sleep(SETTLE).await;

        let member_keys = [&start.writer, &hi.writer, &hello.writer];
        let messages = [(&start_at, "start"), (&hi_at, "hi"), (&hello_at, "hello")];
        for (who, device) in [("Alice", &alice), ("Bob", &bob), ("Carol", &carol)] {
            for (path, said) in messages {
                let held = value_now(&**device, &chat, path).await?;
                ensure!(
                    held.as_deref() == Some(said.as_bytes()),
                    "{who}'s chat holds {held:?} at {path}, a member said {said:?}"
                );
            }
            let seen = look(&**device, &chat, LOOK).await?;
            for held in items(&seen) {
                ensure!(
                    member_keys.contains(&&held.writer),
                    "{who}'s chat holds {:?} at {}, by a key that is not a member",
                    held.name,
                    held.path
                );
            }
            ensure!(
                item(&**device, &chat, &spam_at).await?.is_none(),
                "{who}'s chat holds a post at {spam_at}, where only Mallory wrote"
            );
            if let Some(spam) = &spam {
                ensure!(
                    !has(&**device, &chat, spam).await?,
                    "{who}'s chat holds Mallory's post"
                );
            }
        }
        Ok(())
    })
}
