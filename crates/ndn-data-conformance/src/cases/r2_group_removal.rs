//! Review 2 — a member leaves a group that another person's collection is sealed to.
//!
//! Alice keeps her team as a collection whose readers are its members. Bob seals his own notes
//! to that group. When Alice removes Carol from the team, only Alice's own collections moved to
//! a new epoch under the draft: Bob's notes stayed in the epoch Carol holds, and Carol read
//! everything Bob wrote after she left. The fix (spec §6): a device of Bob's namespace that holds
//! a record naming the group follows the group, and when the group drops a reader it signs a new
//! record of Bob's collection in a new epoch.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "r2",
    title: "A member leaves a group another person seals to",
    slice: 2,
    needs: &[Feature::Merge, Feature::Seal],
    model: &["M4"],
    guards: "A collection sealed to a group moves to a new epoch when the group drops a reader, \
             whoever owns the collection: the member who left reads nothing written after, the \
             members who stay still do.",
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
    p.device("carol", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let team = n("/alice/32=data/groups/team");
        let notes = n("/bob/32=data/notes/plans");
        let (alice, bob, carol) = (w.at(ALICE), w.at(BOB), w.at(CAROL));
        let everyone = [person("/alice"), person("/bob"), person("/carol")];
        alice
            .share(&team, members(Rule::Log, &["/alice"], &everyone))
            .await?;
        bob.share(
            &notes,
            members(
                merge(),
                &["/bob"],
                &[Audience::Group(team.clone()), person("/bob")],
            ),
        )
        .await?;
        let first = bob.put(&notes, text("offsite: march"), note(1)).await?;
        w.until(
            "Carol, a member of the team, opens Bob's note",
            LIMIT,
            || async {
                let seen = look(&*carol, &notes, &Frontier::new(), LOOK).await?;
                Ok(version(&seen, &first).is_some())
            },
        )
        .await?;

        alice
            .share(
                &team,
                members(Rule::Log, &["/alice"], &[person("/alice"), person("/bob")]),
            )
            .await?;
        w.gesture();
        w.sleep(SETTLE).await;

        let later = bob
            .put(&notes, text("offsite: moved to april"), note(1))
            .await?;
        w.until(
            "Alice, still a member, opens Bob's later note",
            LIMIT,
            || async {
                let seen = look(&*alice, &notes, &Frontier::new(), LOOK).await?;
                Ok(version(&seen, &later).is_some())
            },
        )
        .await?;
        w.sleep(SETTLE).await;
        let seen = look(&*carol, &notes, &Frontier::new(), LOOK).await?;
        ensure!(
            version(&seen, &later).is_none(),
            "Carol, removed from the team, opened Bob's note written after she left"
        );
        Ok(())
    })
}
