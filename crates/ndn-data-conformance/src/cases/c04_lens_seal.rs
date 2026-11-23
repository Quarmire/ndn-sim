//! Case 4 — Calendar shows meeting notes.
//!
//! Alice opens a meeting in Calendar and points it at her notes for that meeting. The draft's seal
//! example named an app as audience, which brings back per-app keys and prompts. The fix (M4):
//! seal audiences are people, devices and groups; lenses hold no keys; the host opens exactly what
//! the person pointed at and hands that to the lens. (That an app can never be named is enforced
//! by the type: a space's readers are names of persons, `SpaceShare::readers`.)
//! The note is the path `/meeting-0412` of Alice's space `/alice/32=data/notes`, a space only
//! its readers read: Alice alone.

use std::time::Duration;

use super::kit::{LOOK, SETTLE, has, item_of, look, members_now, n, octets, private, winning};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::SpaceMembers;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c4",
    title: "Calendar shows meeting notes",
    slice: 2,
    needs: &[Feature::Merge, Feature::Seal],
    model: &["M4"],
    guards: "Seal audiences are people, devices and groups: the host opens the note the person \
             pointed at, opening it adds no audience, and a device outside the audience cannot \
             read it.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const HOST: Dev = Dev(0);
const BOB: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

/// Whether `e` is a refusal a device outside the audience may answer: the note is sealed, or it
/// holds nothing of it, or it does not hold the members record that would admit it.
fn outside(e: &Failure) -> bool {
    e.retry_later()
        || ["Sealed", "Unavailable", "NotFound"]
            .iter()
            .any(|k| e.kind_is(k))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n("/alice/32=data/notes");
        let meeting = n("/meeting-0412");
        let (host, bob) = (w.spaces(HOST), w.spaces(BOB));
        let alice = n("/alice");
        let audience = SpaceMembers::new(&alice, Vec::new(), vec![alice.clone()], false);
        host.create(&space, private(&[], &["/alice"])).await?;
        let id = host.put(&space, &meeting, octets("agenda: budget")).await?;

        // Alice points Calendar at the note: the host opens it and hands the value to the lens.
        w.gesture();
        let opened = winning(&*host, &space, &meeting, &[&id]).await?;
        ensure!(
            has(&*host, &space, &id).await? && opened.bytes == b"agenda: budget"[..],
            "the host could not open the note Alice pointed at"
        );

        let after = look(&*host, &space, LOOK).await?;
        ensure!(
            item_of(&after, &id.key()).is_some(),
            "watch does not list the note"
        );
        let readers = members_now(&*host, &space)
            .await?
            .ok_or_else(|| Failure::new("the host holds no members record of the space"))?;
        ensure!(
            readers == audience,
            "the note's audience is {readers:?} after the lens read it; it must stay {audience:?}"
        );

        // A device outside the audience tries to follow the space, and to read the note.
        match bob.open(&space).await {
            Ok(()) => {}
            Err(e) if outside(&e) => {}
            Err(e) => return Err(e),
        }
        w.sleep(SETTLE).await;
        match bob.get(&space, &meeting).await {
            Ok(None) => {}
            Ok(Some(item)) => {
                return Err(Failure::new(format!(
                    "a device outside the seal read the note: {item:?}"
                )));
            }
            Err(e) if outside(&e) => {}
            Err(e) => return Err(e),
        }
        Ok(())
    })
}
