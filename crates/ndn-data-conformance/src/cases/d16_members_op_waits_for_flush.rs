//! Durability, d16 — a members operation is not visible to peers before its flush.
//!
//! Alice's laptop creates a public space and her phone follows it. The laptop's flush is held and
//! the owner changes the members: bob becomes a writer. A members entry, unlike an ordinary one,
//! is served and announced only after a flush covered it, and `change` returns after it. While
//! the flush is held, `change` does not return, and the phone, given a minute of virtual time,
//! neither lists bob among the writers nor is told of a change. When the flush is released
//! `change` returns and the phone lists bob.
//!
//! The guard: a members operation reaches no peer, and returns to its caller, until the owner's
//! disk holds it: what a peer is shown of the members is never lost with the owner's disk.
//!
//! Devices: alice's laptop and phone.

use std::time::Duration;

use super::durability::{create, space};
use super::kit::{LIMIT, LOOK, SETTLE, drain, known, members_now, people};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{SpaceChange, SpaceEvent, SpaceMembers};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "d16",
    title: "A members operation is not visible to peers before its flush",
    slice: 9,
    needs: &[Feature::Crash],
    model: &[],
    guards: "With the owner's flush held, a members change neither returns nor reaches a peer \
             (no listing of the new writer and no members event, however long the peer waits); \
             once the flush is released the change returns and the peer lists the new writer.",
    budget: Duration::from_secs(900),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = space();
        create(w, LAPTOP, &space).await?;
        let (laptop, phone) = (w.spaces(LAPTOP), w.spaces(PHONE));
        w.retry_later(|| phone.open(&space)).await?;
        w.until("the phone holds the space's members", LIMIT, || {
            known(&*phone, &space)
        })
        .await?;
        let owner = super::kit::n("/alice");
        let bob = || people(&["/bob"]);
        let before = SpaceMembers::new(&owner, Vec::new(), Vec::new(), true);
        let after = SpaceMembers::new(&owner, bob(), Vec::new(), true);
        ensure!(
            members_now(&*phone, &space).await? == Some(before.clone()),
            "the phone's members before the change are not the creation's"
        );
        let mut feed = w.retry_later(|| phone.watch(&space)).await?;
        let mut saw = Vec::new();
        drain(&mut *feed, LOOK, &mut saw).await?;
        saw.clear();

        // The owner changes the members with the flush held.
        w.block_flush(LAPTOP, true).await?;
        let mut changing = laptop.change(
            &space,
            SpaceChange {
                add_writers: bob(),
                ..SpaceChange::default()
            },
        );
        ensure!(
            tokio::time::timeout(SETTLE, &mut changing).await.is_err(),
            "the change returned while the flush covering it was held"
        );
        let seen = members_now(&*phone, &space).await?;
        ensure!(
            seen == Some(before.clone()),
            "the phone lists {seen:?} before the owner's flush returned; it must list {before:?}"
        );
        drain(&mut *feed, LOOK, &mut saw).await?;
        ensure!(
            !saw.iter().any(|e| matches!(e, SpaceEvent::Members(_))),
            "the phone was told of a members change before its flush: {saw:?}"
        );

        // The flush is released: the change returns, and the phone lists bob.
        w.block_flush(LAPTOP, false).await?;
        match tokio::time::timeout(LIMIT, &mut changing).await {
            Ok(done) => done?,
            Err(_) => {
                return Err(crate::Failure::new(
                    "the change did not return after its flush was released",
                ));
            }
        }
        w.until("the phone lists bob as a writer", LIMIT, || async {
            Ok(members_now(&*phone, &space).await? == Some(after.clone()))
        })
        .await?;
        Ok(())
    })
}
