//! Open item 5 — a sealed folder converges under loss.
//!
//! ndf ran two devices behind a link that drops one packet in ten: Alice's first sealed version
//! often never reached Bob's folder watch within 90 s, and when it did, it took a minute. Bob's
//! grant for the folder's epoch key was asked once of each device that could grant it; one lost
//! packet and the version stayed locked until something else in the folder moved. A summary or a
//! version that missed was asked again after a pause doubling to a minute. The fix (§17 of the
//! spec): every fetch that missed — a summary, a version, a members record, a piece, a grant —
//! is asked again, from what the device still owes in its durable state and not from a new sync
//! notice, after a pause that doubles from a fraction of a second to a cap of a few seconds,
//! until it is held or no longer wanted.
//!
//! Alice shares a folder sealed to Alice and Bob; Bob watches it; Alice writes her first version
//! into it. One packet in five arriving at either device is dropped. Bob's watch reports the
//! version, opened, within [`BOUND`] of virtual time; the case records how long it took, and what
//! Bob spent.

use std::time::Duration;

use ndn_sim::Faults;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "o5",
    title: "A sealed folder converges under loss",
    slice: 6,
    needs: &[
        Feature::Seal,
        Feature::Log,
        Feature::FolderMembers,
        Feature::FolderWatch,
    ],
    model: &["M15"],
    guards: "With one packet in five dropped on its way to each device, the first version a \
             writer seals in a folder reaches a reader's folder watch, opened, within seconds of \
             virtual time, not minutes: a grant, an epoch key, a summary, a version that missed \
             is asked again, with a capped backoff, until it is held.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// The share of packets dropped on their way into each device.
const DROP: f64 = 0.2;
/// The seed of the drops' draws: one realization of the loss, replayed exactly (the runner's
/// `--fault-seed` replaces it, to draw another).
const SEED: u64 = 1;
/// How long Bob's watch may take to report Alice's first version, from her put. Its path is about
/// ten exchanges in a row (root, three summary nodes, the folder record, the version, the grant
/// and the seal key the granter fetches); at this loss each exchange misses one time in three, and
/// a miss costs one Interest lifetime (2 s, 2.5 s with the consumer's slack) and a pause from
/// 250 ms. Five misses in a row of ten, an unlucky draw, is under 15 s; asked once per granter,
/// with the pause doubling to a minute, the version never came within 120 s.
const BOUND: Duration = Duration::from_secs(20);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.faults(Faults {
        drop: DROP,
        seed: SEED,
        ..Faults::default()
    });
    p
}

fn folder() -> Name {
    n("/alice/32=data/diary")
}

fn page() -> Name {
    folder().append("monday")
}

fn diary() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/diary"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: None,
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let alice = w.at(ALICE);
        w.gesture();
        alice
            .share_folder(
                &folder(),
                members(Rule::Log, &["/alice"], &[person("/alice"), person("/bob")]).into(),
            )
            .await?;
        let mut feed = w.at(BOB).watch(&folder(), &Frontier::new()).await?;

        w.report_from(w.mark());
        let sent = w.net().device_wire(BOB).interests;
        let asked = w.grants(BOB).asked;
        w.gesture();
        let start = tokio::time::Instant::now();
        let id = alice.put(&page(), text("rain all day"), diary()).await?;
        let deadline = start + LIMIT;
        let mut seen = Vec::new();
        while version(&seen, &id).is_none() {
            match tokio::time::timeout_at(deadline, feed.next()).await {
                Ok(Some(item)) => seen.push(item?),
                Ok(None) => return Err(Failure::new("Bob's folder watch ended")),
                Err(_) => {
                    return Err(Failure::new(format!(
                        "Bob's folder watch did not report Alice's first sealed version within \
                         {LIMIT:?} of virtual time, at {DROP} loss"
                    )));
                }
            }
        }
        let took = start.elapsed();
        w.converged(took);
        w.measure(
            format!("drop {DROP}: Alice's first sealed version to Bob's watch"),
            took.as_millis() as u64,
            "ms of virtual time",
        );
        w.measure(
            "Bob's Interests until his watch reported it",
            w.net().device_wire(BOB).interests - sent,
            "Interests",
        );
        w.measure(
            "grants Bob asked until his watch reported it",
            w.grants(BOB).asked - asked,
            "grants",
        );
        let v = version(&seen, &id).expect("drained until it came");
        ensure!(
            field_of(v, "text") == Some("rain all day"),
            "Bob's watch reported Alice's version unopened or altered: {v:?}"
        );
        ensure!(
            took <= BOUND,
            "Bob's folder watch reported Alice's first sealed version after {took:?} of virtual \
             time, at {DROP} loss; a sealed folder converges under loss within {BOUND:?} \
             (spec §17)"
        );
        Ok(())
    })
}
