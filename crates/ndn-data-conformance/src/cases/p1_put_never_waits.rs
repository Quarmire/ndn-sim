//! Round 4, p1 — a put never waits on other devices.
//!
//! Alice's laptop holds the members record of her `notes` space, and her phone, another device
//! of her namespace, writes too: the laptop hears it in the sync group but reaches nothing of its
//! names (they are cut off), so the phone is known and never walked. A put returns once the
//! entry is applied and queued behind the durability barrier, and never waits for a device.
//! Where a device of the namespace was not walked toward a space the laptop holds no record of
//! (the phone created it, with Bob as a writer), a put answers at once with an entry or with
//! retry-later, and the look runs in the background: a device not walked may hold the space's
//! record (a write signed under a default record meanwhile could narrow what its owner meant).
//! The put goes through once the look has resolved, under the record that device holds, and
//! the entry reaches the phone and Bob after the cut ends. Once the walk has resolved, a new
//! path under a held space is written under its record: no look. Creating a space keeps its one
//! bounded look.
//!
//! The cut-off phone is reached again, and the same puts are retried as a host retries a
//! refusal that says retry later ([`World::retry_later`]) until the walk has resolved; then the
//! puts and the first record of a space are timed, and none waits. A last phase repeats them
//! with the phone reachable all along: its walk takes a few round trips on a clean network and
//! seconds under `--faulty` (drop, delay, reorder), which is what a put that waited for it paid;
//! a put now costs the same with or without the cut-off phone once the walk resolved.
//!
//! Every latency is virtual time. It is measured here for the report (`measured`) and judged
//! against a bound a local operation never nears: the cut-off phone costs an operation that
//! waits for it the whole first-look time.

use std::time::Duration;

use ndn_heap::Name;

use super::kit::{LIMIT, SETTLE, agree, has, n, octets, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::Spaces;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "p1",
    title: "A put never waits on other devices",
    slice: 6,
    needs: &[Feature::Merge, Feature::FolderMembers],
    model: &["M8"],
    guards: "A put never waits on another device: one into a collection no record of its own \
             governs here, while a device of its namespace was not walked toward it — under a \
             folder's record the device holds or under none — answers NotReady at once, naming \
             the device, and the look runs in the background; once the walk has resolved, a \
             first keystroke in a new collection under a held folder returns once it is \
             applied locally and queued behind the durability barrier, with no look at the \
             devices of its namespace, clean or faulty, written \
             under the record in force (never a default record that narrows what it had not \
             seen); share_folder creating a first record waits at most the first-look time.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const BOB: Dev = Dev(2);

/// What a put that returns once applied and queued costs in virtual time: nothing a device waits
/// on, so far under the first-look time (4 s) that a wait for the phone cannot hide in it.
const LOCAL: Duration = Duration::from_millis(500);

/// The most `share_folder` may take creating a first record: one bounded look.
const FIRST_LOOK_PLUS: Duration = Duration::from_secs(6);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("bob", "laptop");
    p
}

/// Time `what` in virtual time, record it as a measure called `name`.
async fn timed<T>(w: &World, name: &str, what: impl Future<Output = T>) -> (T, Duration) {
    let start = tokio::time::Instant::now();
    let out = what.await;
    let took = start.elapsed();
    w.measure(name, took.as_millis() as u64, "ms");
    (out, took)
}

/// Put `bytes` at `path` of `space` on `spaces`, timed as `name`, while a device of the
/// namespace is not walked: the put returns at once ([`LOCAL`]) and either signs the entry, which
/// is then applied on the device, or says to retry later — it never waits for the device.
async fn put_at_once(
    w: &World,
    spaces: &dyn Spaces,
    name: &str,
    space: &Name,
    path: &Name,
    bytes: &str,
) -> Result<(), Failure> {
    let (answer, took) = timed(w, name, spaces.put(space, path, octets(bytes))).await;
    ensure!(
        took <= LOCAL,
        "{name}: the put took {took:?}, over {LOCAL:?}: a put waited on a device"
    );
    match answer {
        Ok(entry) => {
            ensure!(
                has(spaces, space, &entry).await?,
                "{name}: the put signed {entry:?} and the device has not applied it"
            );
            Ok(())
        }
        Err(e) if e.retry_later() => Ok(()),
        Err(e) => Err(Failure::new(format!(
            "{name}: the put answered {}, not an entry or retry later, while the phone was not \
             walked",
            e.detail
        ))),
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let notes = n("/alice/32=data/notes");
        let drafts = n("/alice/32=data/drafts");
        let loose = n("/alice/32=data/loose");
        let (note1, d1, x) = (n("/note1"), n("/d1"), n("/x"));
        let share = || private(&["/bob"], &["/bob"]);
        let (laptop, phone, bob) = (w.spaces(LAPTOP), w.spaces(PHONE), w.spaces(BOB));
        let mut late: Vec<String> = Vec::new();
        let mut judge = |what: &str, took: Duration, bound: Duration| {
            if took > bound {
                late.push(format!("{what} took {took:?}, over {bound:?}"));
            }
        };

        // The laptop reaches nothing of the phone's names; the phone reaches the laptop.
        let away = w.net().cut_off(LAPTOP, &n("/alice/phone")).await;
        laptop.create(&notes, share()).await?;
        // The phone records a space the laptop has not seen, `loose`: Bob writes there.
        w.retry_later(|| phone.create(&loose, share())).await?;
        // The laptop hears the phone in the sync group, and cannot walk it.
        w.sleep(SETTLE).await;

        // A put into a new path of the held space, the phone not walked, returns at once.
        put_at_once(
            w,
            &*laptop,
            "put, first entry of a new path under a held space, the phone not walked: virtual ms",
            &notes,
            &note1,
            "h",
        )
        .await?;

        // Creating a space: one bounded look, and only it. The look did not reach the phone, so
        // the puts into it do not wait for the phone's walk either.
        let (created, took) = timed(
            w,
            "create, a space's first record: virtual ms",
            laptop.create(&drafts, share()),
        )
        .await;
        created?;
        judge("creating a space", took, FIRST_LOOK_PLUS);
        put_at_once(
            w,
            &*laptop,
            "put, the first entry under a space just created, the phone not walked: virtual ms",
            &drafts,
            &d1,
            "draft",
        )
        .await?;

        // A space the laptop holds no record of, its owner's phone not reached: the put returns
        // at once, with an entry or saying to retry later.
        put_at_once(
            w,
            &*laptop,
            "put, a space the laptop holds no record of while a device is not walked: virtual ms",
            &loose,
            &x,
            "one",
        )
        .await?;

        // The cut ends: each put is asked again, as a host does what a refusal says, and the
        // entries reach the other devices.
        drop(away);
        let entry_note1 = w.space_put(LAPTOP, &notes, &note1, octets("h")).await?;
        let entry_d1 = w.space_put(LAPTOP, &drafts, &d1, octets("draft")).await?;
        let entry_x = w.space_put(LAPTOP, &loose, &x, octets("one")).await?;
        let record = w.retry_later(|| laptop.members(&loose)).await?;
        ensure!(
            record.writers.contains(&n("/bob")),
            "the space was written under {record:?}, not under the record the phone holds over \
             it (Bob writes there): a default record narrowed it"
        );
        for (spaces, space) in [
            (&phone, &notes),
            (&phone, &drafts),
            (&bob, &notes),
            (&bob, &drafts),
            (&bob, &loose),
        ] {
            w.retry_later(|| spaces.open(space)).await?;
        }
        for (space, path, entry) in [
            (&notes, &note1, &entry_note1),
            (&drafts, &d1, &entry_d1),
            (&loose, &x, &entry_x),
        ] {
            w.until(
                &format!("the phone and Bob hold the laptop's entry at {path} of {space}"),
                LIMIT,
                || async { agree(&[&*laptop, &*phone, &*bob], space, path, &[entry]).await },
            )
            .await?;
        }

        // Walked: a first keystroke in a new path under the held space.
        let (first, took) = timed(
            w,
            "put, first entry of a new path under a held space: virtual ms",
            laptop.put(&notes, &n("/note2"), octets("h")),
        )
        .await;
        first?;
        judge("the first put into a new path", took, LOCAL);

        // A put into a path written already.
        let (again, took) = timed(
            w,
            "put, a path written already under a held space: virtual ms",
            laptop.put(&notes, &note1, octets("hi")),
        )
        .await;
        again?;
        judge("the second put into a path", took, LOCAL);
        let (after, took) = timed(
            w,
            "put, the first entry under a space just created: virtual ms",
            laptop.put(&drafts, &n("/d2"), octets("draft")),
        )
        .await;
        after?;
        judge("the put under a space created, once walked", took, LOCAL);
        // The key of the epoch in force may be on its way (another owner device's epoch took
        // force after the laptop's earlier put): the put says retry later at once, and is put
        // again; every answer, the last included, comes within [`LOCAL`].
        let began = tokio::time::Instant::now();
        let (second, took) = loop {
            let (answer, took) = timed(
                w,
                "put, the space whose look resolved: virtual ms",
                laptop.put(&loose, &x, octets("two")),
            )
            .await;
            match answer {
                Err(e) if e.retry_later() && began.elapsed() < crate::world::AGAIN_FOR => {
                    ensure!(
                        took <= LOCAL,
                        "put, the space whose look resolved: a refusal to retry later took \
                         {took:?}, over {LOCAL:?}"
                    );
                    w.sleep(crate::world::AGAIN_PAUSE).await;
                }
                answer => break (answer, took),
            }
        };
        second?;
        judge("the put after the look resolved", took, LOCAL);

        // The phone is reachable now, but over this network (lossy and slow under `--faulty`)
        // its walk takes time: a look at it takes a few round trips on a clean network and
        // seconds on a faulty one. A put never waits for it: one under the new space is asked
        // again until its walk resolved (`create`'s own look may end before it does under
        // `--faulty`), and then costs the same either way; `create` waits its one bounded look.
        let reach = n("/alice/32=data/reach");
        let (created, took) = timed(
            w,
            "create, a first record, the phone reachable: virtual ms",
            laptop.create(&reach, share()),
        )
        .await;
        created?;
        judge(
            "create of a first record, the phone reachable",
            took,
            FIRST_LOOK_PLUS,
        );
        w.space_put(LAPTOP, &reach, &n("/warm"), octets("w"))
            .await?;
        let (new_note, took) = timed(
            w,
            "put, the first entry of a new path, the phone reachable: virtual ms",
            laptop.put(&reach, &note1, octets("h")),
        )
        .await;
        new_note?;
        judge(
            "the first put into a new path, the phone reachable",
            took,
            LOCAL,
        );
        ensure!(late.is_empty(), "a put waited: {}", late.join("; "));
        Ok(())
    })
}
