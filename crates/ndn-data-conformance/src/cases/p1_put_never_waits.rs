//! Round 4, p1 — a put never waits on other devices.
//!
//! Alice's laptop holds the members record of her `notes` folder, and her phone, another device
//! of her namespace, writes too: the laptop hears it in the sync group but reaches nothing of its
//! summary (its names are cut off), so the phone is known and never walked. Before, every put
//! into a collection new to the laptop first followed it and looked at what every device known to
//! write into the namespace holds of it, waiting the first-look time for the phone — a paste of a
//! dozen paragraphs into new collections waited that time once for each of them, and the first
//! keystroke in a new note waited it once; on a faulty network each look took longer still. The
//! fix: under a folder whose members record the device holds, a new collection inherits that
//! record, and the put returns once the version is applied and queued behind the durability
//! barrier — no look, no record of its own. A collection under no held record, whose namespace
//! has a device not walked yet, answers `NotReady` at once, saying what it waits for, and the
//! look runs in the background: the put goes through once it has resolved, and the phone's
//! record over the collection (which a default record signed meanwhile could have narrowed) is
//! the one the collection is written under. `share_folder` creating a folder's first record
//! keeps its one bounded look.
//!
//! A last phase repeats the puts and the first record of a folder with the phone reachable: its
//! walk then takes a few round trips on a clean network and seconds under `--faulty` (drop, delay,
//! reorder), which is what a put that waited for it paid; a put now costs the same on both.
//!
//! Every latency is virtual time. It is measured here for the report (`measured`) and judged
//! against a bound a local operation never nears: the cut-off phone costs an operation that
//! waits for it the whole first-look time.

use std::time::Duration;

use ndn_data::{Edit, NextStep};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "p1",
    title: "A put never waits on other devices",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::Log,
        Feature::Groups,
        Feature::FolderMembers,
    ],
    model: &["M8"],
    guards: "A put under a folder whose members record the device holds — a first keystroke in a \
             new collection, a paste of a group of new collections — returns once it is applied \
             locally and queued behind the durability barrier, with no look at the devices of its \
             namespace, clean or faulty; a put of a collection no record governs while a device \
             of the namespace was not walked answers NotReady at once, naming the device, and goes \
             through once the background look resolved it, written under the record that device \
             holds (never a default record that narrows what it had not seen); share_folder \
             creating a first record waits at most the first-look time.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);

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

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let notes = n("/alice/32=data/notes");
        let drafts = n("/alice/32=data/drafts");
        let loose = n("/alice/32=data/loose");
        let all = [person("/alice"), person("/bob")];
        let (laptop, phone) = (w.at(LAPTOP), w.at(PHONE));
        let mut late: Vec<String> = Vec::new();
        let mut judge = |what: &str, took: Duration, bound: Duration| {
            if took > bound {
                late.push(format!("{what} took {took:?}, over {bound:?}"));
            }
        };

        // The laptop reaches nothing of the phone's names; the phone reaches the laptop.
        let away = w.net().cut_off(LAPTOP, &n("/alice/phone")).await;
        laptop
            .share_folder(&notes, members(Rule::Log, &["/alice", "/bob"], &all).into())
            .await?;
        // The phone records a folder the laptop has not seen, over `loose`: Bob writes there.
        w.again(|| {
            phone.share_folder(&loose, members(Rule::Log, &["/alice", "/bob"], &all).into())
        })
        .await?;
        // The laptop hears the phone in the sync group, and cannot walk it.
        w.sleep(SETTLE).await;

        // A first keystroke in a new note under the held folder.
        let (first, took) = timed(
            w,
            "put, first entry of a new collection under a held folder: virtual ms",
            laptop.put(&notes.clone().append("note1"), text("h"), note(1)),
        )
        .await;
        first?;
        judge("the first put into a new note", took, LOCAL);

        // A paste: one group of twelve new collections under the held folder.
        let items: Vec<(Name, Edit)> = (0..12)
            .map(|i| {
                (
                    notes.clone().append(format!("paste{i}")),
                    Edit::Fields(text(&format!("paragraph {i}"))),
                )
            })
            .collect();
        let (group, took) = timed(
            w,
            "put_group, twelve new collections under a held folder: virtual ms",
            laptop.put_group(items, note(1)),
        )
        .await;
        ensure!(
            group?.len() == 12,
            "the paste signed fewer than twelve versions"
        );
        judge("a paste of twelve new collections", took, LOCAL);

        // A put into a collection followed already.
        let (again, took) = timed(
            w,
            "put, a collection followed already under a held folder: virtual ms",
            laptop.put(&notes.clone().append("note1"), text("hi"), note(1)),
        )
        .await;
        again?;
        judge("the second put into a note", took, LOCAL);

        // `share_folder` creating a folder's first record: one bounded look, and only it.
        let (shared, took) = timed(
            w,
            "share_folder, a folder's first record: virtual ms",
            laptop.share_folder(
                &drafts,
                members(Rule::Log, &["/alice", "/bob"], &all).into(),
            ),
        )
        .await;
        shared?;
        judge("share_folder of a first record", took, FIRST_LOOK_PLUS);
        let (after, took) = timed(
            w,
            "put, the first entry under a folder just shared: virtual ms",
            laptop.put(&drafts.clone().append("d1"), text("draft"), note(1)),
        )
        .await;
        after?;
        judge("the put right after share_folder", took, LOCAL);

        // A collection no record governs here, its namespace's phone not walked: not ready at
        // once, saying what it waits for.
        let (refused, took) = timed(
            w,
            "put, a collection no held record governs while a device is not walked: virtual ms",
            laptop.put(&loose.clone().append("x"), text("one"), note(1)),
        )
        .await;
        match refused {
            Err(e @ DataError::NotReady { .. }) => {
                ensure!(
                    e.next() == NextStep::RetryLater,
                    "the refusal says {:?}, not retry later: {e}",
                    e.next()
                );
                ensure!(
                    e.to_string().contains("/alice/phone"),
                    "the refusal does not name the device whose walk it waits for: {e}"
                );
            }
            other => {
                return Err(Failure::new(format!(
                    "a put under no held record while the phone was not walked answered \
                     {other:?}, not NotReady"
                )));
            }
        }
        judge("the NotReady of a put under no held record", took, LOCAL);

        // The look resolves in the background once the laptop reaches the phone again.
        drop(away);
        let layer = w.at(LAPTOP);
        let target = loose.clone().append("x");
        w.again(|| layer.put(&target, text("one"), note(1))).await?;
        let record = layer.members(&target).await?;
        ensure!(
            record.writers.contains(&n("/bob")),
            "the collection was written under {record:?}, not under the record the phone holds \
             over it (Bob writes there): a default record narrowed it"
        );
        let (second, took) = timed(
            w,
            "put, the collection whose look resolved: virtual ms",
            layer.put(&target, text("two"), note(1)),
        )
        .await;
        second?;
        judge("the put after the look resolved", took, LOCAL);

        // The phone is reachable now, but over this network (lossy and slow under `--faulty`)
        // its summary takes time to walk: a look at it takes a few round trips on a clean
        // network and seconds on a faulty one. A put never waits for it, so these cost the same
        // either way; `share_folder` creating a first record waits its one bounded look.
        let reach = n("/alice/32=data/reach");
        let (shared, took) = timed(
            w,
            "share_folder, a first record, the phone reachable: virtual ms",
            layer.share_folder(&reach, members(Rule::Log, &["/alice", "/bob"], &all).into()),
        )
        .await;
        shared?;
        judge(
            "share_folder of a first record, the phone reachable",
            took,
            FIRST_LOOK_PLUS,
        );
        let (new_note, took) = timed(
            w,
            "put, the first entry of a new collection, the phone reachable: virtual ms",
            layer.put(&reach.clone().append("note1"), text("h"), note(1)),
        )
        .await;
        new_note?;
        judge(
            "the first put into a new note, the phone reachable",
            took,
            LOCAL,
        );
        let items: Vec<(Name, Edit)> = (0..12)
            .map(|i| {
                (
                    reach.clone().append(format!("paste{i}")),
                    Edit::Fields(text(&format!("paragraph {i}"))),
                )
            })
            .collect();
        let (group, took) = timed(
            w,
            "put_group, twelve new collections, the phone reachable: virtual ms",
            layer.put_group(items, note(1)),
        )
        .await;
        ensure!(
            group?.len() == 12,
            "the second paste signed fewer than twelve versions"
        );
        judge(
            "a paste of twelve new collections, the phone reachable",
            took,
            LOCAL,
        );
        ensure!(late.is_empty(), "a put waited: {}", late.join("; "));
        Ok(())
    })
}
