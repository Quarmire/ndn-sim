//! Open item 4 — a reader keeps up with a writer that never pauses.
//!
//! Alice's phone autosaves her notes many times a second while her laptop starts watching the
//! space. A reader that restarted its walk from the newest state whenever the writer signed a
//! newer one would finish only once the phone paused. The invariant is the reader's: it
//! finishes what it started against the state it started from and continues from there, and so
//! comes to hold everything written before it looked, and reports it to its watcher.
//!
//! On a faulty network the phone's pace is the one workload parameter that follows the path
//! (spec §18.1: a sustained-write case offers the load the path carries): every version is a
//! packet the laptop fetches by name, and a reader with a bounded number of asks in flight
//! fetches at most that many per round trip, so a writer saving every 2 ms over a path whose
//! round trip is over a second outruns any bounded reader. There the phone saves at the pace
//! [`pace`] derives from the profile and the reader's asks in flight; what is asserted is
//! unchanged — everything written before the laptop looked is held and reported, and then
//! every version written up to each later moment, against that pace. A later catch-up's time
//! bound follows the path by the same rule ([`keep_up`]): a version just saved reaches the
//! laptop through a chain of exchanges in a row, which alone takes seconds there. Both paces
//! and both bounds are measured.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::time::Duration;

use ndn_heap::Name;

use super::kit::{LIMIT, item, n, octets, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::feature::Feature;
use crate::spaces::{SpaceChanges, SpaceEntry, SpaceEntryKey, SpaceEvent, SpaceItem, Spaces};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "o4",
    title: "A reader keeps up with a writer that never pauses",
    slice: 1,
    needs: &[Feature::Merge],
    model: &["M8"],
    guards: "A descent finishes against the root it started from while the writer keeps putting: \
             the reader comes to hold everything written before it looked, and then every \
             version written up to any later moment, without the writer ever pausing.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const TABLET: Dev = Dev(2);

/// Notes in the folder: enough that it is paged and its fuller pages sub-paged, so one root
/// supersedes a few hundred packets.
const NOTES: usize = 1_200;
/// The phone saves one version this often on a clean network, for as long as the case runs.
const PACE: Duration = Duration::from_millis(2);
/// The packets the laptop fetches per version the phone saves: the version, and the summary
/// node that lists it, new under every root.
const VERSION_PACKETS: f64 = 2.0;
/// The share of what the path carries the phone's saving may take on a faulty network; the
/// rest carries what the laptop catches up on.
const WRITER_SHARE: f64 = 0.25;
/// The time past its lifetime a reader waits for a reply sent just before it ends (spec §17.1).
const REPLY_SLACK_MS: f64 = 500.0;

/// The phone's pace: [`PACE`] on a clean network. On a faulty one, a sustained-write case offers
/// the load the path carries (spec §18.1): a reader keeping `in_flight` asks in flight (spec
/// §17.1) fetches at most `in_flight` packets per mean time a packet takes — its round trip
/// under the profile (each arrival held a mean of half `delay`, a Data a further half `blocks`,
/// a reordered packet a further `max(delay, 50)` ms), plus, for every ask that misses (dropped
/// either way or forged, `1 / ((1 − drop)² (1 − forge)) − 1` per packet), a lifetime and its
/// slack. The phone saves one version per [`VERSION_PACKETS`] of that rate's
/// [`WRITER_SHARE`], never faster than [`PACE`].
fn pace(w: &World) -> Duration {
    let Some(per_packet) = packet_time(w) else {
        return PACE;
    };
    let in_flight = ndn_heap::Config::new().in_flight as f64;
    let ms = per_packet * VERSION_PACKETS / (in_flight * WRITER_SHARE);
    Duration::from_micros((ms * 1000.0) as u64).max(PACE)
}

/// The mean time one packet takes the reader under the network's fault profile, in ms
/// ([`pace`]); `None` on a clean network.
fn packet_time(w: &World) -> Option<f64> {
    let f = w.net().faults()?;
    let delay = f.delay_ms as f64;
    let round_trip = delay + f.blocks_ms as f64 / 2.0 + 2.0 * f.reorder * delay.max(50.0);
    let answered = (1.0 - f.drop).powi(2) * (1.0 - f.forge);
    let miss = ndn_heap::Config::new().lifetime.as_secs_f64() * 1000.0 + REPLY_SLACK_MS;
    Some(round_trip + (1.0 / answered - 1.0) * miss)
}

/// The exchanges in a row by which a version just saved reaches the laptop: the root, the five
/// summary levels under it (data, notes, page, sub-page, note) and the version.
const CHAIN: f64 = 7.0;
/// How many chains' time a later catch-up may take on a faulty network.
const CHAINS: f64 = 3.0;

/// How long each later catch-up may take: [`KEEP_UP`] on a clean network. On a faulty one it
/// follows the path by the rule the pace does (spec §18.1): [`CHAINS`] times [`CHAIN`]
/// exchanges of [`packet_time`] each, never less than [`KEEP_UP`].
fn keep_up(w: &World) -> Duration {
    packet_time(w).map_or(KEEP_UP, |ms| {
        Duration::from_micros((CHAINS * CHAIN * ms * 1000.0) as u64).max(KEEP_UP)
    })
}

/// How long the phone has been saving when the laptop starts watching.
const BEFORE_LOOK: Duration = Duration::from_secs(1);
/// Moments after the first catch-up at which the laptop must catch up again.
const ROUNDS: usize = 5;
/// How long each later catch-up may take while the phone keeps saving.
const KEEP_UP: Duration = Duration::from_secs(10);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "laptop");
    p.device("alice", "tablet");
    p
}

fn note_path(i: usize) -> Name {
    n(&format!("/n{i}"))
}

/// Whether `reported` holds, for `path`, the entry `want` or a later one of its log.
fn reported_up_to(
    reported: &BTreeMap<Name, SpaceEntryKey>,
    path: &Name,
    want: &SpaceEntry,
) -> bool {
    reported
        .get(path)
        .is_some_and(|key| key.covers(&want.key()))
}

/// Note that the watch reported `item`: the newest entry it reported at the item's path.
fn record(reported: &mut BTreeMap<Name, SpaceEntryKey>, item: &SpaceItem) {
    let key = item.key();
    match reported.get(&item.path) {
        Some(known) if known.covers(&key) => {}
        _ => {
            reported.insert(item.path.clone(), key);
        }
    }
}

/// Read `feed` until, at every path of `want`, it has reported the entry or a later one of the
/// same log (`reported`: the newest each path has been reported at), for at most `limit` of
/// virtual time; returns how long it took. A watch that lags is read again with `get`.
async fn until_reported(
    spaces: &dyn Spaces,
    space: &Name,
    feed: &mut dyn SpaceChanges,
    reported: &mut BTreeMap<Name, SpaceEntryKey>,
    want: &BTreeMap<Name, SpaceEntry>,
    what: &str,
    limit: Duration,
) -> Result<Duration, Failure> {
    let start = tokio::time::Instant::now();
    let deadline = start + limit;
    let mut missing: Vec<&Name> = want
        .iter()
        .filter(|(path, entry)| !reported_up_to(reported, path, entry))
        .map(|(path, _)| path)
        .collect();
    while !missing.is_empty() {
        match tokio::time::timeout_at(deadline, feed.next()).await {
            Err(_) => {
                return Err(Failure::new(format!(
                    "{what}: {} of {} paths not reported at their newest entry within {limit:?} \
                     of virtual time (first missing {})",
                    missing.len(),
                    want.len(),
                    missing[0]
                )));
            }
            Ok(None) => return Err(Failure::new(format!("{what}: the watch ended"))),
            Ok(Some(event)) => match event? {
                SpaceEvent::Put(item) | SpaceEvent::Removed(item) => record(reported, &item),
                SpaceEvent::Lagged => {
                    for path in &missing {
                        if let Some(item) = item(spaces, space, path).await? {
                            record(reported, &item);
                        }
                    }
                }
                _ => {}
            },
        }
        missing.retain(|path| !reported_up_to(reported, path, &want[*path]));
    }
    Ok(start.elapsed())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n("/alice/32=data/notes");
        let (phone, laptop) = (w.spaces(PHONE), w.spaces(LAPTOP));
        phone.create(&space, private(&[], &[])).await?;
        // The newest entry the phone wrote at each path: a later entry of a log covers the
        // earlier ones, so holding each path's newest is holding everything written.
        let written: RefCell<BTreeMap<Name, SpaceEntry>> = RefCell::new(BTreeMap::new());
        for i in 0..NOTES {
            let path = note_path(i);
            let entry = w
                .space_put(PHONE, &space, &path, octets(&format!("note {i}")))
                .await?;
            written.borrow_mut().insert(path, entry);
        }

        // The tablet watches throughout: each of its refreshes has the phone sign a newer root,
        // superseding the nodes of the root the laptop is descending many times over.
        let tablet = w.spaces(TABLET);
        let _tablet_feed = w.retry_later(|| tablet.watch(&space)).await?;
        let pace = pace(w);
        w.measure(
            "the phone's pace on a clean network",
            PACE.as_micros() as u64,
            "µs",
        );
        w.measure(
            "the phone's pace on this network",
            pace.as_micros() as u64,
            "µs",
        );
        let keep_up = keep_up(w);
        w.measure(
            "a catch-up's bound on a clean network",
            KEEP_UP.as_millis() as u64,
            "ms",
        );
        w.measure(
            "a catch-up's bound on this network",
            keep_up.as_millis() as u64,
            "ms",
        );
        let stop = Cell::new(false);
        let saving = async {
            // Each save goes to another note (7 is coprime to the note count), so every save
            // supersedes another branch of the summary.
            let mut k = 0usize;
            while !stop.get() {
                let path = note_path(k * 7 % NOTES);
                let entry = w
                    .space_put(PHONE, &space, &path, octets(&format!("autosave {k}")))
                    .await?;
                written.borrow_mut().insert(path, entry);
                k += 1;
                w.sleep(pace).await;
            }
            Ok::<_, Failure>(())
        };
        let watching = async {
            let outcome = async {
                w.sleep(BEFORE_LOOK).await;
                let before = written.borrow().clone();
                let start = w.mark();
                w.report_from(start);
                let mut feed = w.retry_later(|| laptop.watch(&space)).await?;
                let mut reported = BTreeMap::new();
                let took = until_reported(
                    &*laptop,
                    &space,
                    &mut *feed,
                    &mut reported,
                    &before,
                    "the laptop holds everything written before it looked",
                    LIMIT,
                )
                .await?;
                w.converged(took);
                for round in 1..=ROUNDS {
                    let target = written.borrow().clone();
                    until_reported(
                        &*laptop,
                        &space,
                        &mut *feed,
                        &mut reported,
                        &target,
                        &format!(
                            "catch-up {round}: the laptop holds all {} paths as written so far",
                            target.len()
                        ),
                        keep_up,
                    )
                    .await?;
                }
                Ok::<_, Failure>(())
            }
            .await;
            stop.set(true);
            outcome
        };
        let (saved, watched) = futures::future::join(saving, watching).await;
        watched?;
        saved
    })
}
