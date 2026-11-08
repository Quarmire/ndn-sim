//! Open item 4 — a reader keeps up with a writer that never pauses.
//!
//! Alice's phone autosaves her notes many times a second while her laptop starts watching the
//! folder. A summary root names its nodes by digest; if the writer stopped serving the nodes of a
//! root once newer roots superseded them, the laptop's descent would have to start over from a
//! newer root, and it would finish only once the phone paused. The fix (§7 of the spec): the
//! writer serves every node any root it signed lists, the reader finishes the descent it started
//! against the root it started from and continues from there.
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
use std::collections::HashSet;
use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
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
    let in_flight = ndn_data::Config::new().in_flight as f64;
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
    let miss = ndn_data::Config::new().lifetime.as_secs_f64() * 1000.0 + REPLY_SLACK_MS;
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

fn note_name(i: usize) -> Name {
    n(&format!("/alice/32=data/notes/n{i}"))
}

/// Read `feed` until every id of `want` is among the versions it reported (`held`), for at most
/// `limit` of virtual time; returns how long it took.
async fn until_held(
    feed: &mut Changes,
    held: &mut HashSet<VersionId>,
    want: &[VersionId],
    what: &str,
    limit: Duration,
) -> Result<Duration, Failure> {
    let start = tokio::time::Instant::now();
    let deadline = start + limit;
    let mut missing: Vec<&VersionId> = want.iter().filter(|id| !held.contains(id)).collect();
    while !missing.is_empty() {
        match tokio::time::timeout_at(deadline, feed.next()).await {
            Err(_) => {
                return Err(Failure::new(format!(
                    "{what}: {} of {} versions not reported within {limit:?} of virtual time \
                     (first missing {:?})",
                    missing.len(),
                    want.len(),
                    missing[0]
                )));
            }
            Ok(None) => return Err(Failure::new(format!("{what}: the watch ended"))),
            Ok(Some(change)) => {
                if let Change::Version(v) = change? {
                    held.insert(v.id);
                    missing.retain(|id| !held.contains(id));
                }
            }
        }
    }
    Ok(start.elapsed())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/32=data/notes");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        let written: RefCell<Vec<VersionId>> = RefCell::new(Vec::new());
        for i in 0..NOTES {
            let note_i = note_name(i);
            phone
                .share(&note_i, members(merge(), &["/alice"], &[person("/alice")]))
                .await?;
            let id = phone
                .put(&note_i, text(&format!("note {i}")), note(1))
                .await?;
            written.borrow_mut().push(id);
        }

        // The tablet watches throughout: each of its refreshes has the phone sign a newer root,
        // superseding the nodes of the root the laptop is descending many times over.
        let _tablet_feed = w.at(TABLET).watch(&folder, &Frontier::new()).await?;
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
                let note_k = note_name(k * 7 % NOTES);
                let id = phone
                    .put(&note_k, text(&format!("autosave {k}")), note(1))
                    .await?;
                written.borrow_mut().push(id);
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
                let mut feed = laptop.watch(&folder, &Frontier::new()).await?;
                let mut held = HashSet::new();
                let took = until_held(
                    &mut feed,
                    &mut held,
                    &before,
                    "the laptop holds everything written before it looked",
                    LIMIT,
                )
                .await?;
                w.converged(took);
                for round in 1..=ROUNDS {
                    let target = written.borrow().clone();
                    until_held(
                        &mut feed,
                        &mut held,
                        &target,
                        &format!(
                            "catch-up {round}: the laptop holds all {} versions written so far",
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
