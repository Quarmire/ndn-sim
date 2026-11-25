//! Storage, d8 — a burst of puts, each stored as one batch, reaches another device in order and
//! survives a restart.
//!
//! Alice's laptop and phone share a space of ledgers. The laptop puts sixty entries back to back
//! (each put's writes reach its store as one batch, behind the durability barrier). The phone, on
//! the lossy network of a `--faulty` run too, ends up holding every entry. The laptop then stops
//! and starts again on what it stored: it still holds every entry, and its next put signs the
//! very next seq of its log, one the restart neither reused nor skipped, which the phone then
//! holds too.
//!
//! The guard: grouping a put's store writes changes nothing a peer or the device itself can tell:
//! seqs are consecutive in put order, what a peer is served is what was put, and the log
//! continues where a restart finds it.
//!
//! Each entry goes to a path of its own (`/entries/000`, …), so every one of the sixty stays the
//! head of its path and a watch reports it. That each put's writes reach the store as one batch
//! is not seen through the neutral surface; what is seen, and kept, is what the batch must not
//! change.

use std::time::Duration;

use ndn_heap::Name;

use super::kit::{LIMIT, drain_until, item_of, n, octets, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{SpaceEntry, SpaceEvent};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "d8",
    title: "A burst of puts, each stored as one batch, arrives in order and survives a \
            restart",
    slice: 7,
    needs: &[Feature::Seal, Feature::Log, Feature::FolderMembers],
    model: &[],
    guards: "The writes of a put reach the store as one batch without changing what a peer \
             sees: sixty back-to-back puts take consecutive seqs and all reach the other \
             device; after the device stops and starts on its store, it holds every version \
             and its next put signs the next seq, not one before or after.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const BURST: usize = 60;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p
}

/// The path of entry `i` of the burst.
fn entry_path(i: usize) -> Name {
    n(&format!("/entries/{i:03}"))
}

/// The octets of entry `i` of the burst.
fn words(i: usize) -> String {
    format!("entry {i:03}")
}

/// Whether `seen` reports every entry of `burst`, each with the octets that were put at its path.
fn everything(seen: &[SpaceEvent], burst: &[SpaceEntry]) -> bool {
    burst.iter().enumerate().all(|(i, entry)| {
        item_of(seen, &entry.key())
            .is_some_and(|item| item.path == entry_path(i) && item.bytes == words(i).as_bytes())
    })
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n("/alice/32=data/ledger");
        let (laptop, phone) = (w.spaces(LAPTOP), w.spaces(PHONE));
        w.gesture();
        laptop.create(&space, private(&[], &[])).await?;
        let mut phone_watch = w.retry_later(|| phone.watch(&space)).await?;
        let mut phone_seen = Vec::new();

        // A burst: no put waits for the one before it to be published.
        let mut burst: Vec<SpaceEntry> = Vec::with_capacity(BURST);
        for i in 0..BURST {
            burst.push(
                w.space_put(LAPTOP, &space, &entry_path(i), octets(&words(i)))
                    .await?,
            );
        }
        ensure!(
            burst
                .windows(2)
                .all(|p| p[1].seq == p[0].seq + 1 && p[1].writer == p[0].writer),
            "sixty puts back to back took seqs {:?}, not one after the other in put order",
            burst.iter().map(|e| e.seq).collect::<Vec<_>>()
        );

        let start = tokio::time::Instant::now();
        drain_until(
            &mut *phone_watch,
            &mut phone_seen,
            "the phone holds the burst",
            LIMIT,
            |seen| everything(seen, &burst),
        )
        .await?;
        w.converged(start.elapsed());

        // The laptop stops and starts again on what it stored.
        w.stop(LAPTOP).await?;
        let laptop = w.restart(LAPTOP).await?;
        let mut again = w.retry_later(|| laptop.watch(&space)).await?;
        let mut held = Vec::new();
        drain_until(
            &mut *again,
            &mut held,
            "the restarted laptop holds its burst",
            LIMIT,
            |seen| everything(seen, &burst),
        )
        .await?;

        // Its log goes on where the store left it.
        let next = w
            .space_put(
                LAPTOP,
                &space,
                &n("/entries/after-the-restart"),
                octets("after the restart"),
            )
            .await?;
        let top = burst.last().ok_or_else(|| Failure::new("a burst"))?;
        ensure!(
            next.writer == top.writer && next.seq == top.seq + 1,
            "after a restart the laptop signed seq {} of {}, not {}, the one after its last",
            next.seq,
            next.writer,
            top.seq + 1
        );
        drain_until(
            &mut *phone_watch,
            &mut phone_seen,
            "the phone holds the put after the restart",
            LIMIT,
            |seen| item_of(seen, &next.key()).is_some(),
        )
        .await?;
        w.measure("puts back to back", BURST as u64, "puts");
        Ok(())
    })
}
