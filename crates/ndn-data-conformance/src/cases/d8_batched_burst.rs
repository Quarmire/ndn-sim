//! Storage, d8 — a burst of puts, each stored as one batch, reaches another device in order and
//! survives a restart.
//!
//! Alice's laptop and phone share a folder of ledgers. The laptop puts sixty entries back to back
//! (each put's writes reach its store as one batch, behind the durability barrier). The phone, on
//! the lossy network of a `--faulty` run too, ends up holding every entry. The laptop then stops
//! and starts again on what it stored: it still holds every version, and its next put signs the
//! very next seq of its log, one the restart neither reused nor skipped, which the phone then
//! holds too.
//!
//! The guard: grouping a put's store writes changes nothing a peer or the device itself can tell:
//! seqs are consecutive in put order, what a peer is served is what was put, and the log
//! continues where a restart finds it.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
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

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/32=data/ledger");
        let entries = folder.clone().append("entries");
        let laptop = w.at(LAPTOP);
        w.gesture();
        laptop
            .share_folder(
                &folder,
                members(Rule::Log, &["/alice"], &[person("/alice")]).into(),
            )
            .await?;
        let mut phone_watch = w.at(PHONE).watch(&folder, &Frontier::new()).await?;
        let mut phone_seen = Vec::new();

        // A burst: no put waits for the one before it to be published.
        let mut ids = Vec::with_capacity(BURST);
        for i in 0..BURST {
            ids.push(
                w.put(LAPTOP, &entries, text(&format!("entry {i:03}")), note(1))
                    .await?,
            );
        }
        ensure!(
            ids.windows(2).all(|p| p[1].seq.0 == p[0].seq.0 + 1),
            "sixty puts back to back took seqs {:?}, not one after the other in put order",
            ids.iter().map(|id| id.seq.0).collect::<Vec<_>>()
        );

        let everything = |seen: &[Change]| ids.iter().all(|id| versions(seen).any(|v| v.id == *id));
        let start = tokio::time::Instant::now();
        drain_until(
            &mut phone_watch,
            &mut phone_seen,
            "the phone holds the burst",
            LIMIT,
            |seen| everything(seen),
        )
        .await?;
        w.converged(start.elapsed());

        // The laptop stops and starts again on what it stored.
        w.stop(LAPTOP).await?;
        w.restart(LAPTOP).await?;
        let laptop = w.at(LAPTOP);
        let mut again = laptop.watch(&folder, &Frontier::new()).await?;
        let mut held = Vec::new();
        drain_until(
            &mut again,
            &mut held,
            "the restarted laptop holds its burst",
            LIMIT,
            |seen| everything(seen),
        )
        .await?;

        // Its log goes on where the store left it.
        let next = w
            .put(LAPTOP, &entries, text("after the restart"), note(1))
            .await?;
        let top = ids.last().expect("a burst").seq.0;
        ensure!(
            next.seq.0 == top + 1,
            "after a restart the laptop signed seq {}, not {}, the one after its last",
            next.seq.0,
            top + 1
        );
        drain_until(
            &mut phone_watch,
            &mut phone_seen,
            "the phone holds the put after the restart",
            LIMIT,
            |seen| versions(seen).any(|v| v.id == next),
        )
        .await?;
        w.measure("puts back to back", BURST as u64, "puts");
        Ok(())
    })
}
