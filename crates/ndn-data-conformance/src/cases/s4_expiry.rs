//! Slice 4, s4 — data past its keep is dropped everywhere a clock says so, and refused for it.
//!
//! Alice's soil sensor keeps its readings twenty minutes (`Keep::Until`), then writes one it
//! keeps forever. Her home repo and her vault hold the stream; her laptop follows it. Once the
//! keep has passed, every device whose clock says so drops the expired blocks — record and all —
//! and keeps a tombstone: the repo and the laptop store none of them, `get` of a block or of one
//! of its entries answers `Expired`, the laptop's watch reports each block `Expired`, and a range
//! read over the stream lists them expired while answering the reading kept forever. The vault's
//! clock is a day slow: by its clock nothing expired, so it still holds and serves the blocks.
//! That makes no right-clock device keep them: her phone, which never read the stream, reads one
//! block while the vault is the only device serving it, answers `Expired` and stores nothing.
//! Expiry is each device's housekeeping by its own clock; no validity decision reads one
//! (spec §14.1).
//!
//! Devices: the sensor (the one key), the repo and the vault (holders; the vault's clock slow),
//! the laptop (a reader following the stream) and the phone (a reader with a right clock).
//! Invariants: after the keep passes by their clocks, the repo, the laptop and the sensor store
//! none of the expired blocks; `get` answers `DataError::Expired`; watch reports
//! `Change::Expired`; a range read lists them in `expired`; a right-clock reader served by a
//! slow-clock holder answers `Expired` and stores nothing.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "s4",
    title: "Data past its keep is dropped and refused by every right clock",
    slice: 4,
    needs: &[
        Feature::OneKey,
        Feature::Blocks,
        Feature::Expiry,
        Feature::RangeReads,
        Feature::Custody,
    ],
    model: &["M6"],
    guards: "A version whose keep passed by a device's own clock is dropped there — stored \
             nowhere, `get` answers Expired, watch reports it, a range read lists it expired — \
             and a holder whose clock is slow and still serves it makes no right-clock reader \
             keep it.",
    budget: Duration::from_secs(2 * 3600),
    plan,
    run,
};

const SENSOR: Dev = Dev(0);
const REPO: Dev = Dev(1);
const LAPTOP: Dev = Dev(2);
const VAULT: Dev = Dev(3);
const PHONE: Dev = Dev(4);

/// How long the sensor keeps its readings.
const KEEP: Duration = Duration::from_secs(20 * 60);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "soil-sensor");
    p.holder("alice", "repo");
    p.device("alice", "laptop");
    p.holder("alice", "vault");
    p.device("alice", "phone");
    p
}

/// Whether `e` is `Expired` for `name`.
fn expired_for(e: &DataError, name: &Name) -> bool {
    matches!(e, DataError::Expired { name: n, .. } if n == name)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let soil = soil();
        let (sensor, laptop, phone) = (w.at(SENSOR), w.at(LAPTOP), w.at(PHONE));
        sensor.share(&soil, one_key(w, SENSOR, &[])).await?;
        let mut following = laptop.watch(&soil, &Frontier::new()).await?;

        let keep = Keep::Until(Timestamp(w.net().date(SENSOR).0 + KEEP.as_millis() as u64));
        take_readings(
            w,
            SENSOR,
            &soil,
            (0, 30),
            Duration::from_secs(10),
            reading(keep, Some(Duration::from_secs(60))),
        )
        .await?;
        take_readings(
            w,
            SENSOR,
            &soil,
            (30, 1),
            Duration::from_secs(1),
            reading(Keep::Forever, None),
        )
        .await?;
        let blocks = own_blocks(&*sensor, &soil).await?;
        let (expiring, lasting): (Vec<Version>, Vec<Version>) =
            blocks.into_iter().partition(|v| v.keep == keep);
        ensure!(
            !expiring.is_empty() && lasting.len() == 1,
            "the sensor lists {} blocks kept {keep:?} and {} kept forever",
            expiring.len(),
            lasting.len()
        );

        w.gesture();
        let today = w.net().date(SENSOR).0;
        let want = Hold {
            copies: 2,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
            holders: vec![w.net().spec(REPO).name(), w.net().spec(VAULT).name()],
        };
        let kept = hold_on(w, SENSOR, &soil, &want, "the sensor's hold").await?;
        ensure!(
            kept.leases.len() == 2,
            "two holders asked, {} leases",
            kept.leases.len()
        );
        for holder in [REPO, VAULT] {
            ensure!(
                stored_blocks(w, holder, &expiring) == expiring.len(),
                "{} does not store every block it holds",
                w.net().spec(holder).name()
            );
        }
        w.converge("the laptop holds the stream", LIMIT, || async {
            Ok(stored_blocks(w, LAPTOP, &expiring) == expiring.len())
        })
        .await?;

        // The vault's clock runs a day slow; then the keep passes for every right clock.
        w.net().set_clock(VAULT, ClockSkew::behind(DAY));
        w.sleep(KEEP).await;

        let dropped = w
            .until(
                "the sensor, the repo and the laptop drop the expired blocks",
                LIMIT,
                || async {
                    Ok([SENSOR, REPO, LAPTOP]
                        .iter()
                        .all(|d| expiring.iter().all(|v| w.stored(*d, &v.name) == 0)))
                },
            )
            .await?;
        w.measure(
            "expired blocks dropped after the keep",
            dropped.as_millis() as u64,
            "ms",
        );
        for v in &expiring {
            match laptop.get(&v.name).await {
                Err(e) if expired_for(&e, &v.name) => {}
                other => {
                    return Err(Failure::new(format!(
                        "get of the expired block {} at the laptop answered {other:?}, not \
                         Expired",
                        v.name
                    )));
                }
            }
            let entry = entry_name(&v.name, 0);
            match entries_at(&*laptop, &entry).await? {
                Err(e) if expired_for(&e, &entry) => {}
                other => {
                    return Err(Failure::new(format!(
                        "get of an entry of the expired block {} answered {other:?}, not Expired",
                        v.name
                    )));
                }
            }
        }
        let mut seen = Vec::new();
        drain_until(
            &mut following,
            &mut seen,
            "the laptop's watch reports every expired block",
            LOOK,
            |seen| {
                expiring.iter().all(|v| {
                    seen.iter()
                        .any(|c| matches!(c, Change::Expired { id, .. } if *id == v.id))
                })
            },
        )
        .await?;

        let (lo, hi) = (expiring[0].id.seq.0, lasting[0].id.seq.0);
        let got = entries_at(&*laptop, &range_name(&soil, &Range::Seqs(lo, hi))).await??;
        let expired_ids: Vec<&VersionId> = expiring.iter().map(|v| &v.id).collect();
        ensure!(
            expired_ids.iter().all(|id| got.expired.contains(id)),
            "the range read over the stream does not list every expired block expired: {:?} \
             of {expired_ids:?}",
            got.expired
        );
        ensure!(
            read_entries(&got) == written(&lasting[0]),
            "the range read answered {:?}, not exactly the reading kept forever",
            got.entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );

        // The slow vault still holds and serves them; the phone, never having read the stream,
        // reads a block that only the vault serves.
        let target = &expiring[0];
        ensure!(
            w.stored(VAULT, &target.name) > 0,
            "the vault, its clock a day slow, dropped the block: nothing would still serve it"
        );
        w.net().forget_cached(&target.name).await;
        let answered = w
            .until(
                "the phone reads the block the vault serves",
                LIMIT,
                || async {
                    match phone.get(&target.name).await {
                        Err(e) if expired_for(&e, &target.name) => Ok(true),
                        Err(DataError::Unavailable { .. } | DataError::NotFound { .. }) => {
                            Ok(false)
                        }
                        other => Err(Failure::new(format!(
                            "the phone's get of the expired block {} answered {other:?}, not \
                         Expired",
                            target.name
                        ))),
                    }
                },
            )
            .await?;
        w.measure(
            "a right clock answers Expired from a slow holder",
            answered.as_millis() as u64,
            "ms",
        );
        w.sleep(LOOK).await;
        ensure!(
            stored_blocks(w, PHONE, &expiring) == 0,
            "the phone stored an expired block a slow-clock holder served it"
        );
        Ok(())
    })
}
