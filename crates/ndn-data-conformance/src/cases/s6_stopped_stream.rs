//! Slice 4, s6 — a stopped stream does not keep a new reader waiting on what expired.
//!
//! Alice's soil sensor keeps its readings twenty minutes (`Keep::Until`), writes one last reading
//! it keeps forever, and then never writes again: it stays up, reachable, answering for its
//! stream, but its newest summary node's reference date stays at that last reading. Her home
//! repo holds the stream under a lease. Once the keep has passed by every device's clock, the
//! sensor and the repo drop the expired blocks, and the caches have evicted them: nothing serves
//! them any more. Only then does her phone, which never held any of the stream, start watching
//! it. The sensor's newest node still lists the expired blocks (its reference date is the last
//! reading's, before their keep), and no packet of theirs can tell the phone their keep; the
//! phone must not wait on them forever: it applies the reading kept forever and reports it,
//! without the sensor writing again (spec §7 listing by keep, §14.1 a stopped writer, §5.2).
//!
//! Devices: the sensor (the one key; up, never writing again), the repo (a holder) and the phone
//! (a reader that starts after the expiry).
//! Invariants: the phone's watch reports the reading kept forever, within a bounded time of
//! starting; it reports none of the expired blocks as a version, and stores none of them.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "s6",
    title: "A stopped stream does not keep a new reader waiting on what expired",
    slice: 4,
    needs: &[
        Feature::OneKey,
        Feature::Blocks,
        Feature::Expiry,
        Feature::Custody,
    ],
    model: &[],
    guards: "When a writer stops writing, a reader that starts after its versions expired still \
             applies and reports the versions kept longer that the writer wrote after them, \
             without the writer writing again — it does not wait forever on listed versions \
             whose keep has passed — and reports or stores none of the expired ones.",
    budget: Duration::from_secs(2 * 3600),
    plan,
    run,
};

const SENSOR: Dev = Dev(0);
const REPO: Dev = Dev(1);
const PHONE: Dev = Dev(2);

/// How long the sensor keeps its readings.
const KEEP: Duration = Duration::from_secs(20 * 60);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "soil-sensor");
    p.holder("alice", "repo");
    p.device("alice", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let soil = soil();
        let (sensor, phone) = (w.at(SENSOR), w.at(PHONE));
        sensor.share(&soil, one_key(w, SENSOR, &[])).await?;

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
        let last = &lasting[0];
        ensure!(
            expiring.iter().all(|v| v.id.seq < last.id.seq),
            "the reading kept forever is not the sensor's newest version"
        );

        w.gesture();
        let today = w.net().date(SENSOR).0;
        let want = Hold {
            copies: 1,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
            holders: vec![w.net().spec(REPO).name()],
        };
        let kept = hold_on(w, SENSOR, &soil, &want, "the sensor's hold").await?;
        ensure!(
            kept.leases.len() == 1,
            "one holder asked, {} leases",
            kept.leases.len()
        );
        ensure!(
            stored_blocks(w, REPO, &expiring) == expiring.len(),
            "the repo does not store every block it holds"
        );

        // The sensor writes nothing more; the keep passes for every clock, and the sensor and
        // the repo drop the expired blocks.
        w.sleep(KEEP).await;
        w.until(
            "the sensor and the repo drop the expired blocks",
            LIMIT,
            || async {
                Ok([SENSOR, REPO]
                    .iter()
                    .all(|d| expiring.iter().all(|v| w.stored(*d, &v.name) == 0)))
            },
        )
        .await?;

        // Caches evict them too, so nothing serves them any more: a reader can learn their
        // keep from no packet of theirs.
        let repo = w.net().spec(REPO).name();
        for v in &expiring {
            w.net().forget_cached(&v.name).await;
            w.net().forget_cached(&held_name(&repo, &v.name)).await;
        }

        // Only now does the phone, which never held the stream, start watching it.
        let mut following = phone.watch(&soil, &Frontier::new()).await?;
        let mut seen = Vec::new();
        let took = drain_until(
            &mut following,
            &mut seen,
            "the phone's watch, started after the expiry, reports the reading kept forever \
             (the sensor writing nothing more)",
            LIMIT,
            |seen| version(seen, &last.id).is_some(),
        )
        .await?;
        w.measure(
            "a reader starting after the expiry reports the last reading",
            took.as_millis() as u64,
            "ms",
        );
        let reported = version(&seen, &last.id).expect("drained until reported");
        ensure!(
            written(reported) == written(last),
            "the phone's watch reported the reading kept forever with entries {:?}, not the \
             sensor's",
            written(reported)
                .into_iter()
                .map(|e| e.name)
                .collect::<Vec<_>>()
        );

        drain(&mut following, LOOK, &mut seen).await?;
        let wrong: Vec<&VersionId> = versions(&seen)
            .map(|v| &v.id)
            .filter(|id| expiring.iter().any(|v| v.id == **id))
            .collect();
        ensure!(
            wrong.is_empty(),
            "the phone's watch reported expired blocks as versions: {wrong:?}"
        );
        ensure!(
            stored_blocks(w, PHONE, &expiring) == 0,
            "the phone stored an expired block"
        );
        Ok(())
    })
}
