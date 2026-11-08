//! Slice 4, s5 — a replayed old head does not roll the newest back.
//!
//! Alice's soil sensor writes one reading; a café's cache records the sensor's signed head as it
//! passes, and from then on answers every ask for the head with that packet, however stale (a
//! cache that ignores FreshnessPeriod). The sensor writes two more readings, and Alice's laptop,
//! at home, reads the newest. Then she takes the laptop to the café: the sensor is out of reach,
//! and the only answer to the laptop's ask for the head is the café's old one — genuinely signed
//! by the one key, but naming a lower seq than the head the laptop already verified. The laptop
//! refuses the rollback and keeps answering the newest it verified, stale and saying so: how
//! long it went unconfirmed grows on its own clock; the replayed head confirms nothing
//! (spec §5.3).
//!
//! Devices: the sensor (the one key), the laptop (a reader) and the café's cache (the replayer).
//! Invariant: once the laptop verified the head naming version `n`, `get` of the collection
//! never answers a version older than `n`, and the replayed head does not make the answer look
//! confirmed.

use std::time::Duration;

use ndn_data::{Age, wire::head_prefix};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "s5",
    title: "A replayed old head does not roll the newest back",
    slice: 4,
    needs: &[Feature::OneKey],
    model: &[],
    guards: "A one-key reader refuses a head older than one it verified: a cache replaying an \
             old signed head neither makes get answer an older version than one already \
             verified nor makes the answer look confirmed.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const SENSOR: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const CACHE: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "soil-sensor");
    p.device("alice", "laptop");
    p.device("cafe", "cache");
    p
}

/// The newest the laptop answers for `c`: the version and how long it went unconfirmed. Asked
/// again while the laptop answers RetryLater (its first look at the stream racing the network).
async fn newest(
    w: &World,
    laptop: &dyn DataLayer,
    c: &Name,
) -> Result<(Version, Duration), Failure> {
    match w.again(|| laptop.get(c)).await? {
        Answer {
            got: Got::Version(v),
            age,
        } => {
            let unconfirmed = match age {
                Age::Newest { unconfirmed_for } => unconfirmed_for,
                Age::Exact => Duration::ZERO,
            };
            Ok((v, unconfirmed))
        }
        a => Err(Failure::new(format!(
            "get of the one-key collection {c} answered {:?}, not its newest version",
            a.got
        ))),
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let soil = soil();
        let (sensor, laptop) = (w.at(SENSOR), w.at(LAPTOP));
        sensor.share(&soil, one_key(w, SENSOR, &[])).await?;
        let unbatched = || reading(Keep::Forever, None);
        let old = sensor.put(&soil, soil_reading(0), unbatched()).await?;

        // The café records the head naming the first reading; the laptop is not there yet.
        w.replay(CACHE, &head_prefix(&w.net().spec(SENSOR).name(), &soil))
            .await?;
        w.net().offline(CACHE);

        sensor.put(&soil, soil_reading(1), unbatched()).await?;
        let newer = sensor.put(&soil, soil_reading(2), unbatched()).await?;
        ensure!(old.seq < newer.seq, "the sensor's seqs do not grow");
        w.until("the laptop reads the newest reading", LIMIT, || async {
            Ok(newest(w, &*laptop, &soil).await?.0.id == newer)
        })
        .await?;

        // At the café: the sensor is out of reach, and only the café answers an ask for its
        // head, with the old one.
        w.net().offline(SENSOR);
        w.net().online(CACHE);
        let offline = tokio::time::Instant::now();
        let served = w.net().device_wire(CACHE);
        let deadline = offline + SETTLE;
        let mut reads = 0u64;
        // At the last read: how long the sensor had been away when it was asked, and how long
        // the answer went unconfirmed.
        let (mut away, mut unconfirmed) = (Duration::ZERO, Duration::ZERO);
        while tokio::time::Instant::now() < deadline {
            reads += 1;
            let asked = offline.elapsed();
            let (v, age) = newest(w, &*laptop, &soil).await?;
            ensure!(
                v.id.seq >= newer.seq,
                "after verifying the head naming seq {}, the laptop answered seq {} for the \
                 collection: a replayed head rolled it back",
                newer.seq.0,
                v.id.seq.0
            );
            (away, unconfirmed) = (asked, age);
            w.sleep(Duration::from_secs(5)).await;
        }
        let replayed = (w.net().device_wire(CACHE) - served).data;
        ensure!(
            replayed > 0,
            "the café answered no ask while the sensor was offline: the replay was not exercised"
        );
        ensure!(
            unconfirmed >= away,
            "asked {away:?} after the sensor left, with only a replayed old head reachable, the \
             laptop answered unconfirmed for {unconfirmed:?}: the replayed head counted as \
             confirming it"
        );
        w.measure(
            "reads while only the replayed head answered",
            reads,
            "reads",
        );
        w.measure("packets the café replayed", replayed, "packets");
        w.measure(
            "unconfirmed for, at the last read",
            unconfirmed.as_millis() as u64,
            "ms",
        );
        Ok(())
    })
}
