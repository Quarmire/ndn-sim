//! Case 6 — soil sensor, one reading per second.
//!
//! A battery microcontroller publishes thousands of tiny readings an hour. With one signature per
//! version, every reading cost a signature. The fix (M6): a version may be a signed block — one
//! signature over many readings, a digest per entry — and the producer states the delay it
//! accepts.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c6",
    title: "Soil sensor, 1 reading per second",
    slice: 4,
    model: &["M6"],
    guards: "Readings share signatures in blocks: signatures grow with blocks, not readings; no \
             reading waits longer than the delay its producer accepts; every reading reaches the \
             repo.",
    budget: Duration::from_secs(3 * 3600),
    plan,
    run,
};

const SENSOR: Dev = Dev(0);
const REPO: Dev = Dev(1);

/// One hour at one reading per second.
const READINGS: usize = 3600;
/// The delay the sensor accepts before its readings are signed.
const ACCEPTED: Duration = Duration::from_secs(60);
/// Blocks must cut signatures by at least this factor (one per minute would be 60).
const MIN_SAVING: usize = 10;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "soil-sensor");
    p.device("alice", "repo");
    p
}

fn reading() -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/soil-reading"),
            revision: 1,
        },
        keep: Keep::Forever,
        batch: Some(ACCEPTED),
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let soil = n("/alice/garden/soil");
        let (sensor, repo) = (w.at(SENSOR), w.at(REPO));
        sensor
            .share(
                &soil,
                members(Rule::OneKey, &["/alice"], &[person("/alice")]),
            )
            .await?;

        let start = w.mark();
        let mut pending = Vec::with_capacity(READINGS);
        for i in 0..READINGS {
            let (sensor, soil) = (sensor.clone(), soil.clone());
            pending.push(tokio::spawn(async move {
                let asked = tokio::time::Instant::now();
                let id = sensor
                    .put(
                        &soil,
                        content(&[("moisture", &format!("{}", 300 + i % 50))]),
                        reading(),
                    )
                    .await;
                (id, asked.elapsed())
            }));
            w.sleep(Duration::from_secs(1)).await;
        }
        let mut blocks = std::collections::BTreeSet::new();
        let mut longest = Duration::ZERO;
        for p in pending {
            let (id, waited) = p
                .await
                .map_err(|e| Failure::new(format!("a put task failed: {e}")))?;
            blocks.insert(id?);
            longest = longest.max(waited);
        }
        ensure!(
            longest <= ACCEPTED + Duration::from_secs(5),
            "a reading waited {longest:?} to be signed; the sensor accepts {ACCEPTED:?}"
        );
        ensure!(
            blocks.len() * MIN_SAVING <= READINGS,
            "{} versions for {READINGS} readings: readings are not sharing blocks",
            blocks.len()
        );
        let signed = w
            .cost_since(start)
            .signatures
            .expect("a running world measures signatures");
        ensure!(
            signed as usize * MIN_SAVING <= READINGS,
            "{signed} signatures for {READINGS} readings: signing is per reading, not per block"
        );

        w.converge("the repo holds every reading", LIMIT, || async {
            let seen = look(&*repo, &soil, &Frontier::new(), LOOK).await?;
            Ok(versions(&seen).map(entries).sum::<usize>() >= READINGS)
        })
        .await?;
        Ok(())
    })
}
