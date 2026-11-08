//! Slice 4, s2 — an entry forged inside a block at a holder is never returned.
//!
//! Alice's home repo holds her soil sensor's stream, and her laptop has read the stream's first
//! reading, so it knows the stream's members record and who holds it. The repo turns malicious:
//! it alters one reading inside a block it stores and serves the packet with the block's
//! original signature. The sensor is offline and the caches have long evicted the stream, so
//! the laptop, reading that one entry by its name, can only get the block from the repo. An
//! entry exists only inside its block's signed packet, so a forged entry breaks the block's
//! signature: the block is refused, the forged reading never returned, and nothing is answered
//! while no honest copy is reachable. Once the sensor is back, the laptop reads the genuine
//! entry (spec §4.1).
//!
//! Devices: the sensor (the one key), the repo (a holder of the stream, then the attacker) and
//! the laptop (a reader). Invariant: `get` of the forged entry's name, or of its block's name,
//! never answers the forged content, though the forged block reaches the reader; the genuine
//! entry is answered once its writer is reachable.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::Tamper;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "s2",
    title: "An entry forged inside a block at a holder is never returned",
    slice: 4,
    needs: &[Feature::OneKey, Feature::Blocks, Feature::Custody],
    model: &["M6"],
    guards: "An entry is verifiable only through its block's signature: a holder that alters an \
             entry inside a stored block breaks it, the block is refused, and the forged entry is \
             never returned — by its entry name or its block's — while the genuine entry is, \
             once a path to it exists.",
    budget: Duration::from_secs(1800),
    plan: counted_stream_plan,
    run,
};

const SENSOR: Dev = Dev(0);
const REPO: Dev = Dev(1);
const LAPTOP: Dev = Dev(2);

/// The entry the repo forges, by index in its block.
const FORGED: u32 = 2;

/// Whether `v` carries `entry` of the block with content `content`.
fn carries(v: &Version, entry: u32, content: &Content) -> bool {
    matches!(&v.payload, Payload::Block(es) if es.get(entry as usize).is_some_and(|e| e.content == *content))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let soil = soil();
        let (sensor, laptop) = (w.at(SENSOR), w.at(LAPTOP));
        sensor.share(&soil, one_key(w, SENSOR, &[])).await?;
        take_readings(
            w,
            SENSOR,
            &soil,
            (0, 60),
            Duration::from_secs(10),
            reading(Keep::Forever, Some(Duration::from_secs(60))),
        )
        .await?;
        let blocks = own_blocks(&*sensor, &soil).await?;
        let target = blocks
            .iter()
            .skip(blocks.len() / 2)
            .find(|v| written(v).len() > FORGED as usize)
            .cloned()
            .ok_or_else(|| Failure::new("no block of the stream carries three readings"))?;
        let genuine = written(&target)[FORGED as usize].clone();

        w.gesture();
        let today = w.net().date(SENSOR).0;
        let want = Hold {
            copies: 1,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
            holders: vec![w.net().spec(REPO).name()],
        };
        let kept = hold_on(w, SENSOR, &soil, &want, "the sensor's hold").await?;
        ensure!(
            kept.leases
                .iter()
                .any(|l| l.audit.kept() && l.holds.contains(&target.id)),
            "the repo's lease does not hold the block it is about to forge: {:?}",
            kept.leases
        );
        ensure!(
            w.stored(REPO, &target.name) > 0,
            "the repo stores nothing of the block it holds"
        );

        // The laptop reads the stream's first reading while the sensor is online.
        entries_again(w, &*laptop, &entry_name(&blocks[0].name, 0)).await??;

        // The attack: the sensor is away, the repo forges a reading, no cache has the block.
        w.net().offline(SENSOR);
        w.tamper(REPO, &target.name, Tamper::Forge { entry: FORGED })?;
        w.net().forget_cached(&target.name).await;
        ensure!(
            w.stored(LAPTOP, &target.name) == 0,
            "the laptop already holds the block, so it would not read it from the repo"
        );
        let from_repo = held_name(&w.net().spec(REPO).name(), &target.name);

        let entry = entry_name(&target.name, FORGED);
        let deadline = tokio::time::Instant::now() + SETTLE;
        let mut asked = 0u64;
        while tokio::time::Instant::now() < deadline {
            asked += 1;
            if let Ok(got) = entries_at(&*laptop, &entry).await? {
                let e = got.entries.iter().find(|e| e.name == entry);
                ensure!(
                    e.is_none_or(|e| e.content == genuine.content),
                    "the laptop returned the entry the repo forged: {:?}",
                    e.map(|e| &e.content)
                );
                return Err(Failure::new(
                    "the laptop read the entry while only the forging repo served its block: \
                     the attack was not exercised",
                ));
            }
            match laptop.get(&target.name).await {
                Ok(Answer {
                    got: Got::Version(v),
                    ..
                }) => {
                    ensure!(
                        carries(&v, FORGED, &genuine.content),
                        "the laptop returned the block the repo forged"
                    );
                    return Err(Failure::new(
                        "the laptop read the block while only the forging repo served it: the \
                         attack was not exercised",
                    ));
                }
                Ok(a) => {
                    return Err(Failure::new(format!(
                        "get of block {} answered {:?}, not the version",
                        target.name, a.got
                    )));
                }
                Err(_) => {}
            }
            w.sleep(Duration::from_secs(5)).await;
        }
        let forged_at_laptop = w.net().received(LAPTOP, &from_repo);
        ensure!(
            forged_at_laptop > 0,
            "the forged block never reached the laptop from the repo: the attack was not \
             exercised"
        );
        w.measure("reads refused while only the forger served", asked, "reads");
        w.measure(
            "forged copies the repo served the laptop",
            forged_at_laptop,
            "packets",
        );

        // The sensor is back: the genuine entry is read.
        w.net().online(SENSOR);
        let last = std::cell::RefCell::new(None);
        let took = w
            .converge("the laptop reads the genuine entry", LIMIT, || async {
                match entries_at(&*laptop, &entry).await? {
                    Ok(got) => {
                        let e = got.entries.iter().find(|e| e.name == entry);
                        ensure!(
                            e.is_some_and(|e| e.content == genuine.content),
                            "the laptop answered {entry} with {:?}, not the reading the sensor \
                             took",
                            e.map(|e| &e.content)
                        );
                        Ok(true)
                    }
                    Err(e) => {
                        *last.borrow_mut() = Some(e);
                        Ok(false)
                    }
                }
            })
            .await
            .map_err(|f| {
                Failure::new(format!(
                    "{f}; the laptop last answered {:?}",
                    last.borrow()
                        .as_ref()
                        .map(|e| format!("{e} ({:?})", e.next()))
                ))
            })?;
        w.measure(
            "genuine entry read after the sensor returned",
            took.as_millis() as u64,
            "ms",
        );
        Ok(())
    })
}
