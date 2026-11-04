//! Slice 4, s3 — an entry spliced from another block is never returned.
//!
//! As in s2, Alice's home repo holds her soil sensor's stream and turns malicious, but this
//! time it forges nothing: it replaces one reading of a block with a reading the sensor
//! genuinely signed in the next block, keeping the first block's signature. The laptop, which
//! read a range of the stream earlier and so knows the sensor's head, reads a range covering
//! the doctored block while the sensor is offline and no cache has it. Each entry is verifiable
//! only through the signature of the block that carries it, so the spliced reading breaks the
//! block's signature: the block is refused and the range read says it is missing, never
//! answering the spliced reading as the block's. Once the sensor is back, the read completes
//! with the genuine reading (spec §4.1, §5.4).
//!
//! Devices: the sensor (the one key), the repo (a holder, then the attacker) and the laptop (a
//! reader). Invariant: a range read never answers the spliced entry in the doctored block; while
//! the block cannot be verified the answer lists it missing; once its writer is reachable the
//! read answers the genuine entries, complete.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::Tamper;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "s3",
    title: "An entry spliced from another block is never returned",
    slice: 4,
    needs: &[
        Feature::OneKey,
        Feature::Blocks,
        Feature::RangeReads,
        Feature::Custody,
    ],
    model: &["M6"],
    guards: "An entry travels only inside the signed block that carries it: one spliced from \
             another block breaks the block's signature, so a range read never answers it, lists \
             the block missing while no verifiable copy is reachable, and answers the genuine \
             entries once one is.",
    budget: Duration::from_secs(1800),
    plan: counted_stream_plan,
    run,
};

const SENSOR: Dev = Dev(0);
const REPO: Dev = Dev(1);
const LAPTOP: Dev = Dev(2);

/// The entry the repo replaces, by index in its block.
const SPLICED: u32 = 1;

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
        ensure!(
            blocks.len() >= 4,
            "{} blocks for 60 readings under a minute's delay",
            blocks.len()
        );
        let at = blocks.len() / 2;
        let (target, source) = (blocks[at].clone(), blocks[at + 1].clone());
        let genuine = written(&target);
        ensure!(
            genuine.len() > SPLICED as usize,
            "the block to splice into carries {} readings",
            genuine.len()
        );
        let spliced = written(&source)[0].content.clone();
        ensure!(
            spliced != genuine[SPLICED as usize].content,
            "the substitute reading equals the one it replaces"
        );

        let today = w.net().date(SENSOR).0;
        let want = Hold {
            copies: 1,
            until: Timestamp(today + 365 * DAY.as_millis() as u64),
            holders: vec![w.net().spec(REPO).name()],
        };
        w.gesture();
        let kept = hold_on(w, SENSOR, &soil, &want, "the sensor's hold").await?;
        ensure!(
            kept.leases
                .iter()
                .any(|l| l.audit.kept() && l.holds.contains(&target.id)),
            "the repo's lease does not hold the block it is about to doctor: {:?}",
            kept.leases
        );

        // The laptop reads the first block while the sensor is online: it verifies its head.
        let first = blocks[0].id.seq.0;
        entries_at(&*laptop, &range_name(&soil, &Range::Seqs(first, first))).await??;

        // The attack: the sensor is away, the repo splices, no cache has the block.
        w.net().offline(SENSOR);
        w.tamper(
            REPO,
            &target.name,
            Tamper::Splice {
                entry: SPLICED,
                from: source.name.clone(),
                their: 0,
            },
        )?;
        w.net().forget_cached(&target.name).await;
        ensure!(
            w.stored(LAPTOP, &target.name) == 0,
            "the laptop already holds the block, so it would not read it from the repo"
        );

        let seq = target.id.seq.0;
        let range = range_name(&soil, &Range::Seqs(seq, seq));
        let deadline = tokio::time::Instant::now() + SETTLE;
        let mut reads = 0u64;
        while tokio::time::Instant::now() < deadline {
            reads += 1;
            let got = entries_at(&*laptop, &range).await??;
            let answered = read_entries(&got);
            let doctored = answered
                .iter()
                .find(|e| e.block == target.id && e.content == spliced);
            ensure!(
                doctored.is_none(),
                "the range read answered the reading spliced into block {seq}: {:?}",
                doctored.map(|e| &e.name)
            );
            ensure!(
                answered.iter().all(|e| e.block != target.id),
                "the laptop read block {seq} while only the splicing repo served it: the attack \
                 was not exercised"
            );
            ensure!(
                got.missing.contains(&target.id),
                "the range read of block {seq} answered nothing of it and does not list it \
                 missing: it claims a complete answer (missing {:?}, expired {:?})",
                got.missing,
                got.expired
            );
            w.sleep(Duration::from_secs(5)).await;
        }
        let doctored_at_laptop = w
            .net()
            .received(LAPTOP, &held_name(&w.net().spec(REPO).name(), &target.name));
        ensure!(
            doctored_at_laptop > 0,
            "the doctored block never reached the laptop from the repo: the attack was not \
             exercised"
        );
        w.measure(
            "range reads listing the doctored block missing",
            reads,
            "reads",
        );
        w.measure(
            "doctored copies the repo served the laptop",
            doctored_at_laptop,
            "packets",
        );

        // The sensor is back: the read completes with the genuine readings.
        w.net().online(SENSOR);
        let took = w
            .converge("the laptop reads the genuine block", LIMIT, || async {
                let got = entries_at(&*laptop, &range).await??;
                let answered = read_entries(&got);
                ensure!(
                    answered
                        .iter()
                        .all(|e| !(e.block == target.id && e.content == spliced)),
                    "the range read answered the spliced reading after the sensor returned"
                );
                Ok(got.missing.is_empty() && answered == genuine)
            })
            .await?;
        w.measure(
            "genuine block read after the sensor returned",
            took.as_millis() as u64,
            "ms",
        );
        Ok(())
    })
}
