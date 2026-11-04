//! Slice 4, s1 — a range read returns exactly the entries in range, without the stream.
//!
//! Alice's soil sensor has written two hours of readings, one every five seconds, in blocks of
//! half a minute. Her laptop, which never followed the stream, asks for five minutes of it in
//! the middle (by time), then for ten blocks further on (by seq). A range read names no index:
//! the one key's head names its summary node, whose entries list every block's seq, and each
//! block states its own dates, so the reader searches the listed seqs for the blocks in range,
//! fetches those, and verifies each through its block's signature (spec §5.4).
//!
//! Devices: the sensor (the one key) and the laptop (a reader). Invariants: each read answers
//! exactly the entries the sensor wrote in the range, in order, complete; by seq it fetches no
//! block outside the range; by time it fetches at most the blocks overlapping the range plus a
//! logarithmic search; neither read fetches the whole stream, then or later.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "s1",
    title: "A range read returns exactly the entries in range, without the stream",
    slice: 4,
    needs: &[Feature::OneKey, Feature::Blocks, Feature::RangeReads],
    model: &["M6"],
    guards: "A range read by time or by seq answers exactly the entries the one key wrote in the \
             range, each verified through its block, and fetches the blocks in range plus a \
             logarithmic search — never the whole stream.",
    budget: Duration::from_secs(4 * 3600),
    plan: counted_stream_plan,
    run,
};

const SENSOR: Dev = Dev(0);
const LAPTOP: Dev = Dev(2);

/// Two hours at one reading every five seconds.
const READINGS: usize = 1440;
const EVERY: Duration = Duration::from_secs(5);
/// The delay the sensor accepts: blocks of about six readings.
const ACCEPTED: Duration = Duration::from_secs(30);
/// The time range: sixty readings (five minutes) from reading 600 on.
const FROM: usize = 600;
const SPAN: usize = 60;
/// The seq range: ten blocks, starting at the 180th block of the stream.
const SEQ_FIRST: usize = 180;
const SEQ_BLOCKS: usize = 10;

/// The most blocks a search over `n` listed seqs probes: interpolation falls back to bisection,
/// at most `⌈log2 n⌉ + 1` probes for each of its two ends.
fn search_bound(n: usize) -> usize {
    2 * (n.next_power_of_two().trailing_zeros() as usize + 1)
}

/// Check that `got` answered exactly `want` from the sensor's one key, complete.
fn exactly(
    what: &str,
    got: &Entries,
    want: &[Written],
    writer: &ndn_data::Writer,
) -> Result<(), Failure> {
    let read = read_entries(got);
    ensure!(
        got.writer == *writer,
        "{what}: answered entries of {}, not of the one key {}",
        got.writer.key(),
        writer.key()
    );
    ensure!(
        got.missing.is_empty() && got.expired.is_empty() && got.large.is_empty(),
        "{what}: incomplete with every block reachable: missing {:?}, expired {:?}, large {:?}",
        got.missing,
        got.expired,
        got.large
    );
    if read != want {
        let extra: Vec<&Name> = read
            .iter()
            .filter(|e| !want.contains(e))
            .map(|e| &e.name)
            .collect();
        let lacking: Vec<&Name> = want
            .iter()
            .filter(|e| !read.contains(e))
            .map(|e| &e.name)
            .collect();
        return Err(Failure::new(format!(
            "{what}: answered {} entries, the sensor wrote {} in the range; not written there: \
             {extra:?}; written there, not answered: {lacking:?}",
            read.len(),
            want.len()
        )));
    }
    Ok(())
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
            (0, READINGS),
            EVERY,
            reading(Keep::Forever, Some(ACCEPTED)),
        )
        .await?;
        let blocks = own_blocks(&*sensor, &soil).await?;
        let stream: Vec<Written> = blocks.iter().flat_map(written).collect();
        ensure!(
            stream.len() == READINGS,
            "the sensor lists {} readings of the {READINGS} it took",
            stream.len()
        );
        ensure!(
            blocks.len() >= SEQ_FIRST + SEQ_BLOCKS,
            "{} blocks for {READINGS} readings under a {ACCEPTED:?} delay",
            blocks.len()
        );
        let writer = blocks[0].id.writer.clone();
        w.measure("blocks in the stream", blocks.len() as u64, "versions");
        // Every block that reached the laptop, whether or not its data layer kept it: what the
        // reads fetched.
        let reached = || {
            blocks
                .iter()
                .filter(|v| w.net().received(LAPTOP, &v.name) > 0)
                .map(|v| v.id.seq.0)
                .collect::<std::collections::BTreeSet<u64>>()
        };
        ensure!(
            reached().is_empty() && stored_blocks(w, LAPTOP, &blocks) == 0,
            "the laptop fetched blocks of a stream it never read"
        );

        // By time: five minutes in the middle, from one reading's date to another's.
        let (from, to) = (stream[FROM].dated, stream[FROM + SPAN].dated);
        let want: Vec<Written> = stream
            .iter()
            .filter(|e| from <= e.dated && e.dated < to)
            .cloned()
            .collect();
        let overlapping = blocks
            .iter()
            .filter(|v| {
                let es = written(v);
                es.first().is_some_and(|f| f.dated < to)
                    && es.last().is_some_and(|l| l.dated >= from)
            })
            .count();
        let before = w.net().device_wire(LAPTOP);
        let got = entries_at(&*laptop, &range_name(&soil, &Range::Times(from, to))).await??;
        let spent = w.net().device_wire(LAPTOP) - before;
        exactly("the range read by time", &got, &want, &writer)?;
        let by_time = reached();
        let bound = overlapping + search_bound(blocks.len());
        ensure!(
            by_time.len() <= bound,
            "the range read by time fetched {} of the {} blocks; {overlapping} overlap the \
             range and a search probes at most {} more",
            by_time.len(),
            blocks.len(),
            search_bound(blocks.len())
        );
        ensure!(
            (spent.interests as usize) < blocks.len(),
            "the range read by time sent {} Interests for a stream of {} blocks: it read the \
             stream, not the range",
            spent.interests,
            blocks.len()
        );
        w.measure("by time: entries in range", want.len() as u64, "entries");
        w.measure(
            "by time: blocks overlapping the range",
            overlapping as u64,
            "versions",
        );
        w.measure("by time: blocks fetched", by_time.len() as u64, "versions");
        w.measure("by time: reader Interests", spent.interests, "round trips");
        w.measure("by time: reader bytes received", spent.in_bytes, "bytes");

        // By seq: ten blocks further on, none of which the time read touched.
        let range = &blocks[SEQ_FIRST..SEQ_FIRST + SEQ_BLOCKS];
        let (lo, hi) = (range[0].id.seq.0, range[SEQ_BLOCKS - 1].id.seq.0);
        ensure!(
            by_time.range(lo..=hi).next().is_none(),
            "the range read by time fetched blocks of the seq range {lo}..={hi} it does not \
             overlap"
        );
        let want: Vec<Written> = range.iter().flat_map(written).collect();
        let before = w.net().device_wire(LAPTOP);
        let got = entries_at(&*laptop, &range_name(&soil, &Range::Seqs(lo, hi))).await??;
        let spent = w.net().device_wire(LAPTOP) - before;
        exactly("the range read by seq", &got, &want, &writer)?;
        let by_seq = reached();
        let outside: Vec<&u64> = by_seq
            .difference(&by_time)
            .filter(|s| !(lo..=hi).contains(*s))
            .collect();
        ensure!(
            outside.is_empty(),
            "the range read of seqs {lo}..={hi} fetched blocks outside it: seqs {outside:?}"
        );
        w.measure("by seq: blocks in range", SEQ_BLOCKS as u64, "versions");
        w.measure(
            "by seq: blocks fetched",
            by_seq.difference(&by_time).count() as u64,
            "versions",
        );
        w.measure("by seq: reader Interests", spent.interests, "round trips");
        w.measure("by seq: reader bytes received", spent.in_bytes, "bytes");

        // Reading a range is not following the stream: nothing else is fetched afterwards.
        w.sleep(SETTLE).await;
        let later = reached();
        ensure!(
            later == by_seq,
            "a minute after two range reads the laptop had fetched {} more of the {} blocks: \
             reading a range made it follow the stream",
            later.len().saturating_sub(by_seq.len()),
            blocks.len()
        );
        Ok(())
    })
}
