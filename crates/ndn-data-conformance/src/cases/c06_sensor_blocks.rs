//! Case 6 — soil sensor, one reading per second.
//!
//! A battery microcontroller publishes thousands of tiny readings an hour. With one signature per
//! version, every reading cost a signature. The fix (M6): a version may be a signed block — one
//! signature over many readings, each entry verifiable through it — and the producer states the
//! delay it accepts. The stream is a one-key collection: its members record names the sensor
//! device, whose key is the one key that writes it (spec §4.1, §5.3).
//!
//! Devices: the sensor (the one key), Alice's home repo and her laptop, both following the
//! stream. The sensor takes an hour of readings batched under a minute's delay, then a short
//! phase unbatched. Invariants: no reading waits longer than the delay accepted; signatures grow
//! with blocks, not readings; every reading reaches the repo. Measured per reading, batched and
//! unbatched: the sensor's signatures, Interests, bytes and radio energy, and the repo's and the
//! reader's Interests.

use std::time::Duration;

use ndn_sim::{EnergyModel, RadioEnergyModel};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, DeviceWire, World};

pub(super) const CASE: Case = Case {
    id: "c6",
    title: "Soil sensor, 1 reading per second",
    slice: 4,
    needs: &[Feature::OneKey, Feature::Blocks],
    model: &["M6"],
    guards: "Readings share signatures in blocks: signatures grow with blocks, not readings; no \
             reading waits longer than the delay its producer accepts; every reading reaches the \
             repo.",
    budget: Duration::from_secs(3 * 3600),
    plan: stream_plan,
    run,
};

const SENSOR: Dev = Dev(0);
const REPO: Dev = Dev(1);
const LAPTOP: Dev = Dev(2);

/// One hour at one reading per second.
const READINGS: usize = 3600;
/// The short unbatched phase: two minutes at one reading per second.
const UNBATCHED: usize = 120;
/// The delay the sensor accepts before its readings are signed.
const ACCEPTED: Duration = Duration::from_secs(60);
/// Blocks must cut signatures by at least this factor (one per minute would be 60).
const MIN_SAVING: usize = 10;

/// The sensor's radio, for its energy per reading: an IEEE 802.15.4 (2.4 GHz O-QPSK) low-power
/// radio, CC2420-class, at 0 dBm. About 52 mW transmitting (48 mW of circuit draw, 1 mW
/// radiated through a 25%-efficient amplifier), 56 mW receiving, and a microcontroller drawing
/// 10 mW for 0.2 ms to handle each frame. The radio is duty-cycled: idle listening is not
/// counted, only the frames the sensor's link carried.
const RADIO: RadioEnergyModel = RadioEnergyModel {
    tx_baseline_w: 0.048,
    pa_efficiency: 0.25,
    rx_active_w: 0.056,
    idle_w: 0.0,
    host_cpu_w: 0.010,
    host_process_s: 0.2e-3,
};
/// 802.15.4 at 2.4 GHz: 250 kbit/s.
const BIT_RATE: f64 = 250_000.0;
/// NDN octets one 127-octet frame carries: the PSDU less the MAC header, FCS and a
/// fragmentation header (25 octets).
const FRAME_PAYLOAD: u64 = 102;
/// Octets on air per frame beyond its NDN octets: preamble, SFD and length (6) plus the 25
/// above.
const FRAME_OVERHEAD: u64 = 31;
/// The transmit power, dBm.
const TX_DBM: f64 = 0.0;

/// The sensor radio's energy, in microjoules, for what its link carried in `wire`. Each packet
/// is split into frames of [`FRAME_PAYLOAD`] octets; counting one extra frame per Interest or
/// Data sent or received bounds the last partial frames from above.
fn radio_uj(wire: DeviceWire) -> u64 {
    let frames = |packets: u64, octets: u64| packets + octets.div_ceil(FRAME_PAYLOAD);
    let airtime = |frames: u64, octets: u64| {
        Duration::from_secs_f64(((octets + frames * FRAME_OVERHEAD) * 8) as f64 / BIT_RATE)
    };
    let sent = frames(wire.interests + wire.data, wire.out_bytes);
    let heard = frames(wire.in_interests + wire.in_data, wire.in_bytes);
    let joules = RADIO.tx_energy_j(airtime(sent, wire.out_bytes), TX_DBM, 0)
        + RADIO.rx_energy_j(airtime(heard, wire.in_bytes), 0)
        + (sent + heard) as f64 * RADIO.host_process_energy_j(0);
    (joules * 1e6).round() as u64
}

/// What each device's links carried, and the sensor's signatures, at one moment.
#[derive(Clone, Copy)]
struct Counters {
    sensor: DeviceWire,
    signed: u64,
    repo: DeviceWire,
    laptop: DeviceWire,
}

fn counters(w: &World) -> Counters {
    Counters {
        sensor: w.net().device_wire(SENSOR),
        signed: w.signed_by(SENSOR),
        repo: w.net().device_wire(REPO),
        laptop: w.net().device_wire(LAPTOP),
    }
}

/// Record what `readings` readings cost from `before` to `after`, as `<phase>: …` measures.
fn record(w: &World, phase: &str, readings: usize, before: Counters, after: Counters) {
    let n = readings as u64;
    let sensor = after.sensor - before.sensor;
    let per_mille = |v: u64| v * 1000 / n;
    w.measure(
        format!("{phase}: sensor signatures per 1000 readings"),
        per_mille(after.signed - before.signed),
        "signatures",
    );
    w.measure(
        format!("{phase}: sensor Interests per 1000 readings"),
        per_mille(sensor.interests),
        "round trips",
    );
    w.measure(
        format!("{phase}: sensor bytes sent per reading"),
        sensor.out_bytes / n,
        "bytes",
    );
    w.measure(
        format!("{phase}: sensor bytes received per reading"),
        sensor.in_bytes / n,
        "bytes",
    );
    w.measure(
        format!("{phase}: sensor radio energy per reading (802.15.4, 0 dBm)"),
        radio_uj(sensor) / n,
        "µJ",
    );
    w.measure(
        format!("{phase}: repo Interests per 1000 readings"),
        per_mille((after.repo - before.repo).interests),
        "round trips",
    );
    w.measure(
        format!("{phase}: reader Interests per 1000 readings"),
        per_mille((after.laptop - before.laptop).interests),
        "round trips",
    );
}

/// Drain `stream` until the distinct versions it delivered carry `want` readings.
async fn follow_to(
    stream: &mut Changes,
    seen: &mut Vec<Change>,
    who: &str,
    want: usize,
) -> Result<(), Failure> {
    drain_until(
        stream,
        seen,
        &format!("{who} follows the stream to {want} readings"),
        LIMIT,
        |seen| {
            let distinct: std::collections::BTreeMap<&VersionId, usize> =
                versions(seen).map(|v| (&v.id, entries(v))).collect();
            distinct.values().sum::<usize>() >= want
        },
    )
    .await
    .map(drop)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let soil = soil();
        let (sensor, repo, laptop) = (w.at(SENSOR), w.at(REPO), w.at(LAPTOP));
        sensor
            .share(&soil, one_key(w, SENSOR, &[person("/alice")]))
            .await?;
        // The repo archives the stream and the laptop shows it: both follow it from the start.
        let mut at_repo = repo.watch(&soil, &Frontier::new()).await?;
        let mut at_laptop = laptop.watch(&soil, &Frontier::new()).await?;
        let (mut repo_seen, mut laptop_seen) = (Vec::new(), Vec::new());

        let start = w.mark();
        let before = counters(w);
        let batched = take_readings(
            w,
            SENSOR,
            &soil,
            (0, READINGS),
            Duration::from_secs(1),
            reading(Keep::Forever, Some(ACCEPTED)),
        )
        .await?;
        let longest = batched.iter().map(|(_, waited)| *waited).max();
        let longest = longest.unwrap_or_default();
        ensure!(
            longest <= ACCEPTED + Duration::from_secs(5),
            "a reading waited {longest:?} to be signed; the sensor accepts {ACCEPTED:?}"
        );
        let blocks: std::collections::BTreeSet<&VersionId> =
            batched.iter().map(|(id, _)| id).collect();
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
        follow_to(&mut at_repo, &mut repo_seen, "the repo", READINGS).await?;
        follow_to(&mut at_laptop, &mut laptop_seen, "the laptop", READINGS).await?;
        let after = counters(w);
        record(w, "batched", READINGS, before, after);
        w.measure("batched: blocks", blocks.len() as u64, "versions");

        let before = after;
        take_readings(
            w,
            SENSOR,
            &soil,
            (READINGS, UNBATCHED),
            Duration::from_secs(1),
            reading(Keep::Forever, None),
        )
        .await?;
        let all = READINGS + UNBATCHED;
        follow_to(&mut at_repo, &mut repo_seen, "the repo", all).await?;
        follow_to(&mut at_laptop, &mut laptop_seen, "the laptop", all).await?;
        record(w, "unbatched", UNBATCHED, before, counters(w));

        w.converge("the repo holds every reading", LIMIT, || async {
            let seen = look(&*repo, &soil, &Frontier::new(), LOOK).await?;
            Ok(versions(&seen).map(entries).sum::<usize>() >= all)
        })
        .await?;
        Ok(())
    })
}
