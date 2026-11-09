//! Signals, e14 — one member's devices cannot take a scope's run slots, and removing a member
//! frees its slots at once.
//!
//! Alice's board names Alice, Bob, Carol, Dave, Erin and Frank by their person prefixes, so
//! every device of theirs is a member; it is not sealed. Carol's tablet receives. Dave's and
//! Erin's four devices each open four runs (quiet after one signal): 32 runs. Then Bob, with
//! eight devices, opens four runs on each: 32 more, so one member's devices claim half of the
//! scope's 64 run slots. Alice then opens a new run and drags at 60 Hz for three seconds.
//! Frank's four devices then open fifteen runs, which fill the scope; one more run of Frank's
//! is refused (`flood`). Alice removes Bob from the board, and once Carol holds that record
//! Frank's refused run is pushed again, while Bob's runs are hours from their end. Every run is
//! a member's genuine run: its header signed by the device key, its packets by the run key.
//!
//! The network is lossless here: the guards count packets. The guards: Alice's new run is
//! delivered within three header periods though Bob's devices claimed half of the slots (a
//! receiver caps the runs of one sender namespace, spec §8.4); the scope holding 64 runs
//! refuses one more; and once Carol holds the record removing Bob, Frank's run is admitted at
//! once (a run of a sender no longer a member gives up its slot at the cap, §8.4).

use std::time::Duration;

use ndn_packet::encode::DataBuilder;
use ndn_sim::Faults;
use ndn_surface::signal::RUNS_PER_SCOPE;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e14",
    title: "One member cannot take a scope's run slots; removal frees them",
    slice: 7,
    needs: &[Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "The runs of one member's devices never fill a scope's run slots against another \
             member: a new run of another member is admitted while they claim half of them; a \
             scope holding its 64 runs refuses one more; and from the moment a receiver holds \
             the record removing a member, a new run of a remaining member is admitted at once, \
             the removed member's runs still unexpired.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const CAROL: Dev = Dev(1);
/// Bob's eight devices, then Dave's, Erin's and Frank's four each.
const BOBS: std::ops::Range<usize> = 2..10;
const DAVES: std::ops::Range<usize> = 10..14;
const ERINS: std::ops::Range<usize> = 14..18;
const FRANKS: std::ops::Range<usize> = 18..22;
/// Runs one key may hold at a receiver.
const PER_KEY: u64 = 4;
/// Alice's frames at 60 Hz: three seconds.
const FRAMES: u32 = 180;
/// How many times a run's packet is pushed while it is not delivered.
const ROUNDS: u32 = 3;
/// Packets pushed at once, then [`BATCH_PAUSE`]: a receiver admits a few headers at a time.
const BATCH: usize = 8;
const BATCH_PAUSE: Duration = Duration::from_millis(400);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("carol", "tablet");
    for (person, devices) in [
        ("bob", BOBS),
        ("dave", DAVES),
        ("erin", ERINS),
        ("frank", FRANKS),
    ] {
        for i in 0..devices.len() {
            p.device(person, &format!("dev{i}"));
        }
    }
    p.faults(Faults::default());
    p
}

fn board() -> Name {
    n("/alice/32=data/board")
}

/// A run of a member's device: its payload and the packet carrying its header and one signal.
struct HogRun {
    payload: String,
    packet: bytes::Bytes,
}

/// Run `r` of device `d`: a run key of its own, the header signed by the device's key, one
/// signal signed by the run key; it ends in 23 h.
fn hog_run(w: &World, d: Dev, r: u64) -> Result<HogRun, Failure> {
    let signer = w.signer(d)?;
    let mut seed = [0x3c; 32];
    seed[0] = d.0 as u8;
    seed[1] = r as u8;
    let key = signal::RunKey::from_seed(seed);
    let now = w.net().date(d).0;
    let start = now * 1000 + r;
    let device = w.net().spec(d).name();
    let content = signal::header_content(&key.public(), start, now + 23 * 3_600_000);
    let header = DataBuilder::new(signal::header_name(&device, &board(), &key.id()), &content)
        .sign_sync(signer.sig_type(), Some(signer.key_name()), |region| {
            signer.sign_sync(region).unwrap_or_default()
        });
    let payload = format!("hog:{device}:{r}");
    let packet = signal::body(
        &board(),
        &key.id(),
        Some(&header),
        &[signal::Signal {
            seq: start,
            address: bytes::Bytes::from_static(b"hog"),
            expires: now + 55_000,
            payload: payload.clone().into(),
        }],
        &key,
    );
    Ok(HogRun { payload, packet })
}

/// The runs of `devices`, `PER_KEY` each (the last device `short` fewer).
fn hog_runs(
    w: &World,
    devices: std::ops::Range<usize>,
    short: u64,
) -> Result<Vec<HogRun>, Failure> {
    let last = devices.end - 1;
    let mut out = Vec::new();
    for d in devices {
        let n = if d == last { PER_KEY - short } else { PER_KEY };
        for r in 0..n {
            out.push(hog_run(w, Dev(d), r)?);
        }
    }
    Ok(out)
}

/// Push each of `runs` into Carol's group, [`BATCH`] at a time, again while Carol has not
/// delivered its signal, for at most [`ROUNDS`] rounds. How many Carol delivered.
async fn open(w: &World, carol: &Peer, runs: &[HogRun]) -> Result<usize, Failure> {
    let face = w.net().app_face(ALICE);
    let target = group(&n("/carol"));
    let delivered = |r: &HogRun| carol.delivered(&r.payload) > 0;
    for _ in 0..ROUNDS {
        let pending: Vec<&HogRun> = runs.iter().filter(|r| !delivered(r)).collect();
        if pending.is_empty() {
            break;
        }
        for batch in pending.chunks(BATCH) {
            for r in batch {
                face.send(signal::push(&target, &r.packet))
                    .await
                    .map_err(|e| Failure::new(format!("the node took no packet: {e}")))?;
            }
            w.sleep(BATCH_PAUSE).await;
        }
    }
    w.sleep(BATCH_PAUSE).await;
    Ok(runs.iter().filter(|r| delivered(r)).count())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let everyone = ["/alice", "/bob", "/carol", "/dave", "/erin", "/frank"];
        w.gesture();
        w.at(ALICE)
            .share_folder(&board(), members(Rule::Log, &everyone, &[]).into())
            .await?;
        let carol = Peer::join(w, CAROL, &board()).await?;
        let started = tokio::time::Instant::now();

        let others: Vec<HogRun> = hog_runs(w, DAVES, 0)?
            .into_iter()
            .chain(hog_runs(w, ERINS, 0)?)
            .collect();
        let others_held = open(w, &carol, &others).await?;
        ensure!(
            others_held == others.len(),
            "carol delivered {others_held} of the {} runs of dave's and erin's devices: a scope \
             holding none of them refused some",
            others.len()
        );
        let bobs = hog_runs(w, BOBS, 0)?;
        let bob_held = open(w, &carol, &bobs).await?;
        w.measure("runs of bob's devices carol holds", bob_held as u64, "runs");

        // Alice's new run, while Bob's devices claim half of the slots.
        let before = stats(w, CAROL).await?;
        let alice = Peer::join(w, ALICE, &board()).await?;
        for i in 0..FRAMES {
            alice.send("cursor", &format!("alice:cursor:{i}")).await?;
            w.sleep(FRAME).await;
        }
        w.sleep(Duration::from_secs(1)).await;
        let now = stats(w, CAROL).await?;
        let alices = carol
            .all()
            .iter()
            .filter(|s| sender_of(s) == alice.me)
            .count();
        ensure!(
            alices > 0,
            "carol delivered none of alice's {FRAMES} signals (three header periods at 60 Hz) of \
             the run she opened while bob's devices claimed {} runs (carol holds {bob_held} of \
             them): her run was refused ({} more dropped as flood)",
            bobs.len(),
            now.flood - before.flood
        );

        // Frank's devices fill the scope: 64 runs with Alice's.
        let franks = hog_runs(w, FRANKS, 1)?;
        let frank_held = open(w, &carol, &franks).await?;
        let held = others_held + bob_held + 1 + frank_held;
        ensure!(
            held == RUNS_PER_SCOPE,
            "carol holds {held} runs of the board ({others_held} of dave's and erin's, \
             {bob_held} of bob's, alice's, {frank_held} of frank's), not the {RUNS_PER_SCOPE} \
             that fill it"
        );
        let probe = hog_run(w, Dev(FRANKS.end - 1), PER_KEY - 1)?;
        let face = w.net().app_face(ALICE);
        let target = group(&n("/carol"));
        let before = stats(w, CAROL).await?.flood;
        until_counted(
            w,
            CAROL,
            "carol refusing a run over the board's 64 as a flood",
            |s| s.flood > before,
            || {
                let packet = signal::push(&target, &probe.packet);
                let face = &face;
                async move {
                    face.send(packet)
                        .await
                        .map_err(|e| Failure::new(format!("the node took no packet: {e}")))
                }
            },
        )
        .await?;
        ensure!(
            carol.delivered(&probe.payload) == 0,
            "carol delivered a run over the board's {RUNS_PER_SCOPE}"
        );

        // Alice removes Bob; once Carol holds the record, Frank's run is pushed again.
        w.gesture();
        let rest: Vec<&str> = everyone.into_iter().filter(|p| *p != "/bob").collect();
        w.at(ALICE)
            .share_folder(&board(), members(Rule::Log, &rest, &[]).into())
            .await?;
        let bob_key = w.signer(Dev(BOBS.start))?.key_name().clone();
        let gate = w.gate(CAROL)?;
        w.until("carol holding the record removing bob", LIMIT, || async {
            Ok(!gate.signal_member(&board(), &bob_key))
        })
        .await?;
        w.measure(
            "from the first run to carol holding bob's removal",
            started.elapsed().as_millis() as u64,
            "ms",
        );
        let mut pushes = 0;
        while carol.delivered(&probe.payload) == 0 && pushes < 4 {
            face.send(signal::push(&target, &probe.packet))
                .await
                .map_err(|e| Failure::new(format!("the node took no packet: {e}")))?;
            pushes += 1;
            w.sleep(RESEND).await;
        }
        ensure!(
            carol.delivered(&probe.payload) > 0,
            "carol, holding the record removing bob, refused frank's new run {pushes} times: \
             the {bob_held} runs of bob's devices still hold their slots"
        );

        let hogs: std::collections::BTreeSet<&str> = others
            .iter()
            .chain(&bobs)
            .chain(&franks)
            .chain([&probe])
            .map(|r| r.payload.as_str())
            .collect();
        for s in carol.all() {
            let payload = String::from_utf8_lossy(&s.payload);
            ensure!(
                hogs.contains(payload.as_ref())
                    || (sender_of(&s) == alice.me && payload.starts_with("alice:cursor:")),
                "carol delivered {payload:?} from {}, which no device of the case sent",
                s.sender
            );
        }
        Ok(())
    })
}
