//! Signals, e12 — a flood of run headers whose keys no one can fetch does not shut a member's
//! new run out.
//!
//! Alice's board is open: Alice and Bob write it, and it is not sealed, so anyone whose
//! Interests reach a member's sync group can push packets of it. Bob has written a version of
//! it, which Alice read. Carol, no member, knows only the board's name. From her node she pushes
//! into Alice's group, twenty times a second, packets of fresh runs whose headers are named as
//! Bob's phone's (`/bob/phone/32=signal/<board>/32=run/<id>`) and whose KeyLocators are keys of
//! Bob's phone that do not exist (`/bob/phone/KEY/<random>`); each packet is signed by its own
//! run key, so all a receiver can do with it is look for the key. Four seconds into the flood
//! Bob opens a new run and drags his cursor at 60 Hz for five seconds.
//!
//! The network is lossless here: a guard counts every junk packet. The guards: Alice delivers
//! Bob's signals from within the first three seconds of his run (three header periods: his
//! header is admitted though the flood goes on — spec §5, §8.1); every junk packet is refused
//! with a reason (counted), none delivered; and Bob's last cursor reaches Alice.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ndn_packet::encode::DataBuilder;
use ndn_sim::Faults;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e12",
    title: "A flood of unfetchable run headers does not shut out a member's run",
    slice: 7,
    needs: &[Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "Run headers whose signing keys cannot be fetched, pushed by anyone into a member's \
             group, never keep a member's new run from being admitted: its signals are \
             delivered within a few header periods while the flood goes on, and every junk \
             packet is refused with a reason.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

/// Carol's junk packets: one every 50 ms, twenty a second.
const JUNK_EVERY: Duration = Duration::from_millis(50);
/// How long the flood runs before Bob opens his run.
const HEAD_START: Duration = Duration::from_secs(4);
/// Bob's frames at 60 Hz: five seconds.
const FRAMES: u32 = 300;
/// The frames within which Alice must deliver one of Bob's signals: three header periods.
const ADMITTED_WITHIN: u32 = 180;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "tablet");
    p.faults(Faults::default());
    p
}

/// Open to anyone to read; Alice and Bob write it.
fn board() -> Name {
    n("/alice/32=data/board")
}

/// Carol's junk packet `i`: a fresh run whose header is named as Bob's phone's and whose
/// KeyLocator is a key of his phone that does not exist, with one signal signed by the run key.
fn junk(w: &World, signer: &dyn ndn_security::Signer, i: u64) -> bytes::Bytes {
    let mut seed = [0xf1; 32];
    seed[..8].copy_from_slice(&i.to_be_bytes());
    let key = signal::RunKey::from_seed(seed);
    let now = w.net().date(CAROL).0;
    let phone = w.net().spec(BOB).name();
    let locator = n(&format!("{phone}/KEY/junk{i:016x}"));
    let content = signal::header_content(&key.public(), now * 1000, now + 3_600_000);
    let header = DataBuilder::new(signal::header_name(&phone, &board(), &key.id()), &content)
        .sign_sync(signer.sig_type(), Some(&locator), |region| {
            signer.sign_sync(region).unwrap_or_default()
        });
    signal::body(
        &board(),
        &key.id(),
        Some(&header),
        &[signal::Signal {
            seq: now * 1000,
            address: bytes::Bytes::from_static(b"cursor"),
            expires: now + 10_000,
            payload: format!("junk:{i}").into(),
        }],
        &key,
    )
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.at(ALICE)
            .share_folder(
                &board(),
                members(Rule::Log, &["/alice", "/bob"], &[]).into(),
            )
            .await?;
        let first = w
            .put(BOB, &board().append("plan"), text("Bob's plan"), note(1))
            .await?;
        w.until("alice reading bob's version", LIMIT, || async {
            let changes = look(
                &*w.at(ALICE),
                &board().append("plan"),
                &Frontier::new(),
                LOOK,
            )
            .await?;
            Ok(versions(&changes).any(|v| v.id == first))
        })
        .await?;
        let alice = Peer::join(w, ALICE, &board()).await?;
        let before = stats(w, ALICE).await?;

        let face = w.net().app_face(CAROL);
        let signer = w.signer(CAROL)?;
        let target = group(&n("/alice"));
        let done = AtomicBool::new(false);
        let mut junked = 0u64;
        let flood = async {
            while !done.load(Ordering::Relaxed) {
                junked += 1;
                let packet = junk(w, &*signer, junked);
                face.send(signal::push(&target, &packet))
                    .await
                    .map_err(|e| Failure::new(format!("carol's node took no packet: {e}")))?;
                w.sleep(JUNK_EVERY).await;
            }
            Ok::<(), Failure>(())
        };
        let genuine = async {
            let result = async {
                w.sleep(HEAD_START).await;
                let bob = Peer::join(w, BOB, &board()).await?;
                for i in 0..FRAMES {
                    bob.send("cursor", &format!("bob:cursor:{i}")).await?;
                    w.sleep(FRAME).await;
                }
                Ok::<Peer, Failure>(bob)
            }
            .await;
            done.store(true, Ordering::Relaxed);
            result
        };
        let (flooded, bob) = futures::join!(flood, genuine);
        flooded?;
        let bob = bob?;

        let early = alice.all().into_iter().find(|s| {
            sender_of(s) == bob.me
                && std::str::from_utf8(&s.payload)
                    .ok()
                    .and_then(|p| p.strip_prefix("bob:cursor:"))
                    .and_then(|i| i.parse::<u32>().ok())
                    .is_some_and(|i| i < ADMITTED_WITHIN)
        });
        let now = stats(w, ALICE).await?;
        ensure!(
            early.is_some(),
            "alice delivered none of bob's first {ADMITTED_WITHIN} signals (three header \
             periods at 60 Hz) of the run he opened during carol's flood of {junked} junk \
             headers: his header was not admitted ({} more dropped as flood, {} more \
             unknown_run; {} of his {FRAMES} signals delivered in all)",
            now.flood - before.flood,
            now.unknown_run - before.unknown_run,
            alice
                .all()
                .iter()
                .filter(|s| sender_of(s) == bob.me)
                .count()
        );
        w.until(
            "alice refusing every junk packet with a reason",
            LIMIT,
            || async { Ok(dropped(&stats(w, ALICE).await?) - dropped(&before) >= junked) },
        )
        .await?;
        bob.send_final("cursor", "final:bob:cursor", &[&alice])
            .await?;
        w.sleep(SETTLE).await;
        for p in [&alice, &bob] {
            p.check(&[&alice, &bob])?;
            ensure!(
                p.delivered("junk:") == 0,
                "{} delivered a junk signal carol pushed",
                p.who
            );
        }
        w.measure("junk headers carol pushed", junked, "packets");
        Ok(())
    })
}
