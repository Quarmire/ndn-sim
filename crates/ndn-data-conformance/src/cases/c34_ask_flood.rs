//! Channels, c34 — a member floods a sender with asks while a genuine receiver asks.
//!
//! Alice's laptop sends her pointer to the members of her space. Carol, a member, turns hostile:
//! many loops of hers ask Alice's laptop for its channel again and again, each ask signed afresh
//! and verified by the sender, far over the four a second (burst of eight) one key may ask. (A
//! stranger cannot do this at all: a node signs an ask only as a person its space's record
//! lists, so the ask of a device that is none never leaves it; the sender's own refusal of one
//! is c24.) After three seconds of it Bob asks for the channel.
//!
//! The guard: the sender answers Carol's key no more than its rate allows (a burst of eight, then
//! four a second): the rest are refused or left unanswered, none answered; Bob, whose key is not
//! hers, is answered while the flood still runs, and receives what Alice emits, as hers.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ndn_heap::Name;

use super::channel_kit::{Listener, emit_until_seen, space};
use super::kit::{n, private};
use crate::case::{Case, CaseFuture};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c34",
    title: "A member's flood of asks does not keep a genuine receiver out",
    slice: 8,
    needs: &[Feature::Channels],
    model: &[],
    guards: "A member that asks a sender for its channel faster than one key may ask is answered \
             no more than a burst of eight and four a second, and a receiver of another key is \
             answered while the flood goes on and is given what the sender emits, attributed to \
             the sender.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

/// How long a loop of Carol's waits between two asks.
const BETWEEN: Duration = Duration::from_millis(1);
/// How many loops of hers run at once: an ask nobody answers holds its loop for 4 s, so this
/// many keep her key asking at a dozen a second or more.
const LOOPS: usize = 48;
/// How long the flood runs before Bob asks.
const HEAD_START: Duration = Duration::from_secs(3);
/// The asks of one key the sender answers at once, and in each second after (channel.md 6).
const BURST: u64 = 8;
const PER_SECOND: u64 = 4;
/// What the sender's refusal of an ask over its rate says (heap's `ChanError::Busy`).
const BUSY: &str = "cannot answer this ask now";

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "tablet");
    p
}

fn pointer() -> Name {
    n("/pointer")
}

/// What Carol's loops were told.
#[derive(Default)]
struct Told {
    answered: AtomicU64,
    busy: AtomicU64,
    other: AtomicU64,
    /// The first refusal that was neither an answer nor busy, in its words.
    first_other: Mutex<Option<String>>,
}

/// One loop of Carol's: ask Alice's laptop again and again until `done`.
async fn flood(w: &World, carol: &Listener, alice: &Name, done: &AtomicBool, told: &Told) {
    while !done.load(Ordering::Relaxed) {
        let count = match carol.ch.ask(&space(), alice).await {
            Ok(_) => &told.answered,
            Err(e) if e.detail.contains(BUSY) => &told.busy,
            Err(e) => {
                told.first_other
                    .lock()
                    .expect("the case's lock")
                    .get_or_insert(e.detail);
                &told.other
            }
        };
        count.fetch_add(1, Ordering::Relaxed);
        w.sleep(BETWEEN).await;
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.spaces(ALICE)
            .create(&space(), private(&[], &["/bob", "/carol"]))
            .await?;
        let sender = w.channels(ALICE).await?;
        let carol = Listener::prepare(w, CAROL, ChannelTrust::Prompt).await?;
        let mut bob = Listener::prepare(w, BOB, ChannelTrust::Prompt).await?;
        let alice = w.net().spec(ALICE).name();

        // Bob is answered and receives while the loops run; they stop after.
        let done = AtomicBool::new(false);
        let told = Told::default();
        let began = tokio::time::Instant::now();
        let genuine = async {
            // The flood is under way before Bob asks.
            w.sleep(HEAD_START).await;
            let start = tokio::time::Instant::now();
            let joined = async {
                bob.establish(w, ALICE).await?;
                let took = start.elapsed();
                emit_until_seen(w, &sender, &pointer(), "genuine", &mut [&mut bob]).await?;
                Ok::<_, crate::Failure>(took)
            }
            .await;
            done.store(true, Ordering::Relaxed);
            joined
        };
        let floods =
            futures::future::join_all((0..LOOPS).map(|_| flood(w, &carol, &alice, &done, &told)));
        let (_, took) = futures::join!(floods, genuine);
        let (took, flooded) = (took?, began.elapsed());
        let (answered, busy, other) = (
            told.answered.load(Ordering::Relaxed),
            told.busy.load(Ordering::Relaxed),
            told.other.load(Ordering::Relaxed),
        );
        let asked = answered + busy + other;
        let allowed = BURST + PER_SECOND * (flooded.as_secs() + 1);
        ensure!(
            asked > allowed,
            "Carol asked only {asked} times in {flooded:?} of virtual time: not over the \
             {allowed} her key may be answered, so the flood proved nothing"
        );
        ensure!(
            answered <= allowed,
            "Carol's key was answered {answered} times in {flooded:?} of virtual time ({busy} \
             refused as busy, {other} left unanswered, the first: {:?}): over a burst of {BURST} \
             and {PER_SECOND} a second, her key's rate is not enforced",
            told.first_other.lock().expect("the case's lock")
        );

        bob.pump();
        bob.alive("Bob")?;
        for e in &bob.events {
            if let ChannelEvent::Message { path, writer, .. } = e {
                ensure!(
                    *writer == alice,
                    "{path} reached Bob from {writer}, not from Alice's device"
                );
            }
        }
        w.measure("Carol's asks the sender answered", answered, "asks");
        w.measure("Carol's asks refused as busy", busy, "asks");
        w.measure("Carol's asks refused otherwise", other, "asks");
        w.measure(
            "virtual time Bob waited for his answer during the flood",
            took.as_millis() as u64,
            "ms",
        );
        Ok(())
    })
}
