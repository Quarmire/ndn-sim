//! Channels, c34 — a member floods a sender with asks while a genuine receiver asks.
//!
//! Alice's laptop sends her pointer to the members of her space. Carol, a member, turns hostile:
//! many loops of hers ask Alice's laptop for its channel again and again, each ask signed afresh
//! and verified by the sender, far over the four a second (burst of eight) one key may ask. (A
//! stranger cannot make this half: a node signs an ask only as a person its space's record lists,
//! so the ask of a device that is none never leaves it, and the sender's own refusal of one is
//! c24. A stranger that is no node writes forged asks by hand; the sender's budgets that bound
//! them are per ingress face, and every device of this world reaches Alice over the one face of
//! the hub, so they could not be told apart here: ndn-heap's `setup_tests` test them over two
//! faces, channel.md 13.12 item 28.) After three seconds of it Bob asks for the channel.
//!
//! The guard: the sender answers Carol's key no more than its rate allows (a burst of eight, then
//! four a second); every ask over it is **refused and told so**: a `Busy` Nack (a `Congestion`
//! Nack, over the asker's rate) or a signed `Busy` refusal (a claim of no session over the
//! channel's one replay a second), so no ask of hers is left to time out (the Nack crosses the
//! hub's multicast strategy to her); Bob, whose key is not hers, is answered while the flood
//! still runs, and receives what Alice emits, as hers.
//!
//! The network is lossless here, as in c32 and c35: the property is what the sender does with the
//! asks it judges, and every one it judged must be told (none may end in a timeout). On the
//! faulty profile an ask or its answer is lost about one time in three over its two hops, and
//! Bob's own setup (ask, first Keep, `HELLO`, and again after each loss: channel.md 13.12 item
//! 27) takes a heavy-tailed time: a median of 15 s and a tail past the case's 120 s in about one
//! run of three hundred, with the flood or without it (the same distribution over 300 seeds
//! each). Whether the case passed would then be which packets of Bob's link a seed drops, and
//! the share of Carol's asks the network may lose a margin, not a property.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ndn_heap::Name;
use ndn_sim::Faults;

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
/// How many loops of hers run at once: each asks again as soon as it is told, so this many keep
/// her key asking far over the rate.
const LOOPS: usize = 48;
/// How long the flood runs before Bob asks.
const HEAD_START: Duration = Duration::from_secs(3);
/// The asks of one key the sender answers at once, and in each second after (channel.md 6).
const BURST: u64 = 8;
const PER_SECOND: u64 = 4;
/// What the sender's `Congestion` Nack of an ask over its rate says at the asker (heap's
/// `ChanError::Busy`).
const BUSY_NACK: &str = "cannot answer this ask now";
/// What a signed `Busy` refusal says (heap's `ChanError::Refused`, code `Busy`).
const BUSY_REFUSAL: &str = "refused the ask (Busy)";

fn plan() -> Plan {
    let mut p = Plan::new();
    p.faults(Faults::default());
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
    /// Refused by a `Busy` Nack.
    nacked: AtomicU64,
    /// Refused by a signed `Busy` refusal.
    refused: AtomicU64,
    /// Neither answered nor refused with a reason (an ask left to time out, or any other end).
    other: AtomicU64,
    /// The first of those, in its words.
    first_other: Mutex<Option<String>>,
}

/// One loop of Carol's: ask Alice's laptop again and again until `done`.
async fn flood(w: &World, carol: &Listener, alice: &Name, done: &AtomicBool, told: &Told) {
    while !done.load(Ordering::Relaxed) {
        let count = match carol.ch.ask(&space(), alice).await {
            Ok(_) => &told.answered,
            Err(e) if e.detail.contains(BUSY_NACK) => &told.nacked,
            Err(e) if e.detail.contains(BUSY_REFUSAL) => &told.refused,
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
        let (answered, nacked, refused, other) = (
            told.answered.load(Ordering::Relaxed),
            told.nacked.load(Ordering::Relaxed),
            told.refused.load(Ordering::Relaxed),
            told.other.load(Ordering::Relaxed),
        );
        let asked = answered + nacked + refused + other;
        let allowed = BURST + PER_SECOND * (flooded.as_secs() + 1);
        ensure!(
            asked > allowed,
            "Carol asked only {asked} times in {flooded:?} of virtual time: not over the \
             {allowed} her key may be answered, so the flood proved nothing"
        );
        ensure!(
            answered <= allowed,
            "Carol's key was answered {answered} times in {flooded:?} of virtual time ({nacked} \
             refused by a Busy Nack, {refused} by a signed Busy refusal, {other} otherwise): over \
             a burst of {BURST} and {PER_SECOND} a second, her key's rate is not enforced"
        );
        // No ask ends without a reason: every ask the sender judged was told, and on this
        // network nothing is lost on the way.
        ensure!(
            other == 0,
            "{other} of Carol's {asked} asks ended with no refusal that says why ({nacked} Busy \
             Nacks, {refused} signed Busy refusals, {answered} answered); the first: {:?}",
            told.first_other.lock().expect("the case's lock")
        );
        ensure!(
            nacked > 0,
            "none of Carol's {asked} asks was refused by a Busy Nack ({refused} by a signed Busy \
             refusal, {answered} answered): the asks over her key's rate were not Nacked"
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
        w.measure("Carol's asks refused by a Busy Nack", nacked, "asks");
        w.measure(
            "Carol's asks refused by a signed Busy refusal",
            refused,
            "asks",
        );
        w.measure("Carol's asks that ended without a reason", other, "asks");
        w.measure(
            "virtual time Bob waited for his answer during the flood",
            took.as_millis() as u64,
            "ms",
        );
        Ok(())
    })
}
