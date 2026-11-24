//! Chain 4 — a cold device never asks for a seq inside a gap a held entry declares.
//!
//! Alice's ledger has Bob as a writer. Bob's phone dies twice, with no clean close, and each time
//! starts again on its disk: an unclean start resumes above everything the earlier run could have
//! signed (its reservation), so the first entry after each restart carries the signed statement
//! that Bob signed nothing between it and the entry before: two voids of about a reservation
//! each, in a log of seven entries, all of which Alice holds. Carol, who never held any of it,
//! joins afterwards while Bob's phone is away, hears the counter of Bob's last entry, and must
//! fetch what is there from Alice. Until she holds the entry that declares a void she cannot tell
//! it from a hole, and asks for the seqs in it as any hole, bounded by the misses; the asks
//! already on their way when she holds it end within a few Interest lifetimes, and after that the
//! seqs in it are never asked again.
//!
//! The guard: a cold device ends up holding every entry the writer signed, and the Interests it
//! sends for the seqs inside the two voids stay within the miss bound before it holds the entries
//! that declare them and stop once the asks then in flight have ended.

use std::cell::Cell;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_data::Name;
use ndn_packet::{Interest, NameComponent};

use super::kit::{LIMIT, RELAYED, SETTLE, has, known, n, octets, public, value_now};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{SpaceEntry, Spaces};
use crate::world::{Dev, Plan, Tap, World};

pub(super) const CASE: Case = Case {
    id: "q4",
    title: "A cold device asks for no seq inside a gap a held entry declares",
    slice: 9,
    needs: &[Feature::Crash, Feature::Chain],
    model: &[],
    guards: "A device that joins a space whose writer crashed twice fetches every entry the \
             writer signed and, once it holds the entry that states a gap and the asks then in \
             flight have ended, asks for no seq inside it; before that it asks for the seqs of a \
             void no more often than the miss bound allows.",
    budget: Duration::from_secs(2400),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

/// The most Interests a cold device sends for one seq of a void before it holds the entry that
/// declares the void: a miss waits 250 ms × 2^m, so a seq asked more often than a handful of
/// times while the walk reaches the declaring entry is asked faster than the backoff allows.
const MISS_BOUND: usize = 4;

/// How long asks launched before a declaring entry arrived get to end.
const IN_FLIGHT: Duration = Duration::from_secs(30);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "laptop");
    p
}

/// A keyword component `32=<word>`.
fn keyword(c: &NameComponent, word: &[u8]) -> bool {
    c.typ == 32 && c.value.as_ref() == word
}

/// `(device, space, seq)` of the entry a name `<device>/32=log/<space>/seq=<n>` names.
fn entry_of(name: &Name) -> Option<(Name, Name, u64)> {
    let comps = name.components();
    let at = comps.iter().position(|c| keyword(c, b"log"))?;
    let (last, space) = comps[at + 1..].split_last()?;
    Some((
        Name::from_components(comps[..at].to_vec()),
        Name::from_components(space.to_vec()),
        last.as_sequence_num()?,
    ))
}

/// The entry an Interest asks for, from its writer by its own name or from a holder through
/// `<holder>/32=held/<name TLV>`.
fn asked(wire: &Bytes) -> Option<(Name, Name, u64)> {
    let interest = Interest::decode(wire.clone()).ok()?;
    if let Some(entry) = entry_of(&interest.name) {
        return Some(entry);
    }
    let comps = interest.name.components();
    let at = comps.iter().position(|c| keyword(c, b"held"))?;
    let [inner] = &comps[at + 1..] else {
        return None;
    };
    entry_of(&Name::decode_from_tlv(inner.value.clone()).ok()?)
}

/// How many Interests the taps saw for the seqs strictly between `from` and `to` of `writer`'s
/// log in `space`.
fn asks_inside(taps: &[&Tap], writer: &Name, space: &Name, from: u64, to: u64) -> usize {
    taps.iter()
        .flat_map(|t| t.interests())
        .filter_map(|wire| asked(&wire))
        .filter(|(device, s, seq)| device == writer && s == space && *seq > from && *seq < to)
        .count()
}

/// Bob writes the next entry: path `/e<k>`.
async fn write(w: &World, ledger: &Name, k: usize) -> Result<(SpaceEntry, Name, String), Failure> {
    let (path, text) = (n(&format!("/e{k}")), format!("entry {k}"));
    let entry = w.space_put(BOB, ledger, &path, octets(&text)).await?;
    Ok((entry, path, text))
}

/// Bob's phone dies and starts again on its disk, which holds what it held, or less: the entries
/// Alice holds come back from her until it holds `last`.
async fn die_and_restart(
    w: &World,
    ledger: &Name,
    last: &SpaceEntry,
) -> Result<Arc<dyn Spaces>, Failure> {
    let bob = w.crash(BOB).await?;
    bob.open(ledger).await?;
    w.until(
        "Bob's phone, started again, holds the last entry it signed",
        LIMIT,
        || has(&*bob, ledger, last),
    )
    .await?;
    Ok(bob)
}

/// Whether `spaces` has applied every entry of `log`: a reader that is to serve what Bob lost, or
/// all of it once Bob is away, holds the whole log, not only its last entry.
async fn holds_all(
    spaces: &dyn Spaces,
    ledger: &Name,
    log: &[(SpaceEntry, Name, String)],
) -> Result<bool, Failure> {
    for (entry, _, _) in log {
        if !has(spaces, ledger, entry).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let ledger = n("/alice/32=data/ledger");
        let (alice, carol) = (w.spaces(ALICE), w.spaces(CAROL));
        w.net().offline(CAROL);

        alice.create(&ledger, public(&["/bob"])).await?;
        let bob = w.spaces(BOB);
        bob.open(&ledger).await?;
        w.until("Bob holds the record admitting him", LIMIT, || {
            known(&*bob, &ledger)
        })
        .await?;

        // Seven entries in three runs of Bob's phone, Alice holding each before the phone dies.
        let mut log: Vec<(SpaceEntry, Name, String)> = Vec::new();
        for k in 1..=3 {
            log.push(write(w, &ledger, k).await?);
        }
        w.until("Alice holds Bob's first three entries", LIMIT, || {
            holds_all(&*alice, &ledger, &log)
        })
        .await?;
        let held = log[2].0.clone();
        die_and_restart(w, &ledger, &held).await?;
        for k in 4..=5 {
            log.push(write(w, &ledger, k).await?);
        }
        w.until("Alice holds Bob's first five entries", LIMIT, || {
            holds_all(&*alice, &ledger, &log)
        })
        .await?;
        let held = log[4].0.clone();
        die_and_restart(w, &ledger, &held).await?;
        for k in 6..=7 {
            log.push(write(w, &ledger, k).await?);
        }
        w.until("Alice holds every entry Bob signed", LIMIT, || {
            holds_all(&*alice, &ledger, &log)
        })
        .await?;

        // The voids: what lies between the last entry before each restart and the first after.
        let seq = |k: usize| log[k - 1].0.seq;
        let voids = [(seq(3), seq(4)), (seq(5), seq(6))];
        for (i, (from, to)) in voids.iter().enumerate() {
            ensure!(
                to > &(from + 1),
                "precondition: Bob's restart {} left a gap in his log: his entry after it is seq \
                 {to}, the one before is seq {from}",
                i + 1
            );
        }

        // Carol, who never held any of it, joins; the Interests for Bob's log, asked of him or
        // of Alice for him, are counted from now. The moment she holds the entry that declares a
        // void, the Interests she has sent for seqs inside it are counted.
        let (bob_name, alice_name) = (w.net().spec(BOB).name(), w.net().spec(ALICE).name());
        let (by_writer, by_holder) = (w.net().tap(&bob_name).await, w.net().tap(&alice_name).await);
        let taps = [&by_writer, &by_holder];
        let declaring = [&log[3].0, &log[5].0];
        let at_declared: [Cell<Option<usize>>; 2] = [Cell::new(None), Cell::new(None)];
        // Bob's phone is away while she catches up, so the Interests counted are hers alone
        // (his own node would ask Alice for the seqs it lost).
        w.net().offline(BOB);
        w.net().online(CAROL);
        carol.open(&ledger).await?;
        w.converge("Carol holds every entry Bob signed", RELAYED, || async {
            for (i, entry) in declaring.iter().enumerate() {
                if at_declared[i].get().is_none() && has(&*carol, &ledger, entry).await? {
                    let (from, to) = voids[i];
                    at_declared[i].set(Some(asks_inside(&taps, &bob_name, &ledger, from, to)));
                }
            }
            for (entry, path, text) in &log {
                if !has(&*carol, &ledger, entry).await?
                    || value_now(&*carol, &ledger, path).await?.as_deref() != Some(text.as_bytes())
                {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await?;

        // Before she held the entries that declare the voids she asked as for any holes, within
        // the miss bound; afterwards she asks for nothing inside them.
        let at_declared: Vec<usize> = at_declared
            .iter()
            .map(|c| {
                c.get()
                    .expect("the entries that declare the voids are held")
            })
            .collect();
        w.measure(
            "Interests Carol sent for seqs inside the two voids before the entries that declare \
             them arrived",
            at_declared.iter().sum::<usize>() as u64,
            "asks",
        );
        for (i, (from, to)) in voids.iter().enumerate() {
            let width = (to - from - 1) as usize;
            ensure!(
                at_declared[i] <= MISS_BOUND * width,
                "Carol sent {} Interests for the {width} seqs of Bob's void {} (between seq \
                 {from} and seq {to}) before she held the entry that declares it: more than \
                 {MISS_BOUND} per seq",
                at_declared[i],
                i + 1
            );
        }
        // Asks launched before she held the declaring entry may still be retrying their
        // Interests; they end within a few Interest lifetimes. What is asked after that is asked
        // because the log still wants it.
        w.sleep(IN_FLIGHT).await;
        let quiet: Vec<usize> = voids
            .iter()
            .map(|(from, to)| asks_inside(&taps, &bob_name, &ledger, *from, *to))
            .collect();
        w.measure(
            "Interests for seqs inside the two voids from asks in flight when the declaring \
             entries arrived",
            quiet
                .iter()
                .sum::<usize>()
                .saturating_sub(at_declared.iter().sum::<usize>()) as u64,
            "asks",
        );
        w.sleep(SETTLE).await;
        for (i, (from, to)) in voids.iter().enumerate() {
            let now = asks_inside(&taps, &bob_name, &ledger, *from, *to);
            ensure!(
                now == quiet[i],
                "Carol asks for seqs inside Bob's void {} (between seq {from} and seq {to}) long \
                 after she holds the entry that declares it: {} Interests more",
                i + 1,
                now.saturating_sub(quiet[i])
            );
        }
        Ok(())
    })
}
