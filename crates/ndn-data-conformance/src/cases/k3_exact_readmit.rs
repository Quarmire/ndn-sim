//! Keys over time 3 — re-admission is exact.
//!
//! Alice's phone writes two garden notes offline after its key leaked with a copy of its
//! storage; she revokes the key at what the laptop held. She re-admits the first offline note
//! only. The thief, meanwhile, writes a kitchen note at the very sequence number of the
//! re-admitted one. A re-admission by sequence number, or by a range, would bring back the
//! neighbouring note or the thief's — the fix (M3, slice 5) names the one version by its full name
//! and digest, per collection.

use std::time::Duration;

use bytes::Bytes;
use ndn_data::Name;

use super::kit::{
    LIMIT, LOOK, SETTLE, has, item_of, items, known, look, loss_time, n, octets, op_is, private,
    stolen, winning, wrote,
};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::SpaceEntry;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k3",
    title: "Re-admission is exact",
    slice: 5,
    needs: &[Feature::Merge, Feature::Revocation, Feature::Readmit],
    model: &["M3"],
    guards: "Re-admitting a version outside a cut brings back that version only: not the next \
             version of the same key, nor a version at the same sequence number in another \
             collection.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const THIEF: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    let phone = p.device("alice", "phone");
    p.device("alice", "laptop");
    p.thief(phone);
    p
}

/// The thief signs `bytes` at `path` of `space` as the phone's entry number `seq`. Its first
/// write into a sealed space races the grant of the epoch key, so it asks again until the
/// device signs, for as long as devices that reach each other get to agree; the last refusal
/// is the failure.
async fn forge(
    w: &World,
    space: &Name,
    path: &Name,
    bytes: Bytes,
    seq: u64,
) -> Result<SpaceEntry, Failure> {
    let start = tokio::time::Instant::now();
    loop {
        match w.sign_at(THIEF, space, path, bytes.clone(), seq).await {
            Ok(entry) => return Ok(entry),
            Err(e) if start.elapsed() >= LIMIT => return Err(e),
            Err(_) => w.sleep(Duration::from_secs(1)).await,
        }
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let garden = n("/alice/32=data/notes/garden");
        let kitchen = n("/alice/32=data/notes/kitchen");
        let path = n("/notes");
        let (phone, laptop) = (w.spaces(PHONE), w.spaces(LAPTOP));
        for space in [&garden, &kitchen] {
            laptop.create(space, private(&[], &[])).await?;
            w.retry_later(|| phone.open(space)).await?;
        }
        w.until("the phone knows both shared spaces", LIMIT, || async {
            Ok(known(&*phone, &garden).await? && known(&*phone, &kitchen).await?)
        })
        .await?;
        // The phone reads a note the owner wrote in each space before the key leaks: it then
        // holds the key of the epoch in force of both, and what the thief's copy of its storage
        // holds with it. A key not held by then never comes: the owner refuses the revoked key's
        // seal key, so no grant is made to it.
        let hello = n("/hello");
        let mut greetings = Vec::new();
        for space in [&garden, &kitchen] {
            greetings.push(
                w.space_put(LAPTOP, space, &hello, octets("welcome, phone"))
                    .await?,
            );
        }
        w.until("the phone reads the owner's notes", LIMIT, || async {
            Ok(has(&*phone, &garden, &greetings[0]).await?
                && has(&*phone, &kitchen, &greetings[1]).await?)
        })
        .await?;
        // The garden is sealed: the phone's first put races its epoch key's grant, and is put
        // again while refused RetryLater (spec §18.1).
        let seen = w
            .space_put(PHONE, &garden, &path, octets("planted beans"))
            .await?;
        w.until("the laptop holds the phone's note", LIMIT, || {
            has(&*laptop, &garden, &seen)
        })
        .await?;

        // The key leaks with the phone's storage; the phone, offline, writes two more notes.
        let lost = loss_time(w, LAPTOP).await;
        let thief = stolen(w, THIEF, &garden, &seen).await?;
        w.net().offline(PHONE);
        let wanted = phone.put(&garden, &path, octets("watered tuesday")).await?;
        let neighbour = phone
            .put(&garden, &path, octets("weeded wednesday"))
            .await?;
        ensure!(
            neighbour.seq == wanted.seq + 1,
            "precondition: the two offline notes are neighbours in the phone's log, got \
             {wanted:?} and {neighbour:?}"
        );
        w.revoke(LAPTOP, PHONE, lost).await?;
        w.gesture();
        w.retry_later(|| thief.open(&kitchen)).await?;
        w.until("the stolen device knows the shared kitchen", LIMIT, || {
            known(&*thief, &kitchen)
        })
        .await?;
        let forged = forge(
            w,
            &kitchen,
            &path,
            octets("same seq, other space"),
            wanted.seq,
        )
        .await?;
        ensure!(
            forged.writer == wanted.writer && forged.seq == wanted.seq,
            "precondition: the thief writes the kitchen at the re-admitted note's seq \
             ({wanted:?}), got {forged:?}"
        );
        w.net().online(PHONE);
        w.sleep(SETTLE).await;
        ensure!(
            !has(&*laptop, &garden, &wanted).await?,
            "precondition: the offline notes outside the cut should be refused before \
             re-admission"
        );

        w.gesture();
        w.readmit_entry(LAPTOP, PHONE, &wanted).await?;
        w.converge("the laptop holds the re-admitted note", LIMIT, || {
            has(&*laptop, &garden, &wanted)
        })
        .await?;
        w.sleep(SETTLE).await;

        let s = winning(&*laptop, &garden, &path, &[&wanted]).await?;
        ensure!(
            has(&*laptop, &garden, &seen).await? && has(&*laptop, &garden, &wanted).await?,
            "the garden lacks the note inside the cut or the re-admitted one"
        );
        ensure!(
            !has(&*laptop, &garden, &neighbour).await? && !wrote(&s, "weeded wednesday"),
            "re-admitting one note brought back its neighbour {neighbour:?}"
        );
        ensure!(
            op_is(&s, "watered tuesday"),
            "the garden reads {:?} once the note is re-admitted",
            String::from_utf8_lossy(&s.bytes)
        );
        let kitchen_seen = look(&*laptop, &kitchen, LOOK).await?;
        ensure!(
            item_of(&kitchen_seen, &forged.key()).is_none()
                && !items(&kitchen_seen).any(|i| wrote(i, "same seq, other space")),
            "re-admitting the garden note let the thief's kitchen version at its seq in"
        );
        ensure!(
            !has(&*laptop, &kitchen, &forged).await?,
            "the kitchen shows the thief's version at the re-admitted note's seq"
        );
        Ok(())
    })
}
