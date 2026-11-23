//! Slice 6, h10 — a device serves the versions it holds that another device wrote: Alice's
//! laptop carries her phone's rewrite to Bob while the phone is away.
//!
//! Alice shares her notes space with Bob, sealed to both of them. She rewrites a paragraph from
//! her phone while Bob is offline; her laptop takes the rewrite; then the phone goes offline
//! for good and every cache forgets what the phone served. Bob comes back. Before, a device
//! served only its own log (ndf's REPLY-12 §1): Bob heard in Alice's group that the phone had
//! moved, but nobody answered for it, and he never received the rewrite, though the laptop held it
//! and stayed online. The fix: any holder answers for a signed packet. When a writer does not
//! answer, a reader asks the other devices of the writer's namespace it hears, each under its own
//! name, for the writer's newest root, its summary nodes, its entries and their pieces, and each
//! answers with exactly the packet it holds — the phone's signed root and entry, the sealed
//! version as its ciphertext. Bob verifies them against the phone's key as from the phone itself,
//! and counts the rewrite: the register on Bob's device reads what Alice's phone wrote.

use std::time::Duration;

use super::kit::{LIMIT, has, known, n, octets, private, winning};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::EntryRead;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "h10",
    title: "A device serves the versions it holds that another device wrote: Alice's laptop \
            carries her phone's rewrite to Bob while the phone is away",
    slice: 6,
    needs: &[Feature::Merge, Feature::Seal, Feature::FolderMembers],
    model: &[],
    guards: "A version one device wrote reaches a reader from another device that holds it, the \
             writer offline and no cache holding it: the holder answers with the writer's own \
             signed root, summary nodes and entry (sealed, as ciphertext), the reader verifies \
             them against the writer's key and counts the version.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const BOB: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "laptop");
    p.device("bob", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n("/alice/32=data/notes");
        let paragraph = n("/p1");
        let (phone, laptop, bob) = (w.spaces(PHONE), w.spaces(LAPTOP), w.spaces(BOB));
        w.gesture();
        laptop.create(&space, private(&["/bob"], &["/bob"])).await?;
        // A device writes into a space once it holds the space's record: following the space, a
        // device fetches it.
        w.retry_later(|| phone.open(&space)).await?;
        w.until("Alice's phone holds the space's record", LIMIT, || {
            known(&*phone, &space)
        })
        .await?;
        let made = w
            .space_put(PHONE, &space, &paragraph, octets("draft"))
            .await?;
        w.retry_later(|| bob.open(&space)).await?;
        w.until("Bob holds the space's record", LIMIT, || {
            known(&*bob, &space)
        })
        .await?;
        w.until("every device holds the paragraph", LIMIT, || async {
            for spaces in [&phone, &laptop, &bob] {
                if !has(&**spaces, &space, &made).await? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await?;

        // Bob is away while Alice rewrites the paragraph from her phone; her laptop takes it.
        w.net().offline(BOB);
        let newer = w
            .space_put(PHONE, &space, &paragraph, octets("final text"))
            .await?;
        w.until("Alice's laptop holds the phone's rewrite", LIMIT, || {
            has(&*laptop, &space, &newer)
        })
        .await?;

        // The phone goes away for good, and no cache keeps what it served.
        w.net().offline(PHONE);
        let phone_name = w.net().spec(PHONE).name();
        w.net().forget_cached(&phone_name).await;
        w.net().online(BOB);
        w.until(
            "Bob holds the phone's rewrite, which only Alice's laptop can give him",
            LIMIT,
            || has(&*bob, &space, &newer),
        )
        .await?;
        let read = winning(&*bob, &space, &paragraph, &[&newer]).await?;
        ensure!(
            read.key() == newer.key() && read.bytes == "final text".as_bytes(),
            "Bob holds the phone's rewrite but his paragraph reads {:?} (entry {:?})",
            String::from_utf8_lossy(&read.bytes),
            read.key()
        );
        // What Bob holds is the phone's own entry, by its name, signed by the phone's key.
        match bob.entry(&space, &newer.name).await? {
            EntryRead::Read(held) => ensure!(
                held.key() == newer.key()
                    && held.writer == phone_name
                    && held.bytes == "final text".as_bytes(),
                "Bob answered the name of the phone's rewrite with {:?}, not the phone's entry",
                held.key()
            ),
            other => {
                return Err(Failure::new(format!(
                    "Bob answered the name of the phone's rewrite with {other:?}, not the entry"
                )));
            }
        }
        Ok(())
    })
}
