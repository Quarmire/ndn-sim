//! Slice 6, h10 — a device serves the versions it holds that another device wrote: Alice's
//! laptop carries her phone's rewrite to Bob while the phone is away.
//!
//! Alice shares her notes folder with Bob, sealed to both of them. She rewrites a paragraph from
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

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
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
        let folder = n("/alice/32=data/notes");
        let paragraph = n("/alice/32=data/notes/p1");
        w.gesture();
        w.at(LAPTOP)
            .share_folder(
                &folder,
                members(
                    register(),
                    &["/alice", "/bob"],
                    &[person("/alice"), person("/bob")],
                )
                .into(),
            )
            .await?;
        // A device writes into a collection under a folder once it holds the folder's record: its
        // first look follows the folder, as a host's first read does.
        w.until("Alice's phone holds the folder's record", LIMIT, || async {
            look(&*w.at(PHONE), &folder, &Frontier::new(), LOOK).await?;
            Ok(w.at(PHONE).members(&folder).await.is_ok())
        })
        .await?;
        let made = w
            .put_op(PHONE, &paragraph, octets("draft"), note(1))
            .await?;
        w.until("Bob holds the folder's record", LIMIT, || async {
            // Bob has not looked at the note yet: his first look follows the folder.
            look(&*w.at(BOB), &folder, &Frontier::new(), LOOK).await?;
            Ok(w.at(BOB).members(&folder).await.is_ok())
        })
        .await?;
        w.until("every device holds the paragraph", LIMIT, || async {
            for d in [PHONE, LAPTOP, BOB] {
                if !has(&*w.at(d), &paragraph, &made).await? {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await?;

        // Bob is away while Alice rewrites the paragraph from her phone; her laptop takes it.
        w.net().offline(BOB);
        let newer = w
            .put_op(PHONE, &paragraph, octets("final text"), note(1))
            .await?;
        w.until(
            "Alice's laptop holds the phone's rewrite",
            LIMIT,
            || async { has(&*w.at(LAPTOP), &paragraph, &newer).await },
        )
        .await?;

        // The phone goes away for good, and no cache keeps what it served.
        w.net().offline(PHONE);
        let phone = w.net().spec(PHONE).name();
        w.net().forget_cached(&phone).await;
        w.net().online(BOB);
        w.until(
            "Bob holds the phone's rewrite, which only Alice's laptop can give him",
            LIMIT,
            || async { has(&*w.at(BOB), &paragraph, &newer).await },
        )
        .await?;
        let s = winning(&*w.at(BOB), &paragraph, &[&newer]).await?;
        ensure!(
            s.at.contains(&newer) && written(&s) == b"final text",
            "Bob holds the phone's rewrite but his paragraph reads {:?}",
            String::from_utf8_lossy(written(&s))
        );
        // What Bob holds is the phone's own version, by its name, signed by the phone's key.
        let name = log_entry(w, PHONE, &paragraph, &newer);
        match w.at(BOB).get(&name).await?.got {
            Got::Version(v) => ensure!(
                v.id == newer,
                "Bob answered the name of the phone's rewrite with {:?}",
                v.id
            ),
            other => {
                return Err(Failure::new(format!(
                    "Bob answered the name of the phone's rewrite with {other:?}, not the version"
                )));
            }
        }
        Ok(())
    })
}
