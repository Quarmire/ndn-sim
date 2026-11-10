//! Round 4, p2 — a put never seals under a folder's record a device not walked may narrow.
//!
//! Alice's phone shares her `vault` folder to Alice and Bob, and holds that record. The phone
//! reaches nothing of her laptop's summary — it still hears the laptop in the sync group — while
//! the laptop follows the folder and shares `vault/secret`, a collection of it, to Alice alone. A
//! put into `vault/secret` that the phone made right then inherited the folder's record, the one
//! it held: it sealed the version in the folder's epoch, which Bob holds the key of, and Bob could
//! read what Alice meant for no one else. The fix: a collection that has no record of its own
//! here, under a folder's, is written only once every device of the namespace this device knows
//! has been walked toward the folder — a record of the collection's own may narrow the folder's —
//! so the put answers `NotReady` at once, naming the device, and goes through once the phone
//! reaches the laptop, written under the collection's own record, which Bob is not in.

use std::time::Duration;

use ndn_data::NextStep;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "p2",
    title: "A put never seals under a folder's record a device not walked may narrow",
    slice: 6,
    needs: &[Feature::Log, Feature::Seal, Feature::FolderMembers],
    model: &["M8"],
    guards: "A put into a collection that has no members record of its own here, under a folder \
             whose record the device holds, while a device of the namespace was not walked toward \
             the folder, answers NotReady at once, naming the device, and signs and seals \
             nothing: that device may hold a record of the collection that narrows who reads it. \
             Once the device is reached, the put goes through under the collection's own record, \
             and a person the folder admits and that record does not cannot read it.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const BOB: Dev = Dev(2);

/// What a refusal that is only a look at the clock costs in virtual time: nothing a device waits
/// on, far under the first-look time (4 s).
const LOCAL: Duration = Duration::from_millis(500);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("bob", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let vault = n("/alice/32=data/vault");
        let secret = vault.clone().append("secret");
        let (laptop, phone, bob) = (w.at(LAPTOP), w.at(PHONE), w.at(BOB));

        // The phone reaches nothing of the laptop's summary, though the laptop reaches it.
        let away = w.net().cut_off(PHONE, &n("/alice/laptop")).await;

        // The folder: Alice and Bob write and read it. The phone holds its record.
        phone
            .share_folder(
                &vault,
                members(
                    Rule::Log,
                    &["/alice", "/bob"],
                    &[person("/alice"), person("/bob")],
                )
                .into(),
            )
            .await?;
        // The laptop follows the folder and takes its record, then narrows `secret` to Alice
        // alone.
        let _follow = laptop.watch(&vault, &Frontier::new()).await?;
        w.until("the laptop holds the folder's record", LIMIT, || async {
            Ok(laptop
                .members(&vault)
                .await
                .is_ok_and(|s| s.readers.contains(&person("/bob"))))
        })
        .await?;
        w.again(|| {
            laptop.share(
                &secret,
                members(Rule::Log, &["/alice"], &[person("/alice")]),
            )
        })
        .await?;
        // The phone hears the laptop's head move in the sync group, and cannot walk it.
        w.sleep(SETTLE).await;

        // The put the phone makes now must not seal under the folder's record.
        let start = tokio::time::Instant::now();
        let refused = phone.put(&secret, text("for Alice only"), note(1)).await;
        let took = start.elapsed();
        w.measure(
            "put, a collection the folder's record would govern while the laptop is not walked: \
             virtual ms",
            took.as_millis() as u64,
            "ms",
        );
        match refused {
            Err(e @ DataError::NotReady { .. }) => {
                ensure!(
                    e.next() == NextStep::RetryLater,
                    "the refusal says {:?}, not retry later: {e}",
                    e.next()
                );
                ensure!(
                    e.to_string().contains("/alice/laptop"),
                    "the refusal does not name the device whose walk it waits for: {e}"
                );
                ensure!(
                    took <= LOCAL,
                    "the refusal took {took:?}, over {LOCAL:?}: a put waited on another device"
                );
            }
            other => {
                return Err(Failure::new(format!(
                    "a put into a collection the folder's record governs here, while the \
                     laptop, which may narrow it, was not walked, answered {other:?}, not \
                     NotReady: it was written under the folder's record, whose readers include \
                     Bob"
                )));
            }
        }

        // The phone reaches the laptop again; the same put goes through, under the record the
        // laptop signed over `secret`.
        drop(away);
        let id = w
            .again(|| phone.put(&secret, text("for Alice only"), note(1)))
            .await?;
        let record = phone.members(&secret).await?;
        ensure!(
            !record.readers.contains(&person("/bob")),
            "the collection was written under {record:?}, which admits Bob: the narrower record \
             the laptop holds over it was not the one in force"
        );
        let v = listed(&*phone, &secret, &id).await?;

        // Bob, in the folder's audience and not in `secret`'s, cannot read it.
        match w.again(|| bob.get(&v.name)).await {
            Err(DataError::Sealed { .. }) => {}
            Ok(answer) => {
                return Err(Failure::new(format!(
                    "Bob read an entry of a collection whose own record leaves him out: {:?}",
                    answer.got
                )));
            }
            Err(e) => {
                return Err(Failure::new(format!(
                    "Bob's read of the narrowed collection's entry answered {e}, not sealed"
                )));
            }
        }
        Ok(())
    })
}
