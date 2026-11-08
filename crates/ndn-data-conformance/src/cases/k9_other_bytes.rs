//! Keys over time 9 — other bytes at a name in the cut.
//!
//! Alice's phone key leaks with a copy of the phone's storage; the phone writes one more journal
//! entry, which her laptop holds, while the thief, offline, signs other bytes at that very name.
//! Alice revokes the key with a cut that keeps the entry. Then the thief comes online and a
//! forwarder on the way sees its copy first; Alice's tablet joins only afterwards. A cut that
//! accepted any bytes at a name in its ranges would let the thief's copy into that forwarder's
//! cache and into every reader that did not hold the honest entry yet (security review S5-03).
//! The fix (M3, slice 5): the root signs, with the cut, a manifest of the digest of every entry
//! it keeps, so readers and forwarders accept at a name in the cut exactly the bytes the root
//! held, and a late joiner fetches each entry by its full name.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k9",
    title: "Other bytes at a name in the cut",
    slice: 5,
    needs: &[Feature::Merge, Feature::Revocation, Feature::CutManifest],
    model: &["M3"],
    guards: "A cut binds the bytes it keeps: a device joining after the revocation reads the \
             honest version at every name in the cut, and the thief's other bytes at one of \
             those names are refused, also when a forwarder on the path saw the thief's copy \
             first.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const TABLET: Dev = Dev(2);
const THIEF: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    let phone = p.device("alice", "phone");
    p.device("alice", "laptop");
    p.device("alice", "tablet");
    p.thief(phone);
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let journal = n("/alice/32=data/journal");
        let (phone, laptop, tablet) = (w.at(PHONE), w.at(LAPTOP), w.at(TABLET));
        w.net().offline(TABLET);
        laptop
            .share(&journal, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the phone knows the shared journal", LIMIT, || {
            known(&*phone, &journal)
        })
        .await?;
        let monday = w
            .put(PHONE, &journal, content(&[("monday", "market")]), note(1))
            .await?;
        w.until("the laptop holds the phone's entry", LIMIT, || {
            has(&*laptop, &journal, &monday)
        })
        .await?;

        // The key leaks with a copy of the storage; the thief stays offline for now. The phone
        // writes on, and the thief signs other bytes at the name of that entry.
        stolen(w, THIEF, &journal, &monday).await?;
        w.net().offline(THIEF);
        let tuesday = w
            .put(PHONE, &journal, content(&[("tuesday", "dentist")]), note(1))
            .await?;
        w.until("the laptop holds the phone's later entry", LIMIT, || {
            has(&*laptop, &journal, &tuesday)
        })
        .await?;
        let forged = w
            .put(
                THIEF,
                &journal,
                content(&[("thief", "other bytes")]),
                note(1),
            )
            .await?;
        ensure!(
            forged == tuesday,
            "precondition: the thief signs at the name of the phone's entry ({tuesday:?}), got \
             {forged:?}"
        );

        // Alice revokes the key with a cut at what her laptop held, both entries; the
        // revocation reaches every honest node.
        let lost = loss_time(w, LAPTOP).await;
        w.net().offline(PHONE);
        w.revoke(LAPTOP, PHONE, lost).await?;
        w.gesture();

        // Caches on the way drop the phone's packets, as they do under load. The thief comes
        // online while Alice's devices are away, and a forwarder on the path (the hub) is asked
        // for the entry by name: only the thief's copy can answer.
        w.net().offline(LAPTOP);
        w.net().forget_cached(&w.net().spec(PHONE).name()).await;
        w.net().online(THIEF);
        let name = log_entry(w, PHONE, &journal, &tuesday);
        let _answered = w.net().ask_at_hub(&name).await;

        // The tablet joins while Alice's devices are still away, so what it reads of the phone
        // comes by the cut alone; then they come back, the phone serving its own log.
        w.net().online(TABLET);
        let _ = state_now(&*tablet, &journal).await?;
        w.sleep(SETTLE).await;
        w.net().online(LAPTOP);
        w.net().online(PHONE);
        w.converge(
            "the tablet, joining after the revocation, lists both entries in the cut",
            LIMIT,
            || async {
                let looked = look(&*tablet, &journal, &Frontier::new(), LOOK).await?;
                Ok(version(&looked, &monday).is_some() && version(&looked, &tuesday).is_some())
            },
        )
        .await?;
        w.sleep(SETTLE).await;

        for (who, layer) in [("tablet", &tablet), ("laptop", &laptop)] {
            let looked = look(&**layer, &journal, &Frontier::new(), LOOK).await?;
            ensure!(
                !versions(&looked).any(|v| field_of(v, "thief").is_some()),
                "the {who} accepts the thief's other bytes at {name}, a name in the cut"
            );
            let s = state(&**layer, &journal).await?;
            ensure!(
                field(&s.value, "thief").is_none(),
                "the {who}'s journal shows the thief's other bytes at {name}"
            );
            ensure!(
                field(&s.value, "monday") == Some("market")
                    && field(&s.value, "tuesday") == Some("dentist"),
                "the {who} lacks the honest bytes of an entry in the cut ({:?})",
                s.value
            );
        }
        Ok(())
    })
}
