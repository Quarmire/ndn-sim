//! Open item 2 — a cut can drop honest work.
//!
//! Alice's phone writes a note entry offline, which nobody sees; meanwhile its key was copied
//! with its storage, and Alice revokes it at what the laptop had seen. The honest offline entry
//! falls outside the cut and is refused — the price of not trusting clocks. The thief signs with
//! the key too, at the very name of the honest entry. The fix (M3): the owner re-admits exact
//! versions — the namespace root signs the honest entry's name and digest into the cut, so it
//! returns and nothing else does, not even the thief's version at the same name.

use std::time::Duration;

use super::kit::{
    LIMIT, SETTLE, contains, has, holds_key, known, loss_time, n, octets, private, same_epoch,
    stolen, winning,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "o2",
    title: "Owner re-admits honest work",
    slice: 5,
    needs: &[Feature::Merge, Feature::Revocation, Feature::Readmit],
    model: &["M3"],
    guards: "Versions outside a revocation cut are refused until the owner signs specific ones \
             back in by name and digest; exactly those return, and the thief's versions stay \
             out, even one at the same name.",
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

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n("/alice/32=data/notes");
        let path = n("/garden");
        let (phone, laptop) = (w.spaces(PHONE), w.spaces(LAPTOP));
        laptop.create(&space, private(&[], &[])).await?;
        w.retry_later(|| phone.open(&space)).await?;
        w.until("the phone knows the shared notes", LIMIT, || {
            known(&*phone, &space)
        })
        .await?;
        // The phone's first put races the epoch key's grant (spec §17.1): put again on RetryLater.
        let seen = w
            .space_put(PHONE, &space, &path, octets("phone: planted beans"))
            .await?;
        w.until("the laptop holds the phone's entry", LIMIT, || {
            has(&*laptop, &space, &seen)
        })
        .await?;
        // The owner's devices each sign an epoch for the readers they see, and the one in force
        // may change under the phone while they learn of each other's: the phone goes offline
        // only once the two devices agree on it and the phone holds its key, as a phone that
        // was online would.
        w.until(
            "the phone holds the key of the epoch in force",
            LIMIT,
            || async {
                Ok(holds_key(&*phone, &space).await?
                    && same_epoch(&*phone, &*laptop, &space).await?)
            },
        )
        .await?;

        // The key leaks with a copy of the phone's storage; the phone goes offline and writes on.
        let lost = loss_time(w, LAPTOP).await;
        let thief = stolen(w, THIEF, &space, &seen).await?;
        w.until(
            "the stolen device holds the key of the epoch in force",
            LIMIT,
            || holds_key(&*thief, &space),
        )
        .await?;
        w.net().offline(PHONE);
        let honest = phone
            .put(&space, &path, octets("phone: watered, offline"))
            .await?;
        w.revoke(LAPTOP, PHONE, lost).await?;
        w.gesture();
        let forged = thief.put(&space, &path, octets("thief: forged")).await?;
        ensure!(
            forged.writer == honest.writer && forged.seq == honest.seq,
            "precondition: the thief writes at the honest entry's name ({honest:?}), got \
             {forged:?}"
        );
        // The phone turns up again and syncs its offline entry.
        w.net().online(PHONE);
        w.sleep(SETTLE).await;
        ensure!(
            !has(&*laptop, &space, &honest).await?,
            "precondition: the honest offline entry outside the cut should be refused before \
             re-admission"
        );

        // Alice signs the honest entry back in, as her phone shows it refused.
        w.gesture();
        w.readmit_entry(LAPTOP, PHONE, &honest).await?;
        w.converge("the laptop holds the re-admitted entry", LIMIT, || {
            has(&*laptop, &space, &honest)
        })
        .await?;
        w.sleep(SETTLE).await;

        ensure!(
            has(&*laptop, &space, &seen).await? && has(&*laptop, &space, &honest).await?,
            "the notes lack the entry inside the cut or the re-admitted one"
        );
        let got = winning(&*laptop, &space, &path, &[&honest]).await?;
        ensure!(
            !contains(&got.bytes, b"thief: forged"),
            "re-admitting one entry let the thief's version ({forged:?}) in"
        );
        ensure!(
            got.bytes == b"phone: watered, offline".as_slice(),
            "the re-admitted entry does not show: {:?}",
            String::from_utf8_lossy(&got.bytes)
        );
        ensure!(
            got.entry() == honest,
            "the register at {path} rests on {:?}, not on the entry the owner re-admitted \
             ({honest:?}); the thief's was {forged:?}",
            got.entry()
        );
        Ok(())
    })
}
