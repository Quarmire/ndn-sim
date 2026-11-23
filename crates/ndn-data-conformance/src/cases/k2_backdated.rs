//! Keys over time 2 — a backdated version of a revoked key.
//!
//! Alice's phone is stolen after writing two journal entries the laptop holds; she revokes its
//! key. The thief writes on with the key, its clock set a month back so the version claims a date
//! before the revocation — before the phone's honest entries, even. Alice's tablet joins only
//! after the revocation and has seen nothing of the phone. A rule that trusted the date would
//! take the thief's version; one that dropped the whole key would lose the honest entries for
//! every reader that did not hold them yet. The fix (M3, slice 5): the revocation carries a cut —
//! the names of the key's versions the owner held — and every device judges by it.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::kit::{
    DAY, LIMIT, LOOK, SETTLE, agree, has, item_of, items, known, look, loss_time, n, octets, op_is,
    private, stolen, winning, wrote,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k2",
    title: "Backdated version of a revoked key",
    slice: 5,
    needs: &[Feature::Merge, Feature::Revocation],
    model: &["M3"],
    guards: "A revoked key's version outside its cut is refused at every honest device whatever \
             date it claims, a device that joins after the revocation included, while the key's \
             versions in the cut stay readable there.",
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
        let space = n("/alice/32=data/journal");
        let path = n("/entries");
        let (phone, laptop, tablet) = (w.spaces(PHONE), w.spaces(LAPTOP), w.spaces(TABLET));
        w.net().offline(TABLET);
        laptop.create(&space, private(&[], &[])).await?;
        w.retry_later(|| phone.open(&space)).await?;
        w.until("the phone knows the shared journal", LIMIT, || {
            known(&*phone, &space)
        })
        .await?;
        let monday = w
            .space_put(PHONE, &space, &path, octets("monday: market"))
            .await?;
        let tuesday = w
            .space_put(PHONE, &space, &path, octets("tuesday: dentist"))
            .await?;
        w.until("the laptop holds the phone's entries", LIMIT, || async {
            agree(&[&*phone, &*laptop], &space, &path, &[&monday, &tuesday]).await
        })
        .await?;

        // Stolen; the thief's clock is a month slow. Alice revokes the key with a cut at what her
        // laptop held when she lost the phone; the revocation reaches every honest device (the
        // tablet holds it from the moment it joins).
        let lost = loss_time(w, LAPTOP).await;
        stolen(w, THIEF, &space, &tuesday).await?;
        w.net().offline(PHONE);
        w.net().set_clock(THIEF, ClockSkew::behind(30 * DAY));
        w.revoke(LAPTOP, PHONE, lost).await?;
        w.gesture();
        let revoked_at = w.net().true_date();

        let forged = w
            .space_put(THIEF, &space, &path, octets("dated last month"))
            .await?;
        ensure!(
            forged.writer == monday.writer && forged.seq > tuesday.seq,
            "precondition: the thief signs as the phone past its entries ({tuesday:?}), got \
             {forged:?}"
        );
        // The thief signs by its own clock: the version claims a date before the revocation.
        let thief_date = w.net().date(THIEF);
        ensure!(
            thief_date < revoked_at,
            "precondition: the thief's clock should read a date before the revocation \
             ({revoked_at:?}), it reads {thief_date:?}"
        );

        w.net().online(TABLET);
        w.converge(
            "the tablet, joining after the revocation, reads the phone's entries in the cut",
            LIMIT,
            || async { agree(&[&*laptop, &*tablet], &space, &path, &[&monday, &tuesday]).await },
        )
        .await?;
        w.sleep(SETTLE).await;

        for (who, spaces) in [("laptop", &laptop), ("tablet", &tablet)] {
            let seen = look(&**spaces, &space, LOOK).await?;
            ensure!(
                item_of(&seen, &forged.key()).is_none()
                    && !items(&seen).any(|i| wrote(i, "dated last month")),
                "the {who} accepted the thief's backdated version"
            );
            let s = winning(&**spaces, &space, &path, &[&tuesday]).await?;
            ensure!(
                has(&**spaces, &space, &monday).await? && has(&**spaces, &space, &tuesday).await?,
                "the {who} lacks an entry of the phone's inside the cut"
            );
            ensure!(
                !has(&**spaces, &space, &forged).await? && !wrote(&s, "dated last month"),
                "the {who}'s journal shows the thief's version"
            );
            ensure!(
                op_is(&s, "tuesday: dentist"),
                "the {who}'s journal reads {:?} for the phone's entries in the cut",
                String::from_utf8_lossy(&s.bytes)
            );
        }
        Ok(())
    })
}
