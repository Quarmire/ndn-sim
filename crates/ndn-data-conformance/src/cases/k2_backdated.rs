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

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
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
        let tuesday = w
            .put(PHONE, &journal, content(&[("tuesday", "dentist")]), note(1))
            .await?;
        w.until("the laptop holds the phone's entries", LIMIT, || async {
            agree(&[&*phone, &*laptop], &journal, &[&monday, &tuesday]).await
        })
        .await?;

        // Stolen; the thief's clock is a month slow. Alice revokes the key with a cut at what her
        // laptop held when she lost the phone; the revocation reaches every honest device (the
        // tablet holds it from the moment it joins).
        let lost = loss_time(w, LAPTOP).await;
        let thief = stolen(w, THIEF, &journal, &tuesday).await?;
        w.net().offline(PHONE);
        w.net().set_clock(THIEF, ClockSkew::behind(30 * DAY));
        w.revoke(LAPTOP, PHONE, lost).await?;
        w.gesture();
        let revoked_at = w.net().true_date();

        let forged = w
            .put(
                THIEF,
                &journal,
                content(&[("thief", "dated last month")]),
                note(1),
            )
            .await?;
        ensure!(
            forged.writer == monday.writer && forged.seq > tuesday.seq,
            "precondition: the thief signs as the phone past its entries ({tuesday:?}), got \
             {forged:?}"
        );
        let own = look(&*thief, &journal, &Frontier::new(), LOOK).await?;
        let dated = version(&own, &forged).map(|v| v.dated);
        ensure!(
            dated.is_some_and(|d| d < revoked_at),
            "precondition: the thief's version should claim a date before the revocation \
             ({revoked_at:?}), it claims {dated:?}"
        );

        w.net().online(TABLET);
        w.converge(
            "the tablet, joining after the revocation, reads the phone's entries in the cut",
            LIMIT,
            || async { agree(&[&*laptop, &*tablet], &journal, &[&monday, &tuesday]).await },
        )
        .await?;
        w.sleep(SETTLE).await;

        for (who, layer) in [("laptop", &laptop), ("tablet", &tablet)] {
            let seen = look(&**layer, &journal, &Frontier::new(), LOOK).await?;
            ensure!(
                version(&seen, &forged).is_none()
                    && !versions(&seen).any(|v| field_of(v, "thief").is_some()),
                "the {who} accepted the thief's backdated version"
            );
            let s = state(&**layer, &journal).await?;
            ensure!(
                s.at.contains(&monday) && s.at.contains(&tuesday),
                "the {who} lacks an entry of the phone's inside the cut"
            );
            ensure!(
                !s.at.contains(&forged) && field(&s.value, "thief").is_none(),
                "the {who}'s journal shows the thief's version"
            );
        }
        Ok(())
    })
}
