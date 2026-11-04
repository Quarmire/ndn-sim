//! Keys over time 6 — recovery after a compromise carries the cut.
//!
//! Alice made a recovery kit when she set up her namespace. Her phone is stolen and she revokes
//! its key with a cut; the thief writes on with it. Then her namespace root is compromised too,
//! and she recovers with the kit: the kit signs a version with a new root (the old one revoked),
//! the new root signs the next, and her devices renew their certificates with it. Alice's tablet
//! joins only after all that. A recovery that rebuilt the trust context from scratch, or dropped
//! the old root's certificates without a care, would either let the thief back in or lose the
//! phone's honest entries. The fix (M3, slice 5): recovery carries every revocation and cut, and
//! certifies each key revoked with a cut again under the new root.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k6",
    title: "Recovery after compromise carries the cut",
    slice: 5,
    needs: &[Feature::Merge, Feature::Revocation, Feature::Recovery],
    model: &["M3"],
    guards: "After the namespace recovers from a compromised root, a revoked key's cut still \
             holds at every honest device, one joining after the recovery included: the key's \
             versions in the cut stay readable, none outside it is accepted, and the honest \
             devices' data verifies under their renewed certificates.",
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
        w.recovery_kit(LAPTOP).await?;
        w.gesture();
        laptop
            .share(&journal, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the phone knows the shared journal", LIMIT, || {
            known(&*phone, &journal)
        })
        .await?;
        let monday = phone
            .put(&journal, content(&[("monday", "market")]), note(1))
            .await?;
        let tuesday = phone
            .put(&journal, content(&[("tuesday", "dentist")]), note(1))
            .await?;
        w.until("the laptop holds the phone's entries", LIMIT, || async {
            agree(&[&*phone, &*laptop], &journal, &[&monday, &tuesday]).await
        })
        .await?;

        let thief = stolen(w, THIEF, &journal, &tuesday).await?;
        w.net().offline(PHONE);
        w.revoke(LAPTOP, PHONE).await?;
        w.gesture();
        let before = thief
            .put(
                &journal,
                content(&[("thief", "before the recovery")]),
                note(1),
            )
            .await?;
        ensure!(
            before.writer == monday.writer && before.seq > tuesday.seq,
            "precondition: the thief signs as the phone past its entries ({tuesday:?}), got \
             {before:?}"
        );

        // The root is compromised: Alice recovers with the kit, and her devices renew.
        w.recover(LAPTOP).await?;
        w.gesture();
        w.renew(LAPTOP).await?;
        w.renew(TABLET).await?;
        let after = thief
            .put(
                &journal,
                content(&[("thief", "after the recovery")]),
                note(1),
            )
            .await?;
        let own = laptop
            .put(&journal, content(&[("laptop", "recovered")]), note(1))
            .await?;

        w.net().online(TABLET);
        w.converge(
            "the tablet, joining after the recovery, reads the cut and the laptop's entry",
            LIMIT,
            || async { agree(&[&*laptop, &*tablet], &journal, &[&monday, &tuesday, &own]).await },
        )
        .await?;
        w.sleep(SETTLE).await;

        for (who, layer) in [("laptop", &laptop), ("tablet", &tablet)] {
            let seen = look(&**layer, &journal, &Frontier::new(), LOOK).await?;
            ensure!(
                !versions(&seen).any(|v| field_of(v, "thief").is_some()),
                "the {who} accepted a version the thief signed with the revoked key"
            );
            let s = state(&**layer, &journal).await?;
            ensure!(
                s.at.contains(&monday) && s.at.contains(&tuesday),
                "after the recovery the {who} lacks an entry of the phone's inside the cut"
            );
            ensure!(
                s.at.contains(&own) && field(&s.value, "laptop") == Some("recovered"),
                "after the recovery the {who} lacks the laptop's entry signed under its renewed \
                 certificate"
            );
            ensure!(
                !s.at.contains(&before) && !s.at.contains(&after),
                "after the recovery the {who}'s journal includes a thief's version ({before:?} \
                 or {after:?})"
            );
        }
        Ok(())
    })
}
