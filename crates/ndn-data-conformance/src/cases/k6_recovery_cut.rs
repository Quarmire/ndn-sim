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

use super::kit::{
    LIMIT, LOOK, SETTLE, agree, has, items, known, look, loss_time, n, octets, op_is, private,
    stolen, winning, wrote,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
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
        let space = n("/alice/32=data/journal");
        let path = n("/entries");
        let (phone, laptop, tablet) = (w.spaces(PHONE), w.spaces(LAPTOP), w.spaces(TABLET));
        w.net().offline(TABLET);
        w.recovery_kit(LAPTOP).await?;
        w.gesture();
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

        let lost = loss_time(w, LAPTOP).await;
        stolen(w, THIEF, &space, &tuesday).await?;
        w.net().offline(PHONE);
        w.revoke(LAPTOP, PHONE, lost).await?;
        w.gesture();
        let before = w
            .space_put(THIEF, &space, &path, octets("thief: before the recovery"))
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
        let after = w
            .space_put(THIEF, &space, &path, octets("thief: after the recovery"))
            .await?;
        let own = w
            .space_put(LAPTOP, &space, &path, octets("recovered"))
            .await?;

        w.net().online(TABLET);
        w.converge(
            "the tablet, joining after the recovery, reads the cut and the laptop's entry",
            LIMIT,
            || async {
                agree(
                    &[&*laptop, &*tablet],
                    &space,
                    &path,
                    &[&monday, &tuesday, &own],
                )
                .await
            },
        )
        .await?;
        w.sleep(SETTLE).await;

        for (who, spaces) in [("laptop", &laptop), ("tablet", &tablet)] {
            let seen = look(&**spaces, &space, LOOK).await?;
            ensure!(
                !items(&seen).any(|i| wrote(i, "the recovery")),
                "the {who} accepted a version the thief signed with the revoked key"
            );
            let s = winning(&**spaces, &space, &path, &[&own]).await?;
            ensure!(
                has(&**spaces, &space, &monday).await? && has(&**spaces, &space, &tuesday).await?,
                "after the recovery the {who} lacks an entry of the phone's inside the cut"
            );
            ensure!(
                has(&**spaces, &space, &own).await? && op_is(&s, "recovered"),
                "after the recovery the {who} lacks the laptop's entry signed under its renewed \
                 certificate"
            );
            ensure!(
                !has(&**spaces, &space, &before).await? && !has(&**spaces, &space, &after).await?,
                "after the recovery the {who}'s journal includes a thief's version ({before:?} \
                 or {after:?})"
            );
        }
        Ok(())
    })
}
