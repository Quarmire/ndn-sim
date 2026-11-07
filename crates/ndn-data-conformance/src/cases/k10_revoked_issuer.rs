//! Keys over time 10 — an issuer revoked later.
//!
//! Alice made a recovery kit when she set up her namespace. Her root is compromised, and the
//! attacker uses it to certify a key of its own under her namespace, an "intruder" device, which
//! writes into her journal; her laptop and tablet accept the entry, since it chains to her root.
//! Alice recovers with the kit: the new version revokes the old root, and her devices renew with
//! the new one. The tablet's data layer was down meanwhile and starts again on what it stored. A
//! re-check that looked only at the signing key would keep the intruder's entry on every device
//! that held it, and after every restart, while forwarders refuse it (security review S5-04).
//! The fix (M3, slice 5): on a version that newly revokes, and on restart, a device re-judges
//! what it holds with the walk a fresh fetch gets — the intruder's entry is withdrawn, issuer and
//! all — and an honest device's entry under the old root comes back once its key renewed.

use std::time::Duration;

use ndn_data::{Change, Refusal};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k10",
    title: "Issuer revoked later",
    slice: 5,
    needs: &[
        Feature::Merge,
        Feature::Revocation,
        Feature::Recovery,
        Feature::IssuerRecheck,
    ],
    model: &["M3"],
    guards: "When a later trust-context version revokes an issuer, a device re-judges what it \
             holds through it: an entry of a key only that issuer certified is withdrawn, \
             reported to watchers, on adoption and after a restart, while an honest device's \
             entry is accepted again once its key is certified by the new root.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const TABLET: Dev = Dev(1);
const INTRUDER: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "tablet");
    // A key the attacker certified with Alice's compromised root: the harness certifies every
    // planned device by its person's root, which is exactly what the attacker could do.
    p.device("alice", "intruder");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let journal = n("/alice/32=data/journal");
        let (laptop, tablet, intruder) = (w.at(LAPTOP), w.at(TABLET), w.at(INTRUDER));
        w.recovery_kit(LAPTOP).await?;
        w.gesture();
        laptop
            .share(&journal, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the intruder knows the shared journal", LIMIT, || {
            known(&*intruder, &journal)
        })
        .await?;
        let honest = laptop
            .put(
                &journal,
                content(&[("laptop", "before the recovery")]),
                note(1),
            )
            .await?;
        let planted = intruder
            .put(&journal, content(&[("intruder", "planted")]), note(1))
            .await?;
        w.until(
            "the laptop and the tablet hold the honest and the planted entry",
            LIMIT,
            || async {
                agree(
                    &[&*laptop, &*tablet, &*intruder],
                    &journal,
                    &[&honest, &planted],
                )
                .await
            },
        )
        .await?;

        // The tablet's data layer goes down; Alice recovers with the kit, the old root revoked,
        // and her laptop and tablet renew with the new root.
        w.stop(TABLET).await?;
        let mut laptops_feed = laptop.watch(&journal, &Frontier::new()).await?;
        w.recover(LAPTOP).await?;
        w.gesture();
        w.renew(LAPTOP).await?;
        w.renew(TABLET).await?;
        let tablet = w.restart(TABLET).await?;
        let mut seen = Vec::new();
        drain(&mut laptops_feed, SETTLE, &mut seen).await?;
        w.converge(
            "the honest entry is back at every honest device after the renewal",
            LIMIT,
            || async {
                Ok(has(&*laptop, &journal, &honest).await?
                    && has(&*tablet, &journal, &honest).await?)
            },
        )
        .await?;
        w.sleep(SETTLE).await;
        drain(&mut laptops_feed, LOOK, &mut seen).await?;

        // Both ways of re-judging, each reported on its own.
        let mut wrong = Vec::new();
        let restarted = state(&*tablet, &journal).await?;
        if restarted.at.contains(&planted) || field(&restarted.value, "intruder").is_some() {
            wrong.push(
                "after its restart the tablet still holds the entry of a key whose only issuer \
                 the recovery revoked"
                    .to_owned(),
            );
        }
        let adopted = state(&*laptop, &journal).await?;
        if adopted.at.contains(&planted) || field(&adopted.value, "intruder").is_some() {
            wrong.push(
                "on adopting the recovery the laptop kept the entry of a key whose only issuer \
                 it revokes"
                    .to_owned(),
            );
        } else if !seen.iter().any(|c| {
            matches!(c, Change::Withdrawn { id, why: Refusal::Untrusted { .. }, .. } if *id == planted)
        }) {
            wrong.push(
                "the laptop dropped the intruder's entry without reporting it withdrawn to its \
                 watcher because its chain is refused"
                    .to_owned(),
            );
        }
        ensure!(wrong.is_empty(), "{}", wrong.join("; "));

        for (who, s) in [("tablet", &restarted), ("laptop", &adopted)] {
            ensure!(
                s.at.contains(&honest) && field(&s.value, "laptop") == Some("before the recovery"),
                "the {who} lost the laptop's entry from before the recovery, though the laptop's \
                 key renewed with the new root ({:?})",
                s.value
            );
        }
        Ok(())
    })
}
