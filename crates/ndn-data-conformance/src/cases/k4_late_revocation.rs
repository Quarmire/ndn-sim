//! Keys over time 4 — a revocation that arrives late.
//!
//! Alice revokes her stolen phone's key on her laptop, but the new trust-context version has not
//! reached the rest of the network yet. The thief writes on with the key, and Alice's tablet —
//! which also holds the phone's earlier entry — accepts the thief's version, not knowing better.
//! "Stale, never wrong" then needs the rule o1 gave removal cuts, for revocation (M3, slice 5):
//! when the revocation reaches a device, it re-checks what it accepted from the key against the
//! cut, withdraws what falls outside, and keeps what falls inside.

use std::time::Duration;

use ndn_data::Change;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k4",
    title: "Late revocation withdraws",
    slice: 5,
    needs: &[
        Feature::Merge,
        Feature::Revocation,
        Feature::RevocationRecheck,
    ],
    model: &["M3"],
    guards: "When a revocation reaches a device, it re-checks what it accepted from the key: a \
             version outside the cut is withdrawn from its state and reported withdrawn to its \
             watchers, and the key's versions inside the cut stay.",
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
        laptop
            .share(&journal, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the phone knows the shared journal", LIMIT, || {
            known(&*phone, &journal)
        })
        .await?;
        let inside = phone
            .put(
                &journal,
                content(&[("phone", "last honest entry")]),
                note(1),
            )
            .await?;
        w.until("every device holds the phone's entry", LIMIT, || async {
            agree(&[&*phone, &*laptop, &*tablet], &journal, &[&inside]).await
        })
        .await?;

        // Stolen; Alice revokes on her laptop, and the new version stays there for now.
        let thief = stolen(w, THIEF, &journal, &inside).await?;
        w.net().offline(PHONE);
        w.revoke_at(LAPTOP, PHONE).await?;
        w.gesture();

        let mut tablets_feed = tablet.watch(&journal, &Frontier::new()).await?;
        let outside = thief
            .put(
                &journal,
                content(&[("thief", "written after the revocation")]),
                note(1),
            )
            .await?;
        ensure!(
            outside.writer == inside.writer && outside.seq > inside.seq,
            "precondition: the thief signs as the phone past its entry ({inside:?}), got \
             {outside:?}"
        );
        w.until(
            "the tablet accepts the thief's version, not knowing the revocation",
            LIMIT,
            || has(&*tablet, &journal, &outside),
        )
        .await?;

        // The revocation reaches the network and the tablet.
        w.spread_all().await?;
        let mut seen = Vec::new();
        let took = drain_until(
            &mut tablets_feed,
            &mut seen,
            "the tablet withdraws the thief's version",
            LIMIT,
            |changes| {
                changes
                    .iter()
                    .any(|c| matches!(c, Change::Withdrawn { id, .. } if *id == outside))
            },
        )
        .await?;
        w.converged(took);
        w.sleep(SETTLE).await;

        let s = state(&*tablet, &journal).await?;
        ensure!(
            !s.at.contains(&outside) && field(&s.value, "thief").is_none(),
            "the tablet's journal still includes the thief's version the cut refuses"
        );
        ensure!(
            s.at.contains(&inside) && field(&s.value, "phone") == Some("last honest entry"),
            "the re-check also dropped the phone's entry inside the cut"
        );
        ensure!(
            !has(&*laptop, &journal, &outside).await?,
            "the laptop, which revoked the key, accepted the thief's version"
        );
        Ok(())
    })
}
