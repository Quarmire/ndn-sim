//! Keys over time 4 — a revocation that arrives late.
//!
//! Alice revokes her stolen phone's key on her laptop, but the new trust-context version has not
//! reached the rest of the network yet. The thief writes on with the key, and Alice's tablet —
//! which also holds the phone's earlier entry — accepts the thief's version, not knowing better.
//! "Stale, never wrong" then needs the rule o1 gave removal cuts, for revocation (M3, slice 5):
//! when the revocation reaches a device, it re-checks what it accepted from the key against the
//! cut, withdraws what falls outside, and keeps what falls inside.

use std::time::Duration;

use super::kit::{
    LIMIT, SETTLE, agree, drain_until, has, known, loss_time, n, octets, op_is, private, stolen,
    winning, withdrawn, wrote,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
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
        let space = n("/alice/32=data/journal");
        let path = n("/entries");
        let (phone, laptop, tablet) = (w.spaces(PHONE), w.spaces(LAPTOP), w.spaces(TABLET));
        laptop.create(&space, private(&[], &[])).await?;
        w.retry_later(|| phone.open(&space)).await?;
        w.until("the phone knows the shared journal", LIMIT, || {
            known(&*phone, &space)
        })
        .await?;
        let inside = w
            .space_put(PHONE, &space, &path, octets("last honest entry"))
            .await?;
        w.until("every device holds the phone's entry", LIMIT, || async {
            agree(&[&*phone, &*laptop, &*tablet], &space, &path, &[&inside]).await
        })
        .await?;

        // Stolen; Alice revokes on her laptop, and the new version stays there for now.
        let lost = loss_time(w, LAPTOP).await;
        stolen(w, THIEF, &space, &inside).await?;
        w.net().offline(PHONE);
        w.revoke_at(LAPTOP, PHONE, lost).await?;
        w.gesture();

        let mut tablets_feed = tablet.watch(&space).await?;
        let outside = w
            .space_put(THIEF, &space, &path, octets("written after the revocation"))
            .await?;
        ensure!(
            outside.writer == inside.writer && outside.seq > inside.seq,
            "precondition: the thief signs as the phone past its entry ({inside:?}), got \
             {outside:?}"
        );
        w.until(
            "the tablet accepts the thief's version, not knowing the revocation",
            LIMIT,
            || has(&*tablet, &space, &outside),
        )
        .await?;

        // The revocation reaches the network and the tablet.
        w.spread_all().await?;
        let mut seen = Vec::new();
        let took = drain_until(
            &mut *tablets_feed,
            &mut seen,
            "the tablet withdraws the thief's version",
            LIMIT,
            |events| withdrawn(events, &outside.key()),
        )
        .await?;
        w.converged(took);
        w.sleep(SETTLE).await;

        let s = winning(&*tablet, &space, &path, &[&inside]).await?;
        ensure!(
            !has(&*tablet, &space, &outside).await? && !wrote(&s, "written after the revocation"),
            "the tablet's journal still includes the thief's version the cut refuses"
        );
        ensure!(
            has(&*tablet, &space, &inside).await? && op_is(&s, "last honest entry"),
            "the re-check also dropped the phone's entry inside the cut"
        );
        ensure!(
            !has(&*laptop, &space, &outside).await?,
            "the laptop, which revoked the key, accepted the thief's version"
        );
        Ok(())
    })
}
