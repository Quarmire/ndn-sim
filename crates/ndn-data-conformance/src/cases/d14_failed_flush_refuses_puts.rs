//! Durability, d14 — a failed reservation flush refuses puts past the reservation, with the
//! disk's reason, and reads go on.
//!
//! Alice's laptop has heard her phone, so its puts do not wait for the flush. Its disk then fails
//! every flush (full, or dead; [`World::fail_flush`]) with a reason of its own. The laptop's puts
//! go on being accepted while they stay inside the seqs it had durably reserved; the first one
//! past them is refused: a failure whose next step is `FixLocal` and whose text carries the
//! disk's reason, and a [`AlertKind::StoreFailed`] alert reports it. Nothing already signed is
//! retracted: every put that returned is still read on the laptop and held by the phone, and
//! the laptop goes on reading. The refusal is for good: the next put is refused alike.
//!
//! The guard: a disk that cannot make a reservation durable stops the device signing past it,
//! says why and what to do, and takes nothing back; reading is not touched.
//!
//! Devices: alice's laptop and phone. (A provider's reservation block must be small enough to
//! pass within [`PUTS`] puts; `ndn-heap`'s provider sets 8.)

use std::time::Duration;

use super::durability::{create, peers, space};
use super::kit::{LIMIT, SETTLE, alerted, drain, drain_until, has, item, n, octets};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{AlertKind, SpaceEvent};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "d14",
    title: "A failed reservation flush refuses puts past the reservation with the disk's reason",
    slice: 9,
    needs: &[Feature::Crash],
    model: &[],
    guards: "When every flush fails, puts inside the durable reservation return and the first \
             past it is refused with next step FixLocal and the disk's reason, the refusal \
             stays, a StoreFailed alert is raised, nothing signed is retracted (the device and \
             its peer hold every put that returned) and the device keeps reading.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
/// How many puts the laptop gets before it must have been refused one.
const PUTS: usize = 2500;
const REASON: &str = "the disk is on fire";

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = space();
        create(w, LAPTOP, &space).await?;
        let (laptop, phone) = (w.spaces(LAPTOP), w.spaces(PHONE));
        peers(w, LAPTOP, PHONE, &space).await?;
        let before = w
            .space_put(LAPTOP, &space, &n("/before"), octets("before"))
            .await?;
        let mut feed = w.retry_later(|| laptop.watch(&space)).await?;
        let mut saw: Vec<SpaceEvent> = Vec::new();

        // The disk fails; the laptop writes until it is refused.
        w.fail_flush(LAPTOP, Some(REASON)).await?;
        let path = n("/p");
        let mut accepted = Vec::new();
        let mut refusal = None;
        for i in 0..PUTS {
            match laptop.put(&space, &path, octets(&format!("{i}"))).await {
                Ok(e) => accepted.push((e, format!("{i}"))),
                Err(f) => {
                    refusal = Some(f);
                    break;
                }
            }
        }
        let Some(refusal) = refusal else {
            return Err(crate::Failure::new(format!(
                "{PUTS} puts on a disk whose every flush fails were all accepted: no put was \
                 refused past the reservation"
            )));
        };
        ensure!(
            refusal.next_is("FixLocal"),
            "the refusal names next step {:?}, not FixLocal: {refusal}",
            refusal.next
        );
        ensure!(
            refusal.detail.contains(REASON),
            "the refusal does not carry the disk's reason {REASON:?}: {refusal}"
        );
        let again = laptop.put(&space, &path, octets("again")).await;
        ensure!(
            again.as_ref().is_err_and(|f| f.next_is("FixLocal")),
            "a put after the refusal answered {again:?}: the failure is for good"
        );

        // Nothing signed is retracted, and reading goes on.
        ensure!(
            item(&*laptop, &space, &n("/before"))
                .await?
                .map(|i| i.bytes)
                == Some(octets("before")),
            "the laptop no longer reads what it wrote before the disk failed"
        );
        if let Some((last, text)) = accepted.last() {
            let read = item(&*laptop, &space, &path).await?;
            ensure!(
                read.as_ref()
                    .is_some_and(|i| i.entry() == *last && i.bytes == octets(text)),
                "the laptop reads {read:?} at /p, not the last put that returned ({text})"
            );
        }
        w.until("the phone holds every put that returned", LIMIT, || async {
            for (e, _) in &accepted {
                if !has(&*phone, &space, e).await? {
                    return Ok(false);
                }
            }
            has(&*phone, &space, &before).await
        })
        .await?;

        // The failure is reported.
        drain_until(
            &mut *feed,
            &mut saw,
            "the laptop reports its store failing",
            LIMIT,
            |seen| alerted(seen, |k| matches!(k, AlertKind::StoreFailed)),
        )
        .await?;
        drain(&mut *feed, SETTLE, &mut saw).await?;
        let why = saw.iter().find_map(|e| match e {
            SpaceEvent::Alert(a) if a.kind == AlertKind::StoreFailed => Some(a.detail.clone()),
            _ => None,
        });
        ensure!(
            why.as_deref().is_some_and(|d| d.contains(REASON)),
            "the StoreFailed alert does not say why: {why:?}"
        );
        Ok(())
    })
}
