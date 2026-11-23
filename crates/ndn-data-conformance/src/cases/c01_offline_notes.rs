//! Case 1 — notes on laptop and phone, both offline.
//!
//! Bob edits the same note on the plane (laptop) and in the taxi (phone). Under the draft model
//! both edits were "v=18" by one writer — equivocation for an ordinary offline edit. The fix (M1):
//! a writer is a key; the edits are (laptop, n) and (phone, m), each superseding the shared write,
//! and the register keeps the head with the highest signed digest. Bob's namespace is
//! `/home/bob`, of two components: the space's `32=data` marks where it ends (spec §3), and
//! his devices take it from the trust context that governs them. The note is the path
//! `/trip/day1` of his space `/home/bob/32=data/notes`.

use std::time::Duration;

use super::kit::{
    LIMIT, LOOK, agree, equivocation, has, item_of, look, n, octets, private, winning,
};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c1",
    title: "Notes on laptop and phone, both offline",
    slice: 1,
    needs: &[Feature::Merge],
    model: &["M1"],
    guards: "A writer is one key: two devices' offline edits are distinct versions (writer, seq), \
             each naming the common parent; they converge on both devices to one register value, \
             the head with the highest digest, and are never reported as equivocation.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("home/bob", "laptop");
    p.device("home/bob", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n("/home/bob/32=data/notes");
        let doc = n("/trip/day1");
        let (laptop, phone) = (w.spaces(LAPTOP), w.spaces(PHONE));
        laptop.create(&space, private(&[], &[])).await?;
        w.retry_later(|| phone.open(&space)).await?;
        let v17 = laptop.put(&space, &doc, octets("day 1")).await?;
        w.until("the phone holds the shared version", LIMIT, || {
            has(&*phone, &space, &v17)
        })
        .await?;

        w.net().offline(LAPTOP);
        w.net().offline(PHONE);
        let plane = laptop
            .put(&space, &doc, octets("day 1, on the plane"))
            .await?;
        let taxi = phone
            .put(&space, &doc, octets("day 1, in the taxi"))
            .await?;
        ensure!(
            plane.writer != taxi.writer,
            "both offline edits carry writer {:?}: a writer must be the device's key",
            plane.writer
        );
        w.net().online(LAPTOP);
        w.net().online(PHONE);

        w.converge(
            "laptop and phone agree on a state with both edits",
            LIMIT,
            || async { agree(&[&*laptop, &*phone], &space, &doc, &[&plane, &taxi]).await },
        )
        .await?;
        for device in [&laptop, &phone] {
            winning(&**device, &space, &doc, &[&plane, &taxi]).await?;
        }

        for device in [&laptop, &phone] {
            let changes = look(&**device, &space, LOOK).await?;
            ensure!(
                !equivocation(&changes),
                "an ordinary offline edit was reported as equivocation"
            );
            for entry in [&plane, &taxi] {
                let listed = item_of(&changes, &entry.key())
                    .ok_or_else(|| Failure::new(format!("watch does not list {}", entry.name)))?;
                ensure!(
                    listed.after.iter().any(|a| a.covers(&v17.key())),
                    "{} does not supersede the shared write {}: it lists {:?}",
                    entry.name,
                    v17.name,
                    listed.after
                );
            }
        }
        Ok(())
    })
}
