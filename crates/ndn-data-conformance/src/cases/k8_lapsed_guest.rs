//! Keys over time 8 — a guest's certificate lapses.
//!
//! Alice gives her friend Bob a guest certificate under her namespace and lets him write into her
//! garden notes. Bob writes a note while the certificate is valid; then it lapses, and he writes
//! on with his key. Judging data without any clock (k1) would leave a guest's write access
//! permanent until Alice remembers to revoke it (security review S5-02). The fix (M3, slice 5):
//! a guest's role requires a cut once its certificate lapsed — until the root signs one, every
//! reader whose clock says it lapsed refuses the guest's data (it fails closed); the root, which
//! signs unattended, then revokes the key with a cut at what it held before the lapse, and that
//! cut decides alone: the note from before stays readable with a clock a year ahead, the one
//! after stays out.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::Certs;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k8",
    title: "Lapsed guest key",
    slice: 5,
    needs: &[
        Feature::Merge,
        Feature::Revocation,
        Feature::RevocationRecheck,
        Feature::KeyLifetime,
        Feature::GuestExpiry,
    ],
    model: &["M3"],
    guards: "A guest key's authority over data ends with its certificate: what it signs once \
             its certificate lapsed is refused by every reader whose clock says so, before any \
             revocation; after the root's revoke-with-cut, what it wrote before the lapse is \
             accepted by a reader whose clock is a year ahead, and what it wrote after stays out.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const GUEST: Dev = Dev(1);
const TABLET: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.guest("alice", "bob");
    p.device("alice", "tablet");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let notes = n("/alice/32=data/notes/garden");
        let (laptop, guest, tablet) = (w.at(LAPTOP), w.at(GUEST), w.at(TABLET));
        w.net().offline(TABLET);
        laptop
            .share(&notes, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the guest knows the shared notes", LIMIT, || {
            known(&*guest, &notes)
        })
        .await?;
        // The guest's first put races the epoch key's grant (spec §17.1): put again on RetryLater.
        let before = w
            .put(GUEST, &notes, content(&[("sown", "beans")]), note(1))
            .await?;
        w.until("the laptop holds the guest's note", LIMIT, || {
            has(&*laptop, &notes, &before)
        })
        .await?;
        w.sleep(Duration::from_secs(1)).await;

        // The guest certificate reaches its NotAfter; Bob writes on with his key.
        w.expire(GUEST, Certs::All).await?;
        let after = guest
            .put(
                &notes,
                content(&[("picked", "written after the lapse")]),
                note(1),
            )
            .await?;
        ensure!(
            after.writer == before.writer && after.seq > before.seq,
            "precondition: the guest signs both notes with its one key, got {before:?} and \
             {after:?}"
        );
        w.sleep(SETTLE).await;
        ensure!(
            !has(&*laptop, &notes, &after).await?,
            "the laptop accepted a note the guest signed after its certificate lapsed, before \
             any revocation: a lapsed guest's data must wait for the owner's cut"
        );

        // Alice's root device ends the lapsed key on its own, with a cut at the lapse.
        let ended = w.end_keys(LAPTOP).await?;
        let key = before.writer.key();
        ensure!(
            ended.iter().any(|k| key.has_prefix(k)),
            "the root did not end the lapsed guest key {key} (it ended {ended:?})"
        );

        // A reader whose clock is a year ahead joins.
        w.net().set_clock(TABLET, ClockSkew::ahead(365 * DAY));
        w.net().online(TABLET);
        w.converge(
            "the tablet, a year ahead, reads the guest's note from before the lapse",
            LIMIT,
            || has(&*tablet, &notes, &before),
        )
        .await?;
        w.sleep(SETTLE).await;

        for (who, layer) in [("laptop", &laptop), ("tablet", &tablet)] {
            let looked = look(&**layer, &notes, &Frontier::new(), LOOK).await?;
            ensure!(
                version(&looked, &after).is_none()
                    && !versions(&looked).any(|v| field_of(v, "picked").is_some()),
                "the {who} accepts the note the guest signed after its certificate lapsed"
            );
            let s = state(&**layer, &notes).await?;
            ensure!(
                s.at.contains(&before) && field(&s.value, "sown") == Some("beans"),
                "the {who} lacks the guest's note from before the lapse, which the root's cut \
                 keeps ({:?})",
                s.value
            );
            ensure!(
                !s.at.contains(&after) && field(&s.value, "picked").is_none(),
                "the {who}'s notes include the guest's note from after the lapse"
            );
        }
        Ok(())
    })
}
