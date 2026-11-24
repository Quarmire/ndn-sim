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

use super::kit::{
    DAY, LIMIT, LOOK, SETTLE, has, item_of, items, known, look, n, octets, op_is, private, winning,
    wrote,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
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
        let space = n("/alice/32=data/notes");
        let path = n("/garden");
        let (laptop, guest, tablet) = (w.spaces(LAPTOP), w.spaces(GUEST), w.spaces(TABLET));
        w.net().offline(TABLET);
        laptop.create(&space, private(&[], &[])).await?;
        w.retry_later(|| guest.open(&space)).await?;
        w.until("the guest knows the shared notes", LIMIT, || {
            known(&*guest, &space)
        })
        .await?;
        // The guest's first put races the epoch key's grant (spec §17.1): put again on RetryLater.
        let before = w
            .space_put(GUEST, &space, &path, octets("sown beans"))
            .await?;
        w.until("the laptop holds the guest's note", LIMIT, || {
            has(&*laptop, &space, &before)
        })
        .await?;
        w.sleep(Duration::from_secs(1)).await;

        // The guest certificate reaches its NotAfter; Bob writes on with his key.
        w.expire(GUEST, Certs::All).await?;
        // The key of the epoch in force may still be on its way (a concurrent epoch signed by
        // another owner device took force after the guest's first note): put again as the
        // refusal says (RetryLater); the note is signed after the lapse either way.
        let after = w
            .space_put(GUEST, &space, &path, octets("written after the lapse"))
            .await?;
        ensure!(
            after.writer == before.writer && after.seq > before.seq,
            "precondition: the guest signs both notes with its one key, got {before:?} and \
             {after:?}"
        );
        w.sleep(SETTLE).await;
        ensure!(
            !has(&*laptop, &space, &after).await?,
            "the laptop accepted a note the guest signed after its certificate lapsed, before \
             any revocation: a lapsed guest's data must wait for the owner's cut"
        );

        // Alice's root device ends the lapsed key on its own, with a cut at the lapse.
        let ended = w.end_keys(LAPTOP).await?;
        ensure!(
            ended.iter().any(|k| k.has_prefix(&before.writer)),
            "the root did not end the lapsed key of the guest {} (it ended {ended:?})",
            before.writer
        );

        // A reader whose clock is a year ahead joins.
        w.net().set_clock(TABLET, ClockSkew::ahead(365 * DAY));
        w.net().online(TABLET);
        w.converge(
            "the tablet, a year ahead, reads the guest's note from before the lapse",
            LIMIT,
            || has(&*tablet, &space, &before),
        )
        .await?;
        w.sleep(SETTLE).await;

        for (who, spaces) in [("laptop", &laptop), ("tablet", &tablet)] {
            let looked = look(&**spaces, &space, LOOK).await?;
            ensure!(
                item_of(&looked, &after.key()).is_none()
                    && !items(&looked).any(|i| wrote(i, "written after the lapse")),
                "the {who} accepts the note the guest signed after its certificate lapsed"
            );
            let s = winning(&**spaces, &space, &path, &[&before]).await?;
            ensure!(
                has(&**spaces, &space, &before).await? && op_is(&s, "sown beans"),
                "the {who} lacks the guest's note from before the lapse, which the root's cut \
                 keeps ({:?})",
                String::from_utf8_lossy(&s.bytes)
            );
            ensure!(
                !has(&**spaces, &space, &after).await? && !wrote(&s, "written after the lapse"),
                "the {who}'s notes include the guest's note from after the lapse"
            );
        }
        Ok(())
    })
}
