//! Keys over time 8 — a friend's guest key lapses.
//!
//! Alice lists her friend Bob as a writer of her garden notes. The device that writes is not
//! Alice's: it is `/bob/guest/phone`, a guest of Bob's own namespace that Bob certified for a
//! while (a guest of Alice's namespace would be one of the owner's devices, and holds none of
//! the owner's powers, so it could not write there as Bob's does). The guest writes a note while
//! its certificate is valid; then the certificate lapses, and it writes on with its key. Judging
//! data without any clock (k1) would leave a guest's write access permanent until its owner
//! remembers to revoke it (security review S5-02). The fix (M3, slice 5): a role's data requires
//! a cut once its certificate lapsed — until Bob's root signs one, every reader whose clock says
//! it lapsed refuses the guest's data (it fails closed); Bob's root, which signs unattended,
//! then revokes the key with a cut at what it held before the lapse, and that cut decides
//! alone, at Alice's devices as at Bob's: the note from before stays readable with a clock a
//! year ahead, the one after stays out.
//!
//! The space is public: a member's `guest` device is granted no epoch key (heap spec §6.5
//! condition 2, stage-7 M2: nothing rotates the epoch when a guest lapses), so it could not
//! seal in a private space. Its entries are Bob's, judged by the members entries alone, and
//! a guest may still write where the record admits Bob.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::kit::{
    DAY, LIMIT, LOOK, SETTLE, has, item_of, items, known, look, n, octets, op_is, public, winning,
    wrote,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::provider::Certs;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k8",
    title: "Lapsed guest key of a friend",
    slice: 5,
    needs: &[
        Feature::Merge,
        Feature::Revocation,
        Feature::RevocationRecheck,
        Feature::KeyLifetime,
        Feature::GuestExpiry,
    ],
    model: &["M3"],
    guards: "A guest key's authority over data ends with its certificate: what a friend's \
             guest device signs once its certificate lapsed is refused by every reader whose \
             clock says so, before any revocation; after its root's revoke-with-cut, what it \
             wrote before the lapse is accepted by a reader whose clock is a year ahead, and \
             what it wrote after stays out.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const GUEST: Dev = Dev(1);
const BOB: Dev = Dev(2);
const TABLET: Dev = Dev(3);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.guest("bob", "phone");
    p.device("bob", "laptop");
    p.device("alice", "tablet");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n("/alice/32=data/notes");
        let path = n("/garden");
        let (laptop, guest, bob, tablet) = (
            w.spaces(LAPTOP),
            w.spaces(GUEST),
            w.spaces(BOB),
            w.spaces(TABLET),
        );
        w.net().offline(TABLET);
        laptop.create(&space, public(&["/bob"])).await?;
        w.retry_later(|| guest.open(&space)).await?;
        w.retry_later(|| bob.open(&space)).await?;
        w.until("the guest knows the shared notes", LIMIT, || {
            known(&*guest, &space)
        })
        .await?;
        // The guest first reads a note the owner wrote at another path: a public space needs
        // no key, and the guest has nothing of the owner's but what the space shows.
        let hello = w
            .space_put(LAPTOP, &space, &n("/hello"), octets("welcome, bob"))
            .await?;
        w.until("the guest reads the owner's note", LIMIT, || {
            has(&*guest, &space, &hello)
        })
        .await?;
        // The guest writes a note while its certificate is valid.
        let before = w
            .space_put(GUEST, &space, &path, octets("sown beans"))
            .await?;
        w.until(
            "Alice's laptop and Bob's laptop hold the guest's note",
            LIMIT,
            || async {
                Ok(has(&*laptop, &space, &before).await? && has(&*bob, &space, &before).await?)
            },
        )
        .await?;
        w.sleep(Duration::from_secs(1)).await;

        // The guest certificate reaches its NotAfter; the guest writes on with its key.
        w.expire(GUEST, Certs::All).await?;
        // The key of the epoch in force may still be on its way: put again as the refusal says
        // (RetryLater); the note is signed after the lapse either way.
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
            "Alice's laptop accepted a note the friend's guest signed after its certificate \
             lapsed, before any revocation: a lapsed guest's data must wait for its root's cut"
        );

        // Bob's root device ends the lapsed key on its own, with a cut at the lapse.
        let ended = w.end_keys(BOB).await?;
        ensure!(
            ended.iter().any(|k| k.has_prefix(&before.writer)),
            "Bob's root did not end the lapsed key of the guest {} (it ended {ended:?})",
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
                "the {who} lacks the guest's note from before the lapse, which its root's cut \
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
