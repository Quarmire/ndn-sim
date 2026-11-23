//! Keys over time 1 — an expired key's old data.
//!
//! Alice's phone, a member's device (`/alice/member/phone`), writes two notes while its
//! certificate is valid; later the certificate expires without a renewal, and the phone writes a
//! third. Alice's tablet, offline until then and with a clock a year ahead, reads the notes for
//! the first time. Judging data by its certificate's validity "now" would let any reader's clock
//! — or the calendar — kill honest old data. The fix (M3, slice 5): data is durable, and a key's
//! authority over it ends by a signed revocation. A lapsed key of every role (a member's, as a
//! guest's, a node's and an admin's) is refused until its owner ends it, since the context
//! `ndn-fwd init` makes lists every role: the third note waits, and the root's revoke-with-cut,
//! bounded at the lapse, keeps the two notes from before at every reader, whatever its clock
//! says. A device that renews in time (k5) never waits.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::kit::{
    DAY, LIMIT, LOOK, SETTLE, agree, has, item_of, items, known, look, n, octets, op_is, private,
    winning, wrote,
};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::provider::Certs;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k1",
    title: "Expired key's old data",
    slice: 5,
    needs: &[
        Feature::Merge,
        Feature::Revocation,
        Feature::RevocationRecheck,
        Feature::KeyLifetime,
        Feature::GuestExpiry,
    ],
    model: &["M3"],
    guards: "A version's validity does not depend on a reader's clock: after its writer's \
             certificate expired without a renewal, what the key signs is refused until the \
             owner ends it, and after the root's revoke-with-cut a reader whose clock is a year \
             ahead still accepts what the key signed before the lapse.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const TABLET: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.member("alice", "phone");
    p.device("alice", "laptop");
    p.device("alice", "tablet");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n("/alice/32=data/notes");
        let path = n("/garden");
        let (phone, laptop, tablet) = (w.spaces(PHONE), w.spaces(LAPTOP), w.spaces(TABLET));
        w.net().offline(TABLET);
        laptop.create(&space, private(&[], &[])).await?;
        w.retry_later(|| phone.open(&space)).await?;
        w.until("the phone knows the shared notes", LIMIT, || {
            known(&*phone, &space)
        })
        .await?;
        let first = w
            .space_put(PHONE, &space, &path, octets("sown beans"))
            .await?;
        let second = w
            .space_put(PHONE, &space, &path, octets("watered tuesday"))
            .await?;
        w.until("the laptop holds the phone's notes", LIMIT, || async {
            agree(&[&*phone, &*laptop], &space, &path, &[&first, &second]).await
        })
        .await?;
        w.sleep(Duration::from_secs(1)).await;

        // The phone's certificate runs out unrenewed, and the phone writes on with its key.
        w.expire(PHONE, Certs::All).await?;
        let late = phone
            .put(&space, &path, octets("written after the lapse"))
            .await?;
        ensure!(
            late.writer == first.writer && late.seq > second.seq,
            "precondition: the phone signs every note with its one key, got {first:?}, \
             {second:?} and {late:?}"
        );
        w.sleep(SETTLE).await;
        ensure!(
            !has(&*laptop, &space, &late).await?,
            "the laptop accepted a note the phone signed after its certificate lapsed, before \
             the owner ended the key: a lapsed key's data must wait for the owner's cut"
        );

        // Alice's root device ends the lapsed key, with a cut at the lapse.
        let ended = w.end_keys(LAPTOP).await?;
        ensure!(
            ended.iter().any(|k| k.has_prefix(&first.writer)),
            "the root did not end the lapsed key of {} (it ended {ended:?})",
            first.writer
        );

        // A reader whose clock is a year ahead joins and reads the expired key's old notes.
        w.net().set_clock(TABLET, ClockSkew::ahead(365 * DAY));
        w.net().online(TABLET);
        w.converge(
            "the tablet, a year ahead, reads the expired key's notes from before the lapse",
            LIMIT,
            || async { agree(&[&*laptop, &*tablet], &space, &path, &[&first, &second]).await },
        )
        .await?;
        w.sleep(SETTLE).await;

        for (who, spaces) in [("laptop", &laptop), ("tablet", &tablet)] {
            let s = winning(&**spaces, &space, &path, &[&second]).await?;
            ensure!(
                has(&**spaces, &space, &first).await? && has(&**spaces, &space, &second).await?,
                "the {who} dropped a note the expired key signed while it was valid"
            );
            ensure!(
                op_is(&s, "watered tuesday"),
                "the {who} shows {:?} for the expired key's notes",
                String::from_utf8_lossy(&s.bytes)
            );
            let looked = look(&**spaces, &space, LOOK).await?;
            ensure!(
                !has(&**spaces, &space, &late).await?
                    && item_of(&looked, &late.key()).is_none()
                    && !items(&looked).any(|i| wrote(i, "written after the lapse")),
                "the {who}'s notes include the note the phone signed after its certificate \
                 lapsed"
            );
        }
        Ok(())
    })
}
