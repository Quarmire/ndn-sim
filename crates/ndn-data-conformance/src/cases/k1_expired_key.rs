//! Keys over time 1 — an expired key's old data.
//!
//! Alice's phone writes two notes while its certificate is valid; later the certificate expires
//! (nobody revoked the key: it simply ran out). Alice's tablet, offline until then and with a
//! clock a year ahead, reads the notes for the first time. Judging data by its certificate's
//! validity "now" would let any reader's clock — or the calendar — kill honest old data. The fix
//! (M3, slice 5): data is durable; a key's authority over it ends only by a signed revocation,
//! never by a clock.

use std::time::Duration;

use ndn_sim::ClockSkew;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::Certs;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k1",
    title: "Expired key's old data",
    slice: 5,
    needs: &[Feature::Merge, Feature::KeyLifetime],
    model: &["M3"],
    guards: "A version's validity does not depend on a clock: after its writer's certificate \
             expired, unrevoked, a reader whose clock is a year ahead still accepts what the key \
             signed.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const TABLET: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "laptop");
    p.device("alice", "tablet");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let notes = n("/alice/32=data/notes/garden");
        let (phone, laptop, tablet) = (w.at(PHONE), w.at(LAPTOP), w.at(TABLET));
        w.net().offline(TABLET);
        laptop
            .share(&notes, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the phone knows the shared notes", LIMIT, || {
            known(&*phone, &notes)
        })
        .await?;
        let first = w
            .put(PHONE, &notes, content(&[("sown", "beans")]), note(1))
            .await?;
        let second = w
            .put(PHONE, &notes, content(&[("watered", "tuesday")]), note(1))
            .await?;
        w.until("the laptop holds the phone's notes", LIMIT, || async {
            agree(&[&*phone, &*laptop], &notes, &[&first, &second]).await
        })
        .await?;

        // The phone's certificate runs out; the tablet's clock is a year ahead.
        w.expire(PHONE, Certs::All).await?;
        w.net().set_clock(TABLET, ClockSkew::ahead(365 * DAY));
        w.net().online(TABLET);
        w.converge(
            "the tablet reads the expired key's notes",
            LIMIT,
            || async { agree(&[&*laptop, &*tablet], &notes, &[&first, &second]).await },
        )
        .await?;
        w.sleep(SETTLE).await;

        for (who, layer) in [("laptop", &laptop), ("tablet", &tablet)] {
            let s = state(&**layer, &notes).await?;
            ensure!(
                s.at.contains(&first) && s.at.contains(&second),
                "the {who} dropped a note the expired key signed while it was valid"
            );
            ensure!(
                field(&s.value, "sown") == Some("beans")
                    && field(&s.value, "watered") == Some("tuesday"),
                "the {who} shows {:?} for the expired key's notes",
                s.value
            );
        }
        Ok(())
    })
}
