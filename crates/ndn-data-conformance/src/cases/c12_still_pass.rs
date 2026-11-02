//! Case 12 — offline photo browsing, a summary service, a revoked tablet.
//!
//! Three checks the draft model already passed, kept so they keep passing: offline reads come
//! from held versions and say how old they may be (on a phone whose clock is a year off); a
//! service's answer is sealed to its input's audience, so it leaks nothing new; a revoked tablet
//! stops receiving new keys, and what it already read is the stated forward-only limit.

use std::time::Duration;

use ndn_data::{Age, DataError, Seal};
use ndn_sim::ClockSkew;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c12",
    title: "Offline photo browsing, a summary service, a revoked tablet",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::Seal,
        Feature::Revocation,
        Feature::Functions,
    ],
    model: &[],
    guards: "Offline reads answer held data with an age measured without the wall clock; a \
             service's answer is readable only by its input's audience; a revoked reader cannot \
             open anything new but keeps what it already read.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const TABLET: Dev = Dev(1);
const LAPTOP: Dev = Dev(2);
const SERVICE: Dev = Dev(3);
const BOB: Dev = Dev(4);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "tablet");
    p.device("alice", "laptop");
    p.device("summarizer", "service");
    p.device("bob", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let (phone, tablet, laptop, service, bob) = (
            w.at(PHONE),
            w.at(TABLET),
            w.at(LAPTOP),
            w.at(SERVICE),
            w.at(BOB),
        );
        let alice = person("/alice");

        // 1. Offline browsing on a phone whose clock is a year fast.
        let album = n("/alice/photos/trip");
        laptop
            .share(
                &album,
                members(merge(), &["/alice"], std::slice::from_ref(&alice)),
            )
            .await?;
        let shot = laptop
            .put(&album, content(&[("file", "harbour.jpg")]), note(1))
            .await?;
        w.until("the phone holds the album", LIMIT, || {
            has(&*phone, &album, &shot)
        })
        .await?;
        w.net().set_clock(PHONE, ClockSkew::ahead(365 * DAY));
        w.net().offline(PHONE);
        let away = Duration::from_secs(600);
        w.sleep(away).await;
        let offline = phone.get(&album).await?;
        match offline.age {
            Age::Newest { unconfirmed_for } => ensure!(
                unconfirmed_for >= away,
                "offline for {away:?}, the answer claims to be unconfirmed for only \
                 {unconfirmed_for:?}"
            ),
            Age::Exact => {
                return Err(Failure::new(
                    "a collection's newest state was answered as exact, so not dated",
                ));
            }
        }
        w.net().online(PHONE);
        w.net().set_clock(PHONE, ClockSkew::NONE);

        // 2. A summary service reads a note it was shared and answers under its own name.
        let note_name = n("/alice/notes/meeting");
        let audience = Seal {
            any_of: vec![
                alice.clone(),
                Audience::Device(w.net().spec(SERVICE).name()),
            ],
        };
        laptop
            .share(&note_name, members(merge(), &["/alice"], &audience.any_of))
            .await?;
        let input = laptop
            .put(&note_name, text("decided: ship in May"), note(1))
            .await?;
        w.until("the service holds the note", LIMIT, || {
            has(&*service, &note_name, &input)
        })
        .await?;
        let answer = n("/summarizer/answers/meeting");
        service
            .share(
                &answer,
                members(merge(), &["/summarizer"], &audience.any_of),
            )
            .await?;
        let summary_id = service.put(&answer, text("ship in May"), note(1)).await?;
        let theirs = look(&*service, &answer, &Frontier::new(), LOOK).await?;
        let sealed = &version(&theirs, &summary_id)
            .ok_or_else(|| Failure::new("the service's watch does not list its answer"))?
            .seal;
        ensure!(
            sealed.any_of.iter().all(|a| audience.any_of.contains(a)),
            "the answer is sealed to {:?}, beyond its input's audience {:?}",
            sealed.any_of,
            audience.any_of
        );
        w.until("Alice's laptop reads the answer", LIMIT, || {
            has(&*laptop, &answer, &summary_id)
        })
        .await?;
        ensure!(
            bob.get(&answer).await.is_err(),
            "Bob, outside the input's audience, read the service's answer"
        );

        // 3. A revoked tablet keeps what it read and opens nothing new.
        w.until("the tablet holds the album", LIMIT, || {
            has(&*tablet, &album, &shot)
        })
        .await?;
        let old = state(&*tablet, &album).await?;
        w.revoke(LAPTOP, TABLET).await?;
        w.gesture();
        let fresh = laptop
            .put(&album, content(&[("file", "lighthouse.jpg")]), note(1))
            .await?;
        w.converge("the phone holds the new photo", LIMIT, || {
            has(&*phone, &album, &fresh)
        })
        .await?;
        w.sleep(SETTLE).await;
        match tablet.get(&album).await {
            Ok(a) => {
                if let ndn_data::Got::State(s) = a.got {
                    ensure!(
                        !s.at.contains(&fresh),
                        "the revoked tablet opened a photo added after its revocation"
                    );
                }
            }
            Err(DataError::Sealed { .. } | DataError::Unavailable { .. }) => {}
            Err(e) => return Err(e.into()),
        }
        match tablet.get(&old.name).await {
            Ok(_) => {}
            Err(e) => {
                return Err(Failure::new(format!(
                    "the revoked tablet lost what it had already read: {e}"
                )));
            }
        }
        Ok(())
    })
}
