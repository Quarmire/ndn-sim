//! Case 12 — offline photo browsing, a summary service, a revoked tablet.
//!
//! Three checks the draft model already passed, kept so they keep passing: offline reads come
//! from held versions and say how old they may be (on a phone whose clock is a year off); a
//! service's answer is sealed to its input's audience, so it leaks nothing new; a revoked tablet
//! stops receiving new keys, and what it already read is the stated forward-only limit.

use std::time::Duration;

use ndn_data::{Age, AnswerAsk, AnswerRefusal, DataError, Provenance, ReadSet};
use ndn_sim::ClockSkew;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::Program;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c12",
    title: "Offline photo browsing, a summary service, a revoked tablet",
    slice: 8,
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
    let laptop = p.device("alice", "laptop");
    p.program(laptop, Program::Evaluating);
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
        let album = n("/alice/32=data/photos/trip");
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

        // 2. A summary service reads a note it was shared and answers as a provider: its answer
        // binds its function and the exact state it read (answers.md §4.2, §14 a12, a6), signed
        // by the service, sealed to its input's audience.
        let note_name = n("/alice/32=data/notes/meeting");
        let audience = vec![
            alice.clone(),
            Audience::Device(w.net().spec(SERVICE).name()),
        ];
        laptop
            .share(&note_name, members(merge(), &["/alice"], &audience))
            .await?;
        let input = laptop
            .put(&note_name, text("decided: ship in May"), note(1))
            .await?;
        w.until("the service holds the note", LIMIT, || {
            has(&*service, &note_name, &input)
        })
        .await?;
        w.until("Alice's laptop holds the note", LIMIT, || {
            has(&*laptop, &note_name, &input)
        })
        .await?;
        let (read, _) = w.gate(SERVICE)?.current_read(&note_name).await?;
        let inputs = ReadSet::new([read]).map_err(|e| Failure::new(e.to_string()))?;
        let function = crate::sum::function(1);
        let answer = w
            .gate(SERVICE)?
            .provide(
                &function,
                inputs.clone(),
                bytes::Bytes::from_static(b"ship in May"),
            )
            .await?;
        ensure!(
            answer.len() == 4,
            "the answer's name has a content word: {answer}"
        );
        let q = AnswerAsk::provider(function, inputs)
            .name(Some(&w.net().spec(SERVICE).name()))
            .map_err(Failure::from)?;
        let got = match laptop.get(&q).await?.got {
            ndn_data::Got::Answer(a) => a,
            other => return Err(Failure::new(format!("not an answer: {other:?}"))),
        };
        ensure!(
            got.result.as_ref() == b"ship in May" && matches!(got.how, Provenance::Provider { .. }),
            "Alice's laptop did not read the provider's answer: {:?} {:?}",
            got.result,
            got.how
        );
        let outside = bob.get(&q).await;
        ensure!(
            matches!(
                outside,
                Err(DataError::Sealed { .. })
                    | Err(DataError::Answer {
                        why: AnswerRefusal::NotProvider { .. },
                        ..
                    })
                    | Err(DataError::Unavailable { .. })
            ),
            "Bob, outside the input's audience, read the service's answer: {outside:?}"
        );

        // 3. A revoked tablet keeps what it read and opens nothing new.
        w.until("the tablet holds the album", LIMIT, || {
            has(&*tablet, &album, &shot)
        })
        .await?;
        let old = state(&*tablet, &album).await?;
        let lost = loss_time(w, LAPTOP).await;
        w.revoke(LAPTOP, TABLET, lost).await?;
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
