//! Device events, v3 — a revocation adopted is told, and so is what it withdraws, on a device
//! no one watches.
//!
//! k4's story: Alice revokes her stolen phone's key on her laptop; the thief writes on with the
//! key and Alice's tablet, which has not heard, accepts his version. The new trust-context
//! version then reaches the tablet. Nobody watches the journal on the tablet.
//!
//! The guard: the tablet's device reports a revocation event naming Alice's namespace, the
//! phone's key and the context's version, and a withdrawal event for the thief's version (by
//! name, by the key's cut); Alice's laptop, which adopted the context when it signed it, reports
//! the revocation too.

use std::time::Duration;

use ndn_data::{EntryKind, EventDetail, EventKind, EventSubject, Meaning, WithdrawnBy};

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "v3",
    title: "A revocation and the version it withdraws are told on a device no one watches",
    slice: 7,
    needs: &[
        Feature::Merge,
        Feature::Revocation,
        Feature::RevocationRecheck,
        Feature::DeviceEvents,
    ],
    model: &["M3"],
    guards: "A trust context adopted that revokes a key its predecessor did not is a revocation \
             event on the device that adopts it, and a version of the key it withdraws is a \
             withdrawal event by name, whether or not anyone watches: both say what the device \
             already did, and neither decides anything.",
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
        let journal = n("/alice/32=data/journal");
        let phones = w.net().spec(PHONE).name();
        let (phone, laptop, tablet) = (w.at(PHONE), w.at(LAPTOP), w.at(TABLET));
        laptop
            .share(&journal, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the phone knows the shared journal", LIMIT, || {
            known(&*phone, &journal)
        })
        .await?;
        let inside = w
            .put(
                PHONE,
                &journal,
                content(&[("phone", "last honest entry")]),
                note(1),
            )
            .await?;
        w.until("every device holds the phone's entry", LIMIT, || async {
            agree(&[&*phone, &*laptop, &*tablet], &journal, &[&inside]).await
        })
        .await?;
        ensure!(
            w.gate(TABLET)?.pending_events().is_empty(),
            "precondition: the tablet reports nothing yet: {:?}",
            w.gate(TABLET)?.pending_events()
        );

        let lost = loss_time(w, LAPTOP).await;
        stolen(w, THIEF, &journal, &inside).await?;
        w.net().offline(PHONE);
        w.revoke_at(LAPTOP, PHONE, lost).await?;
        w.gesture();
        let outside = w
            .put(
                THIEF,
                &journal,
                content(&[("thief", "written after the revocation")]),
                note(1),
            )
            .await?;
        w.until(
            "the tablet accepts the thief's version, not knowing the revocation",
            LIMIT,
            || has(&*tablet, &journal, &outside),
        )
        .await?;
        ensure!(
            events_of(w, TABLET, EventKind::Revocation)?.is_empty(),
            "the tablet reports a revocation it has not heard"
        );

        // The revocation reaches the tablet; no one there watches the journal.
        w.spread_all().await?;
        let last = std::cell::RefCell::new(String::new());
        w.until(
            "the tablet reports the revocation and the withdrawal",
            LIMIT,
            || async {
                let r = events_of(w, TABLET, EventKind::Revocation)?;
                let x = events_of(w, TABLET, EventKind::Withdrawal)?;
                let ok = !r.is_empty() && !x.is_empty();
                if !ok {
                    *last.borrow_mut() = format!("revocations {r:?}, withdrawals {x:?}");
                }
                Ok(ok)
            },
        )
        .await
        .map_err(|e| Failure::new(format!("{e}; at the last look: {}", last.borrow())))?;

        for (who, d) in [("the tablet", TABLET), ("the laptop", LAPTOP)] {
            let revocations = events_of(w, d, EventKind::Revocation)?;
            ensure!(
                revocations.len() == 1,
                "{who}: one revocation event, got {revocations:?}"
            );
            let EventDetail::Revocation {
                namespace,
                revoked,
                version,
            } = &revocations[0].detail
            else {
                return Err(Failure::new(format!("{who}: {:?}", revocations[0])));
            };
            ensure!(
                *namespace == n("/alice") && revoked.has_prefix(&phones) && *version >= 2,
                "{who}: the event names /alice, the phone's key and the new context version, got \
                 {:?}",
                revocations[0]
            );
            ensure!(
                revocations[0].subject() == EventSubject::Revoked(revoked.clone())
                    && revocations[0].meaning() == Meaning::KeyRefused,
                "{who}: {:?}",
                revocations[0]
            );
        }
        let withdrawals = events_of(w, TABLET, EventKind::Withdrawal)?;
        ensure!(
            withdrawals.len() == 1,
            "the tablet: one withdrawal event, got {withdrawals:?}"
        );
        let EventDetail::Withdrawal {
            writer,
            collection,
            entry,
            by,
        } = &withdrawals[0].detail
        else {
            return Err(Failure::new(format!("{:?}", withdrawals[0])));
        };
        ensure!(
            *writer == outside.writer.key().clone()
                && collection.as_ref() == Some(&journal)
                && entry.name == log_entry(w, PHONE, &journal, &outside)
                && entry.kind == Some(EntryKind::Version)
                && matches!(by, WithdrawnBy::Cut { of, .. } if of.has_prefix(&phones)),
            "the tablet's withdrawal event names the thief's version by name, by the key's cut: \
             {:?}",
            withdrawals[0]
        );
        Ok(())
    })
}
