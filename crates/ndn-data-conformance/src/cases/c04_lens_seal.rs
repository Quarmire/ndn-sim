//! Case 4 — Calendar shows meeting notes.
//!
//! Alice opens a meeting in Calendar and points it at her notes for that meeting. The draft's seal
//! example named an app as audience, which brings back per-app keys and prompts. The fix (M4): seal
//! audiences are people, devices and groups; lenses hold no keys; the host opens exactly what the
//! person pointed at and hands that to the lens. (That an app can never be named is enforced by
//! the type: `ndn_data::Audience` has no app variant.)

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c4",
    title: "Calendar shows meeting notes",
    slice: 2,
    needs: &[Feature::Merge, Feature::Seal],
    model: &["M4"],
    guards: "Seal audiences are people, devices and groups: the host opens the note the person \
             pointed at, opening it adds no audience, and a device outside the audience cannot \
             read it.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const HOST: Dev = Dev(0);
const BOB: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let notes = n("/alice/32=data/notes/meeting-0412");
        let (host, bob) = (w.at(HOST), w.at(BOB));
        let audience = ndn_data::Seal {
            any_of: vec![person("/alice")],
        };
        host.share(&notes, members(merge(), &["/alice"], &audience.any_of))
            .await?;
        let id = host.put(&notes, text("agenda: budget"), note(1)).await?;

        // Alice points Calendar at the note: the host opens it and hands the value to the lens.
        w.gesture();
        let opened = state(&*host, &notes).await?;
        ensure!(
            opened.at.contains(&id) && field(&opened.value, "text") == Some("agenda: budget"),
            "the host could not open the note Alice pointed at"
        );

        let after = look(&*host, &notes, &Frontier::new(), LOOK).await?;
        let v = version(&after, &id).ok_or_else(|| Failure::new("watch does not list the note"))?;
        ensure!(
            v.seal == audience,
            "the note's seal is {:?} after the lens read it; it must stay {:?}",
            v.seal,
            audience
        );

        w.sleep(SETTLE).await;
        match bob.get(&notes).await {
            Err(ndn_data::DataError::Sealed { .. })
            | Err(ndn_data::DataError::Unavailable { .. })
            | Err(ndn_data::DataError::NotFound { .. }) => {}
            Ok(answer) => {
                return Err(Failure::new(format!(
                    "a device outside the seal read the note: {:?}",
                    answer.got
                )));
            }
            Err(e) => return Err(e.into()),
        }
        Ok(())
    })
}
