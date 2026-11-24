//! Signals, e16 — revoking the issuer of a sender's key ends its held run.
//!
//! Alice made a recovery kit when she set up her namespace. Her root is compromised, and the
//! attacker certifies with it a key of its own under her namespace, an "intruder" device (as in
//! k10). Alice's board is public and names Alice and Bob as writers (persons, by their
//! namespaces), so the intruder is a member. The intruder opens a run and draws; Alice's laptop
//! holds its run. Alice recovers
//! with the kit: the new trust-context version revokes the old root — the only issuer of the
//! intruder's key — and her laptop renews with the new root. The intruder draws on.
//!
//! The guards: from the moment the laptop holds the recovery, none of the intruder's later
//! signals is delivered there — its held run ends at once, not at its next header or its end
//! (spec §8.1 step 7, data-layer §20) — and its header, riding again, is refused.

use std::time::Duration;

use ndn_data::Name;
use ndn_surface::signal::SignalStats;

use super::kit::{LIMIT, n, public};
use super::signal_kit::{FRAME, Peer, RESEND, dropped, stats};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e16",
    title: "Revoking a sender's issuer ends its held run",
    slice: 7,
    needs: &[
        Feature::FolderMembers,
        Feature::Revocation,
        Feature::Recovery,
        Feature::Signals,
    ],
    model: &[],
    guards: "From the moment a receiver holds the trust-context version revoking the issuer of \
             a sender's key, none of that sender's held run's signals is delivered, without \
             waiting for the run's next header or its end, and its header is refused.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const INTRUDER: Dev = Dev(1);
/// The intruder's frames after the recovery: three seconds at 60 Hz, so its header rides again.
const FRAMES: u32 = 180;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    // A key the attacker certified with Alice's compromised root: the harness certifies every
    // planned device by its person's root, which is exactly what the attacker could do.
    p.device("alice", "intruder");
    p
}

fn board() -> Name {
    n("/alice/32=data/board")
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.recovery_kit(LAPTOP).await?;
        w.gesture();
        w.spaces(LAPTOP).create(&board(), public(&["/bob"])).await?;
        let laptop = Peer::join(w, LAPTOP, &board()).await?;
        let intruder = Peer::join(w, INTRUDER, &board()).await?;
        for i in 0..10 {
            intruder
                .send("cursor", &format!("intruder:cursor:{i}"))
                .await?;
            w.sleep(FRAME).await;
        }
        intruder
            .send_final("cursor", "final:intruder:cursor:before", &[&laptop])
            .await?;

        // Alice recovers: the old root is revoked; her laptop renews with the new one.
        w.recover(LAPTOP).await?;
        w.gesture();
        w.renew(LAPTOP).await?;

        // The intruder draws on for three seconds, so its header rides again. Its own device may
        // refuse to send once it learns of the recovery: its run ended there, which is no
        // delivery either. A header that rides again is judged once its certificate chain has
        // been walked, which on a lossy network takes seconds more: the intruder draws on, one
        // signal at a time, until the laptop counts the refusal.
        let refusals = |s: &SignalStats| s.not_member + s.bad_signature;
        let before = stats(w, LAPTOP).await?;
        let (mut sent, mut stopped) = (0u32, false);
        for i in 0..FRAMES {
            if intruder
                .send("cursor", &format!("intruder:after:{i}"))
                .await
                .is_err()
            {
                stopped = true;
                break;
            }
            sent += 1;
            w.sleep(FRAME).await;
        }
        let start = tokio::time::Instant::now();
        let mut now = stats(w, LAPTOP).await?;
        while !stopped && refusals(&now) == refusals(&before) && start.elapsed() < LIMIT {
            w.sleep(RESEND).await;
            if intruder
                .send("cursor", &format!("intruder:after:{sent}"))
                .await
                .is_err()
            {
                stopped = true;
            }
            sent += 1;
            now = stats(w, LAPTOP).await?;
        }
        w.sleep(Duration::from_secs(2)).await;
        let delivered = laptop.delivered("intruder:after:");
        let now = stats(w, LAPTOP).await?;
        ensure!(
            delivered == 0,
            "alice's laptop, holding the recovery that revokes the intruder's issuer, delivered \
             {delivered} of the {sent} signals the intruder sent after it: its held run went on"
        );
        ensure!(
            stopped || refusals(&now) > refusals(&before),
            "alice's laptop never refused the intruder's header, which rode again while it sent \
             {sent} signals over three seconds and {:?} more ({now:?})",
            start.elapsed()
        );
        w.measure(
            "intruder's packets the laptop dropped",
            dropped(&now) - dropped(&before),
            "packets",
        );
        Ok(())
    })
}
