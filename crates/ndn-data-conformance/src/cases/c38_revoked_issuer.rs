//! Channels, c38 — revoking the issuer of a sender's key ends the session held of it.
//!
//! Alice made a recovery kit when she set up her namespace. Her root is compromised, and the
//! attacker certifies with it a key of its own under her namespace, an "intruder" device (as in
//! k10). Alice's space is public and names Alice, so the intruder, a device of her person, is a
//! writer. Alice's laptop asks the intruder for its channel and receives what it emits. Alice
//! recovers with the kit: the new trust-context version revokes the old root, the only issuer of
//! the intruder's key, and her laptop renews with the new root. The intruder emits on.
//!
//! The guard: from the moment the laptop holds the recovery, its session of the intruder is over,
//! and its stream says why (`NotMember`: the sender no longer stands); none of the intruder's
//! later emissions is given to it, though the intruder sends them; and a new ask of the intruder
//! is refused.

use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;

use super::channel_kit::{EMIT_EVERY, Listener, emit_until_seen, space, transient};
use super::kit::{LIMIT, n, public};
use crate::case::{Case, CaseFuture};
use crate::channel::{ChannelEvent, ChannelTrust};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c38",
    title: "Revoking a sender's issuer ends the session held of it",
    slice: 8,
    needs: &[Feature::Channels, Feature::Revocation, Feature::Recovery],
    model: &[],
    guards: "From the moment a receiver holds the trust-context version revoking the issuer of \
             a sender's key, its session of that sender is ended with the reason, none of the \
             sender's later emissions is given to it, and a new ask of that sender is refused.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const INTRUDER: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    // A key the attacker certified with Alice's compromised root: the harness certifies every
    // planned device by its person's root, which is exactly what the attacker could do.
    p.device("alice", "intruder");
    p
}

fn cursor() -> Name {
    n("/cursor")
}

/// The end of a session the stream told, if it did: its index among `events` and its words.
fn ended(l: &Listener) -> Option<(usize, &str)> {
    l.events.iter().enumerate().find_map(|(i, e)| match e {
        ChannelEvent::Ended { why } => Some((i, why.as_str())),
        _ => None,
    })
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.recovery_kit(LAPTOP).await?;
        w.gesture();
        w.spaces(LAPTOP).create(&space(), public(&[])).await?;
        let mut laptop = Listener::prepare(w, LAPTOP, ChannelTrust::Prompt).await?;
        let intruder = Listener::prepare(w, INTRUDER, ChannelTrust::Prompt).await?;
        laptop.establish(w, INTRUDER).await?;
        emit_until_seen(w, &intruder.ch, &cursor(), "before", &mut [&mut laptop]).await?;

        // Alice recovers: the old root is revoked; her laptop renews with the new one.
        w.recover(LAPTOP).await?;
        w.gesture();
        w.renew(LAPTOP).await?;

        // The intruder emits on (its own device may refuse once it learns of the recovery,
        // which is no delivery either) until the laptop's stream says the session is over.
        let start = tokio::time::Instant::now();
        let mut sent = 0u64;
        while ended(&laptop).is_none() {
            let _ = intruder
                .ch
                .emit(&space(), &cursor(), Bytes::from(format!("during:{sent}")))
                .await;
            sent += 1;
            w.sleep(EMIT_EVERY).await;
            laptop.pump();
            ensure!(
                start.elapsed() < LIMIT,
                "alice's laptop, holding the recovery that revokes the intruder's issuer, still \
                 holds its session of the intruder after {LIMIT:?} of virtual time: {:?}",
                laptop.events
            );
        }
        let (end, why) = ended(&laptop).expect("the loop ended on it");
        // A lossy network may end the session first (the stream says so as it does for any
        // receiver); the recovery's own end names the sender no longer standing.
        ensure!(
            why.contains("NotMember") || transient(why),
            "the laptop's session of the intruder ended, but for {why:?}, not because the sender \
             no longer stands (NotMember)"
        );

        // Later emissions are not given, and a new ask is refused.
        for k in 0..20 {
            let _ = intruder
                .ch
                .emit(&space(), &cursor(), Bytes::from(format!("late:{k}")))
                .await;
            w.sleep(EMIT_EVERY).await;
            laptop.pump();
        }
        let given = laptop.events[end..]
            .iter()
            .filter(|e| matches!(e, ChannelEvent::Message { .. }))
            .count();
        ensure!(
            given == 0 && !laptop.has_stem(&cursor(), b"late:"),
            "alice's laptop, holding the recovery that revokes the intruder's issuer, was given \
             {given} messages of the intruder after its session ended: {:?}",
            &laptop.events[end..]
        );
        let again = laptop.ask(w, INTRUDER).await;
        ensure!(
            again.is_err(),
            "alice's laptop was given a session by the intruder, whose issuer her recovery \
             revoked: {again:?}"
        );
        w.measure(
            "messages the intruder emitted after the recovery",
            sent + 20,
            "messages",
        );
        Ok(())
    })
}
