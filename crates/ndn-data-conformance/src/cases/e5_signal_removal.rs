//! Signals, e5 — Alice removes Bob from her sketch space while he draws; later her phone is
//! lost and its key revoked.
//!
//! Alice's laptop (her namespace's root device) creates her sketch space, sealed, with her
//! phone, Bob and Carol, all writers. All four draw. For a while Bob's phone reaches nothing
//! Alice's laptop publishes (its entries), so it learns nothing new of the
//! space, while what it sends still goes out. Alice's laptop removes Bob: from the moment its
//! device holds the entry that removes him — the entry it has just signed — every packet of
//! Bob's that reaches it is refused, and once Carol's device holds the entry, every one that
//! reaches Carol is too. Alice goes on drawing, in the space's new epoch; Bob, whose signals
//! still hear the space's group, receives her packets but cannot open them. Once Bob's
//! phone reaches the laptop again and holds the entry, its own `send`, `open` and `subscribe`
//! answer `NotMember`.
//!
//! Then Alice reports her phone lost and her laptop revokes its key; the revocation reaches
//! Carol's node but not the phone's (a lost device adopts nothing that would stop it), which
//! goes on drawing. Every packet of the phone's that reaches Carol after that is refused.
//!
//! The guards are on signed data's order, not time: the record applied → the next packet of
//! the removed member refused; the revocation held → the next packet of the revoked key
//! refused; the new epoch's packets sealed under a key the removed member does not hold; and
//! nothing refused is ever delivered.

use std::time::Duration;

use super::kit::{LIMIT, SETTLE, holds_key, loss_time, n, same_epoch};
use super::signal_kit::{Peer, pushes, sealed_to, signal_key, stats, until_counted};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::signal;
use crate::spaces::SpaceChange;
use crate::world::{Dev, Plan, World};
use ndn_data::Name;
use ndn_surface::signal::{SignalError, SignalStats};

pub(super) const CASE: Case = Case {
    id: "e5",
    title: "A removed member's and a revoked key's signals are refused",
    slice: 7,
    needs: &[
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Revocation,
        Feature::Signals,
    ],
    model: &[],
    guards: "From the moment a device holds the members record that removes a member, every \
             packet of that member it receives is refused, and once the removed member's own \
             device holds it, its own send answers NotMember; signals sealed in the new epoch \
             cannot be opened by the removed member; and from the moment a node holds the \
             revocation of a device key, every packet of that key it receives is refused. \
             Nothing refused is ever delivered.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const BOB: Dev = Dev(2);
const CAROL: Dev = Dev(3);

/// Whose names Bob's phone is cut off from while it must not learn of its removal: every other
/// device of the space, each of which may publish the owner's entries or hold a copy of them.
const PUBLISHERS: [Dev; 3] = [LAPTOP, PHONE, CAROL];

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("bob", "phone");
    p.device("carol", "tablet");
    p
}

fn folder() -> Name {
    n("/alice/32=data/sketch")
}

/// `from` sends `label:<i>` at `cursor`, one after another, until `rose` holds of `at`'s
/// counters (one of them reached it and was refused). Returns the payloads sent.
async fn until_refused(
    w: &World,
    from: &Peer,
    label: &str,
    at: Dev,
    rose: impl Fn(&SignalStats) -> bool,
) -> Result<Vec<String>, Failure> {
    let mut sent = Vec::new();
    until_counted(
        w,
        at,
        &format!(
            "{} refusing {}'s packets ({label})",
            w.net().spec(at).name(),
            from.who
        ),
        rose,
        || {
            let payload = format!("{label}:{}", sent.len());
            sent.push(payload.clone());
            async move { from.send("cursor", &payload).await.map(|_| ()) }
        },
    )
    .await?;
    Ok(sent)
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let layer = w.spaces(LAPTOP);
        w.gesture();
        layer
            .create(&folder(), sealed_to(&["/bob", "/carol"]))
            .await?;
        let laptop = Peer::join(w, LAPTOP, &folder()).await?;
        let phone = Peer::join(w, PHONE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        let carol = Peer::join(w, CAROL, &folder()).await?;
        let everyone = [&laptop, &phone, &bob, &carol];
        bob.send_final("cursor", "final:bob:cursor:hello", &[&laptop, &carol])
            .await?;
        phone
            .send_final("cursor", "final:phone:cursor:hello", &[&laptop, &carol])
            .await?;
        let (bobs_key, _) = signal_key(w, BOB, &folder())?;
        let tap = w.net().tap(&pushes(&folder())).await;

        // Alice removes Bob; meanwhile his phone reaches nothing of what the other devices
        // publish or hold.
        let mut away = Vec::new();
        for d in PUBLISHERS {
            away.push(w.net().cut_off(BOB, &w.net().spec(d).name()).await);
        }
        w.gesture();
        layer
            .change(
                &folder(),
                SpaceChange {
                    remove: vec![n("/bob")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        let held = layer.members(&folder()).await?;
        ensure!(
            !held.writers.contains(&n("/bob")),
            "alice's laptop does not hold the entry it signed removing bob: {held:?}"
        );
        let before = stats(w, LAPTOP).await?.not_member;
        let to_laptop =
            until_refused(w, &bob, "bob:removed", LAPTOP, |s| s.not_member > before).await?;
        w.until("carol holding the entry removing bob", LIMIT, || async {
            Ok(!w
                .spaces(CAROL)
                .members(&folder())
                .await?
                .writers
                .contains(&n("/bob")))
        })
        .await?;
        let before = stats(w, CAROL).await?.not_member;
        let to_carol = until_refused(w, &bob, "bob:removed-at-carol", CAROL, |s| {
            s.not_member > before
        })
        .await?;

        // The new epoch: Bob hears Alice's packets and cannot open them.
        let before = stats(w, BOB).await?.unknown_key;
        let mut i = 0;
        until_counted(
            w,
            BOB,
            "bob hearing alice's packets of the new epoch, sealed under a key he does not hold",
            |s| s.unknown_key > before,
            || {
                i += 1;
                let laptop = &laptop;
                async move {
                    laptop
                        .send("cursor", &format!("alice:new-epoch:{i}"))
                        .await
                        .map(|_| ())
                }
            },
        )
        .await?;
        let mut new_epoch = 0;
        for wire in tap.interests() {
            let Some(sealed) = signal::pushed(&wire).and_then(|(_, p)| signal::sealed(&p)) else {
                continue;
            };
            if sealed.key_id != bobs_key {
                new_epoch += 1;
            }
        }
        ensure!(
            new_epoch > 0,
            "every packet alice pushed after removing bob was sealed under the key bob holds"
        );

        // Bob's phone fetches again and learns it.
        drop(away);
        w.until(
            "bob's phone holding the entry removing him",
            LIMIT,
            || async {
                Ok(!w
                    .spaces(BOB)
                    .members(&folder())
                    .await?
                    .writers
                    .contains(&n("/bob")))
            },
        )
        .await?;
        let own = bob
            .run
            .lock()
            .await
            .send(b"cursor", b"bob:after-he-knows")
            .await;
        ensure!(
            matches!(own, Err(SignalError::NotMember { .. })),
            "bob's send once his phone holds the record removing him answered {own:?}, not \
             NotMember"
        );
        let signals = w.signals(BOB).await?;
        ensure!(
            matches!(
                signals.open(&folder()).await,
                Err(SignalError::NotMember { .. })
            ) && matches!(
                signals.subscribe(&folder()).await,
                Err(SignalError::NotMember { .. })
            ),
            "bob's open or subscribe once his phone holds the record removing him is not \
             refused NotMember"
        );

        // Alice's phone is lost; her laptop revokes its key, and Carol's node adopts the
        // revocation. The phone's node does not. The laptop, the phone and Carol first hold the
        // key of one epoch in force (the owner's devices each sign an epoch for the readers they
        // see, the greatest is in force): a key not yet granted to the phone would never come
        // once its key is revoked, and the phone would have nothing to seal its packets with;
        // and Carol opens only what is sealed in an epoch she holds.
        let (laptop_spaces, phone_spaces, carol_spaces) =
            (w.spaces(LAPTOP), w.spaces(PHONE), w.spaces(CAROL));
        w.until(
            "the laptop, alice's phone and carol holding the key of one epoch in force",
            LIMIT,
            || async {
                Ok(holds_key(&*phone_spaces, &folder()).await?
                    && holds_key(&*carol_spaces, &folder()).await?
                    && same_epoch(&*laptop_spaces, &*phone_spaces, &folder()).await?
                    && same_epoch(&*laptop_spaces, &*carol_spaces, &folder()).await?)
            },
        )
        .await?;
        // The lost phone reaches nothing that would stop it: not the new epoch the laptop makes
        // once its key is revoked, nor anything else of the other devices'.
        let mut stranded = Vec::new();
        for d in [LAPTOP, BOB, CAROL] {
            stranded.push(w.net().cut_off(PHONE, &w.net().spec(d).name()).await);
        }
        let lost = loss_time(w, LAPTOP).await;
        w.revoke_at(LAPTOP, PHONE, lost).await?;
        w.spread(CAROL).await?;
        // Adopting a revocation lets the revoked key's held run go; its next header is then
        // refused at admission as bad_signature (a revoked key), not per packet as not_member.
        let refusals = |s: &SignalStats| s.not_member + s.bad_signature;
        let before = refusals(&stats(w, CAROL).await?);
        let revoked =
            until_refused(w, &phone, "phone:revoked", CAROL, |s| refusals(s) > before).await?;

        w.sleep(SETTLE).await;
        for p in [&laptop, &carol] {
            p.check(&everyone)?;
        }
        for (at, payloads) in [
            (&laptop, &to_laptop),
            (&carol, &to_carol),
            (&carol, &revoked),
        ] {
            for payload in payloads {
                ensure!(
                    at.delivered(payload) == 0,
                    "{} delivered {payload:?}, sent after it held what refuses its sender",
                    at.who
                );
            }
        }
        ensure!(
            bob.delivered("alice:new-epoch:") == 0,
            "bob delivered a signal alice sealed in the epoch after his removal"
        );
        w.measure(
            "bob's packets until alice's laptop refused one",
            to_laptop.len() as u64,
            "packets",
        );
        Ok(())
    })
}
