//! Signals, e5 — Alice removes Bob from her sketch folder while he draws; later her phone is
//! lost and its key revoked.
//!
//! Alice's laptop (her namespace's root device) shares her sketch folder, sealed, with her
//! phone, Bob and Carol, all writers. All four draw. For a while Bob's phone reaches nothing
//! Alice's laptop publishes (its records, its summaries), so it learns nothing new of the
//! folder, while what it sends still goes out. Alice's laptop removes Bob: from the moment its
//! device holds the record that removes him — the record it has just signed — every packet of
//! Bob's that reaches it is refused, and once Carol's device holds the record, every one that
//! reaches Carol is too. Alice goes on drawing, in the folder's new epoch; Bob, who routes
//! Alice's group to his own signals, receives her packets but cannot open them. Once Bob's
//! phone reaches the laptop again and holds the record, its own `send`, `open` and `subscribe`
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

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

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

/// What Bob's phone is cut off from while it must not learn of its removal: what Alice's laptop
/// publishes.
fn laptops_names() -> Name {
    n("/alice/laptop")
}

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
        let layer = w.at(LAPTOP);
        w.gesture();
        layer
            .share_folder(&folder(), sealed_to(&["/alice", "/bob", "/carol"]).into())
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
        let alice_group = group(&n("/alice"));
        w.listen(BOB, &alice_group).await?;
        let tap = w
            .net()
            .tap(
                &alice_group
                    .clone()
                    .append_component(ndn_packet::NameComponent::new(
                        32,
                        bytes::Bytes::from_static(b"signal"),
                    )),
            )
            .await;

        // Alice removes Bob; meanwhile his phone reaches nothing of her laptop's.
        let away = w.net().cut_off(BOB, &laptops_names()).await;
        w.gesture();
        layer
            .share_folder(&folder(), sealed_to(&["/alice", "/carol"]).into())
            .await?;
        let held = layer.members(&folder()).await?;
        ensure!(
            !held.writers.contains(&n("/bob")),
            "alice's laptop does not hold the record it signed removing bob: {held:?}"
        );
        let before = stats(w, LAPTOP).await?.not_member;
        let to_laptop =
            until_refused(w, &bob, "bob:removed", LAPTOP, |s| s.not_member > before).await?;
        w.until("carol holding the record removing bob", LIMIT, || async {
            Ok(!w
                .at(CAROL)
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
        away.restore();
        w.until(
            "bob's phone holding the record removing him",
            LIMIT,
            || async {
                Ok(!w
                    .at(BOB)
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
        // revocation. The phone's node does not.
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
