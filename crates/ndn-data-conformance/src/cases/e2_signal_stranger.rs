//! Signals, e2 — Carol, no member of Alice's spaces, tries to take part in their signals.
//!
//! Alice keeps two spaces with Bob: a board open to anyone to read, which Alice and Bob write,
//! and a sketch sealed to the two of them. Carol's device follows both spaces, but neither
//! names her. Alice and Bob draw on the board.
//!
//! The guards:
//! - Carol's `open` of a run in either space is refused `NotMember`: her device is no member by
//!   what it holds (a reader of an open space is no member; only a writer the members name is),
//!   and her `subscribe` to the sealed sketch is refused `NotMember` too (she is in no audience
//!   of it, so she holds no key to receive with; a reader may receive what members send).
//! - Carol makes packets by hand: a run header for the board signed by her own device key, and
//!   signals under it, pushed into the board's group. Every member refuses them as from
//!   a key no member's (`not_member`), and delivers none.
//! - Carol routes the spaces' group to her own signals, as an eavesdropper on her node
//!   would: the board's and the sketch's packets reach her signals, which deliver nothing, the
//!   sketch's sealed under a key her device holds no copy of (`unknown_key`).

use std::time::Duration;

use ndn_data::Name;
use ndn_packet::encode::DataBuilder;
use ndn_surface::signal::SignalError;

use super::kit::{SETTLE, n, public};
use super::signal_kit::{Peer, group, sealed_to, signal_again, stats, until_counted};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::signal;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e2",
    title: "A stranger takes no part in a folder's signals",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "A device no members record in force names as a writer is refused NotMember when it \
             opens a run in a space's signals, and when it subscribes to a sealed space it is \
             in no audience of; packets it makes by hand under a run header its own key signs \
             are refused by every member as from no member's key and never delivered; and \
             routing the space's group to its own signals delivers it nothing, a sealed space's \
             packets sealed under a key it does not hold.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);
const CAROL: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "tablet");
    p
}

/// Open to anyone to read; Alice and Bob write it.
fn board() -> Name {
    n("/alice/32=data/board")
}

/// Sealed to Alice and Bob.
fn sketch() -> Name {
    n("/alice/32=data/sketch")
}

/// Carol's signal number `i` on the board, made by hand: a run header for her run key signed by
/// her own device key, and the signal under it, signed by the run key; pushed into each of
/// `groups` from her node.
async fn carols_packet(
    w: &World,
    face: &dyn ndn_app::Connection,
    key: &signal::RunKey,
    i: u64,
    groups: &[Name],
) -> Result<(), Failure> {
    let signer = w.signer(CAROL)?;
    let now = w.net().date(CAROL).0;
    let content = signal::header_content(&key.public(), now * 1000, now + 3_600_000);
    let header = DataBuilder::new(
        signal::header_name(&w.net().spec(CAROL).name(), &board(), &key.id()),
        &content,
    )
    .sign_sync(signer.sig_type(), Some(signer.key_name()), |region| {
        signer.sign_sync(region).unwrap_or_default()
    });
    let packet = signal::body(
        &board(),
        &key.id(),
        Some(&header),
        &[signal::Signal {
            seq: now * 1000 + i,
            address: bytes::Bytes::from_static(b"cursor"),
            expires: now + 10_000,
            payload: format!("carol:cursor:{i}").into(),
        }],
        key,
    );
    for g in groups {
        face.send(signal::push(g, &packet))
            .await
            .map_err(|e| Failure::new(format!("carol's node took no packet: {e}")))?;
    }
    Ok(())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let alice_spaces = w.spaces(ALICE);
        w.gesture();
        alice_spaces.create(&board(), public(&["/bob"])).await?;
        w.gesture();
        alice_spaces.create(&sketch(), sealed_to(&["/bob"])).await?;
        let alice = Peer::join(w, ALICE, &board()).await?;
        let bob = Peer::join(w, BOB, &board()).await?;
        let alice_sketch = Peer::join(w, ALICE, &sketch()).await?;
        alice.send("cursor", "alice:cursor:0").await?;
        bob.send("cursor", "bob:cursor:0").await?;

        // Carol's app opens the spaces she was sent; her device follows both, and neither
        // names her.
        let carol = w.spaces(CAROL);
        let signals = w.signals(CAROL).await?;
        for space in [board(), sketch()] {
            w.retry_later(|| carol.open(&space)).await?;
            let opened = signal_again(|| signals.open(&space)).await;
            ensure!(
                matches!(opened, Err(SignalError::NotMember { .. })),
                "carol's open in {space} answered {:?}, not NotMember",
                opened.as_ref().map(|_| "a run")
            );
        }
        let sealed = sketch();
        let sub = signal_again(|| signals.subscribe(&sealed)).await;
        ensure!(
            matches!(sub, Err(SignalError::NotMember { .. })),
            "carol's subscribe to {sealed} answered {:?}, not NotMember",
            sub.as_ref().map(|_| "a subscription")
        );

        // Her packets made by hand, under her own device key's header.
        let face = w.net().app_face(CAROL);
        let key = signal::RunKey::from_seed([0xca; 32]);
        let groups = [group(&board())];
        let mut tries = 0;
        for (d, who) in [(ALICE, "alice"), (BOB, "bob")] {
            let before = stats(w, d).await?.not_member;
            until_counted(
                w,
                d,
                &format!("{who} refusing carol's hand-made packets as from no member"),
                |s| s.not_member > before,
                || {
                    tries += 1;
                    carols_packet(w, &*face, &key, tries, &groups)
                },
            )
            .await?;
        }

        // She routes the spaces' group to her own signals.
        for space in [board(), sketch()] {
            w.listen(CAROL, &group(&space)).await?;
        }
        let before = stats(w, CAROL).await?;
        let (board_run, sketch_run) = (&alice, &alice_sketch);
        let mut i = 0;
        let heard = until_counted(
            w,
            CAROL,
            "carol's signals hearing the board's and the sketch's packets",
            |s| s.unsubscribed > before.unsubscribed && s.unknown_key > before.unknown_key,
            || {
                i += 1;
                async move {
                    board_run
                        .send("cursor", &format!("alice:cursor:{i}"))
                        .await?;
                    sketch_run
                        .send("cursor", &format!("alice:sketch:{i}"))
                        .await?;
                    Ok(())
                }
            },
        )
        .await?;
        ensure!(
            heard.delivered == 0,
            "carol's signals delivered {} signals of folders that do not name her",
            heard.delivered
        );
        w.sleep(SETTLE).await;
        for p in [&alice, &bob] {
            p.check(&[&alice, &bob])?;
            ensure!(
                p.delivered("carol:") == 0,
                "{} delivered carol's hand-made signal",
                p.who
            );
        }
        w.measure(
            "hand-made packets carol pushed until both members refused one",
            tries,
            "packets",
        );
        Ok(())
    })
}
