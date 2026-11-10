//! Signals, e17 — a scope named in very many words still leaves a full signal its room.
//!
//! Alice names two folders as long as a scope may be named (`SCOPE_MAX` encoded octets, and one
//! octet less): one sealed to her and Bob, one open to them, both writers. In each, Alice and Bob
//! subscribe, open a run and draw: every signal they send has a 64-octet address and a payload of
//! 448, so 512 octets. They end by sending a last such signal until the other acknowledges it.
//! In the open folder the relay between them is tapped.
//!
//! The guards: every member's last signal, whole, reaches the other, in both folders (a name that
//! rode in every packet left none of the room: spec §4.1, §4.3); in the open folder every packet
//! the relay forwarded names its scope by the 16-octet digest of its name and the scope's name
//! rides only beside a run header, once in the header's own name; and a scope one octet longer is
//! refused at `subscribe` and at `open`, with the limit stated.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};
use ndn_surface::signal::{SCOPE_MAX, Signals};

pub(super) const CASE: Case = Case {
    id: "e17",
    title: "A very long scope name leaves a signal of 512 octets its room",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "A signal of 512 octets (address and payload) is delivered whole in a sealed and in \
             an open folder whose names are as long as a scope may be; the packets a relay \
             forwards name the scope by its 16-octet digest, its name only beside a run header; \
             and a scope over the limit is refused at open and subscribe with the limit stated.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// Signals each sends before its last: half a second at 60 Hz.
const MOVES: usize = 30;
/// Octets of the address of every signal, and of its payload.
const ADDRESS: usize = 64;
const PAYLOAD: usize = 448;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p
}

/// Alice's folder whose name takes exactly `octets` encoded octets, in labels of up to 100
/// letters, the first starting with `tag`.
fn folder(octets: usize, tag: char) -> Name {
    // A Name TLV over 252 octets carries a 3-octet length: 4 octets of its own.
    let mut left = octets - 4 - (2 + "alice".len()) - (2 + "data".len());
    let mut labels = Vec::new();
    while left > 0 {
        let take = if left <= 102 {
            left
        } else if left - 102 < 3 {
            left - 3
        } else {
            102
        };
        let letter = if labels.is_empty() { tag } else { 'x' };
        labels.push(letter.to_string().repeat(take - 2));
        left -= take;
    }
    let name = n(&format!("/alice/32=data/{}", labels.join("/")));
    assert_eq!(name.encode_to_tlv().len(), octets, "the folder is exact");
    name
}

/// `text` padded with dots to `len` octets.
fn padded(text: &str, len: usize) -> String {
    assert!(text.len() <= len);
    format!("{text:.<len$}")
}

/// The octets of `scope`'s components, what a header's name holds of it (no Name TLV around).
fn scope_components(scope: &Name) -> Vec<u8> {
    scope
        .components()
        .iter()
        .flat_map(|c| {
            let mut one = vec![c.typ as u8, c.value.len() as u8];
            one.extend_from_slice(&c.value);
            one
        })
        .collect()
}

/// Alice and Bob draw in `scope` (sealed or open) with signals of 512 octets, each ending with
/// a last one the other acknowledged; the relay's taps, if any, are returned.
async fn draw(w: &World, scope: &Name, sealed: bool) -> Result<Vec<bytes::Bytes>, Failure> {
    let share = if sealed {
        sealed_to(&["/alice", "/bob"])
    } else {
        members(Rule::Log, &["/alice", "/bob"], &[])
    };
    w.at(ALICE).share_folder(scope, share.into()).await?;
    let taps = if sealed {
        Vec::new()
    } else {
        let signal = |ns: &str| {
            group(&n(ns)).append_component(ndn_packet::NameComponent::new(
                32,
                bytes::Bytes::from_static(b"signal"),
            ))
        };
        vec![
            w.net().tap(&signal("/alice")).await,
            w.net().tap(&signal("/bob")).await,
        ]
    };
    let alice = Peer::join(w, ALICE, scope).await?;
    let bob = Peer::join(w, BOB, scope).await?;
    let (a_address, b_address) = (
        padded("pointer/alice", ADDRESS),
        padded("pointer/bob", ADDRESS),
    );
    let start = tokio::time::Instant::now();
    for i in 0..MOVES {
        alice
            .send(&a_address, &padded(&format!("alice:{i}:"), PAYLOAD))
            .await?;
        bob.send(&b_address, &padded(&format!("bob:{i}:"), PAYLOAD))
            .await?;
        w.sleep(FRAME).await;
    }
    let finals = [
        (&alice, &bob, &a_address, padded("final:alice:", PAYLOAD)),
        (&bob, &alice, &b_address, padded("final:bob:", PAYLOAD)),
    ];
    for (from, to, address, payload) in &finals {
        from.send_final(address, payload, &[to]).await?;
    }
    w.converged(start.elapsed());
    for (from, to, address, payload) in &finals {
        let got = to.latest(from, address.as_bytes());
        ensure!(
            got.as_ref().is_some_and(|s| {
                s.payload == payload.as_bytes()
                    && s.payload.len() == PAYLOAD
                    && s.address.len() == ADDRESS
                    && s.scope == *scope
            }),
            "{}'s last signal of 512 octets at {address:?} from {} did not arrive whole in the \
             {} folder of {} octets: {got:?}",
            to.who,
            from.who,
            if sealed { "sealed" } else { "open" },
            scope.encode_to_tlv().len()
        );
    }
    for p in [&alice, &bob] {
        p.check(&[&alice, &bob])?;
    }
    Ok(taps.iter().flat_map(|t| t.interests()).collect())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        let sealed = folder(SCOPE_MAX, 's');
        let open = folder(SCOPE_MAX - 1, 'o');
        ensure!(
            Signals::room(&sealed) >= 512 && Signals::room(&open) >= 512,
            "the room of a packet in a scope of {SCOPE_MAX} octets is {}, under 512",
            Signals::room(&sealed)
        );
        draw(w, &sealed, true).await?;
        let seen = draw(w, &open, false).await?;

        // What the relay forwarded of the open folder: the digest of its name in every
        // packet, its name only beside a run header and once there.
        let digest = signal::scope_digest(&open);
        let components = scope_components(&open);
        let (mut with_header, mut without, mut largest) = (0u64, 0u64, 0usize);
        for wire in &seen {
            let (_, packet) = signal::pushed(wire).ok_or_else(|| {
                Failure::new("the relay forwarded a signal Interest that is no push")
            })?;
            let body = signal::parse_body(&packet).ok_or_else(|| {
                Failure::new(format!(
                    "a packet of the open folder the relay forwarded is no SignalBody of the \
                     wire: {} octets",
                    packet.len()
                ))
            })?;
            ensure!(
                body.digest == digest,
                "a packet of the open folder names the scope digest {:02x?}, not the digest of \
                 its name {digest:02x?}",
                body.digest
            );
            let times = packet
                .windows(components.len())
                .filter(|w| *w == components.as_slice())
                .count();
            if body.header.is_some() {
                with_header += 1;
                ensure!(
                    times == 1,
                    "a packet carrying a run header holds the scope's name {times} times, not \
                     once (in the header's name)"
                );
            } else {
                without += 1;
                ensure!(
                    times == 0,
                    "a packet without a run header holds the scope's name: {} octets",
                    packet.len()
                );
            }
            largest = largest.max(packet.len());
        }
        ensure!(
            with_header > 0 && without > 0,
            "the relay forwarded {with_header} packets with a header and {without} without: \
             the check saw only one kind"
        );

        // One octet over the limit: refused, saying so.
        let over = folder(SCOPE_MAX + 1, 'z');
        let signals = w.signals(ALICE).await?;
        for (verb, refused) in [
            ("subscribe", signals.subscribe(&over).await.err()),
            ("open", signals.open(&over).await.err()),
        ] {
            match refused {
                Some(SignalError::ScopeTooLong { size, max, .. })
                    if (size, max) == (SCOPE_MAX + 1, SCOPE_MAX) => {}
                other => {
                    return Err(Failure::new(format!(
                        "{verb} of a scope of {} octets, one over the limit of {SCOPE_MAX}, \
                         answered {other:?}, not ScopeTooLong naming the limit",
                        SCOPE_MAX + 1
                    )));
                }
            }
        }
        w.measure(
            "largest packet of a 512-octet signal",
            largest as u64,
            "octets",
        );
        w.measure("packets the relay forwarded", seen.len() as u64, "packets");
        Ok(())
    })
}
