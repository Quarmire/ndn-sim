//! Signals, e7 — signals leave nothing behind in any store.
//!
//! Alice and Bob draw together in Alice's sealed sketch folder, each sending cursor moves and
//! presence until the other has seen their last. Every link counts what crosses it by name.
//!
//! The guard: afterwards no forwarder's content store — the relay's, Alice's node's, Bob's
//! node's — and no device's data store holds any packet with a `32=signal` component in its
//! name; no Data under such a name ever crossed a link (only push Interests did); and asking
//! the network for a run header by its name gets nothing back, as no one serves or caches one.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "e7",
    title: "No store keeps a signal",
    slice: 7,
    needs: &[Feature::Seal, Feature::FolderMembers, Feature::Signals],
    model: &[],
    guards: "A signal is never Data and never stored: after signals flowed, no forwarder's \
             content store and no device's store holds a packet named under 32=signal, no Data \
             under such a name crossed any link, and no one answers a run header's name.",
    budget: Duration::from_secs(3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    // Deep enough to name `32=signal` in a push (`<ns>/32=sync/32=signal/<digest>`) and in a run
    // header's name (`<ns>/<device>/32=signal/<scope>…`).
    p.count_names(4);
    p
}

fn folder() -> Name {
    n("/alice/32=data/sketch")
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        w.gesture();
        w.at(ALICE)
            .share_folder(&folder(), sealed_to(&["/alice", "/bob"]).into())
            .await?;
        let tap = w
            .net()
            .tap(
                &group(&n("/bob")).append_component(ndn_packet::NameComponent::new(
                    32,
                    bytes::Bytes::from_static(b"signal"),
                )),
            )
            .await;
        let alice = Peer::join(w, ALICE, &folder()).await?;
        let bob = Peer::join(w, BOB, &folder()).await?;
        for i in 0..30 {
            alice.send("cursor", &format!("alice:cursor:{i}")).await?;
            bob.send("cursor", &format!("bob:cursor:{i}")).await?;
            w.sleep(FRAME).await;
        }
        alice
            .send_final("presence", "final:alice:presence:here", &[&bob])
            .await?;
        bob.send_final("presence", "final:bob:presence:here", &[&alice])
            .await?;
        w.sleep(SETTLE).await;

        let cached: Vec<Name> = w
            .net()
            .cached()
            .await
            .into_iter()
            .filter(signal::names_signal)
            .collect();
        ensure!(
            cached.is_empty(),
            "a content store holds packets named under 32=signal: {cached:?}"
        );
        for d in [ALICE, BOB] {
            let stored: Vec<Name> = w
                .stored_names(d)?
                .into_iter()
                .filter(signal::names_signal)
                .collect();
            ensure!(
                stored.is_empty(),
                "{}'s data layer stores packets named under 32=signal: {stored:?}",
                w.net().spec(d).name()
            );
        }
        let rows = w.net().traffic();
        // `32=signal` as the counters write names.
        let marker = n("/32=signal").to_string();
        let data: Vec<_> = rows
            .iter()
            .filter(|r| r.prefix.contains(&marker))
            .filter(|r| r.counters.out_data + r.counters.in_data > 0)
            .collect();
        ensure!(
            data.is_empty(),
            "Data named under 32=signal crossed a link: {data:?}"
        );
        let pushes: u64 = rows
            .iter()
            .filter(|r| r.prefix.contains(&marker))
            .map(|r| r.counters.in_interests)
            .sum();
        ensure!(
            pushes > 0,
            "no signal push crossed a link: the case flowed no signals"
        );

        // A run header rides inside the packets only: no one answers its name.
        let (_, key) = signal_key(w, BOB, &folder())?;
        let alice_run = alice.run_id().await;
        let header = tap
            .interests()
            .iter()
            .filter_map(|wire| opened(wire, &key))
            .filter(|b| b.run == alice_run)
            .find_map(|b| b.header)
            .ok_or_else(|| Failure::new("no packet of alice's run carried its header"))?;
        let name = (*ndn_packet::Data::decode(header)
            .map_err(|e| Failure::new(format!("alice's run header does not decode: {e:?}")))?
            .name)
            .clone();
        ensure!(
            !w.net().ask_at_hub(&name).await,
            "something answered alice's run header by its name {name}"
        );
        for p in [&alice, &bob] {
            p.check(&[&alice, &bob])?;
        }
        w.measure(
            "signal push Interests counted on links",
            pushes,
            "Interests",
        );
        Ok(())
    })
}
