//! Authenticated control-over-NDN (Task #7): with `require_signed_control` installed, a mutating
//! command carried over `/localhop/sim/control` must ride a **signed Interest** the validator
//! accepts. This is the NDN-native answer to actuation security — the command is authenticated by
//! its signature, not by trusting the transport. Read-only queries stay open.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_security::KeyChain;
use ndn_sim::{ControlPlane, NodeId, SimResponse, Simulation};
use tokio_util::sync::CancellationToken;

const CONTROL: &str = "/localhop/sim/control";

/// Fetch a reply for a signed Interest (wire built by the KeyChain) and decode the `SimResponse`.
async fn ask_signed(consumer: &mut ndn_app::Consumer, wire: Bytes) -> SimResponse {
    let data = consumer
        .fetch_wire(wire, Duration::from_secs(5))
        .await
        .expect("control reply");
    let bytes = data.content().map(|c| c.to_vec()).unwrap_or_default();
    serde_json::from_slice::<SimResponse>(&bytes).expect("parse SimResponse")
}

/// Fetch a reply for a plain (unsigned) Interest.
async fn ask_unsigned(consumer: &mut ndn_app::Consumer, json: &[u8]) -> SimResponse {
    let builder = InterestBuilder::new(CONTROL.parse::<Name>().unwrap())
        .app_parameters(json.to_vec())
        .lifetime(Duration::from_secs(5));
    let data = consumer.fetch_with(builder).await.expect("control reply");
    let bytes = data.content().map(|c| c.to_vec()).unwrap_or_default();
    serde_json::from_slice::<SimResponse>(&bytes).expect("parse SimResponse")
}

#[tokio::test]
async fn signed_commands_are_required_over_ndn() {
    let mut sim = Simulation::new();
    let _a = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));

    // The admin identity is a prefix of the control name, so the hierarchical trust schema
    // authorizes it to sign `/localhop/sim/control` commands.
    let admin = KeyChain::ephemeral(CONTROL).expect("ephemeral admin keychain");
    control.require_signed_control(Arc::new(admin.validator()));

    let engine = fabric.engine_of(NodeId(0)).unwrap();
    control.serve_ndn(&engine, CancellationToken::new());
    let mut consumer = engine.app_consumer(CancellationToken::new());

    // 1. An UNSIGNED mutating command is rejected — the fabric never grows.
    let resp = ask_unsigned(&mut consumer, br#"{"command":{"cmd":"spawn_node"}}"#).await;
    assert!(
        matches!(resp, SimResponse::Error { .. }),
        "unsigned command must be rejected, got {resp:?}"
    );

    // 2. A read-only QUERY is open even unsigned (observability isn't gated).
    let resp = ask_unsigned(&mut consumer, br#"{"query":{"query":"topology"}}"#).await;
    let SimResponse::Topology(topo) = resp else {
        panic!("expected topology, got {resp:?}")
    };
    assert_eq!(
        topo.nodes.len(),
        1,
        "the rejected command did not spawn a node"
    );

    // 3. A SIGNED mutating command by the trusted admin key is accepted.
    let signed = admin
        .sign_interest(
            InterestBuilder::new(CONTROL.parse::<Name>().unwrap())
                .app_parameters(br#"{"command":{"cmd":"spawn_node","label":"drone"}}"#.to_vec())
                .lifetime(Duration::from_secs(5)),
        )
        .expect("sign the control Interest");
    let resp = ask_signed(&mut consumer, signed).await;
    assert!(
        matches!(resp, SimResponse::Node { id: 1 }),
        "signed command accepted, got {resp:?}"
    );

    // 4. The signed command took effect: the fabric grew.
    let resp = ask_unsigned(&mut consumer, br#"{"query":{"query":"topology"}}"#).await;
    let SimResponse::Topology(topo) = resp else {
        panic!("expected topology")
    };
    assert_eq!(
        topo.nodes.len(),
        2,
        "the authenticated spawn grew the fabric"
    );

    fabric.shutdown().await;
}
