//! Follow-on integration (ndn-lab): radios declared on the `Simulation` builder. A scenario
//! says "these nodes have radios on a shared medium at these positions" and `start()` wires the
//! shared `RadioBus`, attaches a `SimRadioFace` per node, and publishes each node's `LinkSignals`
//! into its own engine signal table — no manual face plumbing.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_signals_core::SignalView;
use ndn_sim::{FreeSpacePathLoss, Position, Simulation};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn builder_attaches_radios_and_two_nodes_exchange_over_the_air() {
    // A two-node radio mesh declared entirely on the builder.
    let mut sim = Simulation::new().with_radio_medium(Arc::new(FreeSpacePathLoss::default()), 7);
    let a = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
    let b = sim.add_radio_node(EngineConfig::default(), Position::xy(5.0, 0.0)); // metres apart
    let fabric = sim.start().await.unwrap();

    // A reaches /app over its radio face; B serves it.
    fabric.route_over_radio(a, &"/app".parse::<Name>().unwrap()).unwrap();

    let eng_b = fabric.engine_of(b).unwrap();
    let producer = eng_b.register_producer("/app", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r.respond((*i.name).clone(), bytes::Bytes::from_static(b"pong")).await;
            })
            .await;
    });

    let eng_a = fabric.engine_of(a).unwrap();
    let mut consumer = eng_a.app_consumer(CancellationToken::new());
    let builder = InterestBuilder::new("/app/ping".parse::<Name>().unwrap())
        .lifetime(Duration::from_secs(10));
    let data = consumer.fetch_with(builder).await.expect("fetch over builder-wired radio");
    assert_eq!(data.content().map(|c| c.to_vec()).unwrap_or_default(), b"pong");

    // A's own engine signal table was populated by its radio face on receive.
    let face = fabric.radio_face(a).unwrap();
    let link = eng_a
        .signals()
        .link(face)
        .expect("radio face published LinkSignals into the engine's own table");
    assert!(link.rssi_dbm.unwrap() > -60, "metres apart ⇒ strong RSSI");
    assert!(link.ext_get("mcs").is_some(), "mcs surfaced as an ext signal");

    // The scene exposes radio reachability edges (RSSI) — "links light up by RSSI".
    let scene = fabric.scene_snapshot();
    assert_eq!(scene.radio_links.len(), 1, "two in-range radios ⇒ one RSSI edge");
    assert!(scene.radio_links[0].rssi_dbm > -60.0, "metres apart ⇒ strong RSSI");

    fabric.shutdown().await;
}
