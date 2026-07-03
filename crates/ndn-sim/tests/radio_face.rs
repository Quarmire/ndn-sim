//! Slice-4 integration (ndn-lab): the named-radio simulated face plugged into real
//! `ForwarderEngine`s. Two nodes exchange a *signed* Interest/Data over a [`RadioBus`] — no
//! wired link, no driver — and the receiving face publishes [`LinkSignals`] (rssi/snr/mcs)
//! into a `SignalsTable`, exactly as the real monitor-wifi face would.
//!
//! Security: default node config keeps the real accept-all validator; the Data is
//! digest-signed and genuinely verified. Nothing disabled.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::encode::InterestBuilder;
use ndn_signals_core::SignalView;
use ndn_sim::{
    FreeSpacePathLoss, NodeId, Position, RadioBus, RadioMcs, SimRadioFace, Simulation, World,
};
use ndn_strategy::signals::SignalsTable;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn two_radios_exchange_signed_data_and_publish_link_signals() {
    // A world with the two nodes a few metres apart ⇒ very high SNR ⇒ reliable at MCS7.
    let world = World::new();
    world.place(NodeId(0), Position::xy(0.0, 0.0));
    world.place(NodeId(1), Position::xy(5.0, 0.0));

    let mut sim = Simulation::new().world(world);
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    let fabric = sim.start().await.unwrap();

    // One shared radio medium over the fabric's world.
    let bus = RadioBus::new(fabric.world(), Arc::new(FreeSpacePathLoss::default()), 0, 7);

    let eng_a = fabric.engine_of(a).unwrap();
    let eng_b = fabric.engine_of(b).unwrap();

    // Attach a radio face to each engine; A's face publishes signals so we can inspect them.
    let signals_a = Arc::new(SignalsTable::new());
    let face_a_id = eng_a.faces().alloc_id();
    let face_a = SimRadioFace::new(face_a_id, a, Arc::clone(&bus), eng_a.runtime())
        .with_mcs(RadioMcs::Fixed(7))
        .with_signals(Arc::clone(&signals_a));
    eng_a.add_face(face_a, CancellationToken::new());

    let face_b_id = eng_b.faces().alloc_id();
    let face_b = SimRadioFace::new(face_b_id, b, Arc::clone(&bus), eng_b.runtime())
        .with_mcs(RadioMcs::Fixed(7));
    eng_b.add_face(face_b, CancellationToken::new());

    // A reaches /app over its radio face; B serves it.
    eng_a
        .fib()
        .add_nexthop(&"/app".parse().unwrap(), face_a_id, 10);

    let producer = eng_b.register_producer("/app", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|interest, responder| async move {
                let _ = responder
                    .respond((*interest.name).clone(), bytes::Bytes::from_static(b"pong"))
                    .await;
            })
            .await;
    });

    // Consumer on A fetches over the air.
    let mut consumer = eng_a.app_consumer(CancellationToken::new());
    let builder = InterestBuilder::new("/app/ping".parse::<ndn_packet::Name>().unwrap())
        .lifetime(Duration::from_secs(10));
    let data = consumer
        .fetch_with(builder)
        .await
        .expect("fetch over radio");
    assert_eq!(
        data.content().map(|c| c.to_vec()).unwrap_or_default(),
        b"pong"
    );

    // A heard B's Data → its radio face published LinkSignals for that face.
    let link = signals_a
        .link(face_a_id)
        .expect("A's radio face published link signals on receive");
    assert!(
        link.rssi_dbm.unwrap() > -60,
        "metres apart ⇒ strong RSSI, got {:?}",
        link.rssi_dbm
    );
    assert_eq!(
        link.ext_get("mcs"),
        Some(7.0),
        "B transmitted at the fixed MCS7"
    );
    assert!(
        link.observed_tput_bps.unwrap() > 60_000_000,
        "MCS7 phy rate surfaced"
    );

    fabric.shutdown().await;
}
