//! A **named-radio fabric on the discrete-event executor** (ndn-lab): RadioBus + SimRadioFace +
//! ndn-app producer/consumer, all on the from-scratch `DesKernel` event queue. Completes axis 1 —
//! every face type (wired + radio) now runs event-stepped / deterministic on virtual event-time.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{AppSpec, DesKernel, FreeSpacePathLoss, Position, SimKernel, Simulation};
use tokio_util::sync::CancellationToken;

fn radio_exchange() -> Vec<u8> {
    DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        // Two radio nodes 5 m apart on a shared free-space medium, on the DES kernel.
        let mut sim = Simulation::new()
            .kernel(k)
            .with_radio_medium(Arc::new(FreeSpacePathLoss::default()), 7);
        let a = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let b = sim.add_radio_node(EngineConfig::default(), Position::xy(5.0, 0.0));
        sim.add_app(
            b,
            AppSpec::Producer {
                prefix: "/svc".into(),
                content: Some("air".into()),
                freshness_ms: None,
            },
        );
        let fabric = sim.start().await.unwrap();

        // A reaches /svc over its radio face; the exchange broadcasts over the event queue.
        fabric
            .route_over_radio(a, &"/svc".parse::<Name>().unwrap())
            .unwrap();
        let mut consumer = fabric
            .engine_of(a)
            .unwrap()
            .app_consumer(CancellationToken::new());
        let builder = InterestBuilder::new("/svc/0".parse::<Name>().unwrap())
            .lifetime(Duration::from_secs(20));
        let data = consumer
            .fetch_with(builder)
            .await
            .expect("fetch over radio on DES");
        let out = data.content().map(|c| c.to_vec()).unwrap_or_default();
        fabric.shutdown().await;
        out
    })
}

#[test]
fn radio_fabric_exchanges_over_the_des_event_queue() {
    assert_eq!(
        radio_exchange(),
        b"air",
        "Interest+Data crossed the radio medium on the event queue"
    );
}

#[test]
fn radio_fabric_replays_deterministically_on_des() {
    assert_eq!(
        radio_exchange(),
        radio_exchange(),
        "radio fabric replays identically on the event queue"
    );
}
