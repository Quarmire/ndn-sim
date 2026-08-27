//! `broadcast_segment` (DX feedback #3): a collision-free all-hear-all bus for sync/discovery, with
//! no Position / path-loss to reason about. Members exchange over a perfect medium.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{AppSpec, DesKernel, SimKernel, Simulation};
use tokio_util::sync::CancellationToken;

/// A producer on one member, a consumer on another — the fetch crosses the broadcast segment with
/// no geometry declared. Deterministic on DES.
#[test]
fn broadcast_segment_delivers_without_geometry() {
    let got = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new().without_radio_interference().kernel(k);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        let c = sim.add_node(EngineConfig::default());
        sim.add_app(
            a,
            AppSpec::Producer {
                prefix: "/time".into(),
                content: Some("tick".into()),
                freshness_ms: Some(1000),
            },
        );
        // One call: a, b, c all hear each other on /time — no with_radio_medium, no positions.
        sim.broadcast_segment(&[a, b, c], "/time");
        let fabric = sim.start().await.unwrap();

        // True all-hear-all: BOTH other members fetch the producer over the one shared segment.
        let mut cb = fabric
            .engine_of(b)
            .unwrap()
            .app_consumer(CancellationToken::new());
        let ok_b = cb
            .fetch_with(
                InterestBuilder::new("/time/0".parse::<Name>().unwrap())
                    .lifetime(Duration::from_secs(4)),
            )
            .await
            .is_ok();
        let mut cc = fabric
            .engine_of(c)
            .unwrap()
            .app_consumer(CancellationToken::new());
        let ok_c = cc
            .fetch_with(
                InterestBuilder::new("/time/1".parse::<Name>().unwrap())
                    .lifetime(Duration::from_secs(4)),
            )
            .await
            .is_ok();
        fabric.shutdown().await;
        ok_b && ok_c
    });
    assert!(
        got,
        "both b and c fetched the producer on a over the collision-free broadcast segment"
    );
}
