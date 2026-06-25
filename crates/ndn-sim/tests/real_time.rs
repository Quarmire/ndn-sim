//! Real-time governor (ndn-lab): the continuum keystone — real pace (so real devices can
//! participate) with a logical, scenario-relative clock through the Runtime seam. (The
//! foreign-device half is proven in `interop_ndnd.rs`; this checks the kernel's contract.)

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{LinkConfig, NodeId, RealTimeKernel, SimKernel, Simulation};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn governor_runs_a_fabric_on_a_logical_clock_at_real_pace() {
    let mut sim = Simulation::new().kernel(RealTimeKernel::new() as Arc<dyn SimKernel>);
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    sim.link(a, b, LinkConfig::lan());
    sim.add_route(a, "/app", b);
    let fabric = sim.start().await.unwrap();

    // The clock is logical (scenario-relative epoch), not the absolute system clock: it reads
    // well below "now" since the governor's epoch is fixed (~2023) + only real elapsed since start.
    let logical = fabric.engine_of(a).unwrap().runtime().unix_nanos();
    let real_now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64;
    assert!(logical < real_now, "logical clock ({logical}) is scenario-relative, not the wall clock");
    assert!(logical >= 1_700_000_000_000_000_000, "logical epoch base present");

    // Both engines share the one kernel clock.
    let logical_b = fabric.engine_of(b).unwrap().runtime().unix_nanos();
    assert!(logical_b.abs_diff(logical) < 1_000_000_000, "engines share one clock");

    // And a real exchange works at real pace (real I/O — what lets a real device join).
    let producer = fabric.engine_of(b).unwrap().register_producer("/app", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r.respond((*i.name).clone(), bytes::Bytes::from_static(b"pong")).await;
            })
            .await;
    });
    let mut consumer = fabric.engine_of(a).unwrap().app_consumer(CancellationToken::new());
    let builder = InterestBuilder::new("/app/ping".parse::<Name>().unwrap()).lifetime(Duration::from_secs(5));
    let data = consumer.fetch_with(builder).await.expect("exchange under the governor");
    assert_eq!(data.content().map(|c| c.to_vec()).unwrap_or_default(), b"pong");

    // Scene/metrics use the logical clock too (consistent telemetry base).
    let _ = fabric.engine_of(NodeId(0));
    assert!(fabric.scene_snapshot().virtual_time_ns < real_now);

    fabric.shutdown().await;
}
