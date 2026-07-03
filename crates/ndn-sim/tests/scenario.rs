//! Follow-on integration (ndn-lab): a declarative scenario file builds a working fabric. Load
//! TOML → `Scenario::build(kernel)` → `start()` → a real signed Interest/Data exchange. This is
//! the `ndn-lab run scenario.toml` path the front-ends presuppose.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{NodeId, Scenario, SimKernel, VirtualKernel, WallClockKernel};
use tokio_util::sync::CancellationToken;

const LINE: &str = r#"
[[nodes]]
label = "consumer"

[[nodes]]
label = "producer"

[[links]]
a = 0
b = 1
delay_ms = 5

[[routes]]
node = 0
prefix = "/app"
nexthop = 1
"#;

#[tokio::test]
async fn scenario_toml_builds_a_runnable_fabric() {
    let scenario = Scenario::from_toml(LINE).unwrap();
    let kernel: Arc<dyn SimKernel> = Arc::new(WallClockKernel::new());
    let fabric = scenario.build(kernel).unwrap().start().await.unwrap();

    assert_eq!(fabric.topology().nodes.len(), 2);

    let producer = fabric
        .engine_of(NodeId(1))
        .unwrap()
        .register_producer("/app", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r
                    .respond((*i.name).clone(), bytes::Bytes::from_static(b"pong"))
                    .await;
            })
            .await;
    });

    let mut consumer = fabric
        .engine_of(NodeId(0))
        .unwrap()
        .app_consumer(CancellationToken::new());
    let builder = InterestBuilder::new("/app/ping".parse::<Name>().unwrap())
        .lifetime(Duration::from_secs(10));
    let data = consumer
        .fetch_with(builder)
        .await
        .expect("fetch in scenario-built fabric");
    assert_eq!(
        data.content().map(|c| c.to_vec()).unwrap_or_default(),
        b"pong"
    );

    fabric.shutdown().await;
}

/// A radio scenario: nodes opt into a shared medium; positions + the radio flag come from the
/// document, and the built fabric exchanges over the auto-wired radio faces.
#[tokio::test]
async fn radio_scenario_from_toml_exchanges_over_the_air() {
    let toml = r#"
[radio]
seed = 7
[radio.propagation]
kind = "free_space_path_loss"

[[nodes]]
label = "a"
position = [0.0, 0.0, 0.0]
radio = true

[[nodes]]
label = "b"
position = [5.0, 0.0, 0.0]
radio = true
"#;
    let scenario = Scenario::from_toml(toml).unwrap();
    let fabric = scenario
        .build(Arc::new(WallClockKernel::new()))
        .unwrap()
        .start()
        .await
        .unwrap();

    fabric
        .route_over_radio(NodeId(0), &"/svc".parse::<Name>().unwrap())
        .unwrap();
    let producer = fabric
        .engine_of(NodeId(1))
        .unwrap()
        .register_producer("/svc", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r
                    .respond((*i.name).clone(), bytes::Bytes::from_static(b"air"))
                    .await;
            })
            .await;
    });

    let mut consumer = fabric
        .engine_of(NodeId(0))
        .unwrap()
        .app_consumer(CancellationToken::new());
    let builder =
        InterestBuilder::new("/svc/x".parse::<Name>().unwrap()).lifetime(Duration::from_secs(10));
    let data = consumer
        .fetch_with(builder)
        .await
        .expect("fetch over radio scenario");
    assert_eq!(
        data.content().map(|c| c.to_vec()).unwrap_or_default(),
        b"air"
    );

    fabric.shutdown().await;
}

/// The same scenario drives a `VirtualKernel` run when the caller supplies one — proving the
/// document is kernel-agnostic (the `kernel` field is advisory; the caller picks the instance).
#[test]
fn scenario_runs_under_the_virtual_kernel() {
    let scenario = Scenario::from_toml(LINE).unwrap();
    let payload = VirtualKernel::new().run(|k| {
        let scenario = scenario.clone();
        async move {
            let fabric = scenario.build(k).unwrap().start().await.unwrap();
            let producer = fabric
                .engine_of(NodeId(1))
                .unwrap()
                .register_producer("/app", CancellationToken::new());
            tokio::spawn(async move {
                let _ = producer
                    .serve(|i, r| async move {
                        let _ = r
                            .respond((*i.name).clone(), bytes::Bytes::from_static(b"pong"))
                            .await;
                    })
                    .await;
            });
            let mut consumer = fabric
                .engine_of(NodeId(0))
                .unwrap()
                .app_consumer(CancellationToken::new());
            let builder = InterestBuilder::new("/app/ping".parse::<Name>().unwrap())
                .lifetime(Duration::from_secs(20));
            let data = consumer
                .fetch_with(builder)
                .await
                .expect("fetch under virtual kernel");
            let out = data.content().map(|c| c.to_vec()).unwrap_or_default();
            fabric.shutdown().await;
            out
        }
    });
    assert_eq!(payload, b"pong");
}
