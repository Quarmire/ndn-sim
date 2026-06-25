//! App lifecycle (ndn-lab): declarative producers/consumers do the work — no app code written in
//! the test. Proves the "test my apps" surface: declare a producer here + a consumer there, and
//! traffic flows; live spawn/stop too.

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{AppId, AppSpec, NodeId, Scenario, Simulation, WallClockKernel};

/// Wait until `f()` holds (polling), or time out — for real-time app traffic.
async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..100 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    f()
}

#[tokio::test]
async fn declared_apps_generate_traffic_then_stop() {
    let mut sim = Simulation::new();
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    sim.link(a, b, ndn_sim::LinkConfig::lan());
    sim.add_route(a, "/app", b);
    // Producer on B (id 0), consumer on A fetching /app/0../app/4 (id 1) — declared, not coded.
    sim.add_app(b, AppSpec::Producer { prefix: "/app".into(), content: Some("hi".into()) });
    sim.add_app(a, AppSpec::Consumer { prefix: "/app".into(), count: 5, interval_ms: 0 });
    let fabric = sim.start().await.unwrap();

    let consumer = AppId(1);
    assert!(
        eventually(|| fabric.app_successes(consumer) == Some(5)).await,
        "consumer app fetched all 5 (got {:?})",
        fabric.app_successes(consumer)
    );
    assert!(fabric.app_successes(AppId(0)).unwrap() >= 5, "producer served the data");

    // Introspection lists both apps.
    assert_eq!(fabric.apps().len(), 2);

    // Stop the producer; it's gone from the registry.
    fabric.stop_app(AppId(0)).unwrap();
    assert_eq!(fabric.app_successes(AppId(0)), None);
    assert!(fabric.stop_app(AppId(99)).is_err(), "stopping a missing app errors");

    fabric.shutdown().await;
}

#[tokio::test]
async fn scenario_toml_declares_apps() {
    // The "test my apps" pitch as one artifact: topology + route + apps, all declarative.
    let toml = r#"
[[nodes]]
label = "client"
[[nodes.apps]]
app = "consumer"
prefix = "/svc"
count = 3

[[nodes]]
label = "server"
[[nodes.apps]]
app = "producer"
prefix = "/svc"
content = "ok"

[[links]]
a = 0
b = 1
delay_ms = 1

[[routes]]
node = 0
prefix = "/svc"
nexthop = 1
"#;
    let scenario = Scenario::from_toml(toml).unwrap();
    let fabric = scenario
        .build(Arc::new(WallClockKernel::new()))
        .unwrap()
        .start()
        .await
        .unwrap();

    // The consumer app (declared on node 0) fetched its 3 — pure scenario, no Rust app code.
    let consumer = AppId(0);
    assert!(
        eventually(|| fabric.app_successes(consumer) == Some(3)).await,
        "scenario consumer fetched 3 (got {:?})",
        fabric.app_successes(consumer)
    );
    let _ = NodeId(0);

    fabric.shutdown().await;
}
