//! Richer faults (Tier-B): cut/degrade a link and partition/heal the network at runtime — the
//! failure conditions a benchmark measures behavior *under*. Deterministic on DES.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{AppSpec, DesKernel, LinkConfig, NodeId, SimKernel, Simulation};
use tokio_util::sync::CancellationToken;

async fn fetch_ok(fabric: &ndn_sim::RunningSimulation, node: NodeId, name: &str) -> bool {
    let mut c = fabric.engine_of(node).unwrap().app_consumer(CancellationToken::new());
    c.fetch_with(InterestBuilder::new(name.parse::<Name>().unwrap()).lifetime(Duration::from_millis(500)))
        .await
        .is_ok()
}

/// A cut link drops the flow; healing it restores delivery — link state (FIB) survives the cut.
#[test]
fn set_link_cut_and_heal() {
    let (before, during, after) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new().kernel(k);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        sim.link(a, b, LinkConfig::lan());
        sim.add_route(a, "/svc", b);
        sim.add_app(
            b,
            AppSpec::Producer { prefix: "/svc".into(), content: Some("hi".into()), freshness_ms: Some(0) },
        );
        let fabric = sim.start().await.unwrap();

        let before = fetch_ok(&fabric, a, "/svc/0").await;
        fabric.set_link_up(a, b, false).unwrap(); // cut
        let during = fetch_ok(&fabric, a, "/svc/1").await;
        fabric.set_link_up(a, b, true).unwrap(); // heal
        let after = fetch_ok(&fabric, a, "/svc/2").await;

        fabric.shutdown().await;
        (before, during, after)
    });
    assert!(before, "delivered before the cut");
    assert!(!during, "the cut link drops the fetch");
    assert!(after, "healing restores delivery (FIB survived)");
}

/// Partitioning the network isolates a group; `heal` reconnects it.
#[test]
fn partition_isolates_then_heals() {
    let (before, during, after) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        // Line: consumer(0) — relay(1) — producer(2). Partition {2} cuts the 1–2 link.
        let mut sim = Simulation::new().kernel(k);
        let c = sim.add_node(EngineConfig::default());
        let r = sim.add_node(EngineConfig::default());
        let p = sim.add_node(EngineConfig::default());
        sim.link(c, r, LinkConfig::lan());
        sim.link(r, p, LinkConfig::lan());
        sim.add_route(c, "/svc", r);
        sim.add_route(r, "/svc", p);
        sim.add_app(
            p,
            AppSpec::Producer { prefix: "/svc".into(), content: Some("hi".into()), freshness_ms: Some(0) },
        );
        let fabric = sim.start().await.unwrap();

        let before = fetch_ok(&fabric, c, "/svc/0").await;
        fabric.partition(&[p]); // isolate the producer
        let during = fetch_ok(&fabric, c, "/svc/1").await;
        fabric.heal();
        let after = fetch_ok(&fabric, c, "/svc/2").await;

        fabric.shutdown().await;
        (before, during, after)
    });
    assert!(before && !during && after, "before={before} during={during} after={after}");
}

/// Degrading a link to 100% loss makes the flow fail; healing clears the override.
#[test]
fn degrade_link_injects_loss() {
    let (before, during, after) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new().kernel(k);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        sim.link(a, b, LinkConfig::lan());
        sim.add_route(a, "/svc", b);
        sim.add_app(
            b,
            AppSpec::Producer { prefix: "/svc".into(), content: Some("hi".into()), freshness_ms: Some(0) },
        );
        let fabric = sim.start().await.unwrap();

        let before = fetch_ok(&fabric, a, "/svc/0").await;
        fabric.degrade_link(a, b, Some(1.0), None).unwrap(); // total loss
        let during = fetch_ok(&fabric, a, "/svc/1").await;
        fabric.heal();
        let after = fetch_ok(&fabric, a, "/svc/2").await;

        fabric.shutdown().await;
        (before, during, after)
    });
    assert!(before && !during && after, "before={before} during={during} after={after}");
}
