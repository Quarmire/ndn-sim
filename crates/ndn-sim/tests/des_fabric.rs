//! A **full app-driven fabric on the discrete-event executor** (ndn-lab): real ForwarderEngines +
//! SimFaces + an ndn-app producer/consumer, all running on the from-scratch `DesKernel` event
//! queue — no tokio time driver. The payoff of the executor-agnostic migration: the whole stack
//! (engine already seam-clean, SimFace migrated, ndn-app routed through the ambient runtime) runs
//! deterministically on virtual event-time.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{AppId, AppSpec, DesKernel, LinkConfig, SimKernel, Simulation};
use tokio_util::sync::CancellationToken;

#[test]
fn app_driven_exchange_runs_on_the_des_kernel() {
    let (content, name) = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        // A 2-node fabric on the DES kernel; B serves /svc via a declarative producer app.
        let mut sim = Simulation::new().kernel(k);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        sim.link(a, b, LinkConfig { delay: Duration::from_millis(5), ..LinkConfig::default() });
        sim.add_route(a, "/svc", b);
        sim.add_app(b, AppSpec::Producer { prefix: "/svc".into(), content: Some("des".into()) });
        let fabric = sim.start().await.unwrap();

        // A's consumer fetches over the link — Interest and Data traverse the event queue.
        let mut consumer = fabric.engine_of(a).unwrap().app_consumer(CancellationToken::new());
        let builder =
            InterestBuilder::new("/svc/0".parse::<Name>().unwrap()).lifetime(Duration::from_secs(10));
        let data = consumer.fetch_with(builder).await.expect("fetch over the DES fabric");
        let out = (data.content().map(|c| c.to_vec()).unwrap_or_default(), (*data.name).clone());
        fabric.shutdown().await;
        out
    });

    assert_eq!(content, b"des", "the producer's Data traversed the event queue to the consumer");
    assert_eq!(name, "/svc/0".parse::<Name>().unwrap());
}

#[test]
fn app_driven_fabric_replays_deterministically_on_des() {
    let run = || {
        DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
            let mut sim = Simulation::new().kernel(k);
            let a = sim.add_node(EngineConfig::default());
            let b = sim.add_node(EngineConfig::default());
            sim.link(a, b, LinkConfig { delay: Duration::from_millis(2), ..LinkConfig::default() });
            sim.add_route(a, "/svc", b);
            sim.add_app(b, AppSpec::Producer { prefix: "/svc".into(), content: Some("ok".into()) });
            // A declared consumer fetching /svc/0../svc/4 at 10 ms cadence — all on the event queue.
            sim.add_app(
                a,
                AppSpec::Consumer { prefix: "/svc".into(), count: 5, interval_ms: 10 },
            );
            let fabric = sim.start().await.unwrap();

            // Advance virtual time enough for the 5 fetches (rt::sleep rides the DES event queue),
            // then read the consumer's tally.
            ndn_app::rt::sleep(Duration::from_secs(1)).await;
            let n = fabric.app_successes(AppId(1)).unwrap();
            fabric.shutdown().await;
            n
        })
    };
    let first = run();
    assert_eq!(first, 5, "the consumer app fetched all 5 over the DES event queue");
    assert_eq!(first, run(), "the whole app-driven fabric replays identically on the event queue");
}
