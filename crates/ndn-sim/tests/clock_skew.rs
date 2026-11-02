//! Per-node clock skew: a node declared with a `ClockSkew` reads the fabric's true wall clock
//! plus its offset and drift, on its own engine's runtime, while monotonic time (and so link
//! delays and timers) stays shared. Plain `#[test]`s: the virtual kernel owns its runtime.
//!
//! Security note (same as the fabric tests): nodes keep the default fail-closed validator; the
//! Data here is digest-signed and its digest verified. Nothing is disabled.

use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::encode::InterestBuilder;
use ndn_packet::name;
use ndn_sim::{ClockSkew, LinkConfig, NodeProfile, Simulation, VirtualKernel};
use tokio_util::sync::CancellationToken;

const WEEK: Duration = Duration::from_secs(7 * 24 * 3600);

#[test]
fn a_skewed_node_reads_its_own_wall_clock_and_shares_monotonic_time() {
    VirtualKernel::new().run(|k| async move {
        let mut sim = Simulation::new().kernel(k);
        let thief = sim.add_node_profile(
            NodeProfile::new("thief").with_clock_skew(ClockSkew::behind(WEEK).drifting(100)),
        );
        let honest = sim.add_node(EngineConfig::default());
        sim.link(thief, honest, LinkConfig::lan());
        let fabric = sim.start().await.unwrap();

        let truth = fabric.clock();
        let thief_clock = fabric.node_clock(thief).unwrap();
        let honest_clock = fabric.node_clock(honest).unwrap();

        // Read at one virtual instant: the offset is exact; the unskewed node reads true time.
        let t = truth.now_ns();
        assert_eq!(thief_clock.now_ns(), t - WEEK.as_nanos() as u64);
        assert_eq!(honest_clock.now_ns(), t);
        assert_eq!(
            thief_clock.now(),
            truth.now(),
            "monotonic time is not skewed"
        );

        // 1000 s of virtual time later, +100 ppm has added 100 ms on top of the offset.
        tokio::time::sleep(Duration::from_secs(1000)).await;
        let t = truth.now_ns();
        assert_eq!(
            thief_clock.now_ns(),
            t - WEEK.as_nanos() as u64 + 100_000_000
        );
        assert_eq!(
            fabric.clock_skew(thief),
            Some(ClockSkew::behind(WEEK).drifting(100))
        );
        fabric.shutdown().await;
    });
}

#[test]
fn a_declared_clock_steps_on_the_live_fabric_and_an_undeclared_one_refuses() {
    VirtualKernel::new().run(|k| async move {
        let mut sim = Simulation::new().kernel(k);
        let a = sim.add_node(EngineConfig::default());
        let b = sim.add_node(EngineConfig::default());
        sim.set_clock_skew(a, ClockSkew::NONE);
        sim.link(a, b, LinkConfig::lan());
        let fabric = sim.start().await.unwrap();

        let truth = fabric.clock();
        let a_clock = fabric.node_clock(a).unwrap();
        assert_eq!(a_clock.now_ns(), truth.now_ns());

        fabric
            .set_clock_skew(a, ClockSkew::ahead(Duration::from_secs(300)))
            .unwrap();
        assert_eq!(a_clock.now_ns(), truth.now_ns() + 300_000_000_000);

        let err = fabric.set_clock_skew(b, ClockSkew::NONE).unwrap_err();
        assert!(err.to_string().contains("kernel clock"), "{err}");
        assert_eq!(fabric.clock_skew(b), None);
        fabric.shutdown().await;
    });
}

/// Forwarding is unaffected by a wrong wall clock on either end: a consumer an hour fast fetches
/// from a producer a week slow, and the exchange takes the link's round trip in virtual time.
#[test]
fn exchanges_between_skewed_nodes_still_complete() {
    VirtualKernel::new().run(|k| async move {
        let mut sim = Simulation::new().kernel(k);
        let consumer = sim.add_node_profile(
            NodeProfile::new("fast").with_clock_skew(ClockSkew::ahead(Duration::from_secs(3600))),
        );
        let producer =
            sim.add_node_profile(NodeProfile::new("slow").with_clock_skew(ClockSkew::behind(WEEK)));
        sim.link(
            consumer,
            producer,
            LinkConfig {
                delay: Duration::from_millis(50),
                jitter: Duration::ZERO,
                loss_rate: 0.0,
                bandwidth_bps: 0,
            },
        );
        sim.add_route(consumer, "/app", producer);
        let fabric = sim.start().await.unwrap();

        let serving = fabric
            .engine_of(producer)
            .unwrap()
            .register_producer(name!("/app"), CancellationToken::new());
        tokio::spawn(async move {
            let _ = serving
                .serve(|interest, responder| async move {
                    let _ = responder
                        .respond((*interest.name).clone(), bytes::Bytes::from_static(b"pong"))
                        .await;
                })
                .await;
        });

        let truth = fabric.clock();
        let t0 = truth.now_ns();
        let mut c = fabric
            .engine_of(consumer)
            .unwrap()
            .app_consumer(CancellationToken::new());
        let data = c
            .fetch_with(InterestBuilder::new(name!("/app/ping")).lifetime(Duration::from_secs(4)))
            .await
            .expect("fetch across skewed clocks");
        assert_eq!(
            data.content().map(|c| c.to_vec()).unwrap_or_default(),
            b"pong"
        );
        assert!(
            truth.now_ns() - t0 >= 100_000_000,
            "one round trip of link delay"
        );
        fabric.shutdown().await;
    });
}
