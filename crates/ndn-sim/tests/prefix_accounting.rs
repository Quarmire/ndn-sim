//! Gap 2 (miniMUAS lift): name-aware per-prefix accounting on the fabric itself.
//! A known injected traffic pattern (3 interests under one prefix, 3 data back)
//! is counted per `(node, prefix)` — the fabric is the source, no UDP-bridge tap.

use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::Simulation;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn per_prefix_counts_match_the_injected_pattern() {
    // consumer(A) ── wired ── producer(B); names grouped to 3 components.
    let mut sim = Simulation::new().with_prefix_accounting(3);
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    sim.link(a, b, ndn_sim::LinkConfig::lan());
    sim.add_route(a, "/svc", b);
    let fabric = sim.start().await.unwrap();

    // Producer on B under /svc/telemetry/live (4-component names → group to 3 = /svc/telemetry/live).
    let producer = fabric.engine_of(b).unwrap().register_producer("/svc/telemetry/live", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r.respond((*i.name).clone(), bytes::Bytes::from_static(b"sample")).await;
            })
            .await;
    });

    // The KNOWN pattern: 3 interests A→B, 3 data B→A.
    let mut consumer = fabric.engine_of(a).unwrap().app_consumer(CancellationToken::new());
    for n in 0..3u32 {
        let name: Name = format!("/svc/telemetry/live/{n}").parse().unwrap();
        consumer
            .fetch_with(InterestBuilder::new(name).must_be_fresh().lifetime(Duration::from_secs(4)))
            .await
            .expect("fetch");
    }

    let stats = fabric.prefix_stats().expect("accounting enabled");
    let rows = stats.snapshot();
    fabric.shutdown().await;

    eprintln!("per-prefix rows: {rows:#?}");
    // The consumer's emission + delivery under the grouped prefix.
    let a_row = rows.iter().find(|r| r.counters.out_interests > 0).expect("a consumer emission row");
    assert_eq!(a_row.prefix, "/svc/telemetry/live", "grouped to 3 components");
    assert_eq!(a_row.counters.out_interests, 3, "3 interests emitted by A");
    assert_eq!(a_row.counters.in_data, 3, "3 data delivered to A");
    assert!(a_row.counters.out_bytes > 0 && a_row.counters.in_bytes > 0);

    // The producer's mirror: interests delivered to B, data emitted by B.
    let b_row = rows.iter().find(|r| r.counters.in_interests > 0).expect("a producer delivery row");
    assert_eq!(b_row.prefix, "/svc/telemetry/live");
    assert_eq!(b_row.counters.in_interests, 3, "3 interests delivered to B");
    assert_eq!(b_row.counters.out_data, 3, "3 data emitted by B");
    assert_ne!(a_row.node, b_row.node, "attributed to distinct nodes");
}

/// Accounting is opt-in: without the builder flag, `prefix_stats()` is `None`
/// (no per-frame decode on the hot path).
#[tokio::test]
async fn accounting_is_off_by_default() {
    let fabric = Simulation::new().start().await.unwrap();
    assert!(fabric.prefix_stats().is_none());
    fabric.shutdown().await;
}
