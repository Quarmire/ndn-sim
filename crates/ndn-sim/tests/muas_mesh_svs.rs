//! Reproduce the miniMUAS fleet fabric in-sim: does SVS survive `/muas`
//! multicast-to-every-peer on every node?
//!
//! Field 2026-09-15: on the `ndn-fwd wifi` cell every NDNSF service call
//! (video/control, sensor/capture) times out, in BOTH targeted and two-phase
//! mode, while plain Data fetches (telemetry) run happily at ~3.2/s. Both
//! request modes ride SVS pub/sub. NFD on the identical topology works.
//!
//! The fabric's distinguishing feature — and the thing the existing two-node
//! SVS tests do not exercise — is that EVERY node registers `/muas` toward
//! EVERY peer and sets the multicast strategy on it. An Interest therefore
//! fans to all peers, each of which fans it on again, so every node overhears
//! the same Interest several times over. These tests isolate that.

use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_sim::{LinkConfig, Simulation, VirtualKernel};
use tokio_util::sync::CancellationToken;

/// Control: two nodes, one route each way — the shape the existing SVS tests
/// already prove. If this fails the harness is wrong, not the fabric.
#[test]
fn svs_crosses_a_two_node_link() {
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k);
        let gcs = sim.add_node(EngineConfig::default());
        let d1 = sim.add_node(EngineConfig::default());
        sim.link(gcs, d1, LinkConfig::lan());
        sim.add_route(gcs, "/muas", d1);
        sim.add_route(d1, "/muas", gcs);
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();
        let gcs_node = fabric.engine_of(gcs).unwrap().app_node(cancel.child_token());
        let d1_node = fabric.engine_of(d1).unwrap().app_node(cancel.child_token());

        let publisher = d1_node.publish("/muas", "/muas/v2/iuas-01").await.expect("publish");
        let mut sub = gcs_node.subscribe("/muas", "/muas/v2/gcs").await.expect("subscribe");

        ndn_app::rt::sleep(Duration::from_millis(200)).await;
        publisher.put(b"service-request").await.expect("put");

        let got = tokio::time::timeout(Duration::from_secs(10), sub.recv())
            .await
            .expect("two-node SVS timed out");
        assert!(got.is_some(), "two-node SVS delivered nothing");
        cancel.cancel();
    });
}

/// The fleet fabric: GCS + three airframes, full mesh, `/muas` toward every
/// peer on every node, multicast strategy on `/muas` — exactly what
/// `muas-fabric`'s `ndn-fwd wifi` cell installs.
#[test]
fn svs_survives_muas_multicast_to_every_peer() {
    let kernel = VirtualKernel::new();
    kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k);
        let gcs = sim.add_node(EngineConfig::default());
        let d1 = sim.add_node(EngineConfig::default());
        let d2 = sim.add_node(EngineConfig::default());
        let d3 = sim.add_node(EngineConfig::default());
        let all = [gcs, d1, d2, d3];

        // full mesh, as the AP gives every node a face to every other
        for (i, &a) in all.iter().enumerate() {
            for &b in all.iter().skip(i + 1) {
                sim.link(a, b, LinkConfig::lan());
            }
        }
        // every node routes /muas toward EVERY peer (the config's per-peer
        // `[[route]] prefix = "/muas"`)
        for &a in all.iter() {
            for &b in all.iter() {
                if a != b {
                    sim.add_route(a, "/muas", b);
                }
            }
        }
        let fabric = sim.start().await.unwrap();

        // ...and multicast on /muas, so an Interest fans to all of them
        let muas: Name = "/muas".parse().unwrap();
        for &n in all.iter() {
            fabric.set_strategy(n, &muas, "multicast").expect("set multicast");
        }

        let cancel = CancellationToken::new();
        let gcs_node = fabric.engine_of(gcs).unwrap().app_node(cancel.child_token());
        let d1_node = fabric.engine_of(d1).unwrap().app_node(cancel.child_token());

        let publisher = d1_node.publish("/muas", "/muas/v2/iuas-01").await.expect("publish");
        let mut sub = gcs_node.subscribe("/muas", "/muas/v2/gcs").await.expect("subscribe");

        ndn_app::rt::sleep(Duration::from_millis(200)).await;
        publisher.put(b"service-request").await.expect("put");

        let got = tokio::time::timeout(Duration::from_secs(20), sub.recv())
            .await
            .expect("FLEET TOPOLOGY: SVS publication never crossed — this is the field failure");
        assert!(got.is_some(), "fleet topology SVS delivered nothing");
        cancel.cancel();
    });
}
