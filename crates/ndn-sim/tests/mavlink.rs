//! End-to-end MAVLink co-sim (axis 3, 3b): a *fake SITL* (the mavlink crate sending
//! `GLOBAL_POSITION_INT` frames over UDP) drives the real adapter → ChannelSource → the governor
//! loop → the World. Proves the whole socket→decode→drive path without a live ArduPilot.
//!
//! Only compiled with `--features mavlink`.
#![cfg(feature = "mavlink")]

use std::sync::Arc;
use std::time::Duration;

use mavlink::common::{GLOBAL_POSITION_INT_DATA, MavMessage};
use ndn_engine::builder::EngineConfig;
use ndn_sim::mavlink::{MavlinkConfig, mavlink_source};
use ndn_sim::{Position, RealTimeKernel, Simulation};
use tokio_util::sync::CancellationToken;

fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let p = s.local_addr().unwrap().port();
    drop(s);
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mavlink_feed_drives_the_world_end_to_end() {
    let port = free_udp_port();
    let endpoint = format!("udpin:127.0.0.1:{port}");

    // A one-node fabric on the real-time governor (mode B).
    let mut sim = Simulation::new().kernel(RealTimeKernel::new());
    let node = sim.add_node(EngineConfig::default());
    sim.place_node(node, Position::ORIGIN);
    let fabric = Arc::new(sim.start().await.unwrap());

    let (source, _reader) = mavlink_source(MavlinkConfig {
        endpoint,
        reference: None, // adopt the first fix as the ENU origin
        base_sysid: 1,
        node_count: 1,
    })
    .unwrap();

    // Fake SITL: system id 1 reports GLOBAL_POSITION_INT fixes marching north (+0.001°/step).
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100)); // let the listener bind
        let conn = mavlink::connect::<MavMessage>(&format!("udpout:127.0.0.1:{port}")).unwrap();
        for i in 0..30u32 {
            let msg = MavMessage::GLOBAL_POSITION_INT(GLOBAL_POSITION_INT_DATA {
                time_boot_ms: i * 50,
                lat: 470_000_000 + (i as i32) * 10_000,
                lon: 80_000_000,
                alt: 500_000,
                relative_alt: 0,
                vx: 0,
                vy: 0,
                vz: 0,
                hdg: 0,
            });
            let header = mavlink::MavHeader { system_id: 1, component_id: 1, sequence: i as u8 };
            let _ = conn.send(&header, &msg);
            std::thread::sleep(Duration::from_millis(30));
        }
    });

    let cancel = CancellationToken::new();
    let stopper = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(1300)).await;
        stopper.cancel();
    });

    let trace = fabric
        .drive_mobility(Box::new(source), Duration::from_millis(20), cancel)
        .await;
    let _ = sender.join();

    assert!(!trace.states.is_empty(), "received states from the MAVLink feed");
    let pos = fabric.world().snapshot(2.0).position(node).unwrap();
    // Origin adopted from the first fix (47.000°); later fixes march north → large +y (ENU north).
    assert!(pos.y > 100.0, "the node moved north under the live feed, got y={}", pos.y);
    assert!(pos.x.abs() < 5.0, "no east drift (constant longitude), got x={}", pos.x);
    fabric.shutdown().await;
}
