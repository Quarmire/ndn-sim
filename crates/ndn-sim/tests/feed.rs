//! Transport-agnostic mobility feed (axis 3 follow-on): anything that writes JSON NodeStates to a
//! UDP socket drives the World — the seam a Gazebo/Bevy bridge (or any external sim) plugs into
//! without ndn-lab depending on it. Here a plain UDP sender stands in for that bridge.

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{Position, RealTimeKernel, Simulation, udp_json_feed};
use tokio_util::sync::CancellationToken;

fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let p = s.local_addr().unwrap().port();
    drop(s);
    p
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_json_feed_drives_the_world() {
    let port = free_udp_port();
    let (source, _reader) = udp_json_feed(&format!("127.0.0.1:{port}")).unwrap();

    let mut sim = Simulation::new().kernel(RealTimeKernel::new());
    let node = sim.add_node(EngineConfig::default());
    sim.place_node(node, Position::ORIGIN);
    let fabric = Arc::new(sim.start().await.unwrap());

    // A "bridge" (any external sim) streams JSON NodeStates to the feed.
    let sender = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        for i in 0..20 {
            let json = format!(
                r#"{{"node":0,"t_secs":{},"position":{{"x":{},"y":0.0,"z":0.0}},"velocity":null}}"#,
                i as f64 * 0.1,
                (i as f64) * 5.0
            );
            let _ = sock.send_to(json.as_bytes(), format!("127.0.0.1:{port}"));
            std::thread::sleep(Duration::from_millis(20));
        }
    });

    let cancel = CancellationToken::new();
    let c = cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(900)).await;
        c.cancel();
    });
    let trace = fabric
        .drive_mobility(Box::new(source), Duration::from_millis(20), cancel)
        .await;
    let _ = sender.join();

    assert!(!trace.states.is_empty(), "received JSON node states from the feed");
    let pos = fabric.world().snapshot(2.0).position(node).unwrap();
    assert!(pos.x > 20.0, "the feed drove the node along +x, got x={}", pos.x);
    fabric.shutdown().await;
}
