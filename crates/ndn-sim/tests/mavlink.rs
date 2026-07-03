//! End-to-end MAVLink co-sim (axis 3, 3b): a *fake SITL* (the mavlink crate sending
//! `GLOBAL_POSITION_INT` frames over UDP) drives the real adapter → ChannelSource → the governor
//! loop → the World. Proves the whole socket→decode→drive path without a live ArduPilot.
//!
//! Only compiled with `--features mavlink`.
#![cfg(feature = "mavlink")]

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use mavlink::common::{GLOBAL_POSITION_INT_DATA, MavMessage};
use ndn_engine::builder::EngineConfig;
use ndn_sim::mavlink::{MavlinkConfig, mavlink_link, mavlink_source};
use ndn_sim::{
    ControlPlane, NodeId, Position, RealTimeKernel, SimCommand, Simulation, VehicleCommand,
};
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
            let header = mavlink::MavHeader {
                system_id: 1,
                component_id: 1,
                sequence: i as u8,
            };
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

    assert!(
        !trace.states.is_empty(),
        "received states from the MAVLink feed"
    );
    let pos = fabric.world().snapshot(2.0).position(node).unwrap();
    // Origin adopted from the first fix (47.000°); later fixes march north → large +y (ENU north).
    assert!(
        pos.y > 100.0,
        "the node moved north under the live feed, got y={}",
        pos.y
    );
    assert!(
        pos.x.abs() < 5.0,
        "no east drift (constant longitude), got x={}",
        pos.x
    );
    fabric.shutdown().await;
}

const HOME_LAT: f64 = 47.0;
const HOME_LON: f64 = 8.0;
const HOME_ALT: f64 = 500.0;
const EARTH_R: f64 = 6_378_137.0;

/// A minimal *responsive* fake SITL: it streams its GLOBAL_POSITION_INT and, when it receives a
/// SET_POSITION_TARGET_LOCAL_NED (a goto), snaps its position to the commanded NED target. Enough to
/// close the bidirectional loop (command out → vehicle reacts → pose in) without a real autopilot.
fn spawn_fake_sitl(port: u16) -> Arc<std::sync::atomic::AtomicBool> {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = Arc::clone(&stop);
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100)); // let ndn-lab bind
        let conn: Arc<dyn mavlink::MavConnection<MavMessage> + Send + Sync> =
            Arc::from(mavlink::connect::<MavMessage>(&format!("udpout:127.0.0.1:{port}")).unwrap());
        // Shared global position (lat_deg, lon_deg, alt_m), updated by received goto commands.
        let pos = Arc::new(Mutex::new((HOME_LAT, HOME_LON, HOME_ALT)));

        // Receiver: apply goto (NED) commands.
        let rconn = Arc::clone(&conn);
        let rpos = Arc::clone(&pos);
        let rstop = Arc::clone(&stop2);
        std::thread::spawn(move || {
            while !rstop.load(std::sync::atomic::Ordering::Relaxed) {
                if let Ok((_h, MavMessage::SET_POSITION_TARGET_LOCAL_NED(d))) = rconn.recv() {
                    // NED target → global, relative to home (inverse of the adapter's ENU mapping).
                    let north = d.x as f64; // metres
                    let east = d.y as f64;
                    let down = d.z as f64;
                    let lat = HOME_LAT + (north / EARTH_R).to_degrees();
                    let lon =
                        HOME_LON + (east / (EARTH_R * HOME_LAT.to_radians().cos())).to_degrees();
                    let alt = HOME_ALT - down;
                    *rpos.lock().unwrap() = (lat, lon, alt);
                }
            }
        });

        // Sender: stream the current global position at ~30 Hz.
        while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
            let (lat, lon, alt) = *pos.lock().unwrap();
            let msg = MavMessage::GLOBAL_POSITION_INT(GLOBAL_POSITION_INT_DATA {
                time_boot_ms: 0,
                lat: (lat * 1e7) as i32,
                lon: (lon * 1e7) as i32,
                alt: (alt * 1e3) as i32,
                relative_alt: 0,
                vx: 0,
                vy: 0,
                vz: 0,
                hdg: 0,
            });
            let header = mavlink::MavHeader {
                system_id: 1,
                component_id: 1,
                sequence: 0,
            };
            let _ = conn.send(&header, &msg);
            std::thread::sleep(Duration::from_millis(30));
        }
    });
    stop
}

/// The full BIDIRECTIONAL loop: ndn-lab commands a `Cosim { goto }` through the CONTROL PLANE, the
/// (fake) autopilot reacts, its new pose streams back, and the World reflects it — single-surface,
/// bidirectional co-simulation, proven without a real ArduPilot.
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn control_plane_commands_the_swarm_and_the_world_follows() {
    let port = free_udp_port();
    let sitl_stop = spawn_fake_sitl(port);

    let mut sim = Simulation::new().kernel(RealTimeKernel::new());
    let node = sim.add_node(EngineConfig::default());
    sim.place_node(node, Position::ORIGIN);
    let fabric = Arc::new(sim.start().await.unwrap());

    // The bidirectional MAVLink link: positions IN + an actuator OUT, over one connection.
    let (source, _reader, actuator) = mavlink_link(MavlinkConfig {
        endpoint: format!("udpin:127.0.0.1:{port}"),
        reference: None,
        base_sysid: 1,
        node_count: 1,
    })
    .unwrap();

    let control = ControlPlane::new(Arc::clone(&fabric));
    control.set_actuator(Arc::new(actuator));

    // Drive incoming mobility in the background.
    let drive_cancel = CancellationToken::new();
    let dc = drive_cancel.clone();
    let df = Arc::clone(&fabric);
    let driver = tokio::spawn(async move {
        df.drive_mobility(Box::new(source), Duration::from_millis(20), dc)
            .await;
    });

    // Let a few poses arrive (so the node exists at ~origin and ndn-lab has learned the peer).
    tokio::time::sleep(Duration::from_millis(400)).await;
    let before = fabric.world().snapshot(1.0).position(node).unwrap();
    assert!(
        before.x.abs() < 5.0 && before.y.abs() < 5.0,
        "starts near origin, got {before:?}"
    );

    // Command the vehicle to fly to ENU (120, 60, 0) — THROUGH the control plane (rides NDN too).
    let resp = control
        .execute(SimCommand::Cosim {
            command: VehicleCommand::Goto {
                node: 0,
                x: 120.0,
                y: 60.0,
                z: 0.0,
            },
        })
        .await;
    assert!(
        matches!(resp, ndn_sim::SimResponse::Ok),
        "the Cosim command should be accepted, got {resp:?}"
    );

    // The fake autopilot snaps there and streams the new pose back → the World follows.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let after = fabric.world().snapshot(2.0).position(node).unwrap();
    assert!(
        (after.x - 120.0).abs() < 5.0,
        "east ≈ 120 m after the goto, got x={}",
        after.x
    );
    assert!(
        (after.y - 60.0).abs() < 5.0,
        "north ≈ 60 m after the goto, got y={}",
        after.y
    );

    drive_cancel.cancel();
    sitl_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = driver.await;
    fabric.shutdown().await;
}

/// A `Cosim` command routes through `handle_json` (the codec every transport uses, incl. the NDN
/// `/localhop/sim/control` producer) to the actuator — so flying the swarm over an NDN Interest works.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cosim_command_rides_the_json_ndn_codec_to_the_actuator() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // A recording actuator that just counts commands.
    struct Counting(Arc<AtomicUsize>);
    impl ndn_sim::CosimActuator for Counting {
        fn command(&self, _cmd: &VehicleCommand) -> anyhow::Result<()> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    let mut sim = Simulation::new().kernel(RealTimeKernel::new());
    sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));
    let count = Arc::new(AtomicUsize::new(0));
    control.set_actuator(Arc::new(Counting(Arc::clone(&count))));

    // The exact JSON an NDN control Interest (or WS/CLI) carries — a SimRequest envelope.
    let json = r#"{"command":{"cmd":"cosim","command":{"action":"goto","node":0,"x":10.0,"y":20.0,"z":0.0}}}"#;
    let reply = control.handle_json(json).await;
    assert!(reply.contains("\"ok\""), "expected Ok, got {reply}");
    assert_eq!(
        count.load(Ordering::Relaxed),
        1,
        "the command reached the actuator via the codec"
    );

    // Sanity: MoveNode of the fabric node still works alongside (single surface).
    let _ = control
        .execute(SimCommand::MoveNode {
            node: 0,
            x: 1.0,
            y: 2.0,
            z: 0.0,
        })
        .await;
    assert_eq!(
        fabric.world().snapshot(0.0).position(NodeId(0)).unwrap(),
        Position::xyz(1.0, 2.0, 0.0)
    );
    fabric.shutdown().await;
}
