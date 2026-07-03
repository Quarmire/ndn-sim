//! Foreign-forwarder interop smoke test (ndn-lab): validate the load-bearing "any conformant
//! forwarder peers over the wire" claim against a *real* foreign implementation — `ndnd` (Go,
//! named-data.net). A simulated ndn-lab node bridges over real UDP to a real `ndnd fw` running a
//! real `ndnd pingserver`; if the sim node fetches the ndnd-produced, ndnd-signed Data, ndn-rs's
//! UDP wire is compatible with ndnd both directions (ndn-rs Interest parsed by ndnd; ndnd Data
//! parsed by ndn-rs).
//!
//! Runs under the **real-time governor** ([`RealTimeKernel`]) — the continuum keystone: a logical
//! scenario clock at real pace, hosting a real external device.
//!
//! `#[ignore]` so CI (no ndnd) is unaffected. Run it with a built ndnd:
//!   cargo build --manifest-path .../ndnd/cmd/ndnd  (or `go build -o /tmp/ndnd ./cmd/ndnd`)
//!   NDND_BIN=/tmp/ndnd cargo test -p ndn-sim --test interop_ndnd -- --ignored --nocapture

use std::io::Write;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{RealTimeKernel, SimKernel, Simulation};
use tokio_util::sync::CancellationToken;

/// Kills spawned children on drop so a failed assertion never leaks `ndnd` processes.
struct Reaper(Vec<Child>);
impl Drop for Reaper {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn ndnd_bin() -> Option<String> {
    if let Ok(p) = std::env::var("NDND_BIN") {
        return std::path::Path::new(&p).exists().then_some(p);
    }
    let default = "/tmp/ndnd";
    std::path::Path::new(default)
        .exists()
        .then(|| default.to_string())
}

fn write_config(socket: &str) -> std::path::PathBuf {
    let cfg = format!(
        r#"core:
  log_level: ERROR
  log_file: ""
faces:
  queue_size: 1024
  congestion_marking: true
  lock_threads_to_cores: false
  udp:
    enabled_unicast: true
    enabled_multicast: false
    port_unicast: 6363
    port_multicast: 56363
    multicast_address_ipv4: 224.0.23.170
    multicast_address_ipv6: ff02::114
    lifetime: 600
    default_mtu: 1420
  tcp:
    enabled: false
    port_unicast: 6363
    lifetime: 600
    reconnect_interval: 10
  unix:
    enabled: true
    socket_path: {socket}
  websocket:
    enabled: false
    bind: ""
    port: 9696
    tls_enabled: false
    tls_cert: ""
    tls_key: ""
  http3:
    enabled: false
    bind: ""
    port: 443
    tls_cert: ""
    tls_key: ""
fw:
  threads: 2
  queue_size: 1024
  lock_threads_to_cores: false
mgmt:
  allow_localhop: false
tables:
  content_store:
    capacity: 1024
    admit: true
    serve: true
    replacement_policy: lru
  dead_nonce_list:
    lifetime: 6000
  network_region:
    regions: []
  rib:
    readvertise_nlsr: false
  fib:
    algorithm: nametree
    hashtable:
      m: 5
"#
    );
    let path = std::env::temp_dir().join("ndn-lab-interop-fw.yml");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(cfg.as_bytes()).unwrap();
    path
}

#[tokio::test]
#[ignore = "needs a built ndnd binary (set NDND_BIN or build to /tmp/ndnd)"]
async fn sim_node_interops_with_real_ndnd_over_udp() {
    let Some(ndnd) = ndnd_bin() else {
        eprintln!(
            "SKIP: ndnd binary not found (set NDND_BIN); build with `go build -o /tmp/ndnd ./cmd/ndnd`"
        );
        return;
    };
    let socket = std::env::temp_dir().join("ndn-lab-interop.sock");
    let _ = std::fs::remove_file(&socket);
    let socket_str = socket.to_string_lossy().to_string();
    let config = write_config(&socket_str);

    // 1. Start a real ndnd forwarder (UDP :6363 + unix socket).
    let fw = Command::new(&ndnd)
        .args(["fw", "run", config.to_str().unwrap()])
        .spawn()
        .unwrap();
    let mut reaper = Reaper(vec![fw]);

    // Wait for the forwarder's unix socket to appear.
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        socket.exists(),
        "ndnd fw did not come up (no socket at {socket_str})"
    );
    tokio::time::sleep(Duration::from_millis(500)).await; // let the UDP listener bind

    // 2. Start a real ndnd ping server under /interop (registers via the unix socket).
    let pingserver = Command::new(&ndnd)
        .args(["pingserver", "/interop"])
        .env("NDN_CLIENT_TRANSPORT", format!("unix://{socket_str}"))
        .spawn()
        .unwrap();
    reaper.0.push(pingserver);
    tokio::time::sleep(Duration::from_secs(1)).await; // let it register /interop/ping

    // 3. A simulated ndn-lab node, on the real-time governor, bridges to ndnd over real UDP.
    let mut sim = Simulation::new().kernel(RealTimeKernel::new() as Arc<dyn SimKernel>);
    let node = sim.add_node(ndn_engine::builder::EngineConfig::default());
    let fabric = sim.start().await.unwrap();

    let face = fabric
        .bridge_udp(
            node,
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:6363".parse().unwrap(),
        )
        .await
        .unwrap();
    fabric.engine_of(node).unwrap().fib().add_nexthop(
        &"/interop".parse::<Name>().unwrap(),
        face,
        10,
    );

    // 4. The sim node fetches a ping from the real ndnd pingserver.
    let mut consumer = fabric
        .engine_of(node)
        .unwrap()
        .app_consumer(CancellationToken::new());
    let interest = InterestBuilder::new("/interop/ping/0".parse::<Name>().unwrap())
        .must_be_fresh()
        .lifetime(Duration::from_secs(4));
    let data = consumer.fetch_with(interest).await;

    fabric.shutdown().await;
    drop(reaper);

    let data = data.expect("sim node should fetch ndnd-produced Data over the UDP bridge");
    assert_eq!(*data.name, "/interop/ping/0".parse::<Name>().unwrap());
    eprintln!(
        "INTEROP OK: ndn-lab fetched {} from real ndnd over UDP",
        *data.name
    );
}
