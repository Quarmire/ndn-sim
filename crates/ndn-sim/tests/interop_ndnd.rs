//! Foreign-forwarder interop conformance suite (Tier-1): validate the load-bearing
//! "any conformant forwarder peers over the wire" claim against a *real* foreign
//! implementation — `ndnd` (Go, named-data.net) — beyond the smoke test:
//!
//! - **baseline + signature**: a sim node fetches ndnd-produced, ndnd-signed Data
//!   over the UDP bridge (Interest parsed by ndnd; Data parsed by us), and the
//!   foreign signature parses into a *recognized* `SignatureType`.
//! - **unrouted Interest (documented divergence)**: ndnd deliberately sends no
//!   Nacks — an unrouted Interest is silently dropped there and must surface
//!   here as a clean `Timeout`; the test also guards the divergence record.
//! - **LP fragmentation, both directions + CanBePrefix**: a >MTU Data produced by
//!   ndnd is NDNLPv2-fragmented by *their* forwarder and reassembled by *us*
//!   (fetched via CanBePrefix discovery); then ndnd's ping client fetches >MTU
//!   Data from *our* producer, fragmented by *us* (face MTU forced below the
//!   payload) and reassembled by *them*.
//!
//! Every test runs the bridged region under the **real-time governor**
//! ([`RealTimeKernel`]) — external processes live on real time; the bridge stays
//! at the edge (the doctrine `bridge.rs` fixes). Each test uses its own UDP port
//! + unix socket so the suite parallelizes.
//!
//! All `#[ignore]` so CI without ndnd is unaffected. Run with a built ndnd:
//!   go build -o /tmp/ndnd ./cmd/ndnd     (in the ndnd repo)
//!   NDND_BIN=/tmp/ndnd cargo test -p ndn-sim --test interop_ndnd -- --ignored --nocapture
//! or use `testbed/interop.sh`, which builds ndnd and runs the suite.

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ndn_app::{AppError, EngineAppExt};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{NodeId, RealTimeKernel, RunningSimulation, SimKernel, Simulation};
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

fn write_config(tag: &str, socket: &str, udp_port: u16) -> std::path::PathBuf {
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
    port_unicast: {udp_port}
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
    let path = std::env::temp_dir().join(format!("ndn-lab-interop-{tag}.yml"));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(cfg.as_bytes()).unwrap();
    path
}

/// A running foreign forwarder + the tools attached to it over its unix socket.
struct Ndnd {
    bin: String,
    socket_str: String,
    reaper: Reaper,
}

impl Ndnd {
    /// Start `ndnd fw` on its own UDP port + unix socket. `None` (with a SKIP
    /// note) when the binary is absent — the suite degrades to a no-op, never a
    /// failure, on machines without ndnd.
    async fn start(tag: &str, udp_port: u16) -> Option<Ndnd> {
        let Some(bin) = ndnd_bin() else {
            eprintln!(
                "SKIP: ndnd binary not found (set NDND_BIN); build with `go build -o /tmp/ndnd ./cmd/ndnd`"
            );
            return None;
        };
        let socket = std::env::temp_dir().join(format!("ndn-lab-interop-{tag}.sock"));
        let _ = std::fs::remove_file(&socket);
        let socket_str = socket.to_string_lossy().to_string();
        let config = write_config(tag, &socket_str, udp_port);

        let fw = Command::new(&bin)
            .args(["fw", "run", config.to_str().unwrap()])
            .spawn()
            .unwrap();
        let reaper = Reaper(vec![fw]);

        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(socket.exists(), "ndnd fw did not come up (no socket at {socket_str})");
        tokio::time::sleep(Duration::from_millis(500)).await; // let the UDP listener bind
        Some(Ndnd { bin, socket_str, reaper })
    }

    /// Spawn an ndnd tool attached to this forwarder; it stays alive until the reaper.
    fn tool(&mut self, args: &[&str]) -> &mut Self {
        let child = Command::new(&self.bin)
            .args(args)
            .env("NDN_CLIENT_TRANSPORT", format!("unix://{}", self.socket_str))
            .spawn()
            .unwrap();
        self.reaper.0.push(child);
        self
    }

    /// Spawn an ndnd tool feeding `stdin_bytes` on its standard input.
    fn tool_with_stdin(&mut self, args: &[&str], stdin_bytes: &[u8]) {
        let mut child = Command::new(&self.bin)
            .args(args)
            .env("NDN_CLIENT_TRANSPORT", format!("unix://{}", self.socket_str))
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(stdin_bytes).unwrap(); // drop closes → EOF
        self.reaper.0.push(child);
    }

    /// Run an ndnd tool to completion and return its stdout (for clients like
    /// `ping -c N`, which exit on their own).
    async fn tool_output(&self, args: &[&str]) -> String {
        let child = Command::new(&self.bin)
            .args(args)
            .env("NDN_CLIENT_TRANSPORT", format!("unix://{}", self.socket_str))
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let out = tokio::task::spawn_blocking(move || child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

/// A one-node sim fabric on the real-time governor, bridged to `ndnd`'s UDP port
/// (optionally with a clamped bridge-face send MTU, to force our-side LP frag).
async fn bridged_fabric(
    ndnd_port: u16,
    local: &str,
    route: &str,
    mtu: Option<u64>,
) -> (RunningSimulation, NodeId, ndn_transport::FaceId) {
    let mut sim = Simulation::new().kernel(RealTimeKernel::new() as Arc<dyn SimKernel>);
    let node = sim.add_node(ndn_engine::builder::EngineConfig::default());
    let fabric = sim.start().await.unwrap();
    let face = fabric
        .bridge_udp_mtu(
            node,
            local.parse().unwrap(),
            format!("127.0.0.1:{ndnd_port}").parse().unwrap(),
            mtu,
        )
        .await
        .unwrap();
    fabric
        .engine_of(node)
        .unwrap()
        .fib()
        .add_nexthop(&route.parse::<Name>().unwrap(), face, 10);
    (fabric, node, face)
}

/// Baseline + signature scrutiny: fetch ndnd-signed Data; the foreign signature
/// must parse into a recognized `SignatureType` (unrecognized codes would mean
/// wire drift in SignatureInfo parsing).
#[tokio::test]
#[ignore = "needs a built ndnd binary (set NDND_BIN or build to /tmp/ndnd)"]
async fn sim_node_interops_with_real_ndnd_over_udp() {
    let Some(mut ndnd) = Ndnd::start("ping", 16363).await else { return };
    ndnd.tool(&["pingserver", "/interop"]);
    tokio::time::sleep(Duration::from_secs(1)).await; // let it register /interop

    let (fabric, node, _face) = bridged_fabric(16363, "127.0.0.1:0", "/interop", None).await;
    let mut consumer = fabric.engine_of(node).unwrap().app_consumer(CancellationToken::new());
    let interest = InterestBuilder::new("/interop/ping/0".parse::<Name>().unwrap())
        .must_be_fresh()
        .lifetime(Duration::from_secs(4));
    let data = consumer.fetch_with(interest).await;

    fabric.shutdown().await;
    let data = data.expect("sim node should fetch ndnd-produced Data over the UDP bridge");
    assert_eq!(*data.name, "/interop/ping/0".parse::<Name>().unwrap());

    let sig = data.sig_info().expect("ndnd Data carries SignatureInfo we can parse");
    assert!(
        !matches!(sig.sig_type, ndn_packet::SignatureType::Other(_)),
        "foreign signature type must be recognized, got {:?}",
        sig.sig_type
    );
    eprintln!("INTEROP OK: fetched {} from real ndnd; signature {:?}", *data.name, sig.sig_type);
}

/// **Documented divergence** — the wire's "no" here is silence, not a Nack.
/// ndnd deliberately generates no Nacks (`fw/fw/thread.go`: *"since we don't
/// use Nacks, just drop"*), so an unrouted Interest must surface on our side as
/// a clean [`AppError::Timeout`] — never a hang, never a mis-parse. (NFD's
/// best-route would Nack `NoRoute` here; exercising our `Nacked` surface
/// cross-stack therefore waits for an NFD peer — pending, not manufactured.)
/// If this test ever sees a Nack, ndnd changed behavior and this divergence
/// record needs updating — that failure is the test working.
#[tokio::test]
#[ignore = "needs a built ndnd binary (set NDND_BIN or build to /tmp/ndnd)"]
async fn unrouted_interest_at_ndnd_times_out_by_design_not_nacks() {
    let Some(_ndnd) = Ndnd::start("nack", 16364).await else { return };
    // No producer, no route on the ndnd side: /void is unroutable there.
    let (fabric, node, _face) = bridged_fabric(16364, "127.0.0.1:0", "/void", None).await;
    let mut consumer = fabric.engine_of(node).unwrap().app_consumer(CancellationToken::new());
    let interest =
        InterestBuilder::new("/void/x".parse::<Name>().unwrap()).lifetime(Duration::from_secs(2));
    let res = consumer.fetch_with(interest).await;
    fabric.shutdown().await;

    match res {
        Err(AppError::Timeout) => {
            eprintln!("INTEROP OK: unrouted Interest timed out cleanly (ndnd drops, by design)");
        }
        Err(AppError::Nacked { reason }) => panic!(
            "ndnd sent a Nack ({reason:?}) — it no longer silently drops; update this divergence record"
        ),
        other => panic!("expected a clean timeout against no-Nack ndnd, got {other:?}"),
    }
}

/// NDNLPv2 fragmentation across the wire, both directions, + CanBePrefix:
/// their-frag→our-reassembly (a 3 kB ndnd object crosses the 1420-byte-MTU UDP
/// face), then our-frag→their-reassembly (a 4 kB Data from our producer over a
/// face clamped to 1200 bytes, fetched by ndnd's own ping client).
#[tokio::test]
#[ignore = "needs a built ndnd binary (set NDND_BIN or build to /tmp/ndnd)"]
async fn lp_fragmentation_reassembles_in_both_directions() {
    let Some(mut ndnd) = Ndnd::start("lpfrag", 16365).await else { return };

    // ── their fragmentation → our reassembly ────────────────────────────────
    // `ndnd put` publishes one 8000-byte-segment object; 3 kB fits one segment,
    // whose Data (> 1420 MTU) ndnd must LP-fragment onto the wire.
    ndnd.tool_with_stdin(&["put", "/interop/big"], &vec![b'x'; 3000]);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Our local port is fixed so ndnd can route back toward us for phase 2.
    let (fabric, node, face) = bridged_fabric(16365, "127.0.0.1:17365", "/interop", Some(1200)).await;
    let mut consumer = fabric.engine_of(node).unwrap().app_consumer(CancellationToken::new());
    // CanBePrefix: we don't know the version component `put` minted — discovery
    // by prefix is itself part of the conformance surface.
    let interest = InterestBuilder::new("/interop/big".parse::<Name>().unwrap())
        .can_be_prefix()
        .lifetime(Duration::from_secs(4));
    let data = consumer
        .fetch_with(interest)
        .await
        .expect("fetch the >MTU ndnd object via CanBePrefix (their frag, our reassembly)");
    let content_len = data.content().map(|c| c.len()).unwrap_or(0);
    assert_eq!(content_len, 3000, "reassembled content must be intact");
    eprintln!("INTEROP OK: reassembled {} bytes fragmented by ndnd ({})", content_len, *data.name);

    // ── our fragmentation → their reassembly ────────────────────────────────
    // A 4 kB Data over a face clamped to 1200 bytes forces our LpLinkService to
    // fragment; ndnd's forwarder reassembles and its ping client verifies.
    let engine = fabric.engine_of(node).unwrap();
    let _ = face; // bridge face already clamped to 1200 B at attach time
    let producer = engine.register_producer("/rev", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r.respond((*i.name).clone(), bytes::Bytes::from(vec![b'y'; 4000])).await;
            })
            .await;
    });
    // Point ndnd at us (rib/register auto-creates the UDP face toward 17365).
    ndnd.tool(&["fw", "route-add", "prefix=/rev", "face=udp://127.0.0.1:17365"]);
    tokio::time::sleep(Duration::from_millis(800)).await;

    let out = ndnd.tool_output(&["ping", "/rev", "-c", "3", "-i", "300"]).await;
    fabric.shutdown().await;
    assert!(
        out.contains("content from /rev"),
        "ndnd's ping client should reassemble our >MTU Data; ping output:\n{out}"
    );
    eprintln!("INTEROP OK: ndnd reassembled our 1200-byte LP fragments\n{}", out.trim_end());
}
