//! Foreign-forwarder interop against **real NFD** (C++, ndn-cxx / named-data.net):
//!
//! - **the Nack corner** `ndnd` structurally cannot reach — NFD's default
//!   `best-route` strategy *does* send a `NoRoute` **Nack** for an unrouted
//!   Interest, so this exercises our `AppError::Nacked` surface cross-stack (the
//!   wire's real "no" from a foreign forwarder, parsed by us);
//! - **the Tier-2 differential harness** — the *same* fetch workload run through
//!   two forwarder implementations (an ndn-rs relay, pure and in-fabric; then a
//!   real NFD, foreign and bridged) with the delivered counts diffed. Equal
//!   delivery means NFD forwards ndn-rs Interest→Data identically; a divergence
//!   would be a *semantic* finding (the class the PIT PSDC bug was in), which
//!   wire-format tests can't catch.
//!
//! Runs the bridged region under the real-time governor ([`RealTimeKernel`]).
//! `#[ignore]` so CI without NFD is unaffected. NFD is C++; it needs its ndn-cxx
//! dylib at runtime — pass its directory in `NDN_CXX_LIB` (the harness sets
//! `DYLD_FALLBACK_LIBRARY_PATH` for the child). Run with a built NFD:
//!   NFD_BIN=/path/to/NFD/build/bin/nfd \
//!   NDN_CXX_LIB=/path/to/ndn-cxx/build \
//!   cargo test -p ndn-sim --test interop_nfd -- --ignored --nocapture
//! or use `testbed/interop.sh` (which locates both).

use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use ndn_app::{AppError, EngineAppExt};
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{RealTimeKernel, SimKernel, Simulation};
use tokio_util::sync::CancellationToken;

struct Reaper(Vec<Child>);
impl Drop for Reaper {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn nfd_bin() -> Option<String> {
    [
        std::env::var("NFD_BIN").ok(),
        Some(format!("{}/Documents/Dev/NFD/build/bin/nfd", std::env::var("HOME").unwrap_or_default())),
    ]
    .into_iter()
    .flatten()
    .find(|p| std::path::Path::new(p).exists())
}

/// The ndn-cxx dylib directory NFD (C++) needs at runtime.
fn ndn_cxx_lib() -> String {
    std::env::var("NDN_CXX_LIB")
        .unwrap_or_else(|_| format!("{}/Documents/Dev/ndn-cxx/build", std::env::var("HOME").unwrap_or_default()))
}

/// The unix socket NFD's in-process RIB manager talks to the forwarder over
/// (without it, NFD aborts at startup: "No transport is available").
fn nfd_socket(port: u16) -> String {
    std::env::temp_dir().join(format!("ndn-lab-nfd-{port}.sock")).to_string_lossy().into_owned()
}

/// A minimal, self-contained NFD config: a UDP unicast listener on `port` (with
/// on-demand faces, so our sim node dialing in gets a face), a unix channel for
/// the RIB manager, and the default best-route strategy.
fn write_config(port: u16) -> std::path::PathBuf {
    let sock = nfd_socket(port);
    let cfg = format!(
        r#"general {{ }}
log {{ default_level NONE }}
tables {{ cs_max_packets 100 }}
face_system {{
  general {{ enable_congestion_marking no }}
  unix {{ path {sock} }}
  udp {{
    listen yes
    port {port}
    enable_v4 yes
    enable_v6 no
    idle_timeout 600
    mcast no
  }}
}}
authorizations {{
  authorize {{
    certfile any
    privileges {{ faces route strategy-choice }}
  }}
}}
rib {{
  localhost_security {{ trust-anchor {{ type any }} }}
}}
"#
    );
    let path = std::env::temp_dir().join(format!("ndn-lab-interop-nfd-{port}.conf"));
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(cfg.as_bytes()).unwrap();
    path
}

/// Start NFD on `port`; `None` (with a SKIP note) if the binary is absent.
async fn start_nfd(port: u16) -> Option<Reaper> {
    let Some(bin) = nfd_bin() else {
        eprintln!("SKIP: NFD binary not found (set NFD_BIN; a built NFD/build/bin/nfd)");
        return None;
    };
    let _ = std::fs::remove_file(nfd_socket(port));
    let config = write_config(port);
    let nfd = Command::new(&bin)
        .args(["--config", config.to_str().unwrap()])
        .env("DYLD_FALLBACK_LIBRARY_PATH", ndn_cxx_lib())
        .env("NDN_CLIENT_TRANSPORT", format!("unix://{}", nfd_socket(port)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let reaper = Reaper(vec![nfd]);
    tokio::time::sleep(Duration::from_millis(1200)).await; // let the UDP channel bind
    Some(reaper)
}

/// The corner: an unrouted Interest at NFD comes back as a **`NoRoute` Nack**
/// that our consumer surfaces as `AppError::Nacked` — the cross-stack "no" that
/// no-Nack ndnd structurally can't produce.
#[tokio::test]
#[ignore = "needs a built NFD (set NFD_BIN + NDN_CXX_LIB)"]
async fn nfd_best_route_nacks_noroute_and_we_surface_it() {
    let port = 26363u16;
    let Some(_nfd) = start_nfd(port).await else { return };

    let mut sim = Simulation::new().kernel(RealTimeKernel::new() as Arc<dyn SimKernel>);
    let node = sim.add_node(ndn_engine::builder::EngineConfig::default());
    let fabric = sim.start().await.unwrap();
    let face = fabric
        .bridge_udp(node, "127.0.0.1:0".parse().unwrap(), format!("127.0.0.1:{port}").parse().unwrap())
        .await
        .unwrap();
    // Route /nfd-void toward NFD; NFD has no route for it ⇒ best-route Nacks NoRoute.
    fabric.engine_of(node).unwrap().fib().add_nexthop(&"/nfd-void".parse::<Name>().unwrap(), face, 10);

    let mut consumer = fabric.engine_of(node).unwrap().app_consumer(CancellationToken::new());
    let interest =
        InterestBuilder::new("/nfd-void/x".parse::<Name>().unwrap()).lifetime(Duration::from_secs(4));
    let res = consumer.fetch_with(interest).await;
    fabric.shutdown().await;

    match res {
        Err(AppError::Nacked { reason }) => {
            eprintln!("INTEROP OK: NFD best-route Nacked the unrouted Interest ({reason:?})");
        }
        other => panic!("expected a NoRoute Nack from real NFD, got {other:?}"),
    }
}

/// Run an `nfdc` command against the NFD on `port` (over its unix socket).
fn nfdc(port: u16, args: &[&str]) {
    let nfd = nfd_bin().unwrap();
    let nfdc_path = std::path::Path::new(&nfd).with_file_name("nfdc");
    let ok = Command::new(nfdc_path)
        .args(args)
        .env("DYLD_FALLBACK_LIBRARY_PATH", ndn_cxx_lib())
        .env("NDN_CLIENT_TRANSPORT", format!("unix://{}", nfd_socket(port)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "nfdc {args:?} failed");
}

/// Fetch `/diff/obj/0..n` through a consumer, returning how many Data arrived.
async fn fetch_n(consumer: &mut ndn_app::Consumer, n: u32) -> u32 {
    let mut got = 0;
    for i in 0..n {
        let name: Name = format!("/diff/obj/{i}").parse().unwrap();
        if consumer
            .fetch_with(InterestBuilder::new(name).must_be_fresh().lifetime(Duration::from_secs(4)))
            .await
            .is_ok()
        {
            got += 1;
        }
    }
    got
}

/// **Tier-2 differential harness**: run the *same* fetch workload through two
/// forwarder implementations — an ndn-rs relay (pure, in-fabric) and a real NFD
/// (foreign, bridged) — and diff the delivered count. Equal delivery means NFD
/// forwards ndn-rs Interest→Data identically; a divergence would be a semantic
/// finding (the class the PIT PSDC bug was in), not a wire-format one.
#[tokio::test]
#[ignore = "needs a built NFD (set NFD_BIN + NDN_CXX_LIB)"]
async fn differential_ndn_rs_relay_vs_nfd_forwarder_agree() {
    const N: u32 = 4;
    let serve = |producer: ndn_app::Producer| async move {
        let _ = producer
            .serve(|i, r| async move {
                let _ = r.respond((*i.name).clone(), bytes::Bytes::from_static(b"diff-payload")).await;
            })
            .await;
    };

    // ── Run A: pure ndn-rs, a relay in the middle (C — R — P) ────────────────
    let received_pure = {
        let mut sim = Simulation::new();
        let (c, r, p) = (
            sim.add_node(ndn_engine::builder::EngineConfig::default()),
            sim.add_node(ndn_engine::builder::EngineConfig::default()),
            sim.add_node(ndn_engine::builder::EngineConfig::default()),
        );
        sim.link(c, r, ndn_sim::LinkConfig::lan());
        sim.link(r, p, ndn_sim::LinkConfig::lan());
        sim.add_route(c, "/diff", r);
        sim.add_route(r, "/diff", p);
        let fabric = sim.start().await.unwrap();
        tokio::spawn(serve(fabric.engine_of(p).unwrap().register_producer("/diff/obj", CancellationToken::new())));
        let mut consumer = fabric.engine_of(c).unwrap().app_consumer(CancellationToken::new());
        let got = fetch_n(&mut consumer, N).await;
        fabric.shutdown().await;
        got
    };

    // ── Run B: foreign, real NFD in the middle (C — NFD — P) ─────────────────
    let port = 28363u16;
    let Some(_nfd) = start_nfd(port).await else { return };
    let received_foreign = {
        let mut sim = Simulation::new().kernel(RealTimeKernel::new() as Arc<dyn SimKernel>);
        let (c, p) = (
            sim.add_node(ndn_engine::builder::EngineConfig::default()),
            sim.add_node(ndn_engine::builder::EngineConfig::default()),
        );
        let fabric = sim.start().await.unwrap();
        let nfd_addr = format!("127.0.0.1:{port}");
        // Producer node P listens on a FIXED port so NFD can route toward it.
        let p_port = 28401u16;
        fabric.bridge_udp(p, format!("127.0.0.1:{p_port}").parse().unwrap(), nfd_addr.parse().unwrap()).await.unwrap();
        tokio::spawn(serve(fabric.engine_of(p).unwrap().register_producer("/diff/obj", CancellationToken::new())));
        // Consumer node C bridges to NFD; route /diff over that face.
        let c_face = fabric.bridge_udp(c, "127.0.0.1:0".parse().unwrap(), nfd_addr.parse().unwrap()).await.unwrap();
        fabric.engine_of(c).unwrap().fib().add_nexthop(&"/diff".parse::<Name>().unwrap(), c_face, 10);
        // NFD forwards /diff toward P.
        nfdc(port, &["route", "add", "/diff", &format!("udp://127.0.0.1:{p_port}")]);
        tokio::time::sleep(Duration::from_millis(400)).await;
        let mut consumer = fabric.engine_of(c).unwrap().app_consumer(CancellationToken::new());
        let got = fetch_n(&mut consumer, N).await;
        fabric.shutdown().await;
        got
    };

    eprintln!("DIFFERENTIAL: pure ndn-rs relay delivered {received_pure}/{N}; real NFD delivered {received_foreign}/{N}");
    assert_eq!(received_pure, N, "the pure ndn-rs path delivers everything");
    assert_eq!(
        received_pure, received_foreign,
        "NFD forwards ndn-rs Interest→Data identically to an ndn-rs relay (no semantic divergence)"
    );
}
