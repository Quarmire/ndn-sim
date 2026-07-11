//! Gap 1 (miniMUAS lift): a FOREIGN (non-NDN) UDP flow carried across a real
//! SimLink experiences the `LinkConfig` impairment — the fabric's own loss/delay
//! semantics, not a hand-rolled relay duplicating the numbers. The payload here
//! is arbitrary bytes (`b"rc-frame-…"` / raw telemetry), never NDN, never parsed.

use std::time::{Duration, Instant};

use ndn_sim::{LinkConfig, Simulation};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// The gate, in two unambiguous probes: the profile's **delay** is applied to a
/// lossless flow (a single datagram arrives ~delay later, not instantly), and the
/// profile's **loss** thins a batch (fewer-than-sent survive, not zero, not all).
/// Either would be a hand-rolled relay's job; here it's the real SimLink.
#[tokio::test(flavor = "multi_thread")]
async fn foreign_flow_experiences_configured_loss_and_delay() {
    let fabric = Simulation::new().start().await.unwrap(); // default WallClockKernel

    // ── delay probe: lossless, 120 ms — one datagram, timed clean ────────────
    {
        let (a, b) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let link = LinkConfig { delay: Duration::from_millis(120), jitter: Duration::ZERO, loss_rate: 0.0, bandwidth_bps: 0 };
        let cancel = CancellationToken::new();
        let relay = fabric.bridge_udp_flow(a.local_addr().unwrap(), b.local_addr().unwrap(), link, cancel.clone()).await.unwrap();
        let t = Instant::now();
        a.send_to(b"delay-probe", relay).await.unwrap();
        let mut buf = [0u8; 64];
        tokio::time::timeout(Duration::from_secs(2), b.recv_from(&mut buf)).await.expect("probe arrives").unwrap();
        let d = t.elapsed();
        cancel.cancel();
        eprintln!("delay probe arrived at {d:?} (configured 120 ms)");
        assert!(d >= Duration::from_millis(90), "the 120 ms link delay is applied, not passthrough: {d:?}");
    }

    // ── loss batch: 0.4 loss, no delay — count survivors ─────────────────────
    let (a, b) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let link = LinkConfig { delay: Duration::ZERO, jitter: Duration::ZERO, loss_rate: 0.4, bandwidth_bps: 0 };
    let cancel = CancellationToken::new();
    let relay = fabric.bridge_udp_flow(a.local_addr().unwrap(), b.local_addr().unwrap(), link, cancel.clone()).await.unwrap();

    const SENT: usize = 60;
    for i in 0..SENT {
        a.send_to(format!("rc-frame-{i}").as_bytes(), relay).await.unwrap();
        tokio::time::sleep(Duration::from_millis(3)).await;
    }
    let mut buf = [0u8; 256];
    let mut arrived = 0usize;
    while tokio::time::timeout(Duration::from_millis(300), b.recv_from(&mut buf)).await.is_ok_and(|r| r.is_ok()) {
        arrived += 1;
    }
    cancel.cancel();
    fabric.shutdown().await;

    eprintln!("loss batch: {arrived}/{SENT} survived (configured loss 0.4)");
    assert!(arrived > 0 && arrived < SENT, "loss applied, not lossless and not total: {arrived}/{SENT}");
}

/// The interpose is bidirectional: both peers reach each other across the link.
#[tokio::test(flavor = "multi_thread")]
async fn foreign_flow_is_bidirectional() {
    let fabric = Simulation::new().start().await.unwrap();
    let peer_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (addr_a, addr_b) = (peer_a.local_addr().unwrap(), peer_b.local_addr().unwrap());

    // A clean (lossless, small-delay) link so both directions deterministically arrive.
    let link = LinkConfig { delay: Duration::from_millis(5), jitter: Duration::ZERO, loss_rate: 0.0, bandwidth_bps: 0 };
    let cancel = CancellationToken::new();
    let relay = fabric.bridge_udp_flow(addr_a, addr_b, link, cancel.clone()).await.unwrap();

    let mut buf = [0u8; 256];
    let win = Duration::from_secs(2);

    // A → B
    peer_a.send_to(b"a-to-b", relay).await.unwrap();
    let (n, _) = tokio::time::timeout(win, peer_b.recv_from(&mut buf)).await.expect("a→b timed out").unwrap();
    assert_eq!(&buf[..n], b"a-to-b");
    // B → A
    peer_b.send_to(b"b-to-a", relay).await.unwrap();
    let (n, _) = tokio::time::timeout(win, peer_a.recv_from(&mut buf)).await.expect("b→a timed out").unwrap();
    assert_eq!(&buf[..n], b"b-to-a");

    cancel.cancel();
    fabric.shutdown().await;
}
