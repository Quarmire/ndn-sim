//! **Ground-truth self-verification (#32), LoRa half.** Pins the studies LoRa model against KNOWN
//! physics (the Semtech airtime calculator) and the shared ALOHA medium's two defining behaviours —
//! collisions rise with offered load, and the duty-cycle regulator gates an over-budget node. The
//! Wi-Fi airtime / Friis / PER anchors for the core radio face live in ndn-sim's `ground_truth.rs`.

use std::sync::Arc;
use std::time::Duration;

use ndn_sim::world::Position;
use ndn_sim::{DesKernel, SimKernel};
use ndn_sim_studies::lora::{LoraConfig, SpreadingFactor};
use ndn_sim_studies::{IpNetwork, LoraLinkConfig, ShortestPath};

#[test]
fn lora_airtime_matches_semtech_calculator() {
    // Semtech LoRa airtime (BW125, CR 4/5, explicit header + CRC, low-DR-optimize at SF≥11):
    // SF12 / 20 B ≈ 1.319 s; SF7 / 20 B ≈ 41.2 ms. Absolute values, not just relative ordering.
    let t12 = LoraConfig::new(SpreadingFactor::Sf12)
        .airtime(20)
        .as_secs_f64();
    assert!(
        (t12 - 1.319).abs() < 0.02,
        "SF12/20B airtime {t12}s should be ~1.319s (Semtech)"
    );
    let t7 = LoraConfig::new(SpreadingFactor::Sf7)
        .airtime(20)
        .as_secs_f64();
    assert!(
        (t7 - 0.0565).abs() < 0.002,
        "SF7/20B airtime {t7}s should be ~56.5ms (8-symbol preamble + 43 payload symbols x 1.024ms)"
    );
}

// ---- F6: LoRa shared ALOHA medium — collisions + duty cycle -----------------------------------------

/// F6 ground truth (a): on the shared ALOHA medium, two same-SF LoRa senders transmitting toward a
/// common receiver lose MORE as offered load rises. At a low rate their (staggered) airtime windows
/// rarely overlap and nearly every request is delivered; at a high rate the windows overlap
/// constantly, both frames collide, and delivery collapses — the ALOHA capacity limit the old
/// point-to-point model could never show.
#[test]
fn lora_aloha_collisions_engage_as_offered_load_rises() {
    // node 0 = receiver at the origin; nodes 1 & 2 = senders EQUIDISTANT (equal RSSI ⇒ no capture ⇒
    // both frames lose when they overlap). SF9 keeps airtime ~0.17 s so the test is quick.
    fn run(interval: Duration, lifetime: Duration, stagger: Duration) -> (u64, u64) {
        DesKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
            let rt = k.runtime();
            let positions = vec![
                Position::xy(0.0, 0.0),
                Position::xy(-500.0, 0.0),
                Position::xy(500.0, 0.0),
            ];
            let cfg = LoraLinkConfig::new(10_000.0, SpreadingFactor::Sf9);
            let net = IpNetwork::from_positions_lora(rt, positions, &cfg, &ShortestPath);
            let f1 = net.node(1).ping(net.addr(0), 8, 16, interval, lifetime);
            let f2 = async {
                ndn_app::rt::sleep(stagger).await;
                net.node(2)
                    .ping(net.addr(0), 8, 16, interval, lifetime)
                    .await
            };
            let _ = tokio::join!(f1, f2);
            // The receiver's `delivered` counts request frames that actually arrived (uplink success);
            // plus the medium's collision tally.
            (net.node(0).stats().delivered, net.lora_collisions())
        })
    }

    // Low load: 5 s spacing, senders offset 2.5 s ⇒ windows never overlap.
    let (low_delivered, low_collisions) = run(
        Duration::from_secs(5),
        Duration::from_secs(2),
        Duration::from_millis(2500),
    );
    // High load: back-to-back, offset a fraction of the airtime ⇒ windows overlap on every round.
    let (high_delivered, high_collisions) = run(
        Duration::ZERO,
        Duration::from_millis(800),
        Duration::from_millis(80),
    );

    assert!(
        low_collisions < high_collisions,
        "collisions must rise with offered load: low={low_collisions} high={high_collisions}"
    );
    assert!(
        high_delivered < low_delivered,
        "delivery must collapse under load (ALOHA): low={low_delivered} high={high_delivered}"
    );
    assert!(
        low_delivered >= 14,
        "at low load nearly all 16 requests are delivered collision-free: {low_delivered}"
    );
    assert!(
        high_collisions >= 8,
        "at high load the medium is saturated with collisions: {high_collisions}"
    );
}

/// F6 ground truth (b): a node whose offered load exceeds its duty-cycle budget is GATED — the
/// regulator (DutyCycle::off_time) drops transmissions once the on-air fraction would blow past the
/// 1 % ceiling. Pinging an SF12 link (≈1.15 s airtime ⇒ ~114 s mandatory off-time) once a second, only
/// the first frame gets out; the rest are gated. With enforcement off, every frame flows.
#[test]
fn lora_duty_cycle_gates_over_budget_node() {
    fn run(duty_enforced: bool) -> (u64, u64) {
        DesKernel::new().run(move |k: Arc<dyn SimKernel>| async move {
            let rt = k.runtime();
            let positions = vec![Position::xy(0.0, 0.0), Position::xy(500.0, 0.0)];
            let cfg = LoraLinkConfig::new(10_000.0, SpreadingFactor::Sf12);
            let net = IpNetwork::from_positions_lora_shared(
                rt,
                positions,
                &cfg,
                duty_enforced,
                &ShortestPath,
            );
            let stats = net
                .node(0)
                .ping(
                    net.addr(1),
                    10,
                    16,
                    Duration::from_secs(1),
                    Duration::from_secs(3),
                )
                .await;
            (stats.received, net.lora_duty_gated())
        })
    }

    let (free_received, free_gated) = run(false);
    let (gated_received, gated_gated) = run(true);

    assert_eq!(free_gated, 0, "with enforcement off, nothing is duty-gated");
    assert!(
        free_received >= 8,
        "with enforcement off, a 2-node sequential flow delivers nearly all 10 pings: {free_received}"
    );
    assert!(
        gated_gated >= 8,
        "the duty-cycle regulator gates the over-budget transmissions: {gated_gated}"
    );
    assert!(
        gated_received < free_received,
        "gating suppresses delivery: gated={gated_received} free={free_received}"
    );
}
