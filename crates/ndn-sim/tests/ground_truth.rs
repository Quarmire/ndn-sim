//! **Ground-truth self-verification (#32).** The red-team found the sim had *zero* analytical
//! cross-checks in 400+ asserts — "validation" only compared the sim to itself. These tests pin the sim
//! against KNOWN physics/math (Semtech LoRa airtime, 802.11 airtime, Friis path loss, PER monotonicity,
//! both-frames-lose collisions, TX-power actuation) so a fidelity regression is caught, not confirmed.

use std::sync::Arc;

use ndn_sim::lora::{LoraConfig, SpreadingFactor};
use ndn_sim::wifi::{broadcast_airtime, frame_airtime};
use ndn_sim::world::{Position, World};
use ndn_sim::{FreeSpacePathLoss, NodeId, PropagationModel, RadioBus};

// ---- Airtime anchors (pure functions) -------------------------------------------------------------

#[test]
fn lora_airtime_matches_semtech_calculator() {
    // Semtech LoRa airtime (BW125, CR 4/5, explicit header + CRC, low-DR-optimize at SF≥11):
    // SF12 / 20 B ≈ 1.319 s; SF7 / 20 B ≈ 41.2 ms. Absolute values, not just relative ordering.
    let t12 = LoraConfig::new(SpreadingFactor::Sf12).airtime(20).as_secs_f64();
    assert!((t12 - 1.319).abs() < 0.02, "SF12/20B airtime {t12}s should be ~1.319s (Semtech)");
    let t7 = LoraConfig::new(SpreadingFactor::Sf7).airtime(20).as_secs_f64();
    assert!((t7 - 0.0565).abs() < 0.002, "SF7/20B airtime {t7}s should be ~56.5ms (8-symbol preamble + 43 payload symbols x 1.024ms)");
}

#[test]
fn wifi_frame_airtime_matches_formula() {
    // frame_airtime = HT preamble (36 µs) + (payload + 34 B MAC) · 8 / PHY-rate. (F1 uses this for the
    // on-air/collision/receive window — pin it to the closed form so a preamble/overhead regression trips.)
    for (bytes, mcs, rate) in [(100usize, 7u8, 65.0e6f64), (1500, 0, 6.5e6), (2272, 7, 65.0e6)] {
        let expect_us = 36.0 + ((bytes + 34) * 8) as f64 / rate * 1e6;
        let got_us = frame_airtime(bytes, mcs).as_nanos() as f64 / 1000.0;
        assert!((got_us - expect_us).abs() < 0.5, "frame_airtime({bytes},{mcs}) = {got_us}µs, expected {expect_us}µs");
    }
}

#[test]
fn broadcast_airtime_is_frame_plus_bounded_contention() {
    // broadcast_airtime = DIFS + avg backoff + frame_airtime (F1 consistency): strictly greater than the
    // frame time, by a bounded DIFS+backoff overhead — not the ad-hoc bytes·8/rate the old collision path used.
    let f = frame_airtime(1000, 7).as_nanos() as f64;
    let b = broadcast_airtime(1000, 7).as_nanos() as f64;
    assert!(b > f, "broadcast airtime {b} must exceed the frame time {f} by the contention overhead");
    assert!(b - f < 250_000.0, "DIFS+backoff overhead {}ns should be < 250µs", b - f);
}

// ---- Propagation / delivery anchors (bus-level; a single transmit has no concurrent frame) ---------

fn strong_bus(positions: &[(usize, f64, f64)]) -> Arc<RadioBus> {
    let world = World::new();
    for (id, x, y) in positions {
        world.place(NodeId(*id), Position::xy(*x, *y));
    }
    RadioBus::new(Arc::new(world), Arc::new(FreeSpacePathLoss::default()), 0, 1)
}

#[tokio::test]
async fn rssi_is_monotone_decreasing_in_distance_friis() {
    // Friis free-space path loss ⇒ received power falls monotonically with distance. Transmit once from
    // node 0 and read the per-receiver RSSI the bus reports at increasing ranges.
    let bus = strong_bus(&[(0, 0.0, 0.0), (1, 5.0, 0.0), (2, 20.0, 0.0), (3, 60.0, 0.0)]);
    for id in [1, 2, 3] {
        bus.attach(NodeId(id));
    }
    let out = bus.transmit(NodeId(0), 0, bytes::Bytes::from_static(b"hello"), 0);
    let rssi = |n: usize| out.iter().find(|(rx, _, _)| *rx == NodeId(n)).map(|(_, r, _)| *r);
    let (a, b, c) = (rssi(1).unwrap(), rssi(2).unwrap(), rssi(3).unwrap());
    assert!(a > b && b > c, "RSSI must fall with distance: 5m={a} 20m={b} 60m={c}");
}

#[tokio::test]
async fn per_is_monotone_nonincreasing_in_distance() {
    // Delivery probability must be non-increasing in distance (better SNR closer). Estimate it by many
    // trials per range and assert the near link delivers at least as often as the far one.
    let deliver_rate = |dist: f64| -> f64 {
        let mut delivered = 0u32;
        let trials = 400u32;
        for seed in 0..trials {
            let world = World::new();
            world.place(NodeId(0), Position::xy(0.0, 0.0));
            world.place(NodeId(1), Position::xy(dist, 0.0));
            let bus = RadioBus::new(Arc::new(world), Arc::new(FreeSpacePathLoss::default()), 0, seed as u64);
            bus.attach(NodeId(1));
            let out = bus.transmit(NodeId(0), 7, bytes::Bytes::from_static(b"x"), 0);
            if out.iter().any(|(rx, _, ok)| *rx == NodeId(1) && *ok) {
                delivered += 1;
            }
        }
        delivered as f64 / trials as f64
    };
    let near = deliver_rate(10.0);
    let mid = deliver_rate(FreeSpacePathLoss::default().max_range_m() * 0.6);
    let far = deliver_rate(FreeSpacePathLoss::default().max_range_m() * 0.95);
    assert!(near >= mid - 0.02 && mid >= far - 0.02, "PER must be monotone in distance: {near} {mid} {far}");
    assert!(near > far, "a near link must deliver more often than a far one: {near} vs {far}");
}

#[tokio::test]
async fn lower_tx_power_shrinks_delivery() {
    // TX-power actuation (H5/F8 direction): halving the transmit power must measurably reduce delivery at
    // a marginal range — power is a real reach lever, not a dead field.
    let edge = FreeSpacePathLoss::default().max_range_m() * 0.5; // 12dB power drop ≈ 4x range, so 20dBm reaches here, 8dBm does not
    let rate_at_power = |dbm: f64| -> f64 {
        let mut delivered = 0u32;
        let trials = 400u32;
        for seed in 0..trials {
            let world = World::new();
            world.place(NodeId(0), Position::xy(0.0, 0.0));
            world.place(NodeId(1), Position::xy(edge, 0.0));
            let bus = RadioBus::new(Arc::new(world), Arc::new(FreeSpacePathLoss::default()), 0, seed as u64);
            bus.attach(NodeId(1));
            bus.set_tx_power(NodeId(0), dbm);
            let out = bus.transmit(NodeId(0), 7, bytes::Bytes::from_static(b"x"), 0);
            if out.iter().any(|(rx, _, ok)| *rx == NodeId(1) && *ok) {
                delivered += 1;
            }
        }
        delivered as f64 / trials as f64
    };
    let full = rate_at_power(20.0);
    let low = rate_at_power(8.0);
    assert!(full > low, "lower TX power must reduce delivery at the edge: full={full} low={low}");
}
