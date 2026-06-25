//! `SimLink` — configurable bidirectional link between two simulated faces.
//!
//! In the slice-3 world model this is the **wired static channel**: a fixed point-to-point
//! pipe whose delay/loss/bandwidth are properties of the *link*, not of node positions. It is
//! the degenerate counterpart of the position-driven [`WirelessMedium`](crate::WirelessMedium)
//! — same "deliver a frame after a delay over a Tokio channel" mechanism (so both are virtual
//! under a [`VirtualKernel`](crate::VirtualKernel)), minus propagation/range/fan-out. Existing
//! callers are unaffected; reach for the medium when delivery should depend on *where* nodes
//! are and *how they move*.

use std::time::Duration;

use ndn_transport::{FaceId, FaceKind, LinkType};

use crate::sim_face::SimFace;

/// Link properties for a simulated connection.
#[derive(Clone, Debug)]
pub struct LinkConfig {
    /// Base one-way propagation delay.
    pub delay: Duration,
    /// Random jitter added to each packet's delay (uniform in `[0, jitter]`).
    pub jitter: Duration,
    /// Packet loss rate (0.0 = no loss, 1.0 = all packets dropped).
    pub loss_rate: f64,
    /// Link bandwidth in bits per second. `0` means unlimited.
    pub bandwidth_bps: u64,
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self {
            delay: Duration::ZERO,
            jitter: Duration::ZERO,
            loss_rate: 0.0,
            bandwidth_bps: 0,
        }
    }
}

impl LinkConfig {
    /// Lossless, zero-delay link (in-process direct connection).
    pub fn direct() -> Self {
        Self::default()
    }

    /// Typical LAN link: 1ms delay, no loss, 1 Gbps.
    pub fn lan() -> Self {
        Self {
            delay: Duration::from_millis(1),
            jitter: Duration::from_micros(100),
            loss_rate: 0.0,
            bandwidth_bps: 1_000_000_000,
        }
    }

    /// Typical WiFi link: 5ms delay, 1% loss, 54 Mbps.
    pub fn wifi() -> Self {
        Self {
            delay: Duration::from_millis(5),
            jitter: Duration::from_millis(2),
            loss_rate: 0.01,
            bandwidth_bps: 54_000_000,
        }
    }

    /// WAN link: 50ms delay, 0.1% loss, 100 Mbps.
    pub fn wan() -> Self {
        Self {
            delay: Duration::from_millis(50),
            jitter: Duration::from_millis(5),
            loss_rate: 0.001,
            bandwidth_bps: 100_000_000,
        }
    }

    /// Lossy wireless link: 10ms delay, 5% loss, 11 Mbps.
    pub fn lossy_wireless() -> Self {
        Self {
            delay: Duration::from_millis(10),
            jitter: Duration::from_millis(5),
            loss_rate: 0.05,
            bandwidth_bps: 11_000_000,
        }
    }
}

/// A **per-face-type behavioral profile**: what the engine sees (`FaceKind`, `LinkType`,
/// `send_mtu`) + delivery semantics (`reliable` stream vs lossy/reorderable datagram) + the base
/// link properties. The §5 "simulate each face we support" catalogue — a logical model per face
/// *type*, so a scenario can express UDP-vs-TCP-vs-BLE behavior the forwarder reacts to (scope,
/// LP fragmentation, multi-access suppression, loss/ordering) without a real transport.
///
/// Defaults are representative, not calibrated; override the base link with [`with_link`](Self::with_link).
#[derive(Clone, Debug)]
pub struct FaceProfile {
    pub kind: FaceKind,
    pub link_type: LinkType,
    /// `Some(n)` makes the LinkService LP-fragment above `n` bytes (per-type MTU); `None` = none.
    pub send_mtu: Option<usize>,
    /// Reliable stream (no loss, in-order) vs datagram (loss + jitter-reorder).
    pub reliable: bool,
    pub link: LinkConfig,
}

impl FaceProfile {
    /// Override the base link (delay/jitter/loss/bandwidth), keeping the type behavior.
    pub fn with_link(mut self, link: LinkConfig) -> Self {
        self.link = link;
        self
    }

    /// In-proc wired channel (the default — what `SimLink::pair` builds). `reliable = false` so
    /// it honors the configured `loss_rate`/`jitter` (back-compatible with raw `SimLink`); use
    /// [`shm`](Self::shm) for the truly lossless in-order in-proc transport.
    pub fn internal() -> Self {
        Self { kind: FaceKind::Internal, link_type: LinkType::PointToPoint, send_mtu: None, reliable: false, link: LinkConfig::direct() }
    }
    /// UDP: unreliable datagram, MTU-bounded, may reorder under jitter.
    pub fn udp() -> Self {
        Self { kind: FaceKind::Udp, link_type: LinkType::PointToPoint, send_mtu: Some(1420), reliable: false, link: LinkConfig::lan() }
    }
    /// TCP: ordered, reliable stream (no loss, head-of-line ordering).
    pub fn tcp() -> Self {
        Self { kind: FaceKind::Tcp, link_type: LinkType::PointToPoint, send_mtu: None, reliable: true, link: LinkConfig::lan() }
    }
    /// QUIC: ordered, reliable (modeled like TCP at this fidelity).
    pub fn quic() -> Self {
        Self { kind: FaceKind::Quic, link_type: LinkType::PointToPoint, send_mtu: None, reliable: true, link: LinkConfig::lan() }
    }
    /// WebSocket: ordered, reliable stream over a WAN-ish link.
    pub fn websocket() -> Self {
        Self { kind: FaceKind::WebSocket, link_type: LinkType::PointToPoint, send_mtu: None, reliable: true, link: LinkConfig::wan() }
    }
    /// WebTransport (HTTP/3): reliable stream.
    pub fn web_transport() -> Self {
        Self { kind: FaceKind::WebTransport, link_type: LinkType::PointToPoint, send_mtu: None, reliable: true, link: LinkConfig::wan() }
    }
    /// Ethernet unicast: L2, MTU-bounded, near-lossless.
    pub fn ethernet() -> Self {
        Self { kind: FaceKind::Ethernet, link_type: LinkType::PointToPoint, send_mtu: Some(1450), reliable: false,
               link: LinkConfig { delay: Duration::from_micros(100), jitter: Duration::ZERO, loss_rate: 0.0, bandwidth_bps: 1_000_000_000 } }
    }
    /// Ethernet/UDP multicast: L2 broadcast domain (multi-access), lossy.
    pub fn multicast() -> Self {
        Self { kind: FaceKind::EtherMulticast, link_type: LinkType::MultiAccess, send_mtu: Some(1450), reliable: false,
               link: LinkConfig { delay: Duration::from_millis(1), jitter: Duration::from_micros(200), loss_rate: 0.01, bandwidth_bps: 1_000_000_000 } }
    }
    /// Shared memory / in-proc: near-zero-loss, in-order, near-zero delay, huge bandwidth.
    pub fn shm() -> Self {
        Self { kind: FaceKind::Shm, link_type: LinkType::PointToPoint, send_mtu: None, reliable: true,
               link: LinkConfig { delay: Duration::from_nanos(100), jitter: Duration::ZERO, loss_rate: 0.0, bandwidth_bps: 0 } }
    }
    /// Serial: small MTU, low bandwidth, mild loss.
    pub fn serial() -> Self {
        Self { kind: FaceKind::Serial, link_type: LinkType::PointToPoint, send_mtu: Some(256), reliable: false,
               link: LinkConfig { delay: Duration::from_millis(5), jitter: Duration::from_millis(1), loss_rate: 0.005, bandwidth_bps: 115_200 } }
    }
    /// BLE advertising: tiny ext-adv frames, slow, lossy beacon.
    pub fn ble() -> Self {
        Self { kind: FaceKind::Bluetooth, link_type: LinkType::PointToPoint, send_mtu: Some(245), reliable: false,
               link: LinkConfig { delay: Duration::from_millis(20), jitter: Duration::from_millis(5), loss_rate: 0.05, bandwidth_bps: 1_000_000 } }
    }
    /// Wi-Fi Aware (NAN): connectionless, AdHoc, moderate rate + small loss.
    pub fn nan() -> Self {
        Self { kind: FaceKind::WifiAware, link_type: LinkType::AdHoc, send_mtu: Some(1420), reliable: false,
               link: LinkConfig { delay: Duration::from_millis(5), jitter: Duration::from_millis(2), loss_rate: 0.01, bandwidth_bps: 50_000_000 } }
    }

    /// Resolve a profile by name (for scenario files / control commands). `None` if unknown.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "internal" => Self::internal(),
            "udp" => Self::udp(),
            "tcp" => Self::tcp(),
            "quic" => Self::quic(),
            "websocket" | "ws" => Self::websocket(),
            "web_transport" | "webtransport" => Self::web_transport(),
            "ethernet" | "ether" => Self::ethernet(),
            "multicast" => Self::multicast(),
            "shm" => Self::shm(),
            "serial" => Self::serial(),
            "ble" | "bluetooth" => Self::ble(),
            "nan" | "wifi_aware" => Self::nan(),
            _ => return None,
        })
    }
}

/// A simulated bidirectional link between two faces.
pub struct SimLink;

impl SimLink {
    /// Create a pair of connected `SimFace`s with symmetric link properties.
    /// For asymmetric directions, use [`pair_asymmetric`](Self::pair_asymmetric).
    pub fn pair(
        id_a: FaceId,
        id_b: FaceId,
        config: LinkConfig,
        buffer: usize,
    ) -> (SimFace, SimFace) {
        // Default = an in-proc wired channel carrying these link properties.
        Self::pair_profiled(id_a, id_b, &FaceProfile::internal().with_link(config), buffer)
    }

    /// Create a pair with different link properties per direction (in-proc wired).
    pub fn pair_asymmetric(
        id_a: FaceId,
        id_b: FaceId,
        config_a_to_b: LinkConfig,
        config_b_to_a: LinkConfig,
        buffer: usize,
    ) -> (SimFace, SimFace) {
        Self::pair_profiled_asymmetric(
            id_a,
            id_b,
            &FaceProfile::internal().with_link(config_a_to_b),
            &FaceProfile::internal().with_link(config_b_to_a),
            buffer,
        )
    }

    /// Create a pair of faces of a given [`FaceProfile`] (the per-type behavioral catalogue):
    /// both endpoints present that type's `FaceKind`/`LinkType`/`send_mtu` + delivery semantics.
    pub fn pair_profiled(
        id_a: FaceId,
        id_b: FaceId,
        profile: &FaceProfile,
        buffer: usize,
    ) -> (SimFace, SimFace) {
        Self::pair_profiled_asymmetric(id_a, id_b, profile, profile, buffer)
    }

    /// As [`pair_profiled`](Self::pair_profiled) but with a distinct profile per direction.
    pub fn pair_profiled_asymmetric(
        id_a: FaceId,
        id_b: FaceId,
        profile_a: &FaceProfile,
        profile_b: &FaceProfile,
        buffer: usize,
    ) -> (SimFace, SimFace) {
        let (tx_a, rx_a) = tokio::sync::mpsc::channel(buffer);
        let (tx_b, rx_b) = tokio::sync::mpsc::channel(buffer);
        // face_a writes into tx_b → rx_b (face_b's recv); face_b writes into tx_a → rx_a.
        let face_a = SimFace::new(id_a, tx_b, rx_a, profile_a);
        let face_b = SimFace::new(id_b, tx_a, rx_b, profile_b);
        (face_a, face_b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_transport::Transport;

    #[tokio::test]
    async fn direct_link_delivers_packet() {
        let (face_a, face_b) = SimLink::pair(FaceId(1), FaceId(2), LinkConfig::direct(), 16);

        let payload = bytes::Bytes::from_static(b"hello");
        face_a.send_bytes(payload.clone()).await.unwrap();

        let received = face_b.recv_bytes().await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn bidirectional_delivery() {
        let (face_a, face_b) = SimLink::pair(FaceId(1), FaceId(2), LinkConfig::direct(), 16);

        face_a
            .send_bytes(bytes::Bytes::from_static(b"ping"))
            .await
            .unwrap();
        face_b
            .send_bytes(bytes::Bytes::from_static(b"pong"))
            .await
            .unwrap();

        let at_b = face_b.recv_bytes().await.unwrap();
        let at_a = face_a.recv_bytes().await.unwrap();
        assert_eq!(at_b, &b"ping"[..]);
        assert_eq!(at_a, &b"pong"[..]);
    }

    #[tokio::test]
    async fn delayed_link() {
        let config = LinkConfig {
            delay: Duration::from_millis(50),
            ..Default::default()
        };
        let (face_a, face_b) = SimLink::pair(FaceId(1), FaceId(2), config, 16);

        let start = tokio::time::Instant::now();
        face_a
            .send_bytes(bytes::Bytes::from_static(b"hi"))
            .await
            .unwrap();
        let _received = face_b.recv_bytes().await.unwrap();
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(45),
            "expected ~50ms delay, got {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn lossy_link_drops_some_packets() {
        let config = LinkConfig {
            loss_rate: 1.0, // drop everything
            ..Default::default()
        };
        let (face_a, face_b) = SimLink::pair(FaceId(1), FaceId(2), config, 16);

        for _ in 0..10 {
            face_a
                .send_bytes(bytes::Bytes::from_static(b"x"))
                .await
                .unwrap();
        }

        // With 100% loss, nothing should arrive. Use a short timeout.
        let result = tokio::time::timeout(Duration::from_millis(100), face_b.recv_bytes()).await;
        assert!(result.is_err(), "expected timeout with 100% loss");
    }

    /// Slice 0: the seeded RNG makes a partial-loss link **reproducible** — the same face
    /// ids + config drop the same packets every run (was `thread_rng`, nondeterministic).
    #[tokio::test]
    async fn partial_loss_is_deterministic_across_runs() {
        async fn run() -> Vec<u8> {
            let config = LinkConfig {
                loss_rate: 0.5,
                delay: Duration::ZERO, // zero delay ⇒ inline delivery, stable ordering
                jitter: Duration::ZERO,
                bandwidth_bps: 0,
            };
            // Same ids ⇒ same seed ⇒ same drop pattern.
            let (face_a, face_b) = SimLink::pair(FaceId(7), FaceId(8), config, 64);
            for i in 0..40u8 {
                face_a.send_bytes(bytes::Bytes::copy_from_slice(&[i])).await.unwrap();
            }
            // Drain whatever survived, in order.
            let mut got = Vec::new();
            while let Ok(Ok(b)) =
                tokio::time::timeout(Duration::from_millis(20), face_b.recv_bytes()).await
            {
                got.push(b[0]);
            }
            got
        }

        let first = run().await;
        let second = run().await;
        assert_eq!(first, second, "same topology must replay the identical drop pattern");
        assert!(!first.is_empty() && first.len() < 40, "~half delivered, not all/none");
    }
}
