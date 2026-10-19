//! `SimLink` — configurable bidirectional link between two simulated faces.
//!
//! In the slice-3 world model this is the **wired static channel**: a fixed point-to-point
//! pipe whose delay/loss/bandwidth are properties of the *link*, not of node positions. It is
//! the degenerate counterpart of the position-driven [`RadioBus`](crate::RadioBus)
//! — same "deliver a frame after a delay over a Tokio channel" mechanism (so both are virtual
//! under a [`VirtualKernel`](crate::VirtualKernel)), minus propagation/range/fan-out. Existing
//! callers are unaffected; reach for the medium when delivery should depend on *where* nodes
//! are and *how they move*.

use std::sync::Arc;
use std::time::Duration;

use ndn_runtime::Runtime;
use ndn_transport::{FaceId, FaceKind, FacePersistency, LinkType};

use crate::shared_channel::SharedChannel;
use crate::sim_face::{Outbound, SimFace};

/// IPv4 header bytes every IP fragment carries.
pub const IPV4_HEADER: usize = 20;
/// UDP header bytes (carried once, in the first IP fragment).
pub const UDP_HEADER: usize = 8;
/// Ethernet / managed Wi-Fi IP MTU — the path the fleet's UDP faces ride. A UDP payload above
/// `1500 - 28 = 1472` bytes is IP-fragmented.
pub const ETHERNET_IP_MTU: usize = 1500;

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
/// It also carries how the fabric **attaches** the face to its engine (`persistency`,
/// `lp_reliability`) — the part of a fleet face that is not the transport but decided fleet
/// behavior (a Persistent peer face destroyed on the first send error; reliability flipped on
/// per face at runtime). [`udp`](Self::udp) is the production peer link and the default for
/// [`Simulation::link`](crate::Simulation::link).
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
    /// Persistency the engine wires the face with (governs what a send error does to it).
    pub persistency: FacePersistency,
    /// Enable NDNLPv2 reliability once the face is up, the way an operator does on the fleet
    /// (`faces/update` flag bit 1): `FaceOption::LpReliability(true)` + the face-flags bit.
    pub lp_reliability: bool,
    /// `Some(mtu)`: the face is IP-carried over a path of this IP MTU, so a datagram above
    /// `mtu - 28` is IP-fragmented and lost if ANY fragment is. `None` = not IP-carried.
    pub ip_mtu: Option<usize>,
    /// A contended medium this link shares airtime on (managed Wi-Fi: every peer face of every
    /// node on the cell). `None` = a dedicated link shaped by `link.bandwidth_bps` alone.
    pub channel: Option<Arc<SharedChannel>>,
    /// `Some(n)`: `link.loss_rate` is the loss of an `n`-byte frame (IP bytes on the wire) and a
    /// shorter frame is lost proportionally less often — independent bit/symbol errors, so a frame
    /// of `b` bytes survives with `(1 - loss_rate)^(b / n)`. `None` = every frame (IP fragment)
    /// is lost with `loss_rate` whatever its size. See [`with_loss_frame_bytes`](Self::with_loss_frame_bytes).
    pub loss_frame_bytes: Option<usize>,
}

impl FaceProfile {
    /// A face type with the catalogue's attach defaults: OnDemand, no LP reliability, not
    /// IP-carried, dedicated link.
    fn typed(
        kind: FaceKind,
        link_type: LinkType,
        send_mtu: Option<usize>,
        reliable: bool,
        link: LinkConfig,
    ) -> Self {
        Self {
            kind,
            link_type,
            send_mtu,
            reliable,
            link,
            persistency: FacePersistency::OnDemand,
            lp_reliability: false,
            ip_mtu: None,
            channel: None,
            loss_frame_bytes: None,
        }
    }

    /// Override the base link (delay/jitter/loss/bandwidth), keeping the type behavior.
    pub fn with_link(mut self, link: LinkConfig) -> Self {
        self.link = link;
        self
    }

    /// Turn NDNLPv2 reliability on/off for this link's faces (see [`lp_reliability`](Self::lp_reliability)).
    pub fn with_lp_reliability(mut self, on: bool) -> Self {
        self.lp_reliability = on;
        self
    }

    /// Override the persistency the faces are wired with.
    pub fn with_persistency(mut self, persistency: FacePersistency) -> Self {
        self.persistency = persistency;
        self
    }

    /// Put this link on a shared, airtime-serialised medium (see [`SharedChannel`]).
    pub fn on_channel(mut self, channel: Arc<SharedChannel>) -> Self {
        self.channel = Some(channel);
        self
    }

    /// Scale loss by frame size (see [`loss_frame_bytes`](Self::loss_frame_bytes)): `loss_rate`
    /// becomes the loss of a `bytes`-byte frame. On a radio cell a 45-byte NDNLPv2 Ack is not as
    /// likely to die as a 1480-byte fragment: the fleet measured Acks delivered at 99.8% on the
    /// cell where data fragments needed repair, which `(1 - 0.05)^(45 / 1500)` reproduces and a
    /// size-blind 5% (every Ack lost as often as a fragment) does not.
    pub fn with_loss_frame_bytes(mut self, bytes: usize) -> Self {
        self.loss_frame_bytes = Some(bytes.max(1));
        self
    }

    /// In-proc app/wired channel: `FaceKind::Internal` → passthrough link service, no NDNLPv2,
    /// local scope. Explicit opt-in (not the fabric default): it is what an in-process app face
    /// looks like, not what two fleet forwarders run between them. `reliable = false` so it
    /// honors the configured `loss_rate`/`jitter`; use [`shm`](Self::shm) for the truly
    /// lossless in-order in-proc transport.
    pub fn internal() -> Self {
        Self::typed(
            FaceKind::Internal,
            LinkType::PointToPoint,
            None,
            false,
            LinkConfig::direct(),
        )
    }
    /// UDP peer link exactly as the fleet runs it between two forwarders: `FaceKind::Udp`
    /// (so the engine picks the NDNLPv2 `LpLinkService`, fragments at the transport's send MTU
    /// and applies the lossy-link retry profile), the transport advertising the same send MTU as
    /// `ndn_face::net::UdpFace` ([`DEFAULT_UDP_MTU`](ndn_packet::fragment::DEFAULT_UDP_MTU)),
    /// wired `Permanent` like a configured `[[face]]` peer, LP reliability ON as the fleet enables
    /// it, and carried over a 1500-byte IP path (so oversize datagrams IP-fragment).
    pub fn udp() -> Self {
        Self {
            persistency: ndn_config::boot::CONFIGURED_FACE_PERSISTENCY,
            lp_reliability: true,
            ip_mtu: Some(ETHERNET_IP_MTU),
            ..Self::typed(
                FaceKind::Udp,
                LinkType::PointToPoint,
                Some(ndn_packet::fragment::DEFAULT_UDP_MTU),
                false,
                LinkConfig::lan(),
            )
        }
    }
    /// TCP: ordered, reliable stream (no loss, head-of-line ordering).
    pub fn tcp() -> Self {
        Self::typed(
            FaceKind::Tcp,
            LinkType::PointToPoint,
            None,
            true,
            LinkConfig::lan(),
        )
    }
    /// QUIC: ordered, reliable (modeled like TCP at this fidelity).
    pub fn quic() -> Self {
        Self::typed(
            FaceKind::Quic,
            LinkType::PointToPoint,
            None,
            true,
            LinkConfig::lan(),
        )
    }
    /// WebSocket: ordered, reliable stream over a WAN-ish link.
    pub fn websocket() -> Self {
        Self::typed(
            FaceKind::WebSocket,
            LinkType::PointToPoint,
            None,
            true,
            LinkConfig::wan(),
        )
    }
    /// WebTransport (HTTP/3): reliable stream.
    pub fn web_transport() -> Self {
        Self::typed(
            FaceKind::WebTransport,
            LinkType::PointToPoint,
            None,
            true,
            LinkConfig::wan(),
        )
    }
    /// Ethernet unicast: L2, MTU-bounded, near-lossless.
    pub fn ethernet() -> Self {
        Self::typed(
            FaceKind::Ethernet,
            LinkType::PointToPoint,
            Some(1450),
            false,
            LinkConfig {
                delay: Duration::from_micros(100),
                jitter: Duration::ZERO,
                loss_rate: 0.0,
                bandwidth_bps: 1_000_000_000,
            },
        )
    }
    /// Ethernet/UDP multicast: L2 broadcast domain (multi-access), lossy.
    pub fn multicast() -> Self {
        Self::typed(
            FaceKind::EtherMulticast,
            LinkType::MultiAccess,
            Some(1450),
            false,
            LinkConfig {
                delay: Duration::from_millis(1),
                jitter: Duration::from_micros(200),
                loss_rate: 0.01,
                bandwidth_bps: 1_000_000_000,
            },
        )
    }
    /// Shared memory / in-proc: near-zero-loss, in-order, near-zero delay, huge bandwidth.
    pub fn shm() -> Self {
        Self::typed(
            FaceKind::Shm,
            LinkType::PointToPoint,
            None,
            true,
            LinkConfig {
                delay: Duration::from_nanos(100),
                jitter: Duration::ZERO,
                loss_rate: 0.0,
                bandwidth_bps: 0,
            },
        )
    }
    /// Serial: small MTU, low bandwidth, mild loss.
    pub fn serial() -> Self {
        Self::typed(
            FaceKind::Serial,
            LinkType::PointToPoint,
            Some(256),
            false,
            LinkConfig {
                delay: Duration::from_millis(5),
                jitter: Duration::from_millis(1),
                loss_rate: 0.005,
                bandwidth_bps: 115_200,
            },
        )
    }
    /// BLE advertising: tiny ext-adv frames, slow, lossy beacon.
    pub fn ble() -> Self {
        Self::typed(
            FaceKind::Bluetooth,
            LinkType::PointToPoint,
            Some(245),
            false,
            LinkConfig {
                delay: Duration::from_millis(20),
                jitter: Duration::from_millis(5),
                loss_rate: 0.05,
                bandwidth_bps: 1_000_000,
            },
        )
    }
    /// Wi-Fi Aware (NAN): connectionless, AdHoc, moderate rate + small loss.
    pub fn nan() -> Self {
        Self::typed(
            FaceKind::WifiAware,
            LinkType::AdHoc,
            Some(1420),
            false,
            LinkConfig {
                delay: Duration::from_millis(5),
                jitter: Duration::from_millis(2),
                loss_rate: 0.01,
                bandwidth_bps: 50_000_000,
            },
        )
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

    /// Attach one face of this profile to `engine` the way the fleet attaches a peer face: wired
    /// with [`persistency`](Self::persistency), then — when [`lp_reliability`](Self::lp_reliability)
    /// is set — NDNLPv2 reliability switched on exactly as `faces/update` flag bit 1 does it,
    /// through the link service AND the face-flags bitmap `faces/list` reports. Reliability is a
    /// runtime per-face switch on the fleet (no `[[face]]` field sets it), so mirroring the mgmt
    /// verb — not constructing a pre-armed link service — is what keeps the sim honest.
    pub fn attach(
        &self,
        engine: &ndn_engine::ForwarderEngine,
        face: SimFace,
        cancel: tokio_util::sync::CancellationToken,
    ) -> FaceId {
        use ndn_transport::Transport;
        let id = face.id();
        engine.add_face_with_persistency(face, cancel, self.persistency);
        if self.lp_reliability {
            let lp = ndn_transport::BIT_LP_RELIABILITY;
            if let Some(face) = engine.faces().get(id)
                && face
                    .link_service
                    .apply(ndn_transport::FaceOption::LpReliability(true))
                    .is_ok()
                && let Some(state) = engine.face_states().get(&id)
            {
                state.apply_face_flags_mask(lp, lp);
            }
        }
        id
    }
}

/// A simulated bidirectional link between two faces.
pub struct SimLink;

impl SimLink {
    /// Create a pair of connected `SimFace`s with symmetric link properties.
    /// For asymmetric directions, use [`pair_asymmetric`](Self::pair_asymmetric).
    ///
    /// A raw transport pair is an in-proc `Internal` channel: it has no engine to attach to, so
    /// the production peer semantics (UDP + NDNLPv2 reliability + Permanent) live in
    /// [`FaceProfile::udp`] + [`FaceProfile::attach`], which [`Simulation::link`](crate::Simulation::link) uses.
    pub fn pair(
        id_a: FaceId,
        id_b: FaceId,
        config: LinkConfig,
        buffer: usize,
    ) -> (SimFace, SimFace) {
        Self::pair_profiled(
            id_a,
            id_b,
            &FaceProfile::internal().with_link(config),
            buffer,
        )
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
    /// Uses the default (Tokio) runtime; use [`pair_profiled_on`](Self::pair_profiled_on) to run
    /// the faces on a specific kernel (virtual / discrete-event).
    pub fn pair_profiled(
        id_a: FaceId,
        id_b: FaceId,
        profile: &FaceProfile,
        buffer: usize,
    ) -> (SimFace, SimFace) {
        Self::pair_profiled_on(
            id_a,
            id_b,
            profile,
            buffer,
            ndn_runtime::default_runtime(),
            0,
        )
    }

    /// As [`pair_profiled`](Self::pair_profiled) but with a distinct profile per direction.
    pub fn pair_profiled_asymmetric(
        id_a: FaceId,
        id_b: FaceId,
        profile_a: &FaceProfile,
        profile_b: &FaceProfile,
        buffer: usize,
    ) -> (SimFace, SimFace) {
        Self::pair_profiled_asymmetric_on(
            id_a,
            id_b,
            profile_a,
            profile_b,
            buffer,
            ndn_runtime::default_runtime(),
            0,
        )
    }

    /// [`pair_profiled`](Self::pair_profiled) on a specific [`Runtime`] — the faces' delivery
    /// delay + task spawn ride it, so the link runs on whatever kernel drives the fabric
    /// (wall-clock, virtual, or the discrete-event executor). This is what the fabric uses.
    pub fn pair_profiled_on(
        id_a: FaceId,
        id_b: FaceId,
        profile: &FaceProfile,
        buffer: usize,
        runtime: Arc<dyn Runtime>,
        world_seed: u64,
    ) -> (SimFace, SimFace) {
        Self::pair_profiled_asymmetric_on(id_a, id_b, profile, profile, buffer, runtime, world_seed)
    }

    /// The full form: distinct profile per direction, on a specific runtime, with a `world_seed`
    /// that perturbs the faces' loss/jitter RNG (0 = the id-only default; a seed sweep varies it).
    pub fn pair_profiled_asymmetric_on(
        id_a: FaceId,
        id_b: FaceId,
        profile_a: &FaceProfile,
        profile_b: &FaceProfile,
        buffer: usize,
        runtime: Arc<dyn Runtime>,
        world_seed: u64,
    ) -> (SimFace, SimFace) {
        let (tx_a, rx_a) = tokio::sync::mpsc::channel(buffer);
        let (tx_b, rx_b) = tokio::sync::mpsc::channel(buffer);
        // face_a writes into tx_b → rx_b (face_b's recv); face_b writes into tx_a → rx_a.
        let face_a = SimFace::new(
            id_a,
            Outbound::Pipe(tx_b),
            rx_a,
            profile_a,
            Arc::clone(&runtime),
            world_seed,
        );
        let face_b = SimFace::new(
            id_b,
            Outbound::Pipe(tx_a),
            rx_b,
            profile_b,
            runtime,
            world_seed,
        );
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
                face_a
                    .send_bytes(bytes::Bytes::copy_from_slice(&[i]))
                    .await
                    .unwrap();
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
        assert_eq!(
            first, second,
            "same topology must replay the identical drop pattern"
        );
        assert!(
            !first.is_empty() && first.len() < 40,
            "~half delivered, not all/none"
        );
    }
}
