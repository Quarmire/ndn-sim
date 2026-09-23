//! **ndn-sim-studies** — the research sandbox that sits *on top of* the `ndn-sim` core.
//!
//! The core crate (`ndn-sim`) is the fleet-predictive simulator: real `ForwarderEngine`s, the
//! named-radio face, kernels, validation. Everything here is exploratory — it depends on the core,
//! never the reverse, and nothing in here is a fleet contract:
//!
//! - the deterministic **IP plane** ([`IpNetwork`]) with pluggable routing ([`routing`]) and the
//!   NDN-vs-IP diff harness ([`compare`]);
//! - the statistical 802.11 MAC ([`wifi_mac`]), the LoRa PHY/MAC ([`lora`]) and the multi-radio PHY
//!   reference ([`phy`]) the IP plane runs over;
//! - the `ndn-radio-cognition` bridge ([`cognition`]);
//! - the research examples (`examples/*.rs`, their committed dashboards and `data/` CSVs) and the
//!   experiment-shaped tests (`tests/`).
//!
//! The IP plane rides the same byte substrate as the NDN plane (`SimFace`/`SimLink`, faults, the
//! kernels), so a workload can be benchmarked both ways under identical conditions:
//!
//! ```rust,no_run
//! use ndn_sim::{Position, WifiMode};
//! use ndn_sim_studies::{IpNetwork, RadioLinkConfig, ShortestPath, Wifi};
//! # fn f(rt: std::sync::Arc<dyn ndn_runtime::Runtime>) {
//! // Three stations on a shared Wi-Fi medium; IP routes itself over the in-range links.
//! let net = IpNetwork::from_positions_wifi(
//!     rt,
//!     vec![Position::xy(0.0, 0.0), Position::xy(20.0, 0.0), Position::xy(40.0, 0.0)],
//!     &Wifi::new(),
//!     &RadioLinkConfig::new(30.0, WifiMode::Managed),
//!     &ShortestPath,
//! );
//! # let _ = net; }
//! ```
//!
//! The IP side enters differently from the NDN side *by design*: [`IpNetwork`]'s `from_*`
//! constructors take the whole topology up front (routing tables are computed from the complete
//! graph), while the NDN `Simulation` builder grows incrementally.
//! [`from_scenario`](IpNetwork::from_scenario) bridges them: one `Scenario` drives both planes.

pub mod cognition;
pub mod compare;
pub mod ip;
pub mod lora;
pub mod phy;
pub mod routing;
pub mod wifi_mac;

pub use compare::{ComparisonSpec, ProtocolComparison, compare_ndn_vs_ip};
pub use ip::{
    IpMetricsSample, IpNetwork, IpNode, IpNodeStats, IpPacket, Ipv4, RadioLinkConfig,
    RunningIpNode, ip_link, ip_metrics_payload,
};
pub use lora::{
    CodingRate, DeviceClass, DutyCycle, LoraConfig, LoraLinkConfig, SpreadingFactor, adr_select,
};
// NB: `phy::FreeSpace` (a PropagationBackend) is intentionally not re-exported at the crate root —
// it would read as core's `ndn_sim::FreeSpace` (an Environment). Reach it via `phy::FreeSpace`.
pub use phy::{
    Antenna, AntennaPlacement, Channel, DefaultInterference, Dipole, Directional,
    InterferenceBackend, Isotropic, LogDistance, PropagationBackend, Radio, RadioEnvironment,
    RadioPlatform,
};
pub use routing::{
    Aodv, DistanceVector, Dsr, Gpsr, GreedyGeographic, NetworkKind, Olsr, RoutingAlgorithm,
    RoutingCategory, ShortestPath, TopologyView,
};
pub use wifi_mac::{FixedRate, MinstrelHt, RateControl, TxOutcome, Wifi, WifiOperatingMode};
