//! Boot sim nodes the way `ndn-fwd` boots: from its TOML [`ForwarderConfig`], through
//! [`ndn_config::boot`] — the one implementation the forwarder binary itself runs.
//!
//! Each config-booted node has an IP identity and a UDP stack ([`crate::sim_udp`]): its
//! `[[face]] kind = "udp"` listeners, and a face per UDP peer entry whose `remote` is another sim
//! node, bound as [`ndn_config::boot::udp_peer_binding`] decides. A peer face's FaceId is the one
//! reserved for its entry's index, so `[[route]] face = N` lands on exactly the face that entry
//! created, as in `ndn-fwd`'s `main`. Entries that create no face here (listeners, TCP, multicast,
//! a remote outside the sim) still reserve their index's FaceId — a route naming them points at a
//! face that does not exist, exactly as a route to a dead configured face does on the fleet.
//!
//! Routes and strategy choices the builder installs directly go through the same functions, so
//! a sim route is a STATIC + CHILD_INHERIT RIB route like `nfdc route add`, never a bare FIB
//! nexthop (which the RIB silently overwrites the first time an app registers the prefix).

use std::net::{IpAddr, SocketAddr};

use anyhow::{Result, bail};
use ndn_config::boot::{DEFAULT_UDP_PORT, UdpPeerBinding};
use ndn_config::{FaceConfig, ForwarderConfig, RouteConfig, StrategyConfig};
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_transport::FaceId;

use crate::NodeId;

/// A node declared from an ndn-fwd config, applied at [`start`](crate::Simulation::start).
pub(crate) struct ConfiguredNode {
    pub node: NodeId,
    pub cfg: ForwarderConfig,
    pub addr: IpAddr,
}

/// The UDP ports a node's listeners bind, as ndn-fwd's face setup starts them: one per
/// `[[face]] kind = "udp"` entry without a `remote`, or the default listener when the config
/// declares no `[[face]]` at all. An unparseable `bind` starts no listener (ndn-fwd logs it).
pub(crate) fn udp_listener_ports(cfg: &ForwarderConfig) -> Vec<u16> {
    if cfg.faces.is_empty() {
        return vec![DEFAULT_UDP_PORT];
    }
    cfg.faces
        .iter()
        .filter_map(|f| match f {
            FaceConfig::Udp { bind, remote: None } => match bind.as_deref() {
                None => Some(DEFAULT_UDP_PORT),
                Some(b) => b.parse::<SocketAddr>().ok().map(|a| a.port()),
            },
            _ => None,
        })
        .collect()
}

/// `(remote, binding)` of a UDP peer entry, if it is one.
pub(crate) fn udp_peer(face: &FaceConfig) -> Option<(SocketAddr, UdpPeerBinding)> {
    match face {
        FaceConfig::Udp {
            bind,
            remote: Some(remote),
        } => match remote.parse::<SocketAddr>() {
            Ok(peer) => Some((peer, ndn_config::boot::udp_peer_binding(bind.as_deref()))),
            Err(e) => {
                tracing::warn!(%remote, error = %e, "ndn-lab: invalid UDP remote in [[face]]; no face");
                None
            }
        },
        _ => None,
    }
}

/// Install `prefix → face` exactly as a `[[route]]` / `nfdc route add` does (origin STATIC,
/// CHILD_INHERIT, cost 10, via the RIB).
pub(crate) fn install_route(engine: &ForwarderEngine, prefix: &Name, face: FaceId) {
    ndn_config::boot::install_routes(
        engine,
        &[RouteConfig {
            prefix: prefix.to_string(),
            face: 0,
            cost: 10,
        }],
        &[face],
    );
}

/// Install a strategy choice through the `strategy-choice/set` resolver (bare short names such
/// as `"multicast"` and full `/localhost/nfd/strategy/...` names both resolve).
pub(crate) fn install_strategy(
    engine: &ForwarderEngine,
    prefix: &Name,
    strategy: &str,
) -> Result<()> {
    let choice = StrategyConfig {
        prefix: prefix.to_string(),
        strategy: strategy.to_string(),
    };
    if ndn_config::boot::install_strategies(engine, std::slice::from_ref(&choice)) == 0 {
        bail!("unknown forwarding strategy {strategy:?}");
    }
    Ok(())
}
