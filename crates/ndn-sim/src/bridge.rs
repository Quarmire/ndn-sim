//! Interop bridge (ndn-lab slice 9): attach a **real UDP transport** to a fabric node so an
//! external NDN endpoint — a phone app, NFD, NDNts, or any conformant forwarder — peers with the
//! simulated fabric over the real NDN wire.
//!
//! This is the cheapest possible interop and the doctrine the design fixes: the bridge lives at
//! the **edge** (a real face on a node), never inside the engine. The bridged region runs under
//! the [`WallClockKernel`](crate::WallClockKernel) (a real device = real time), so these methods
//! are wall-clock only.
//!
//! Two modes (mirroring NFD's UDP face vs UDP channel):
//! - [`bridge_udp`](crate::RunningSimulation::bridge_udp) / `bridge_udp_socket` — a **unicast**
//!   face to a known peer (two endpoints you control; e.g. a co-sim or a second forwarder).
//! - [`bridge_udp_listener`](crate::RunningSimulation::bridge_udp_listener) — an NFD-style **UDP
//!   channel** that accepts inbound datagrams from any peer and auto-creates a per-peer face — for
//!   external devices / NFD / NDNts that dial in on an unknown source port.

use std::net::SocketAddr;

use anyhow::{Result, bail};
use ndn_face::net::UdpFace;
use ndn_transport::FaceId;

use crate::{NodeId, RunningSimulation};

impl RunningSimulation {
    /// Attach a real **unicast UDP face** on `node`, bound to `local`, sending to `peer`. Returns
    /// the [`FaceId`] — route over it with `engine_of(node).fib().add_nexthop(prefix, id, cost)`.
    /// Both ends must bind known ports (each targets the other). Wall-clock kernel only.
    pub async fn bridge_udp(
        &self,
        node: NodeId,
        local: SocketAddr,
        peer: SocketAddr,
    ) -> Result<FaceId> {
        let engine = self
            .engine_of(node)
            .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?;
        let cancel = self
            .node_cancel(node)
            .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?;
        let id = engine.faces().alloc_id();
        let face = UdpFace::bind(local, peer, id).await?;
        engine.add_face(face, cancel);
        Ok(id)
    }

    /// Like [`bridge_udp`](Self::bridge_udp) but over an already-bound socket — lets the caller
    /// learn both ephemeral ports first (avoiding the bind-order chicken-and-egg of two `:0`
    /// endpoints), e.g. in tests.
    pub fn bridge_udp_socket(
        &self,
        node: NodeId,
        socket: tokio::net::UdpSocket,
        peer: SocketAddr,
    ) -> Result<FaceId> {
        let engine = self
            .engine_of(node)
            .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?;
        let cancel = self
            .node_cancel(node)
            .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?;
        let id = engine.faces().alloc_id();
        let face = UdpFace::from_socket(id, socket, peer);
        engine.add_face(face, cancel);
        Ok(id)
    }

    /// Run an NFD-style **UDP channel** on `node`, bound to `bind_addr`: it accepts inbound
    /// datagrams from any peer and auto-creates a per-peer face, so external devices / NFD /
    /// NDNts can dial in. Spawned on the kernel runtime; runs until `cancel` fires. Use a fixed
    /// port (e.g. `0.0.0.0:6363`) so peers know where to reach it.
    pub fn bridge_udp_listener(
        &self,
        node: NodeId,
        bind_addr: SocketAddr,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<()> {
        let engine = self
            .engine_of(node)
            .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?;
        if bind_addr.port() == 0 {
            bail!("bridge_udp_listener needs a fixed port so peers can reach it");
        }
        tokio::spawn(ndn_mgmt::run_udp_listener(bind_addr, engine, cancel, 0));
        Ok(())
    }
}
