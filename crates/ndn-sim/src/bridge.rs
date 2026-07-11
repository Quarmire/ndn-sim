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
use std::sync::Arc;

use anyhow::{Result, bail};
use ndn_face::net::UdpFace;
use ndn_transport::{FaceId, Transport};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::sim_face::SimFace;
use crate::sim_link::{FaceProfile, LinkConfig, SimLink};
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
        self.bridge_udp_mtu(node, local, peer, None).await
    }

    /// [`bridge_udp`](Self::bridge_udp) with an explicit **send MTU** on the bridge face —
    /// outbound packets larger than it are NDNLPv2-fragmented. Use it to match a constrained
    /// external link (or to force fragmentation in an interop test). `None` keeps the transport
    /// default.
    pub async fn bridge_udp_mtu(
        &self,
        node: NodeId,
        local: SocketAddr,
        peer: SocketAddr,
        mtu: Option<u64>,
    ) -> Result<FaceId> {
        let engine = self
            .engine_of(node)
            .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?;
        let cancel = self
            .node_cancel(node)
            .ok_or_else(|| anyhow::anyhow!("no such node {node}"))?;
        let id = engine.faces().alloc_id();
        let face = UdpFace::bind(local, peer, id).await?;
        if mtu.is_some() {
            ndn_transport::Transport::set_send_mtu(&face, mtu)
                .map_err(|e| anyhow::anyhow!("bridge MTU: {e}"))?;
        }
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

    /// Carry a **foreign (non-NDN) UDP flow** across a real [`SimLink`], so it experiences the
    /// [`LinkConfig`] impairment (loss / delay / jitter / bandwidth) the fabric's own links use —
    /// instead of hand-rolling an impairment relay that re-implements those numbers. The payload
    /// is opaque bytes (a MAVLink stream, an RC channel, a raw telemetry lane); nothing is parsed.
    ///
    /// A [`SimLink`] carries NDN frames between engines and cannot host a foreign flow; this
    /// interposes an engine-less link on a UDP seam and pumps the datagrams through it. Point both
    /// peers at the returned address: datagrams from `peer_a` cross the link A→B and go to `peer_b`,
    /// datagrams from `peer_b` cross B→A and go to `peer_a` — both directions ride the same profile.
    ///
    /// **Wall-clock only:** real UDP endpoints live on real time (the link's delivery rides the
    /// fabric runtime), so run the fabric under a `wall_clock`/`real_time` kernel. Runs until
    /// `cancel` fires.
    pub async fn bridge_udp_flow(
        &self,
        peer_a: SocketAddr,
        peer_b: SocketAddr,
        link: LinkConfig,
        cancel: CancellationToken,
    ) -> Result<SocketAddr> {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let addr = socket.local_addr()?;

        // An engine-less impaired link: its two faces carry the foreign bytes with the fabric's
        // real LinkConfig semantics (send_bytes applies the loss roll, bandwidth, delay + jitter).
        let profile = FaceProfile::internal().with_link(link);
        let (fa, fb) = SimLink::pair_profiled_on(
            FaceId(0),
            FaceId(1),
            &profile,
            self.flow_channel_buffer(),
            self.kernel().runtime(),
            self.flow_seed(),
        );
        let (fa, fb) = (Arc::new(fa), Arc::new(fb));

        // Ingress: route each datagram by source into the matching link end. fa.send → fb.recv
        // (A→B), fb.send → fa.recv (B→A); the impairment happens inside the link.
        {
            let (socket, fa, fb, cancel) =
                (socket.clone(), fa.clone(), fb.clone(), cancel.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                loop {
                    tokio::select! {
                        () = cancel.cancelled() => break,
                        r = socket.recv_from(&mut buf) => {
                            let Ok((n, src)) = r else { break };
                            let bytes = bytes::Bytes::copy_from_slice(&buf[..n]);
                            let _ = if src == peer_a {
                                fa.send_bytes(bytes).await
                            } else if src == peer_b {
                                fb.send_bytes(bytes).await
                            } else {
                                continue; // stray datagram: not one of the two peers
                            };
                        }
                    }
                }
            });
        }
        // Egress: impaired bytes emerging from each end go out to the opposite peer.
        spawn_flow_egress(socket.clone(), fb, peer_b, cancel.clone());
        spawn_flow_egress(socket, fa, peer_a, cancel);
        Ok(addr)
    }
}

/// Drain a link end and forward each impaired datagram to `dest`.
fn spawn_flow_egress(
    socket: Arc<UdpSocket>,
    face: Arc<SimFace>,
    dest: SocketAddr,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                r = face.recv_bytes() => match r {
                    Ok(b) => { let _ = socket.send_to(&b, dest).await; }
                    Err(_) => break,
                }
            }
        }
    });
}
