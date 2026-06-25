//! The control + telemetry plane (ndn-lab slice 6): one **declarative, serializable** command
//! / query surface over [`FabricControl`](crate::FabricControl), exposed over multiple
//! transports so no front-end is privileged — the seam that makes ndn-lab a hub, not a silo.
//!
//! - **In-process** (Rust): hold a [`ControlPlane`] and call [`execute`](ControlPlane::execute)
//!   / [`query`](ControlPlane::query) directly (the scenario runner, embedded tests).
//! - **NDN-native named control**: [`serve_ndn`](ControlPlane::serve_ndn) serves
//!   `/localhop/sim/control` Interests — the JSON request rides in ApplicationParameters, the
//!   JSON [`SimResponse`] comes back as Data — and installs a reusable
//!   [`NotificationStream`](ndn_mgmt::NotificationStream) of [`SimNotification`]s at
//!   `/localhop/sim/control/notifications`. Drivable (and *attachable*) over the network.
//! - **RPC / WebSocket**: [`handle_json`](ControlPlane::handle_json) is the per-message codec
//!   (request string → response string). A WS/TCP server is a thin loop around it (the socket
//!   bind is platform glue, left to the binary).
//!
//! Designed for MCP from the onset (slice 7): the MCP tools are a thin adapter over exactly
//! these `SimCommand`/`SimQuery` variants.
//!
//! Scope today: topology (spawn/remove/connect/route) + queries (topology/metrics). Live-world
//! mutation (move/mobility) and lifecycle (pause/step/seek) await the mutable-`World` and
//! DES-event-queue follow-ons; they are deliberately not yet in the command set.

use std::sync::Arc;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::ForwarderEngine;
use ndn_mgmt::{NotificationEvent, NotificationStream};
use ndn_packet::Name;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::telemetry::MetricsSample;
use crate::{LinkConfig, NodeId, NodeProfile, RunningSimulation, TopologySnapshot};

/// Serde-friendly mirror of [`LinkConfig`] (durations as milliseconds).
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub struct LinkSpec {
    #[serde(default)]
    pub delay_ms: u64,
    #[serde(default)]
    pub jitter_ms: u64,
    #[serde(default)]
    pub loss_rate: f64,
    #[serde(default)]
    pub bandwidth_bps: u64,
}

impl From<LinkSpec> for LinkConfig {
    fn from(s: LinkSpec) -> Self {
        LinkConfig {
            delay: std::time::Duration::from_millis(s.delay_ms),
            jitter: std::time::Duration::from_millis(s.jitter_ms),
            loss_rate: s.loss_rate,
            bandwidth_bps: s.bandwidth_bps,
        }
    }
}

/// A declarative, mutating fabric command.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum SimCommand {
    /// Spawn a node (default engine config; `label` optional).
    SpawnNode { label: Option<String> },
    /// Remove a node and its links.
    RemoveNode { node: usize },
    /// Connect two nodes with a (optional) link spec.
    Connect {
        a: usize,
        b: usize,
        #[serde(default)]
        link: LinkSpec,
    },
    /// Install a FIB route at `node`: `prefix` → the link face toward `nexthop`.
    Route {
        node: usize,
        prefix: String,
        nexthop: usize,
    },
    /// Move a node to a fixed position (metres) in the world — live drag-to-move.
    MoveNode {
        node: usize,
        x: f64,
        y: f64,
        #[serde(default)]
        z: f64,
    },
    /// Give a node constant-velocity motion (m/s per axis) from a start position.
    SetLinearMobility {
        node: usize,
        x: f64,
        y: f64,
        #[serde(default)]
        z: f64,
        vx: f64,
        vy: f64,
        #[serde(default)]
        vz: f64,
    },
    /// Spawn an app (producer/consumer) on a node.
    SpawnApp {
        node: usize,
        app: crate::app::AppSpec,
    },
    /// Stop a running app by id.
    StopApp {
        app: usize,
    },
}

/// A read-only introspection query.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "query", rename_all = "snake_case")]
pub enum SimQuery {
    /// The current topology graph.
    Topology,
    /// A metrics snapshot of every node at the current (virtual) time.
    Metrics,
    /// A renderable scene (positions + links + metric badges + bounds) — what a GUI draws.
    Scene,
}

/// The request envelope decoded from a transport (`{"command": …}` or `{"query": …}`).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimRequest {
    Command(SimCommand),
    Query(SimQuery),
}

/// The response to a [`SimRequest`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum SimResponse {
    Ok,
    Node { id: usize },
    App { id: usize },
    Topology(TopologySnapshot),
    Metrics(Vec<MetricsSample>),
    Scene(crate::scene::SceneSnapshot),
    Error { message: String },
}

/// A live control-plane notification (published on each mutating command).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum SimNotification {
    NodeSpawned { node: usize, label: String },
    NodeRemoved { node: usize },
    LinkAdded { a: usize, b: usize },
    RouteAdded { node: usize, prefix: String, nexthop: usize },
    NodeMoved { node: usize, x: f64, y: f64, z: f64 },
}

impl NotificationEvent for SimNotification {
    fn encode(&self) -> Bytes {
        Bytes::from(serde_json::to_vec(self).unwrap_or_default())
    }
}

/// The one control + telemetry surface over a running fabric.
pub struct ControlPlane {
    fabric: Arc<RunningSimulation>,
    notifications: Arc<NotificationStream<SimNotification>>,
}

impl ControlPlane {
    /// Wrap a running fabric. The notification stream is created (publish-ready); call
    /// [`serve_ndn`](Self::serve_ndn) to also serve it + the command verbs over NDN.
    pub fn new(fabric: Arc<RunningSimulation>) -> Arc<Self> {
        let notifications = NotificationStream::new(
            "/localhop/sim/control/notifications"
                .parse()
                .expect("static prefix"),
        );
        Arc::new(Self { fabric, notifications })
    }

    pub fn fabric(&self) -> &Arc<RunningSimulation> {
        &self.fabric
    }

    /// The live notification stream (control-plane events).
    pub fn notifications(&self) -> &Arc<NotificationStream<SimNotification>> {
        &self.notifications
    }

    /// Execute a mutating command, publishing a [`SimNotification`] on success.
    pub async fn execute(&self, cmd: SimCommand) -> SimResponse {
        match cmd {
            SimCommand::SpawnNode { label } => {
                let label = label.unwrap_or_else(|| "node".to_string());
                match self.fabric.spawn_node(NodeProfile::new(label.clone())).await {
                    Ok(id) => {
                        self.notifications
                            .publish(SimNotification::NodeSpawned { node: id.0, label });
                        SimResponse::Node { id: id.0 }
                    }
                    Err(e) => SimResponse::Error { message: e.to_string() },
                }
            }
            SimCommand::RemoveNode { node } => {
                match self.fabric.remove_node(NodeId(node)).await {
                    Ok(()) => {
                        self.notifications.publish(SimNotification::NodeRemoved { node });
                        SimResponse::Ok
                    }
                    Err(e) => SimResponse::Error { message: e.to_string() },
                }
            }
            SimCommand::Connect { a, b, link } => {
                match self.fabric.connect(NodeId(a), NodeId(b), link.into()) {
                    Ok(()) => {
                        self.notifications.publish(SimNotification::LinkAdded { a, b });
                        SimResponse::Ok
                    }
                    Err(e) => SimResponse::Error { message: e.to_string() },
                }
            }
            SimCommand::Route { node, prefix, nexthop } => {
                let name: Name = match prefix.parse() {
                    Ok(n) => n,
                    Err(e) => return SimResponse::Error { message: format!("bad prefix: {e}") },
                };
                match self.fabric.route(NodeId(node), &name, NodeId(nexthop)) {
                    Ok(()) => {
                        self.notifications
                            .publish(SimNotification::RouteAdded { node, prefix, nexthop });
                        SimResponse::Ok
                    }
                    Err(e) => SimResponse::Error { message: e.to_string() },
                }
            }
            SimCommand::MoveNode { node, x, y, z } => {
                self.fabric.move_node(NodeId(node), crate::world::Position::xyz(x, y, z));
                self.notifications.publish(SimNotification::NodeMoved { node, x, y, z });
                SimResponse::Ok
            }
            SimCommand::SetLinearMobility { node, x, y, z, vx, vy, vz } => {
                self.fabric.set_mobility(
                    NodeId(node),
                    std::sync::Arc::new(crate::world::LinearMobility {
                        start: crate::world::Position::xyz(x, y, z),
                        velocity: (vx, vy, vz),
                    }),
                );
                self.notifications.publish(SimNotification::NodeMoved { node, x, y, z });
                SimResponse::Ok
            }
            SimCommand::SpawnApp { node, app } => match self.fabric.spawn_app(NodeId(node), app) {
                Ok(id) => SimResponse::App { id: id.0 },
                Err(e) => SimResponse::Error { message: e.to_string() },
            },
            SimCommand::StopApp { app } => match self.fabric.stop_app(crate::app::AppId(app)) {
                Ok(()) => SimResponse::Ok,
                Err(e) => SimResponse::Error { message: e.to_string() },
            },
        }
    }

    /// Answer a read-only query.
    pub fn query(&self, q: SimQuery) -> SimResponse {
        match q {
            SimQuery::Topology => SimResponse::Topology(self.fabric.topology()),
            SimQuery::Metrics => SimResponse::Metrics(self.fabric.snapshot_metrics()),
            SimQuery::Scene => SimResponse::Scene(self.fabric.scene_snapshot()),
        }
    }

    /// The RPC/WebSocket per-message codec: a JSON [`SimRequest`] string → a JSON
    /// [`SimResponse`] string. A socket server is a thin loop around this.
    pub async fn handle_json(&self, request: &str) -> String {
        let response = match serde_json::from_str::<SimRequest>(request) {
            Ok(SimRequest::Command(c)) => self.execute(c).await,
            Ok(SimRequest::Query(q)) => self.query(q),
            Err(e) => SimResponse::Error { message: format!("bad request: {e}") },
        };
        serde_json::to_string(&response).unwrap_or_else(|e| {
            format!(r#"{{"result":"error","message":"encode: {e}"}}"#)
        })
    }

    /// Serve the control surface over NDN on `engine`: a producer at `/localhop/sim/control`
    /// (JSON request in ApplicationParameters → JSON Data) plus the notification stream at
    /// `/localhop/sim/control/notifications`. Runs until `cancel` fires.
    pub fn serve_ndn(self: &Arc<Self>, engine: &ForwarderEngine, cancel: CancellationToken) {
        Arc::clone(&self.notifications).install(engine, cancel.clone());

        let producer = engine.register_producer("/localhop/sim/control", cancel);
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let result = producer
                .serve(move |interest, responder| {
                    let me = Arc::clone(&me);
                    async move {
                        let request = interest
                            .app_parameters()
                            .map(|b| String::from_utf8_lossy(b).into_owned())
                            .unwrap_or_default();
                        let reply = me.handle_json(&request).await;
                        let _ = responder
                            .respond((*interest.name).clone(), Bytes::from(reply))
                            .await;
                    }
                })
                .await;
            if let Err(e) = result {
                warn!(error = %e, "ndn-lab control producer stopped");
            }
        });
    }

    /// Serve the control surface over **TCP** as newline-delimited JSON (one
    /// [`handle_json`](Self::handle_json) request/response per line) — the thin RPC/WS transport
    /// for the GUI and external tooling. Binds `addr`, spawns the accept loop, and returns the
    /// bound [`SocketAddr`] (pass `"127.0.0.1:0"` for an ephemeral port). Runs until `cancel`.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn serve_tcp(
        self: &Arc<Self>,
        addr: impl tokio::net::ToSocketAddrs,
        cancel: CancellationToken,
    ) -> std::io::Result<std::net::SocketAddr> {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let me = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    accepted = listener.accept() => {
                        let Ok((stream, _peer)) = accepted else { break };
                        let me = Arc::clone(&me);
                        tokio::spawn(async move {
                            if let Err(e) = me.handle_tcp_conn(stream).await {
                                warn!(error = %e, "ndn-lab control TCP connection ended");
                            }
                        });
                    }
                }
            }
        });
        Ok(local)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn handle_tcp_conn(&self, stream: tokio::net::TcpStream) -> std::io::Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let reply = self.handle_json(&line).await;
            write.write_all(reply.as_bytes()).await?;
            write.write_all(b"\n").await?;
            write.flush().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_and_query_json_round_trip() {
        let cmd: SimRequest =
            serde_json::from_str(r#"{"command":{"cmd":"spawn_node","label":"edge"}}"#).unwrap();
        assert!(matches!(
            cmd,
            SimRequest::Command(SimCommand::SpawnNode { label: Some(ref l) }) if l == "edge"
        ));

        let connect: SimRequest = serde_json::from_str(
            r#"{"command":{"cmd":"connect","a":0,"b":1,"link":{"delay_ms":5}}}"#,
        )
        .unwrap();
        if let SimRequest::Command(SimCommand::Connect { a, b, link }) = connect {
            assert_eq!((a, b), (0, 1));
            assert_eq!(LinkConfig::from(link).delay, std::time::Duration::from_millis(5));
        } else {
            panic!("expected connect");
        }

        let q: SimRequest = serde_json::from_str(r#"{"query":{"query":"topology"}}"#).unwrap();
        assert!(matches!(q, SimRequest::Query(SimQuery::Topology)));
    }

    #[test]
    fn notification_encodes_as_json() {
        let n = SimNotification::NodeSpawned { node: 3, label: "drone".into() };
        let bytes = n.encode();
        let s = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(s.contains("node_spawned") && s.contains("drone"));
    }
}
