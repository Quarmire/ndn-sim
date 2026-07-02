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

use std::sync::{Arc, Mutex};

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

/// A live telemetry frame — a periodic metric snapshot pushed to subscribers and/or an OTLP
/// collector (axis 4c). Subscribe with [`ControlPlane::subscribe_telemetry`]; drive with
/// [`ControlPlane::spawn_telemetry`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryFrame {
    pub t_ns: u64,
    pub metrics: Vec<MetricsSample>,
}

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
    /// Command the external co-simulator (bidirectional co-sim) — arm/takeoff/goto/velocity a
    /// vehicle. Requires a live actuator (a `--mavlink` link); observe-only otherwise.
    Cosim {
        command: crate::cosim::VehicleCommand,
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
    /// A server-rendered SVG of the topology — a client with no shared Rust types just displays it.
    SceneSvg {
        #[serde(default = "default_svg_dim")]
        width: u32,
        #[serde(default = "default_svg_dim")]
        height: u32,
    },
    /// Causal analysis (axis 4): explain why node `from` could (not) reach node `to` over the radio,
    /// from recorded delivery evidence. Requires radio capture (enabled by `serve`).
    Explain {
        from: usize,
        to: usize,
    },
}

fn default_svg_dim() -> u32 {
    600
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
    Svg { svg: String },
    Explanation(crate::analysis::Explanation),
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
    /// Optional engine-span capture (see [`span_capture`](crate::span_capture)) — when set,
    /// `why_did` returns the causal trace, not just lifecycle events.
    span_log: Mutex<Option<Arc<crate::span_capture::SpanLog>>>,
    /// Command journal (the [`replay`](crate::replay) recording) — `None` until recording starts.
    journal: Mutex<Option<Vec<crate::replay::RecordedCommand>>>,
    /// Initial scenario embedded in the recording, if `start_recording_with` was used.
    recording_scenario: Mutex<Option<crate::scenario::Scenario>>,
    /// The co-sim actuation back-channel (a MAVLink sender to ArduPilot, …) — when set, a
    /// [`SimCommand::Cosim`] flies the external swarm. `None` ⇒ observe-only.
    actuator: Mutex<Option<Arc<dyn crate::cosim::CosimActuator>>>,
    /// Radio delivery capture (axis 4) — the evidence `SimQuery::Explain` reads. Enabled on demand.
    radio_log: Mutex<Option<Arc<crate::analysis::RadioLog>>>,
    /// Live telemetry fan-out (axis 4c) — periodic metric frames to every subscriber.
    telemetry: tokio::sync::broadcast::Sender<TelemetryFrame>,
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
        Arc::new(Self {
            fabric,
            notifications,
            span_log: Mutex::new(None),
            journal: Mutex::new(None),
            recording_scenario: Mutex::new(None),
            actuator: Mutex::new(None),
            radio_log: Mutex::new(None),
            telemetry: tokio::sync::broadcast::channel(64).0,
        })
    }

    /// Subscribe to the live telemetry stream (axis 4c) — each [`spawn_telemetry`] tick delivers a
    /// [`TelemetryFrame`] here. A WebSocket / NDN server forwards these to remote dashboards.
    pub fn subscribe_telemetry(&self) -> tokio::sync::broadcast::Receiver<TelemetryFrame> {
        self.telemetry.subscribe()
    }

    /// Start periodic live telemetry: every `interval`, sample metrics, broadcast a [`TelemetryFrame`]
    /// to subscribers, and (if `otlp` is set, e.g. `"127.0.0.1:4318"`) export them to an OTLP/HTTP
    /// collector (Grafana / Jaeger / Prometheus-OTLP). Returns a token that stops the emitter.
    /// Call from a Tokio context (`serve`).
    pub fn spawn_telemetry(
        self: &Arc<Self>,
        interval: std::time::Duration,
        otlp: Option<String>,
    ) -> CancellationToken {
        let cancel = CancellationToken::new();
        let me = Arc::clone(self);
        let stop = cancel.clone();
        tokio::spawn(async move {
            let exporter = otlp.map(crate::otel_export::OtlpExporter::new);
            let mut tick = tokio::time::interval(interval);
            let mut span_cursor = 0usize; // only export spans captured since the last tick
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tick.tick() => {
                        let metrics = me.fabric.snapshot_metrics();
                        let t_ns = metrics.first().map(|m| m.virtual_time_ns).unwrap_or(0);
                        // Broadcast to live subscribers (ignore if none).
                        let _ = me.telemetry.send(TelemetryFrame { t_ns, metrics: metrics.clone() });
                        if let Some(ex) = &exporter {
                            // Metrics.
                            if let Err(e) = ex.export_metrics(&metrics).await {
                                warn!(error = %e, "ndn-lab: OTLP metrics export failed");
                            }
                            // New captured engine spans (fwd.pipeline / fwd.pit / …), if capture is on.
                            let spans = me.span_log.lock().unwrap().clone();
                            if let Some(log) = spans {
                                let all = log.entries();
                                if span_cursor < all.len() {
                                    let fresh = &all[span_cursor..];
                                    if let Err(e) = ex.export_captured_spans(fresh).await {
                                        warn!(error = %e, "ndn-lab: OTLP span export failed");
                                    }
                                    span_cursor = all.len();
                                }
                            }
                        }
                    }
                }
            }
        });
        cancel
    }

    /// Start recording radio delivery decisions so [`SimQuery::Explain`] can answer causal "why"
    /// queries. No-op if the fabric has no radio medium.
    pub fn enable_radio_capture(&self) {
        if let Some(log) = self.fabric.capture_radio() {
            *self.radio_log.lock().unwrap() = Some(log);
        }
    }

    /// The most recent recorded radio delivery decisions (axis 4) — the packet-level radio flow, for
    /// `why_did` / debugging. Empty unless [`enable_radio_capture`](Self::enable_radio_capture) is on.
    pub fn recent_radio(&self, limit: usize) -> Vec<crate::analysis::RadioDelivery> {
        self.radio_log
            .lock()
            .unwrap()
            .as_ref()
            .map(|l| {
                let mut r = l.records();
                let start = r.len().saturating_sub(limit);
                r.split_off(start)
            })
            .unwrap_or_default()
    }

    /// Install the co-sim actuation back-channel — after this, a [`SimCommand::Cosim`] arriving on
    /// ANY transport (CLI, WebSocket, MCP, an NDN Interest) commands the external simulator.
    pub fn set_actuator(&self, actuator: Arc<dyn crate::cosim::CosimActuator>) {
        *self.actuator.lock().unwrap() = Some(actuator);
    }

    /// Start journaling every executed command (the [`replay`](crate::replay) recording).
    pub fn start_recording(&self) {
        *self.journal.lock().unwrap() = Some(Vec::new());
    }

    /// Start journaling with an embedded initial [`Scenario`](crate::Scenario), so the recording
    /// is self-contained (build the scenario, replay the journal).
    pub fn start_recording_with(&self, scenario: crate::scenario::Scenario) {
        *self.recording_scenario.lock().unwrap() = Some(scenario);
        *self.journal.lock().unwrap() = Some(Vec::new());
    }

    /// Snapshot the recording so far (scenario + journaled commands). Empty journal if recording
    /// was never started.
    pub fn recording(&self) -> crate::replay::Recording {
        crate::replay::Recording {
            scenario: self.recording_scenario.lock().unwrap().clone(),
            commands: self.journal.lock().unwrap().clone().unwrap_or_default(),
        }
    }

    fn now_ns(&self) -> u64 {
        self.fabric.kernel().runtime().unix_nanos()
    }

    /// Attach a [`SpanLog`](crate::span_capture::SpanLog) so `why_did` (MCP) and
    /// [`span_log`](Self::span_log) expose the captured engine causal trace.
    pub fn set_span_log(&self, log: Arc<crate::span_capture::SpanLog>) {
        *self.span_log.lock().unwrap() = Some(log);
    }

    /// The attached engine span log, if any.
    pub fn span_log(&self) -> Option<Arc<crate::span_capture::SpanLog>> {
        self.span_log.lock().unwrap().clone()
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
        // Journal the command (with its virtual timestamp) if recording is on.
        if let Some(journal) = self.journal.lock().unwrap().as_mut() {
            journal.push(crate::replay::RecordedCommand { at_ns: self.now_ns(), command: cmd.clone() });
        }
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
            SimCommand::Cosim { command } => {
                let actuator = self.actuator.lock().unwrap().clone();
                match actuator {
                    Some(a) => match a.command(&command) {
                        Ok(()) => SimResponse::Ok,
                        Err(e) => SimResponse::Error { message: e.to_string() },
                    },
                    None => SimResponse::Error {
                        message: "no co-sim actuator configured (run with a live --mavlink link)"
                            .to_string(),
                    },
                }
            }
        }
    }

    /// Answer a read-only query.
    pub fn query(&self, q: SimQuery) -> SimResponse {
        match q {
            SimQuery::Topology => SimResponse::Topology(self.fabric.topology()),
            SimQuery::Metrics => SimResponse::Metrics(self.fabric.snapshot_metrics()),
            SimQuery::Scene => SimResponse::Scene(self.fabric.scene_snapshot()),
            SimQuery::SceneSvg { width, height } => {
                let svg = crate::scene::render_topology_svg(&self.fabric.scene_snapshot(), width, height);
                SimResponse::Svg { svg }
            }
            SimQuery::Explain { from, to } => {
                let log = self.radio_log.lock().unwrap().clone();
                match log {
                    Some(log) => SimResponse::Explanation(crate::analysis::explain_link(
                        &log,
                        NodeId(from),
                        NodeId(to),
                    )),
                    None => SimResponse::Error {
                        message: "radio capture not enabled (no radio medium, or start with `serve`)"
                            .to_string(),
                    },
                }
            }
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

    /// Serve the control surface over **WebSocket** (one JSON [`handle_json`](Self::handle_json)
    /// request/response per message) — the transport a browser / Dioxus (`ndn-dashboard`) client
    /// uses, since wasm can't open raw TCP. Binds `addr`, spawns the accept loop, returns the
    /// bound [`SocketAddr`]. Runs until `cancel`.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn serve_ws(
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
                            if let Err(e) = me.handle_ws_conn(stream).await {
                                warn!(error = %e, "ndn-lab control WebSocket connection ended");
                            }
                        });
                    }
                }
            }
        });
        Ok(local)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn handle_ws_conn(&self, stream: tokio::net::TcpStream) -> anyhow::Result<()> {
        use futures::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let ws = tokio_tungstenite::accept_async(stream).await?;
        let (mut write, mut read) = ws.split();
        // Also push live telemetry frames to this client (axis 4c streaming), tagged so the client
        // can tell a `{"telemetry": …}` push apart from a `{"result": …}` response.
        let mut telemetry = self.subscribe_telemetry();
        loop {
            tokio::select! {
                incoming = read.next() => {
                    let Some(msg) = incoming else { break };
                    match msg? {
                        Message::Text(text) => {
                            let reply = self.handle_json(&text).await;
                            write.send(Message::text(reply)).await?;
                        }
                        Message::Binary(bytes) => {
                            let req = String::from_utf8_lossy(&bytes);
                            let reply = self.handle_json(&req).await;
                            write.send(Message::text(reply)).await?;
                        }
                        Message::Close(_) => break,
                        Message::Ping(p) => write.send(Message::Pong(p)).await?,
                        _ => {}
                    }
                }
                frame = telemetry.recv() => {
                    match frame {
                        Ok(f) => {
                            let json = serde_json::json!({ "telemetry": f }).to_string();
                            write.send(Message::text(json)).await?;
                        }
                        // Dropped frames on a slow client — keep going; the socket closing ends the loop.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
            }
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
