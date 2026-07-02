//! MCP server (ndn-lab slice 7): a **thin adapter** that projects the [`ControlPlane`] as
//! Model Context Protocol tools — so a model can build and inspect simulations the way Unreal's
//! MCP builds a room → a city.
//!
//! It is deliberately *not* a separate integration: each MCP tool is a near-1:1 projection of a
//! [`SimCommand`](crate::SimCommand) / [`SimQuery`](crate::SimQuery), plus read/reason tools and
//! a machine-readable **capability catalogue** so the model can discover the palette. MCP, the
//! NDN-native control names, the RPC codec, and (later) the GUI all drive the *same*
//! `FabricControl` — a thing one can do, all can do.
//!
//! Transport: the MCP wire is JSON-RPC 2.0. [`handle_rpc`](SimMcp::handle_rpc) is the tested
//! core (one request string → one response string); [`serve_stdio`](SimMcp::serve_stdio) is the
//! thin newline-delimited stdin/stdout loop a `ndn-lab-mcp` binary runs. Implements
//! `initialize` / `tools/list` / `tools/call` / `ping`.
//!
//! Deferred: split into an optional `ndn-sim-mcp` crate (kept a module for now — it adds no new
//! dependency beyond serde_json); build tools for the not-yet-built live-world / lifecycle verbs.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{ControlPlane, SimCommand, SimQuery, SimResponse};

/// The MCP protocol version this server speaks.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// An MCP server projecting a fabric's [`ControlPlane`] as tools.
pub struct SimMcp {
    control: Arc<ControlPlane>,
}

#[derive(Deserialize)]
struct RpcRequest {
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Deserialize)]
struct ToolCall {
    name: String,
    #[serde(default)]
    arguments: Value,
}

impl SimMcp {
    pub fn new(control: Arc<ControlPlane>) -> Arc<Self> {
        Arc::new(Self { control })
    }

    /// The `tools/list` payload: every tool's name, description, and JSON-Schema input — the
    /// palette a model discovers. Read/reason tools first, then build tools.
    pub fn tool_catalog() -> Value {
        json!([
            {
                "name": "describe_topology",
                "description": "Return the current fabric graph: nodes (id, label) and directed link faces.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "query_metrics",
                "description": "Snapshot every node's engine metrics (CS hit-rate, PIT depth, per-face throughput/drops) at the current virtual time.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "node_state",
                "description": "Detailed state for one node: its label, links, and current metrics.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "node": { "type": "integer", "description": "node id" } },
                    "required": ["node"]
                }
            },
            {
                "name": "capabilities",
                "description": "The machine-readable palette: which commands, queries, mediums, propagation/mobility models, and radio modes exist.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "spawn_node",
                "description": "Add a forwarding node (default engine config). Returns its id.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "label": { "type": "string" } }
                }
            },
            {
                "name": "remove_node",
                "description": "Remove a node and its links.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "node": { "type": "integer" } },
                    "required": ["node"]
                }
            },
            {
                "name": "connect",
                "description": "Connect two nodes with a wired link (optional delay/jitter/loss/bandwidth).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "a": { "type": "integer" },
                        "b": { "type": "integer" },
                        "delay_ms": { "type": "integer" },
                        "jitter_ms": { "type": "integer" },
                        "loss_rate": { "type": "number" },
                        "bandwidth_bps": { "type": "integer" }
                    },
                    "required": ["a", "b"]
                }
            },
            {
                "name": "route",
                "description": "Install a FIB route at a node: a name prefix toward a nexthop node.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node": { "type": "integer" },
                        "prefix": { "type": "string" },
                        "nexthop": { "type": "integer" }
                    },
                    "required": ["node", "prefix", "nexthop"]
                }
            },
            {
                "name": "move_node",
                "description": "Move a node to a fixed world position (metres) — live drag-to-move.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node": { "type": "integer" },
                        "x": { "type": "number" },
                        "y": { "type": "number" },
                        "z": { "type": "number" }
                    },
                    "required": ["node", "x", "y"]
                }
            },
            {
                "name": "spawn_app",
                "description": "Run an app on a node: a 'producer' serving a prefix, or a 'consumer' fetching prefix/<i>.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node": { "type": "integer" },
                        "kind": { "type": "string", "enum": ["producer", "consumer"] },
                        "prefix": { "type": "string" },
                        "content": { "type": "string", "description": "producer payload" },
                        "count": { "type": "integer", "description": "consumer fetch count (0 = until stopped)" },
                        "interval_ms": { "type": "integer", "description": "consumer pace" }
                    },
                    "required": ["node", "kind", "prefix"]
                }
            },
            {
                "name": "stop_app",
                "description": "Stop a running app by id.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "app": { "type": "integer" } },
                    "required": ["app"]
                }
            },
            {
                "name": "cosim",
                "description": "Command the external co-simulator (bidirectional co-sim): fly a vehicle. Requires a live --mavlink link. E.g. command={\"action\":\"goto\",\"node\":1,\"x\":100,\"y\":0,\"z\":0}; actions: arm/disarm/takeoff/goto/velocity/land/set_mode/return_to_launch.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "command": { "type": "object", "description": "a VehicleCommand: {action, node, ...}" } },
                    "required": ["command"]
                }
            },
            {
                "name": "explain_link",
                "description": "Causal 'why': explain why node `from` could (not) reach node `to` over the radio, from recorded delivery evidence (out-of-range / obstructed / weak / collision / erased) with distance + RSSI. The observability-that-explains surface.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "from": { "type": "integer" }, "to": { "type": "integer" } },
                    "required": ["from", "to"]
                }
            },
            {
                "name": "why_did",
                "description": "Explain recent fabric activity: the last N captured sim events (face up/down, control-plane changes) — the trace/explain surface.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "limit": { "type": "integer", "description": "max events (default 20)" } }
                }
            },
            {
                "name": "scene_svg",
                "description": "Server-rendered SVG of the topology (positions, links, node fill by CS hit-rate) — a client with no shared Rust types just displays the returned `svg` string.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "width": { "type": "integer", "description": "px (default 600)" },
                        "height": { "type": "integer", "description": "px (default 600)" }
                    }
                }
            },
            {
                "name": "set_strategy",
                "description": "Change a node's forwarding strategy for a prefix. 'multicast' floods all nexthops (retx-free failover round a dead relay); 'best-route' is the default single-path.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node": { "type": "integer" },
                        "prefix": { "type": "string" },
                        "strategy": { "type": "string", "description": "e.g. 'multicast' or 'best-route'" }
                    },
                    "required": ["node", "prefix", "strategy"]
                }
            },
            {
                "name": "add_radio_route",
                "description": "Install a broadcast route on a node's radio face: the prefix is offered to every neighbour over the shared wireless medium (the wireless FIB nexthop).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "node": { "type": "integer" },
                        "prefix": { "type": "string" }
                    },
                    "required": ["node", "prefix"]
                }
            },
            {
                "name": "start_recording",
                "description": "Begin journaling every mutating command (with its virtual timestamp) so the session can be replayed deterministically. Pair with get_recording.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "get_recording",
                "description": "Return the recording so far (embedded scenario + timestamped command journal) as JSON — save it, then `ndn-lab replay` it.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "run_validation",
                "description": "Run a validation spec (scenario + fault schedule + property assertions + optional seed sweep) headless across kernels and return the pass/fail report. The property-based testing surface. `spec` is the TOML text of a ValidationSpec.",
                "inputSchema": {
                    "type": "object",
                    "properties": { "spec": { "type": "string", "description": "TOML of a ValidationSpec" } },
                    "required": ["spec"]
                }
            },
            {
                "name": "generate_topology",
                "description": "Generate a topology (line/ring/star/grid/mesh/tree/random) as a ready-to-run scenario, without hand-authoring nodes/links. Returns the scenario `toml` (+ node/link/route counts) — feed it to run_validation or `ndn-lab run`. Optional `toward` (\"/prefix@node\") installs shortest-path routes so it forwards immediately.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "shape": { "type": "string", "enum": ["line", "ring", "star", "grid", "mesh", "tree", "random"] },
                        "n": { "type": "integer", "description": "node count (line/ring/star/mesh/random)" },
                        "rows": { "type": "integer" },
                        "cols": { "type": "integer" },
                        "branching": { "type": "integer", "description": "tree branching factor" },
                        "depth": { "type": "integer", "description": "tree depth" },
                        "prob": { "type": "number", "description": "random edge probability 0..1" },
                        "seed": { "type": "integer", "description": "random PRNG seed" },
                        "toward": { "type": "string", "description": "install routes for a prefix toward a node, e.g. \"/demo@0\"" }
                    },
                    "required": ["shape"]
                }
            }
        ])
    }

    /// Execute one MCP tool by name. `Ok` carries structured JSON; `Err` a message (surfaced to
    /// the model as an `isError` tool result).
    pub async fn call_tool(&self, name: &str, args: &Value) -> Result<Value, String> {
        match name {
            "describe_topology" => Ok(to_value(self.control.query(SimQuery::Topology))),
            "query_metrics" => Ok(to_value(self.control.query(SimQuery::Metrics))),
            "explain_link" => {
                let from = req_usize(args, "from")?;
                let to = req_usize(args, "to")?;
                Ok(to_value(self.control.query(SimQuery::Explain { from, to })))
            }
            "capabilities" => Ok(capability_catalogue()),
            "node_state" => self.node_state(req_usize(args, "node")?),
            "why_did" => {
                let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(20) as usize;
                let mut events = self.control.fabric().tracer().events();
                let start = events.len().saturating_sub(limit);
                let recent = events.split_off(start);
                // If engine-span capture is attached, include the causal trace (the rich
                // fwd.pipeline/fwd.pit spans), not just lifecycle events.
                let engine_spans = self
                    .control
                    .span_log()
                    .map(|log| log.recent(limit))
                    .unwrap_or_default();
                // Radio delivery decisions (out-of-range / obstructed / collision / erased) — the
                // packet-level radio flow, so "why" covers the medium, not just lifecycle + engine.
                let radio = self.control.recent_radio(limit);
                Ok(serde_json::json!({
                    "events": recent,
                    "engine_spans": engine_spans,
                    "radio": radio,
                }))
            }
            "spawn_node" => {
                let label = args.get("label").and_then(Value::as_str).map(String::from);
                self.run(SimCommand::SpawnNode { label }).await
            }
            "remove_node" => {
                self.run(SimCommand::RemoveNode { node: req_usize(args, "node")? }).await
            }
            "connect" => {
                let link = serde_json::from_value(args.clone()).unwrap_or_default();
                self.run(SimCommand::Connect {
                    a: req_usize(args, "a")?,
                    b: req_usize(args, "b")?,
                    link,
                })
                .await
            }
            "route" => {
                let prefix = args
                    .get("prefix")
                    .and_then(Value::as_str)
                    .ok_or("missing 'prefix'")?
                    .to_string();
                self.run(SimCommand::Route {
                    node: req_usize(args, "node")?,
                    prefix,
                    nexthop: req_usize(args, "nexthop")?,
                })
                .await
            }
            "move_node" => {
                self.run(SimCommand::MoveNode {
                    node: req_usize(args, "node")?,
                    x: req_f64(args, "x")?,
                    y: req_f64(args, "y")?,
                    z: args.get("z").and_then(Value::as_f64).unwrap_or(0.0),
                })
                .await
            }
            "spawn_app" => {
                let node = req_usize(args, "node")?;
                let prefix = args
                    .get("prefix")
                    .and_then(Value::as_str)
                    .ok_or("missing 'prefix'")?
                    .to_string();
                let kind = args.get("kind").and_then(Value::as_str).unwrap_or("producer");
                let app = match kind {
                    "producer" => crate::AppSpec::Producer {
                        prefix,
                        content: args.get("content").and_then(Value::as_str).map(String::from),
                        freshness_ms: args.get("freshness_ms").and_then(Value::as_u64),
                    },
                    "consumer" => crate::AppSpec::Consumer {
                        prefix,
                        count: args.get("count").and_then(Value::as_u64).unwrap_or(0),
                        interval_ms: args.get("interval_ms").and_then(Value::as_u64).unwrap_or(0),
                        lifetime_ms: args.get("lifetime_ms").and_then(Value::as_u64),
                    },
                    other => return Err(format!("unknown app kind: {other}")),
                };
                self.run(SimCommand::SpawnApp { node, app }).await
            }
            "stop_app" => self.run(SimCommand::StopApp { app: req_usize(args, "app")? }).await,
            "cosim" => {
                // Fly the external swarm: {"command": {"action": "goto", "node": 1, ...}}.
                let command: crate::cosim::VehicleCommand =
                    serde_json::from_value(args.get("command").cloned().unwrap_or(Value::Null))
                        .map_err(|e| format!("bad co-sim command: {e}"))?;
                self.run(SimCommand::Cosim { command }).await
            }
            "scene_svg" => {
                let width = args.get("width").and_then(Value::as_u64).unwrap_or(600) as u32;
                let height = args.get("height").and_then(Value::as_u64).unwrap_or(600) as u32;
                Ok(to_value(self.control.query(SimQuery::SceneSvg { width, height })))
            }
            "set_strategy" => {
                let prefix = req_str(args, "prefix")?;
                let strategy = req_str(args, "strategy")?;
                self.run(SimCommand::SetStrategy { node: req_usize(args, "node")?, prefix, strategy })
                    .await
            }
            "add_radio_route" => {
                let prefix = req_str(args, "prefix")?;
                self.run(SimCommand::RouteOverRadio { node: req_usize(args, "node")?, prefix }).await
            }
            "start_recording" => {
                self.control.start_recording();
                Ok(json!({ "result": "ok" }))
            }
            "get_recording" => Ok(to_value(self.control.recording())),
            #[cfg(not(target_arch = "wasm32"))]
            "run_validation" => {
                let spec_toml = req_str(args, "spec")?;
                let spec = crate::validate::ValidationSpec::from_toml(&spec_toml)
                    .map_err(|e| format!("bad validation spec: {e}"))?;
                // `run_validation` drives its own kernel runtimes (block_on), so it must run off the
                // async worker — otherwise it nests a runtime inside this one and panics.
                let report = tokio::task::spawn_blocking(move || crate::validate::run_validation(&spec))
                    .await
                    .map_err(|e| format!("validation task panicked: {e}"))?
                    .map_err(|e| format!("validation failed to run: {e}"))?;
                Ok(to_value(report))
            }
            "generate_topology" => {
                let shape = req_str(args, "shape")?;
                let n = |d: usize| args.get("n").and_then(Value::as_u64).map(|v| v as usize).unwrap_or(d);
                let usize_arg = |k: &str, d: usize| {
                    args.get(k).and_then(Value::as_u64).map(|v| v as usize).unwrap_or(d)
                };
                let mut scenario = match shape.as_str() {
                    "line" => crate::topo::line(n(3)),
                    "ring" => crate::topo::ring(n(4)),
                    "star" => crate::topo::star(n(5)),
                    "grid" => crate::topo::grid(usize_arg("rows", 3), usize_arg("cols", 3)),
                    "mesh" | "full_mesh" => crate::topo::full_mesh(n(5)),
                    "tree" => crate::topo::tree(usize_arg("branching", 2), usize_arg("depth", 3)),
                    "random" => crate::topo::random(
                        n(20),
                        args.get("prob").and_then(Value::as_f64).unwrap_or(0.15),
                        args.get("seed").and_then(Value::as_u64).unwrap_or(0),
                    ),
                    other => return Err(format!("unknown shape '{other}'")),
                };
                if let Some(spec) = args.get("toward").and_then(Value::as_str) {
                    let (prefix, dest) = spec
                        .rsplit_once('@')
                        .ok_or("'toward' must be PREFIX@NODE, e.g. /demo@0")?;
                    let dest: usize = dest.parse().map_err(|_| "'toward' node index")?;
                    crate::topo::add_routes_toward(&mut scenario, prefix, dest);
                }
                let toml = scenario.to_toml().map_err(|e| format!("encode scenario: {e}"))?;
                Ok(json!({
                    "toml": toml,
                    "nodes": scenario.nodes.len(),
                    "links": scenario.links.len(),
                    "routes": scenario.routes.len(),
                }))
            }
            other => Err(format!("unknown tool: {other}")),
        }
    }

    async fn run(&self, cmd: SimCommand) -> Result<Value, String> {
        match self.control.execute(cmd).await {
            SimResponse::Error { message } => Err(message),
            ok => Ok(to_value(ok)),
        }
    }

    fn node_state(&self, node: usize) -> Result<Value, String> {
        let topo = self.control.fabric().topology();
        let info = topo
            .nodes
            .iter()
            .find(|n| n.id.0 == node)
            .ok_or_else(|| format!("no such node {node}"))?;
        let links: Vec<_> = topo.links.iter().filter(|l| l.from.0 == node).collect();
        let metrics = self
            .control
            .fabric()
            .snapshot_metrics()
            .into_iter()
            .find(|s| s.node.0 == node);
        Ok(json!({
            "node": node,
            "label": info.label,
            "links": to_value(links),
            "metrics": metrics.map(to_value),
        }))
    }

    /// Handle one JSON-RPC 2.0 request, returning the response string (empty for notifications /
    /// requests without an `id`).
    pub async fn handle_rpc(&self, request: &str) -> String {
        let req: RpcRequest = match serde_json::from_str(request) {
            Ok(r) => r,
            Err(e) => return rpc_error(Value::Null, -32700, &format!("parse error: {e}")),
        };
        // Notifications (no id) get no response.
        let Some(id) = req.id.clone() else {
            return String::new();
        };

        match req.method.as_str() {
            "initialize" => rpc_ok(
                id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "ndn-lab", "version": env!("CARGO_PKG_VERSION") }
                }),
            ),
            "ping" => rpc_ok(id, json!({})),
            "tools/list" => rpc_ok(id, json!({ "tools": Self::tool_catalog() })),
            "tools/call" => {
                let call: ToolCall = match serde_json::from_value(req.params) {
                    Ok(c) => c,
                    Err(e) => return rpc_error(id, -32602, &format!("invalid params: {e}")),
                };
                let (text, is_error) = match self.call_tool(&call.name, &call.arguments).await {
                    Ok(v) => (serde_json::to_string(&v).unwrap_or_default(), false),
                    Err(e) => (e, true),
                };
                rpc_ok(
                    id,
                    json!({
                        "content": [ { "type": "text", "text": text } ],
                        "isError": is_error
                    }),
                )
            }
            other => rpc_error(id, -32601, &format!("method not found: {other}")),
        }
    }

    /// Run the MCP server over stdin/stdout (newline-delimited JSON-RPC) — what a `ndn-lab-mcp`
    /// binary calls. Returns when stdin closes.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn serve_stdio(self: Arc<Self>) -> std::io::Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        let mut stdout = tokio::io::stdout();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let response = self.handle_rpc(&line).await;
            if !response.is_empty() {
                stdout.write_all(response.as_bytes()).await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
            }
        }
        Ok(())
    }
}

fn to_value<T: serde::Serialize>(v: T) -> Value {
    serde_json::to_value(v).unwrap_or(Value::Null)
}

fn req_usize(args: &Value, key: &str) -> Result<usize, String> {
    args.get(key)
        .and_then(Value::as_u64)
        .map(|n| n as usize)
        .ok_or_else(|| format!("missing or non-integer '{key}'"))
}

fn req_f64(args: &Value, key: &str) -> Result<f64, String> {
    args.get(key)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("missing or non-number '{key}'"))
}

fn req_str(args: &Value, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| format!("missing or non-string '{key}'"))
}

fn rpc_ok(id: Value, result: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "result": result }).to_string()
}

fn rpc_error(id: Value, code: i64, message: &str) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } }).to_string()
}

/// The discovery palette (design rule 2): what the fabric can do, machine-readable, so a model
/// composes scenarios from real building blocks rather than guessing.
fn capability_catalogue() -> Value {
    json!({
        "commands": ["spawn_node", "remove_node", "connect", "route", "move_node", "set_linear_mobility", "spawn_app", "stop_app", "cosim", "set_strategy", "route_over_radio"],
        "queries": ["topology", "metrics", "scene", "scene_svg", "explain"],
        "tools": ["describe_topology", "query_metrics", "node_state", "capabilities", "explain_link", "why_did", "scene_svg", "spawn_node", "remove_node", "connect", "route", "move_node", "spawn_app", "stop_app", "cosim", "set_strategy", "add_radio_route", "start_recording", "get_recording", "run_validation", "generate_topology"],
        "topology_generators": ["line", "ring", "star", "grid", "mesh", "tree", "random"],
        "apps": ["producer", "consumer"],
        "mediums": ["wired_static_channel", "wireless_medium", "radio_bus"],
        "propagation_models": ["range_threshold", "free_space_path_loss", "obstructed"],
        "mobility_models": ["static", "linear", "waypoint"],
        "mobility_via_commands": ["static (move_node)", "linear (set_linear_mobility)"],
        "interference_models": ["none", "carrier_sense"],
        "radio_mcs_modes": ["fixed", "adaptive"],
        "forwarding_strategies": ["best-route", "multicast"],
        "kernels": ["wall_clock", "virtual", "des", "real_time"],
        "validation": "run_validation gates a ValidationSpec (faults + property assertions + seed sweep + baselines) across kernels",
        "recording": "start_recording + get_recording journal a session for deterministic `ndn-lab replay`",
        "co_simulation": "a live --mavlink or --feed link streams external vehicle positions in; `cosim` commands actuate them out",
        "notes": "Interactive DES lifecycle verbs (pause/step/seek) exist in the engine (DesSession) but are not yet projected as tools. Scenario export from a live fabric is not yet available."
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Simulation;
    use ndn_engine::builder::EngineConfig;

    async fn mcp_over_fabric() -> Arc<SimMcp> {
        let mut sim = Simulation::new();
        let _a = sim.add_node(EngineConfig::default());
        let fabric = Arc::new(sim.start().await.unwrap());
        SimMcp::new(ControlPlane::new(fabric))
    }

    #[tokio::test]
    async fn tools_list_returns_the_catalogue() {
        let mcp = mcp_over_fabric().await;
        let resp = mcp
            .handle_rpc(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#)
            .await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        let tools = v["result"]["tools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t["name"] == "spawn_node"));
        assert!(tools.iter().any(|t| t["name"] == "describe_topology"));
        // Every tool carries a JSON-Schema input.
        assert!(tools.iter().all(|t| t["inputSchema"]["type"] == "object"));
    }

    #[tokio::test]
    async fn tools_call_spawn_then_query_topology() {
        let mcp = mcp_over_fabric().await;

        let spawn = mcp
            .handle_rpc(
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"spawn_node","arguments":{"label":"edge"}}}"#,
            )
            .await;
        let v: Value = serde_json::from_str(&spawn).unwrap();
        assert_eq!(v["result"]["isError"], false);
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains(r#""result":"node""#) && text.contains(r#""id":1"#), "{text}");

        let topo = mcp
            .handle_rpc(
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"describe_topology","arguments":{}}}"#,
            )
            .await;
        let v: Value = serde_json::from_str(&topo).unwrap();
        let text = v["result"]["content"][0]["text"].as_str().unwrap();
        let topo: Value = serde_json::from_str(text).unwrap();
        assert_eq!(topo["nodes"].as_array().unwrap().len(), 2, "spawn took effect");
    }

    #[tokio::test]
    async fn tool_error_sets_is_error() {
        let mcp = mcp_over_fabric().await;
        let resp = mcp
            .handle_rpc(
                r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"remove_node","arguments":{"node":999}}}"#,
            )
            .await;
        let v: Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(v["result"]["isError"], true, "removing a missing node is a tool error");
    }

    #[tokio::test]
    async fn initialize_and_unknown_method() {
        let mcp = mcp_over_fabric().await;
        let init = mcp
            .handle_rpc(r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}"#)
            .await;
        let v: Value = serde_json::from_str(&init).unwrap();
        assert_eq!(v["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(v["result"]["serverInfo"]["name"], "ndn-lab");

        let bad = mcp
            .handle_rpc(r#"{"jsonrpc":"2.0","id":5,"method":"nope"}"#)
            .await;
        let v: Value = serde_json::from_str(&bad).unwrap();
        assert_eq!(v["error"]["code"], -32601);

        // A notification (no id) yields no response.
        let note = mcp
            .handle_rpc(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .await;
        assert!(note.is_empty());
    }

    #[tokio::test]
    async fn why_did_returns_recent_events() {
        let mcp = mcp_over_fabric().await;
        // Spawn a node so there is fabric activity to explain.
        let _ = mcp.call_tool("spawn_node", &serde_json::json!({})).await.unwrap();
        let v = mcp.call_tool("why_did", &serde_json::json!({ "limit": 10 })).await.unwrap();
        assert!(v["events"].is_array(), "why_did returns a structured event list: {v}");
    }

    #[tokio::test]
    async fn capabilities_tool_lists_the_palette() {
        let mcp = mcp_over_fabric().await;
        let v = mcp.call_tool("capabilities", &Value::Null).await.unwrap();
        assert!(v["propagation_models"].as_array().unwrap().iter().any(|m| m == "free_space_path_loss"));
        assert!(v["kernels"].as_array().unwrap().iter().any(|k| k == "virtual"));
        // The refreshed catalogue advertises the newly-projected tools + drops the stale claim.
        assert!(v["commands"].as_array().unwrap().iter().any(|c| c == "set_strategy"));
        assert!(v["kernels"].as_array().unwrap().iter().any(|k| k == "des"));
        assert!(v["tools"].as_array().unwrap().iter().any(|t| t == "run_validation"));
    }

    #[tokio::test]
    async fn scene_svg_tool_renders() {
        let mcp = mcp_over_fabric().await;
        let v = mcp.call_tool("scene_svg", &json!({ "width": 320, "height": 240 })).await.unwrap();
        let svg = v["svg"].as_str().expect("an svg string");
        assert!(svg.contains("<svg"), "returns a rendered SVG document");
    }

    #[tokio::test]
    async fn recording_tools_journal_a_session() {
        let mcp = mcp_over_fabric().await;
        let _ = mcp.call_tool("start_recording", &Value::Null).await.unwrap();
        let _ = mcp.call_tool("spawn_node", &json!({ "label": "edge" })).await.unwrap();
        let rec = mcp.call_tool("get_recording", &Value::Null).await.unwrap();
        let cmds = rec["commands"].as_array().expect("a command journal");
        assert!(!cmds.is_empty(), "the spawn was journaled: {rec}");
    }

    #[tokio::test]
    async fn run_validation_tool_gates_a_spec() {
        let mcp = mcp_over_fabric().await;
        // A trivial spec: a two-node line where a consumer fetches from a producer; assert it works.
        let spec = r#"
duration_ms = 2000
kernels = ["des"]

[scenario.kernel]
kind = "des"
[[scenario.nodes]]
label = "prod"
[[scenario.nodes.apps]]
app = "producer"
prefix = "/svc"
content = "hi"
freshness_ms = 4000
[[scenario.nodes]]
label = "cons"
[[scenario.nodes.apps]]
app = "consumer"
prefix = "/svc"
count = 3
interval_ms = 200
[[scenario.links]]
a = 0
b = 1
[[scenario.routes]]
node = 1
prefix = "/svc"
nexthop = 0

[[properties]]
name = "consumer fetches at least one segment"
probe = { kind = "app_successes", app = 1 }
cmp = "ge"
value = 1
"#;
        let v = mcp.call_tool("run_validation", &json!({ "spec": spec })).await.unwrap();
        assert_eq!(v["passed"], true, "the consumer fetched from the producer: {v}");
    }

    #[tokio::test]
    async fn generate_topology_tool_emits_a_runnable_scenario() {
        let mcp = mcp_over_fabric().await;
        let v = mcp
            .call_tool("generate_topology", &json!({ "shape": "grid", "rows": 3, "cols": 3, "toward": "/demo@0" }))
            .await
            .unwrap();
        assert_eq!(v["nodes"], 9);
        assert_eq!(v["routes"], 8, "every non-destination node routes toward node 0");
        let toml = v["toml"].as_str().expect("scenario toml");
        // The emitted TOML round-trips back into a Scenario.
        let scenario = crate::Scenario::from_toml(toml).unwrap();
        assert_eq!(scenario.nodes.len(), 9);
    }
}
