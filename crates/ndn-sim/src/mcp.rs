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
                Ok(serde_json::json!({ "events": recent, "engine_spans": engine_spans }))
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
        "commands": ["spawn_node", "remove_node", "connect", "route", "move_node", "set_linear_mobility", "spawn_app", "stop_app"],
        "queries": ["topology", "metrics", "scene"],
        "apps": ["producer", "consumer"],
        "mediums": ["wired_static_channel", "wireless_medium", "radio_bus"],
        "propagation_models": ["range_threshold", "free_space_path_loss"],
        "mobility_models": ["static", "linear", "waypoint"],
        "interference_models": ["none", "carrier_sense"],
        "radio_mcs_modes": ["fixed", "adaptive"],
        "kernels": ["wall_clock", "virtual"],
        "notes": "Lifecycle (pause/step/seek) verbs require the DES event-queue and are not yet available."
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
    }
}
