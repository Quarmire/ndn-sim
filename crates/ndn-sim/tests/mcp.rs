//! Slice-7 integration (ndn-lab): a model builds and inspects a network entirely through MCP
//! `tools/call` — the "compose a scenario, then interpret it" trajectory the design is for.

use std::sync::Arc;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{ControlPlane, SimMcp, Simulation};
use serde_json::Value;

/// Call an MCP tool over the JSON-RPC surface and return its (parsed) structured result.
async fn tool(mcp: &Arc<SimMcp>, id: u32, name: &str, arguments: Value) -> Value {
    let req = serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    });
    let resp = mcp.handle_rpc(&req.to_string()).await;
    let v: Value = serde_json::from_str(&resp).unwrap();
    assert_eq!(v["result"]["isError"], false, "{name} failed: {resp}");
    let text = v["result"]["content"][0]["text"].as_str().unwrap();
    serde_json::from_str(text).unwrap()
}

#[tokio::test]
async fn model_builds_a_line_topology_via_mcp_tools() {
    // Start from a single node; the model grows the rest through tools.
    let mut sim = Simulation::new();
    let _root = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let mcp = SimMcp::new(ControlPlane::new(Arc::clone(&fabric)));

    // Discover the palette first (what the model would do).
    let caps = tool(&mcp, 1, "capabilities", Value::Null).await;
    assert!(
        caps["commands"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "connect")
    );

    // Build: spawn two more nodes (ids 1, 2) and wire 0—1—2 with a 5 ms link.
    let n1 = tool(&mcp, 2, "spawn_node", serde_json::json!({ "label": "mid" })).await;
    assert_eq!(n1["id"], 1);
    let n2 = tool(
        &mcp,
        3,
        "spawn_node",
        serde_json::json!({ "label": "leaf" }),
    )
    .await;
    assert_eq!(n2["id"], 2);

    tool(
        &mcp,
        4,
        "connect",
        serde_json::json!({ "a": 0, "b": 1, "delay_ms": 5 }),
    )
    .await;
    tool(
        &mcp,
        5,
        "connect",
        serde_json::json!({ "a": 1, "b": 2, "delay_ms": 5 }),
    )
    .await;
    tool(
        &mcp,
        6,
        "route",
        serde_json::json!({ "node": 0, "prefix": "/leaf", "nexthop": 1 }),
    )
    .await;

    // Interpret: the topology now has 3 nodes and the links we asked for.
    let topo = tool(&mcp, 7, "describe_topology", Value::Null).await;
    assert_eq!(topo["nodes"].as_array().unwrap().len(), 3);
    assert!(
        topo["links"].as_array().unwrap().len() >= 4,
        "two bidirectional links"
    );

    // node_state composes label + links + metrics for one node.
    let state = tool(&mcp, 8, "node_state", serde_json::json!({ "node": 1 })).await;
    assert_eq!(state["label"], "mid");
    assert!(
        state["metrics"]["pit_depth"].is_number(),
        "metrics present: {state}"
    );
    assert!(
        !state["links"].as_array().unwrap().is_empty(),
        "node 1 is linked"
    );

    fabric.shutdown().await;
}
