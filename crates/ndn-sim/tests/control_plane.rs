//! Slice-6 integration (ndn-lab): the control plane over its transports — in-process Rust,
//! the JSON RPC codec, and NDN-native `/localhop/sim/control` — all driving the same
//! `FabricControl`, plus the control-event notification stream.

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{ControlPlane, NodeId, SimCommand, SimQuery, SimResponse, Simulation};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn in_process_commands_drive_the_fabric_and_emit_notifications() {
    let mut sim = Simulation::new();
    let _a = sim.add_node(EngineConfig::default());
    let _b = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));

    // Spawn a third node via the declarative command.
    let resp = control.execute(SimCommand::SpawnNode { label: Some("edge".into()) }).await;
    let SimResponse::Node { id } = resp else {
        panic!("expected Node, got {resp:?}");
    };
    assert_eq!(id, 2);

    // Connect + route are accepted.
    assert!(matches!(
        control
            .execute(SimCommand::Connect { a: 0, b: 1, link: Default::default() })
            .await,
        SimResponse::Ok
    ));
    assert!(matches!(
        control
            .execute(SimCommand::Route {
                node: 0,
                prefix: "/app".into(),
                nexthop: 1,
            })
            .await,
        SimResponse::Ok
    ));

    // The topology query reflects all three nodes.
    let SimResponse::Topology(topo) = control.query(SimQuery::Topology) else {
        panic!("expected topology");
    };
    assert_eq!(topo.nodes.len(), 3);

    // Each mutating command published a notification (spawn + connect + route = 3).
    assert_eq!(control.notifications().current_seq(), 3);
    let events = control.notifications().recent_event_bytes();
    let joined: String = events
        .iter()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect();
    assert!(joined.contains("node_spawned") && joined.contains("edge"));
    assert!(joined.contains("link_added") && joined.contains("route_added"));

    // A bad command surfaces an error, doesn't panic.
    assert!(matches!(
        control.execute(SimCommand::RemoveNode { node: 999 }).await,
        SimResponse::Error { .. }
    ));

    fabric.shutdown().await;
}

#[tokio::test]
async fn json_rpc_codec_round_trips() {
    let mut sim = Simulation::new();
    let _a = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));

    let reply = control.handle_json(r#"{"query":{"query":"topology"}}"#).await;
    assert!(reply.contains(r#""result":"topology""#), "got {reply}");

    let reply = control.handle_json(r#"{"command":{"cmd":"spawn_node"}}"#).await;
    assert!(reply.contains(r#""result":"node""#) && reply.contains(r#""id":1"#), "got {reply}");

    let reply = control.handle_json("not json").await;
    assert!(reply.contains(r#""result":"error""#), "bad input → error, got {reply}");

    fabric.shutdown().await;
}

#[tokio::test]
async fn ndn_native_control_serves_commands_and_queries() {
    let mut sim = Simulation::new();
    let _a = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));

    let engine = fabric.engine_of(NodeId(0)).unwrap();
    control.serve_ndn(&engine, CancellationToken::new());

    // A client speaks the control surface purely over NDN: JSON request in
    // ApplicationParameters, JSON SimResponse back as Data.
    let mut consumer = engine.app_consumer(CancellationToken::new());

    // Query topology over the air → 1 node.
    let resp = ask(&mut consumer, br#"{"query":{"query":"topology"}}"#).await;
    let SimResponse::Topology(topo) = resp else { panic!("expected topology, got {resp:?}") };
    assert_eq!(topo.nodes.len(), 1);

    // Spawn a node over the air.
    let resp = ask(&mut consumer, br#"{"command":{"cmd":"spawn_node","label":"drone"}}"#).await;
    assert!(matches!(resp, SimResponse::Node { id: 1 }), "got {resp:?}");

    // Re-query: the spawn took effect.
    let resp = ask(&mut consumer, br#"{"query":{"query":"topology"}}"#).await;
    let SimResponse::Topology(topo) = resp else { panic!("expected topology") };
    assert_eq!(topo.nodes.len(), 2, "spawn over NDN grew the fabric");

    fabric.shutdown().await;
}

#[tokio::test]
async fn move_node_command_relocates_the_node_in_the_scene() {
    let mut sim = Simulation::new();
    let _a = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));

    // Drag node 0 to (123, 456) live.
    assert!(matches!(
        control
            .execute(SimCommand::MoveNode { node: 0, x: 123.0, y: 456.0, z: 0.0 })
            .await,
        SimResponse::Ok
    ));

    // The scene reflects the new position immediately.
    let scene = fabric.scene_snapshot();
    let n0 = scene.nodes.iter().find(|n| n.id == 0).unwrap();
    assert_eq!((n0.x, n0.y), (123.0, 456.0));

    // And it was announced on the notification stream.
    let joined: String = control
        .notifications()
        .recent_event_bytes()
        .iter()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect();
    assert!(joined.contains("node_moved"));

    fabric.shutdown().await;
}

#[tokio::test]
async fn set_strategy_command_applies_over_the_control_plane() {
    let mut sim = Simulation::new();
    let _a = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));

    // Switch node 0 to the multicast strategy for /x (the failover knob) over the wire.
    let resp = control
        .execute(SimCommand::SetStrategy {
            node: 0,
            prefix: "/x".into(),
            strategy: "multicast".into(),
        })
        .await;
    assert!(matches!(resp, SimResponse::Ok), "multicast strategy applied, got {resp:?}");

    // An unknown strategy name is a clean error, not a panic.
    let bad = control
        .execute(SimCommand::SetStrategy {
            node: 0,
            prefix: "/x".into(),
            strategy: "no-such-strategy".into(),
        })
        .await;
    assert!(matches!(bad, SimResponse::Error { .. }), "unknown strategy → error, got {bad:?}");

    fabric.shutdown().await;
}

#[tokio::test]
async fn tcp_rpc_server_handles_json_lines() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut sim = Simulation::new();
    let _a = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));

    let addr = control
        .serve_tcp("127.0.0.1:0", CancellationToken::new())
        .await
        .unwrap();

    // A plain TCP client speaks newline-delimited JSON.
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();

    write.write_all(b"{\"command\":{\"cmd\":\"spawn_node\"}}\n").await.unwrap();
    let line = lines.next_line().await.unwrap().unwrap();
    assert!(line.contains(r#""result":"node""#) && line.contains(r#""id":1"#), "got {line}");

    write.write_all(b"{\"query\":{\"query\":\"topology\"}}\n").await.unwrap();
    let line = lines.next_line().await.unwrap().unwrap();
    assert!(line.contains(r#""result":"topology""#), "got {line}");
    let resp: SimResponse = serde_json::from_str(&line).unwrap();
    let SimResponse::Topology(topo) = resp else { panic!("expected topology") };
    assert_eq!(topo.nodes.len(), 2, "the spawn over TCP took effect");

    fabric.shutdown().await;
}

#[tokio::test]
async fn ws_rpc_server_handles_json_and_renders_svg() {
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let mut sim = Simulation::new();
    let _a = sim.add_node(EngineConfig::default());
    let fabric = Arc::new(sim.start().await.unwrap());
    let control = ControlPlane::new(Arc::clone(&fabric));
    let addr = control.serve_ws("127.0.0.1:0", CancellationToken::new()).await.unwrap();

    // A browser-style WebSocket client speaks the same JSON-RPC.
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}")).await.unwrap();

    ws.send(Message::text(r#"{"command":{"cmd":"spawn_node"}}"#.to_string())).await.unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    assert!(reply.to_text().unwrap().contains(r#""result":"node""#));

    // Server-rendered SVG — a client with no shared Rust types just displays this.
    ws.send(Message::text(r#"{"query":{"query":"scene_svg","width":300,"height":300}}"#.to_string()))
        .await
        .unwrap();
    let reply = ws.next().await.unwrap().unwrap();
    let resp: SimResponse = serde_json::from_str(reply.to_text().unwrap()).unwrap();
    match resp {
        SimResponse::Svg { svg } => assert!(svg.starts_with("<svg") && svg.contains("<circle")),
        other => panic!("expected svg, got {other:?}"),
    }

    fabric.shutdown().await;
}

/// Send a JSON control request over NDN (ApplicationParameters) and parse the JSON reply.
async fn ask(consumer: &mut ndn_app::Consumer, json: &[u8]) -> SimResponse {
    let builder = InterestBuilder::new("/localhop/sim/control".parse::<Name>().unwrap())
        .app_parameters(json.to_vec())
        .lifetime(Duration::from_secs(5));
    let data = consumer.fetch_with(builder).await.expect("control reply");
    let bytes = data.content().map(|c| c.to_vec()).unwrap_or_default();
    serde_json::from_slice::<SimResponse>(&bytes).expect("parse SimResponse")
}
