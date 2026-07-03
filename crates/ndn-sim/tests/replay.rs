//! Session record + replay (ndn-lab): a hand-driven session is journaled and replays
//! identically on a fresh fabric — the deterministic-replay tool, pairing the command journal
//! with the (already-deterministic) scenario.

use std::sync::Arc;

use ndn_sim::{
    ControlPlane, LinkSpec, Recording, SimCommand, SimKernel, Simulation, VirtualKernel,
};

/// Drive a fixed live session through `control`, returning nothing (state is in the fabric).
async fn drive(control: &ControlPlane) {
    control
        .execute(SimCommand::SpawnNode {
            label: Some("a".into()),
        })
        .await; // id 0
    control
        .execute(SimCommand::SpawnNode {
            label: Some("b".into()),
        })
        .await; // id 1
    control
        .execute(SimCommand::Connect {
            a: 0,
            b: 1,
            link: LinkSpec::default(),
        })
        .await;
    control
        .execute(SimCommand::Route {
            node: 0,
            prefix: "/x".into(),
            nexthop: 1,
        })
        .await;
    control
        .execute(SimCommand::MoveNode {
            node: 0,
            x: 5.0,
            y: 0.0,
            z: 0.0,
        })
        .await;
}

#[test]
fn record_then_replay_reproduces_the_session() {
    // Run 1 — record the session.
    let (recording_json, original_topo, original_x0) = VirtualKernel::new().run(|k| async move {
        let fabric = Arc::new(Simulation::new().kernel(k).start().await.unwrap());
        let control = ControlPlane::new(Arc::clone(&fabric));
        control.start_recording();
        drive(&control).await;

        let rec = control.recording();
        assert_eq!(rec.len(), 5, "all five commands journaled");
        let topo = serde_json::to_string(&fabric.topology()).unwrap();
        let x0 = fabric
            .scene_snapshot()
            .nodes
            .iter()
            .find(|n| n.id == 0)
            .unwrap()
            .x;
        fabric.shutdown().await;
        (rec.to_json().unwrap(), topo, x0)
    });
    assert_eq!(original_x0, 5.0, "node 0 was moved during the session");

    // Run 2 — replay the journal onto a fresh fabric (no live driving).
    let (replayed_topo, replayed_x0) = VirtualKernel::new().run(|k| async move {
        let recording = Recording::from_json(&recording_json).unwrap();
        let fabric = Arc::new(Simulation::new().kernel(k).start().await.unwrap());
        let control = ControlPlane::new(Arc::clone(&fabric));
        recording.replay(&control, false).await.unwrap();

        let topo = serde_json::to_string(&fabric.topology()).unwrap();
        let x0 = fabric
            .scene_snapshot()
            .nodes
            .iter()
            .find(|n| n.id == 0)
            .unwrap()
            .x;
        fabric.shutdown().await;
        (topo, x0)
    });

    // The replayed fabric matches the recorded one: same topology graph, same moved position.
    assert_eq!(
        original_topo, replayed_topo,
        "replay reproduced the topology"
    );
    assert_eq!(replayed_x0, 5.0, "replay reproduced the live MoveNode");
}

#[test]
fn recording_round_trips_through_json() {
    let json = VirtualKernel::new().run(|k| async move {
        let fabric = Arc::new(Simulation::new().kernel(k).start().await.unwrap());
        let control = ControlPlane::new(Arc::clone(&fabric));
        control.start_recording();
        control.execute(SimCommand::SpawnNode { label: None }).await;
        let json = control.recording().to_json().unwrap();
        fabric.shutdown().await;
        json
    });
    let rec = Recording::from_json(&json).unwrap();
    assert_eq!(rec.len(), 1);
    assert!(matches!(
        rec.commands[0].command,
        SimCommand::SpawnNode { .. }
    ));
    // Re-serialize → identical structure.
    assert_eq!(
        serde_json::to_value(&rec).unwrap(),
        serde_json::from_str::<serde_json::Value>(&json).unwrap()
    );
}

/// Paced replay honors the recorded virtual cadence and still works under the virtual kernel.
#[test]
fn paced_replay_runs_under_virtual_time() {
    let recording_json = VirtualKernel::new().run(|k| async move {
        let fabric = Arc::new(Simulation::new().kernel(k).start().await.unwrap());
        let control = ControlPlane::new(Arc::clone(&fabric));
        control.start_recording();
        control.execute(SimCommand::SpawnNode { label: None }).await;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await; // 2s of virtual cadence
        control.execute(SimCommand::SpawnNode { label: None }).await;
        let json = control.recording().to_json().unwrap();
        fabric.shutdown().await;
        json
    });

    let node_count = VirtualKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let rec = Recording::from_json(&recording_json).unwrap();
        let fabric = Arc::new(Simulation::new().kernel(k).start().await.unwrap());
        let control = ControlPlane::new(Arc::clone(&fabric));
        rec.replay(&control, true).await.unwrap(); // paced
        let n = fabric.nodes();
        fabric.shutdown().await;
        n
    });
    assert_eq!(node_count, 2);
}
