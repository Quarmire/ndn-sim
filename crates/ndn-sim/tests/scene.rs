//! Slice-8 integration (ndn-lab): the GUI seam — a renderable scene off a live fabric, fetched
//! over the control plane like any client, with positions tracking the world (incl. mobility)
//! and a valid SVG out the other end. Headless: no browser, no UI toolkit.

use std::sync::Arc;
use std::time::Duration;

use ndn_engine::builder::EngineConfig;
use ndn_sim::{
    ControlPlane, LinearMobility, LinkConfig, NodeId, Position, SimKernel, SimQuery, SimResponse,
    Simulation, VirtualKernel, World, render_topology_svg,
};

#[tokio::test]
async fn scene_reflects_world_positions_and_renders_svg() {
    let world = World::new();
    world.place(NodeId(0), Position::xy(0.0, 0.0));
    world.place(NodeId(1), Position::xy(30.0, 40.0)); // 50 m away

    let mut sim = Simulation::new().world(world);
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    sim.link(a, b, LinkConfig::lan());
    let fabric = Arc::new(sim.start().await.unwrap());

    let scene = fabric.scene_snapshot();
    assert_eq!(scene.nodes.len(), 2);
    // Positions come from the world, not the fallback layout.
    let n0 = scene.nodes.iter().find(|n| n.id == 0).unwrap();
    let n1 = scene.nodes.iter().find(|n| n.id == 1).unwrap();
    assert_eq!((n0.x, n0.y), (0.0, 0.0));
    assert_eq!((n1.x, n1.y), (30.0, 40.0));
    assert_eq!(scene.links.len(), 1);
    assert_eq!(scene.links[0].distance_m, Some(50.0));

    // The same scene is reachable over the control plane (what a GUI client fetches).
    let control = ControlPlane::new(Arc::clone(&fabric));
    let SimResponse::Scene(via_api) = control.query(SimQuery::Scene) else {
        panic!("expected a scene response");
    };
    assert_eq!(via_api.nodes.len(), 2);

    // And it renders to a well-formed SVG: one circle per node, one line per edge.
    let svg = render_topology_svg(&scene, 600, 600);
    assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
    assert_eq!(svg.matches("<circle").count(), 2);
    assert_eq!(svg.matches("<line").count(), 1);

    fabric.shutdown().await;
}

/// Under the virtual kernel a mobile node's scene position advances with virtual time — the
/// "live world view" animates deterministically.
#[test]
fn scene_animates_mobility_under_virtual_time() {
    let kernel = VirtualKernel::new();
    let (x0, x1) = kernel.run(|k: Arc<dyn SimKernel>| async move {
        let world = World::new();
        world.set_mobility(
            NodeId(0),
            Arc::new(LinearMobility { start: Position::xy(0.0, 0.0), velocity: (10.0, 0.0, 0.0) }),
        );
        let mut sim = Simulation::new().kernel(k).world(world);
        let _n = sim.add_node(EngineConfig::default());
        let fabric = sim.start().await.unwrap();

        let x0 = fabric.scene_snapshot().nodes[0].x; // ~t=0
        tokio::time::sleep(Duration::from_secs(5)).await;
        let x1 = fabric.scene_snapshot().nodes[0].x; // ~t=5 ⇒ 10 m/s × 5 s = 50 m
        fabric.shutdown().await;
        (x0, x1)
    });

    assert!(x0 < 1.0, "starts near the origin, got {x0}");
    assert!(x1 > 45.0, "moved ~50 m by t=5 s, got {x1}");
}
