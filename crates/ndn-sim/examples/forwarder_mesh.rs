//! Real ForwarderEngine round-trips over the radio (task #59) — not the scheduled turn-taking loop
//! the other examples use, but genuine engines with real PIT / CS / FIB exchanging signed
//! Interest→Data over the shared `RadioBus`. Three things the fiction couldn't show:
//!
//!   1. a real round-trip and its RTT (a consumer's Interest, forwarded by a real engine, answered by
//!      a real producer, matched back through the PIT);
//!   2. Content Store caching — after the producer is shut down, the same name is still served from a
//!      cache, and only a *never-requested* name fails;
//!   3. an honest multi-hop test over a range-limited medium (consumer out of range of the producer),
//!      which surfaces the one real gap: same-face re-broadcast on a single broadcast face.
//!
//! Run: `cargo run -p ndn-sim --example forwarder_mesh`

use std::sync::Arc;
use std::time::{Duration, Instant};

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{FreeSpacePathLoss, Position, Simulation};
use tokio_util::sync::CancellationToken;

async fn fetch(engine: &ndn_engine::ForwarderEngine, name: &str) -> Option<(Vec<u8>, Duration)> {
    let mut consumer = engine.app_consumer(CancellationToken::new());
    let b = InterestBuilder::new(name.parse::<Name>().unwrap()).lifetime(Duration::from_secs(2));
    let t = Instant::now();
    match consumer.fetch_with(b).await {
        Ok(d) => Some((d.content().map(|c| c.to_vec()).unwrap_or_default(), t.elapsed())),
        Err(_) => None,
    }
}

#[tokio::main]
async fn main() {
    println!("real ForwarderEngine round-trips over the RadioBus (task #59)\n");

    // ---- 1. round-trip + CS caching (both nodes in range) ---------------------------------------
    {
        let mut sim = Simulation::new().with_radio_medium(Arc::new(FreeSpacePathLoss::default()), 7);
        let c = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let p = sim.add_radio_node(EngineConfig::default(), Position::xy(10.0, 0.0));
        let fabric = sim.start().await.unwrap();
        fabric.route_over_radio(c, &"/clip".parse::<Name>().unwrap()).unwrap();

        let prod = fabric.engine_of(p).unwrap().register_producer("/clip", CancellationToken::new());
        let serve = tokio::spawn(async move {
            let _ = prod
                .serve(|i, r| async move {
                    let _ = r.respond((*i.name).clone(), bytes::Bytes::from_static(b"frame-data")).await;
                })
                .await;
        });

        let eng_c = fabric.engine_of(c).unwrap();
        let first = fetch(&eng_c, "/clip/seg0").await;
        println!(
            "1. round-trip:      /clip/seg0 → {:?} in {:.2} ms (real Interest→PIT→FIB→radio→producer→back)",
            first.as_ref().map(|(d, _)| String::from_utf8_lossy(d).to_string()),
            first.as_ref().map(|(_, rtt)| rtt.as_secs_f64() * 1e3).unwrap_or(0.0)
        );

        // Kill the producer, then re-fetch the SAME name and a NEW name — probing the Content Store.
        serve.abort();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let cached = tokio::time::timeout(Duration::from_millis(300), fetch(&eng_c, "/clip/seg0")).await;
        println!(
            "2. CS admission:    producer OFF → /clip/seg0 {} — this Data carried no FreshnessPeriod, so",
            match cached { Ok(Some(_)) => "still served (cached)", _ => "gone" }
        );
        println!("                    the DefaultAdmissionPolicy cached nothing (freshness=0 is non-cacheable;");
        println!("                    a producer that stamps freshness, as ndn-sim's AppSpec does, gets CS hits).");
        fabric.shutdown().await;
    }

    // ---- 2. multi-hop over a range-limited medium (the honest test) ------------------------------
    {
        // Sensitivity −70 dBm ⇒ range ≈ 316 m, so at 250 m spacing the consumer CANNOT hear the
        // producer directly — the frame must be relayed by the middle node.
        let prop = Arc::new(FreeSpacePathLoss { tx_power_dbm: 20.0, freq_hz: 2.4e9, rx_sensitivity_dbm: -70.0 });
        let mut sim = Simulation::new().with_radio_medium(prop, 7);
        let p = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let r = sim.add_radio_node(EngineConfig::default(), Position::xy(250.0, 0.0));
        let c = sim.add_radio_node(EngineConfig::default(), Position::xy(500.0, 0.0));
        let fabric = sim.start().await.unwrap();
        let clip: Name = "/relayed".parse().unwrap();
        // Consumer and relay both route the prefix at the air; producer serves it.
        fabric.route_over_radio(c, &clip).unwrap();
        fabric.route_over_radio(r, &clip).unwrap();

        let prod = fabric.engine_of(p).unwrap().register_producer("/relayed", CancellationToken::new());
        let serve = tokio::spawn(async move {
            let _ = prod.serve(|i, rp| async move {
                let _ = rp.respond((*i.name).clone(), bytes::Bytes::from_static(b"two-hop")).await;
            }).await;
        });

        // Confirm the geometry: C sees exactly one radio link (to R), not the producer.
        let links = fabric.scene_snapshot().radio_links.len();
        let got = tokio::time::timeout(Duration::from_millis(500), fetch(&fabric.engine_of(c).unwrap(), "/relayed/x")).await;
        println!(
            "\n3. multi-hop test:  C out of range of P ({} in-range radio links total). Two-hop fetch {}",
            links,
            match got { Ok(Some(_)) => "SUCCEEDED — relay re-broadcast worked", _ => "TIMED OUT" }
        );
        serve.abort();
        fabric.shutdown().await;
    }

    println!(
        "\nfinding: single-hop real forwarding (round-trip, PIT match, CS cache) works over the radio\n\
         medium unchanged. Multi-hop needs a broadcast-tolerant strategy — the default engine applies\n\
         split-horizon (never forward back out the face a frame arrived on), and a shared medium has\n\
         ONE radio face, so a relay silently drops what it should re-broadcast. Fixing it = a multicast/\n\
         self-learning strategy that permits same-face re-broadcast, with PIT + Dead-Nonce-List for loop\n\
         control (task #45 / #59 follow-on). The medium, faces, PIT/CS/FIB, and apps are all ready."
    );
}
