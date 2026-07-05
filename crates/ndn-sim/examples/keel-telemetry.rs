//! keel-telemetry — ndn-lab telemetry through the Keel, end to end on real data.
//!
//! Runs a small named-radio exchange (one producer, three in-range consumers),
//! samples the shared medium's airtime into a `FabricGauges` stream, then renders
//! that ONE self-describing metric through TWO lenses the matcher selects:
//!
//!   series.window ⇒ Express                    → an SVG sparkline
//!   otlp.gauge    ⇒ Approximate [loss: …]      → an OTLP/JSON gauge
//!
//! The metric is described once; nobody wrote an exporter integration; the OTLP
//! lens's lossiness is a *named term* in the trace, not buried in serializer code.
//!
//!   cargo run -p ndn-sim --example keel-telemetry

use std::sync::Arc;
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{
    AppSpec, DesKernel, FabricGauges, Floor, KeelView, Position, RangeThreshold, SimKernel,
    Simulation, WifiMode,
};
use tokio_util::sync::CancellationToken;

fn main() {
    // ── real sim telemetry: airtime over a managed-Wi-Fi radio exchange ──────
    let stream: Vec<FabricGauges> = DesKernel::new().run(|k: Arc<dyn SimKernel>| async move {
        let mut sim = Simulation::new()
            .kernel(k)
            .with_radio_medium(Arc::new(RangeThreshold { range_m: 50.0, tx_power_dbm: 20.0 }), 7);
        let p = sim.add_radio_node(EngineConfig::default(), Position::xy(0.0, 0.0));
        let consumers = [
            sim.add_radio_node(EngineConfig::default(), Position::xy(10.0, 0.0)),
            sim.add_radio_node(EngineConfig::default(), Position::xy(20.0, 0.0)),
            sim.add_radio_node(EngineConfig::default(), Position::xy(10.0, 10.0)),
        ];
        sim.add_app(
            p,
            AppSpec::Producer { prefix: "/svc".into(), content: Some("air".into()), freshness_ms: None },
        );
        let fabric = sim.start().await.unwrap();
        let bus = fabric.radio_bus().unwrap();
        bus.set_mac_mode(WifiMode::Managed); // per-neighbour unicast ⇒ airtime grows

        let mut stream = Vec::new();
        for (i, c) in consumers.into_iter().enumerate() {
            fabric.route_over_radio(c, &"/svc".parse::<Name>().unwrap()).unwrap();
            let mut consumer = fabric.engine_of(c).unwrap().app_consumer(CancellationToken::new());
            let _ = consumer
                .fetch_with(
                    InterestBuilder::new(format!("/svc/{i}").parse::<Name>().unwrap())
                        .lifetime(Duration::from_secs(10)),
                )
                .await;
            // Snapshot the shared-medium airtime as a fabric gauge.
            stream.push(FabricGauges {
                virtual_time_ns: (i as u64 + 1) * 1_000_000,
                radio_airtime_ns: bus.total_airtime().as_nanos() as u64,
                handoffs: 0,
                association_overhead_ns: 0,
            });
        }
        fabric.shutdown().await;
        stream
    });

    // ── one metric, three surfaces, and the choice is declared ───────────────
    println!("── ndn-lab telemetry through the Keel ──");
    println!("{} fabric-gauge samples; final airtime {} µs", stream.len(), stream.last().map(|g| g.radio_airtime_ns / 1000).unwrap_or(0));

    // A graphical surface holds every lens; series.window has two competing offers.
    let gui = KeelView::for_fabric_gauges(/* otlp bridge */ true, /* svg-capable */ true);
    println!("\n[graphical surface] lenses:");
    for m in gui.lenses() {
        println!("  {}", gui.render(m, &stream).expect("renders").trace);
    }
    // select resolves the competition for series.window: the lossless SVG wins.
    let picked = gui.select_for("series.window", Floor::Approximate).unwrap();
    println!("  select(series.window, ≥Approximate) → {:?} (the SVG)", picked.verdict);

    // A CLI surface can't render SVG, so it doesn't hold that contract. series.window
    // degrades — honestly — to the ASCII lens; an Express floor filters the CLI out.
    let cli = KeelView::for_fabric_gauges(true, /* svg-capable */ false);
    let ascii = cli.select_for("series.window", Floor::Approximate).unwrap();
    let rendered = cli.render(&ascii, &stream).unwrap();
    println!("\n[cli surface] select(series.window, ≥Approximate) degrades honestly:");
    println!("  {}", rendered.trace);
    println!("  → {}", rendered.body);
    println!("  select(series.window, ≥Express) → {:?} (CLI filtered out — no lossless offer)",
        cli.select_for("series.window", Floor::Express).map(|m| m.verdict));

    println!("\none metric, three surfaces; resolved once; the choice between them is declared,\ndeterministic, and auditable — nobody wrote an integration, and every loss is a term.");
}
