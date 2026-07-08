//! keel-live — **a human watching it happen**: a live browser surface over a
//! running fabric, rendered entirely through the Keel.
//!
//! A real NDN radio fabric runs on the wall clock (one producer, three
//! consumers fetching continuously, so shared-medium airtime grows). Its scene
//! and its gauges stream through the *same* render-contract machinery the
//! one-shot demo proved — but live:
//!
//! - **Resolve once, stream forever.** [`KeelView`] and [`SceneView`] are
//!   constructed a single time at startup; every page load renders the *current*
//!   frame through the **cached** matches. The schema is the Block; the frames
//!   are Sparks — the matcher never runs again while you watch.
//! - The page shows the `series.window` **competition** (the select pick
//!   highlighted, the fallbacks with their named losses) beside the live
//!   topology map, refreshing once a second.
//!
//! ```text
//! cargo run -p ndn-sim --example keel-live            # serve http://127.0.0.1:8737
//! cargo run -p ndn-sim --example keel-live -- --snapshot   # print one page, exit (CI)
//! ```
//!
//! No new dependencies: the server is a minimal HTTP/1.1 responder on
//! `tokio::net` (the same hand-rolled style as the crate's OTLP client).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::scene::SceneSnapshot;
use ndn_sim::{
    AppSpec, FabricGauges, Floor, KeelView, Position, RangeThreshold, Rendered, SceneView,
    Simulation, Surface, Verdict,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

const ADDR: &str = "127.0.0.1:8737";
/// Sample-ring depth: enough for a minute of 500 ms ticks.
const RING: usize = 120;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let snapshot_mode = std::env::args().any(|a| a == "--snapshot");

    // ── a real fabric on the wall clock ─────────────────────────────────────
    let mut sim = Simulation::new() // default WallClockKernel: live time
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
    let fabric = Arc::new(sim.start().await?);
    for c in consumers {
        fabric.route_over_radio(c, &"/svc".parse::<Name>()?)?;
    }
    let bus = fabric.radio_bus().expect("radio fabric");

    // ── resolve ONCE (the Block); everything after streams past it ──────────
    let keel = Arc::new(KeelView::for_fabric_gauges(true, Surface::Graphical));
    let scene0 = fabric.scene_snapshot();
    let scene_view = Arc::new(SceneView::for_scene(&scene0).expect("finite positions"));

    // ── the driver: continuous fetches grow airtime into a sample ring ──────
    let samples: Arc<Mutex<Vec<FabricGauges>>> = Arc::new(Mutex::new(Vec::new()));
    let fetches = Arc::new(AtomicU64::new(0));
    let t0 = std::time::Instant::now();
    {
        let (fabric, bus, samples, fetches) =
            (Arc::clone(&fabric), Arc::clone(&bus), Arc::clone(&samples), Arc::clone(&fetches));
        tokio::spawn(async move {
            let mut n = 0u64;
            loop {
                // Unique names so the fetch crosses the radio instead of the CS.
                let c = consumers[(n % 3) as usize];
                let mut consumer =
                    fabric.engine_of(c).unwrap().app_consumer(CancellationToken::new());
                let name: Name = format!("/svc/live/{n}").parse().unwrap();
                let _ = consumer
                    .fetch_with(InterestBuilder::new(name).lifetime(Duration::from_secs(2)))
                    .await;
                n += 1;
                fetches.store(n, Ordering::Relaxed);
                {
                    let mut s = samples.lock().unwrap();
                    s.push(FabricGauges {
                        virtual_time_ns: t0.elapsed().as_nanos() as u64,
                        radio_airtime_ns: bus.total_airtime().as_nanos() as u64,
                        ..Default::default()
                    });
                    let len = s.len();
                    if len > RING {
                        s.drain(..len - RING);
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });
    }

    if snapshot_mode {
        // CI mode: let a few fetches land, print one composed page, exit.
        tokio::time::sleep(Duration::from_millis(1800)).await;
        let s = samples.lock().unwrap().clone();
        println!("{}", page(&keel, &scene_view, &fabric.scene_snapshot(), &s, fetches.load(Ordering::Relaxed)));
        fabric.shutdown().await;
        return Ok(());
    }

    // ── the surface: a minimal HTTP responder; every GET renders live state ─
    let listener = tokio::net::TcpListener::bind(ADDR).await?;
    eprintln!("keel-live: watching at http://{ADDR}  (Ctrl-C to stop)");
    loop {
        let (mut stream, _) = listener.accept().await?;
        let (keel, scene_view, fabric, samples, fetches) = (
            Arc::clone(&keel),
            Arc::clone(&scene_view),
            Arc::clone(&fabric),
            Arc::clone(&samples),
            Arc::clone(&fetches),
        );
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await; // drain the GET; path is irrelevant
            let s = samples.lock().unwrap().clone();
            let body = page(&keel, &scene_view, &fabric.scene_snapshot(), &s, fetches.load(Ordering::Relaxed));
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        });
    }
}

/// Compose the live page from the CACHED lenses over the CURRENT frame — no
/// matching happens here; only rendering.
fn page(
    keel: &KeelView,
    scene_view: &SceneView,
    scene: &SceneSnapshot,
    samples: &[FabricGauges],
    fetches: u64,
) -> String {
    use std::fmt::Write as _;
    let airtime_us = samples.last().map(|g| g.radio_airtime_ns / 1000).unwrap_or(0);

    let mut h = String::new();
    let _ = write!(
        h,
        "<!doctype html><meta charset=utf-8><meta http-equiv=refresh content=1>\
         <title>ndn-lab · live</title>\
         <style>body{{font:14px system-ui;margin:2rem;max-width:56rem}}\
         .row{{display:flex;gap:1rem;flex-wrap:wrap}}\
         .card{{border:1px solid #ccc;padding:.5rem 1rem;border-radius:6px;margin:.4rem 0}}\
         .pick{{border:2px solid #0a7;background:#f4fffb}}\
         pre{{margin:.3rem 0;white-space:pre-wrap}}.v{{color:#555;font-weight:600}}\
         h1{{font-size:1.2rem}}h2{{font-size:1rem;color:#333}}</style>\
         <h1>ndn-lab — live, through the Keel</h1>\
         <p>{} fetches over the shared radio · airtime {} µs · {} samples in the window · \
         resolved <b>once</b>; every refresh streams the current frame past the cached matches.</p>",
        fetches,
        airtime_us,
        samples.len()
    );

    let _ = write!(h, "<div class=row><div>");
    let _ = write!(h, "<h2>topology.map ⇒ Express</h2>");
    if let Some(m) = scene_view.topology_lens()
        && let Some(r) = scene_view.render(m, scene)
    {
        let _ = write!(h, "{}", r.body);
    }
    let _ = write!(h, "</div><div>");

    let _ = write!(h, "<h2>series.window — the competition</h2>");
    let picked = keel.select_for("series.window", Floor::Approximate);
    let mut offers: Vec<&_> = keel.offers_for("series.window");
    offers.sort_by_key(|m| (m.verdict.rank(), m.verdict.loss_len()));
    for m in offers {
        let is_pick = picked.is_some_and(|p| std::ptr::eq(p, m));
        let Some(Rendered { verdict, body, trace, .. }) = keel.render(m, samples) else { continue };
        let _ = write!(h, "<div class=\"card{}\">", if is_pick { " pick" } else { "" });
        let _ = write!(h, "<div class=v>{verdict:?}{}</div>", if is_pick { " — selected" } else { "" });
        let is_glyphs = matches!(verdict, Verdict::Approximate(_)) && !body.contains('{');
        if body.contains("<svg") {
            let _ = write!(h, "{body}");
        } else if is_glyphs {
            let _ = write!(h, "<pre style=\"font-size:1.4rem\">{body}</pre>");
        } else {
            let head: String = body.chars().take(80).collect();
            let _ = write!(h, "<pre>{head}…</pre>");
        }
        let _ = write!(h, "<pre>{trace}</pre></div>");
    }
    let _ = write!(h, "</div></div>");
    h
}
