//! `ndn-lab` — the doorway into the fabric.
//!
//! The library builds the whole simulation/emulation hub; this binary is the thin CLI that lets
//! you actually drive it: run a scenario, serve the control plane over TCP JSON-RPC, expose the
//! MCP server over stdio (so a model can build + inspect sims), or replay a recording.
//!
//!   ndn-lab run   scenario.toml [--secs N]     # build + run, print topology + metrics
//!   ndn-lab serve [scenario.toml] [--addr A]   # control plane over TCP JSON-RPC (+ NDN-native)
//!   ndn-lab mcp   [scenario.toml]              # MCP server over stdio
//!   ndn-lab replay recording.json             # rebuild + replay a recorded session
//!
//! Built with `--features bin`. Logs go to stderr (stdout is data / the MCP channel).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use ndn_sim::{
    ControlPlane, DesKernel, KernelSpec, NodeId, RealTimeKernel, Recording, RunningSimulation,
    Scenario, SimKernel, SimMcp, Simulation, Stepper, ValidationSpec, VirtualKernel, WallClockKernel,
    run_validation, run_validation_against, topo,
};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(name = "ndn-lab", version, about = "NDN network simulation / emulation hub")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build a scenario, run it for a while, and print its topology + metrics as JSON.
    Run {
        scenario: PathBuf,
        /// Seconds to run (virtual seconds under a `virtual` kernel — near-instant).
        #[arg(long, default_value_t = 5)]
        secs: u64,
        /// Also write a diff-able run capture (metrics + radio evidence + app successes) here.
        #[arg(long)]
        capture: Option<PathBuf>,
    },
    /// Diff two run captures (from `run --capture`) and explain where they diverge (axis 4b).
    Diff {
        a: PathBuf,
        b: PathBuf,
        /// Emit the full structured diff as JSON instead of the human summary.
        #[arg(long)]
        json: bool,
    },
    /// Serve the control plane over TCP + WebSocket (JSON-RPC) + NDN-native control. With
    /// `--mavlink`, this is the unified live co-sim session: poses stream IN and `Cosim` commands
    /// fly the swarm OUT — one surface for the network and the vehicles (needs the `mavlink` feature).
    Serve {
        scenario: Option<PathBuf>,
        /// TCP JSON-RPC bind address.
        #[arg(long, default_value = "127.0.0.1:6464")]
        addr: String,
        /// WebSocket bind address (for browser / Dioxus dashboard clients).
        #[arg(long, default_value = "127.0.0.1:6465")]
        ws_addr: String,
        /// Live MAVLink endpoint (e.g. `udpin:0.0.0.0:14550`): stream vehicle positions in AND
        /// enable `Cosim` actuation out. Turns `serve` into the bidirectional single-pane session.
        #[arg(long)]
        mavlink: Option<String>,
        /// A shell command that launches the external simulator (e.g. an ArduPilot SITL invocation).
        /// ndn-lab spawns and supervises it, so the whole loop is one command.
        #[arg(long)]
        launch: Option<String>,
        /// MAVLink system id that maps to node 0.
        #[arg(long, default_value_t = 1)]
        base_sysid: u8,
        /// Emit a live telemetry frame every N ms (a subscribable stream + OTLP export). 0 = off.
        #[arg(long, default_value_t = 0)]
        telemetry_ms: u64,
        /// Export live telemetry to an OTLP/HTTP collector at `host:port` (e.g. 127.0.0.1:4318 —
        /// Grafana / Jaeger / Prometheus-OTLP). Implies a 1 s telemetry tick if `--telemetry-ms` is 0.
        #[arg(long)]
        otlp: Option<String>,
        /// Transport-agnostic mobility feed: bind a UDP socket at `host:port` and drive node
        /// positions from JSON NodeStates (what a Gazebo / Bevy / any-sim bridge writes). Read-only.
        #[arg(long)]
        feed: Option<String>,
        /// Journal every mutating command (with its virtual timestamp) and write the recording
        /// (JSON) to this file on shutdown — replay it later with `ndn-lab replay`.
        #[arg(long)]
        record: Option<PathBuf>,
        /// Require signed Interests for mutating commands over NDN control. Opens (or creates) a
        /// KeyChain PIB at this path and trusts it; unsigned or untrusted NDN commands are rejected.
        /// Read-only queries stay open. The loopback TCP/WS transports are unaffected.
        #[arg(long)]
        require_signed: Option<PathBuf>,
    },
    /// Run the MCP server over stdio — point an MCP client (e.g. Claude) at this.
    Mcp { scenario: Option<PathBuf> },
    /// Rebuild the recorded scenario and replay its command journal, then print the topology.
    Replay { recording: PathBuf },
    /// Interactively step a scenario on the deterministic DES event queue: pause between events,
    /// inspect the topology / metrics / positions, and continue. Reads commands from stdin
    /// (step/run/until/topo/metrics/where/help/quit) — the deterministic debugger surface.
    Step { scenario: PathBuf },
    /// Generate a topology (line/ring/star/grid/mesh/tree/random) as a scenario TOML — build a
    /// 50-node grid without hand-authoring it. Writes to stdout, or a file with `-o`.
    Gen {
        /// line | ring | star | grid | mesh | tree | random
        shape: String,
        /// Node count (line/ring/star/mesh/random).
        #[arg(long)]
        n: Option<usize>,
        /// Grid rows.
        #[arg(long)]
        rows: Option<usize>,
        /// Grid columns.
        #[arg(long)]
        cols: Option<usize>,
        /// Tree branching factor.
        #[arg(long)]
        branching: Option<usize>,
        /// Tree depth.
        #[arg(long)]
        depth: Option<usize>,
        /// Random edge probability (0..1).
        #[arg(long)]
        prob: Option<f64>,
        /// PRNG seed for `random` (same seed → same graph).
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Install shortest-path routes for a prefix toward a node, e.g. `--toward /demo@0`.
        #[arg(long)]
        toward: Option<String>,
        /// Write the scenario TOML here (default: stdout).
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Run a validation spec (scenario + fault schedule + property assertions) headless and report
    /// pass/fail. Exits non-zero on failure — drop it straight into CI.
    Check {
        spec: PathBuf,
        /// Emit the full report as JSON instead of the human summary.
        #[arg(long)]
        json: bool,
        /// Gate the run against a recorded baseline file (fails on a regression beyond tolerance).
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Run the spec and WRITE its measured baseline values to this file (then exit on the
        /// property verdict). Use this to capture/refresh a baseline.
        #[arg(long)]
        record_baseline: Option<PathBuf>,
    },
    /// Fly a live ArduPilot SITL (MAVLink) co-simulation: stream vehicle positions into the World on
    /// the real-time governor, run NDN over the moving swarm, and record a MobilityTrace for
    /// deterministic replay (`ndn-lab run`/`check` a scenario with `mobility_trace = "..."`).
    #[cfg(feature = "mavlink")]
    Fly {
        scenario: PathBuf,
        /// MAVLink endpoint to listen on (SITL streams telemetry to a GCS port).
        #[arg(long, default_value = "udpin:0.0.0.0:14550")]
        mavlink: String,
        /// Write the recorded MobilityTrace JSON here.
        #[arg(long)]
        record: Option<PathBuf>,
        /// The MAVLink system id that maps to node 0 (ArduPilot vehicles usually start at 1).
        #[arg(long, default_value_t = 1)]
        base_sysid: u8,
        /// Stop after this many seconds (default: run until Ctrl-C).
        #[arg(long)]
        secs: Option<u64>,
        /// ENU origin latitude (deg). Omit to adopt the first vehicle fix as the origin.
        #[arg(long, requires = "ref_lon")]
        ref_lat: Option<f64>,
        /// ENU origin longitude (deg).
        #[arg(long)]
        ref_lon: Option<f64>,
        /// ENU origin altitude (m MSL).
        #[arg(long, default_value_t = 0.0)]
        ref_alt: f64,
    },
}

fn main() -> Result<()> {
    init_tracing();
    match Cli::parse().command {
        Command::Run { scenario, secs, capture } => cmd_run(scenario, secs, capture),
        Command::Diff { a, b, json } => cmd_diff(a, b, json),
        Command::Serve {
            scenario,
            addr,
            ws_addr,
            mavlink,
            launch,
            base_sysid,
            telemetry_ms,
            otlp,
            feed,
            record,
            require_signed,
        } => runtime()?.block_on(cmd_serve(
            scenario, addr, ws_addr, mavlink, launch, base_sysid, telemetry_ms, otlp, feed, record,
            require_signed,
        )),
        Command::Mcp { scenario } => runtime()?.block_on(cmd_mcp(scenario)),
        Command::Replay { recording } => runtime()?.block_on(cmd_replay(recording)),
        Command::Step { scenario } => cmd_step(scenario),
        Command::Gen { shape, n, rows, cols, branching, depth, prob, seed, toward, out } => {
            cmd_gen(shape, n, rows, cols, branching, depth, prob, seed, toward, out)
        }
        Command::Check { spec, json, baseline, record_baseline } => {
            cmd_check(spec, json, baseline, record_baseline)
        }
        #[cfg(feature = "mavlink")]
        Command::Fly { scenario, mavlink, record, base_sysid, secs, ref_lat, ref_lon, ref_alt } => {
            runtime()?.block_on(cmd_fly(
                scenario, mavlink, record, base_sysid, secs, ref_lat, ref_lon, ref_alt,
            ))
        }
    }
}

/// A multi-thread Tokio runtime for the real-time (wall-clock) subcommands.
fn runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Runtime::new()?)
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = fmt().with_writer(std::io::stderr).with_env_filter(filter).try_init();
}

fn read_scenario(path: &PathBuf) -> Result<Scenario> {
    Scenario::from_toml(&std::fs::read_to_string(path)?)
}

/// Build a fabric from an optional scenario on `kernel`.
async fn build_fabric(
    scenario: Option<Scenario>,
    kernel: Arc<dyn SimKernel>,
) -> Result<RunningSimulation> {
    Ok(match scenario {
        Some(s) => s.build(kernel)?.start().await?,
        None => Simulation::new().kernel(kernel).start().await?,
    })
}

fn cmd_run(path: PathBuf, secs: u64, capture: Option<PathBuf>) -> Result<()> {
    let scenario = read_scenario(&path)?;
    let dur = Duration::from_secs(secs);

    // A `virtual` scenario runs deterministically + faster-than-real on the VirtualKernel; a `des`
    // scenario runs on ndn-lab's own discrete-event executor (deterministic, no tokio clock);
    // anything else runs at real pace on a wall-clock runtime. Each branch also captures radio
    // evidence so `--capture` produces a diff-able RunCapture (axis 4b).
    let (topology, metrics, run_capture) = if scenario.kernel.is_des() {
        let kernel = match scenario.kernel {
            KernelSpec::Des { epoch_ns: Some(ns) } => DesKernel::with_epoch_ns(ns),
            _ => DesKernel::new(),
        };
        kernel.run(move |k| async move {
            let fabric = scenario.build(k)?.start().await?;
            let radio = fabric.capture_radio();
            ndn_app::rt::sleep(dur).await;
            let out = (fabric.topology(), fabric.snapshot_metrics(), fabric.capture_run(radio.as_deref()));
            fabric.shutdown().await;
            anyhow::Ok(out)
        })?
    } else if scenario.kernel.is_virtual() {
        VirtualKernel::new().run(|k| async move {
            let fabric = scenario.build(k)?.start().await?;
            let radio = fabric.capture_radio();
            tokio::time::sleep(dur).await;
            let out = (fabric.topology(), fabric.snapshot_metrics(), fabric.capture_run(radio.as_deref()));
            fabric.shutdown().await;
            anyhow::Ok(out)
        })?
    } else {
        runtime()?.block_on(async move {
            let fabric = build_fabric(Some(scenario), Arc::new(WallClockKernel::new())).await?;
            let radio = fabric.capture_radio();
            tokio::time::sleep(dur).await;
            let out = (fabric.topology(), fabric.snapshot_metrics(), fabric.capture_run(radio.as_deref()));
            fabric.shutdown().await;
            anyhow::Ok(out)
        })?
    };

    if let Some(out) = capture {
        std::fs::write(&out, run_capture.to_json()?)?;
        eprintln!("ndn-lab: wrote run capture → {}", out.display());
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "topology": topology,
            "metrics": metrics,
        }))?
    );
    Ok(())
}

/// Diff two run captures (`ndn-lab run --capture …`) and explain where they diverge.
fn cmd_diff(a: PathBuf, b: PathBuf, json: bool) -> Result<()> {
    let base = ndn_sim::RunCapture::from_json(&std::fs::read_to_string(&a)?)?;
    let cand = ndn_sim::RunCapture::from_json(&std::fs::read_to_string(&b)?)?;
    let diff = ndn_sim::diff_runs(&base, &cand, 0.05);
    if json {
        println!("{}", serde_json::to_string_pretty(&diff)?);
    } else {
        println!("{} vs {}\n{}", a.display(), b.display(), diff.summary);
    }
    Ok(())
}

fn cmd_check(
    path: PathBuf,
    json: bool,
    baseline: Option<PathBuf>,
    record_baseline: Option<PathBuf>,
) -> Result<()> {
    let spec = ValidationSpec::from_toml(&std::fs::read_to_string(&path)?)?;
    let report = match &baseline {
        Some(bpath) => {
            let base = ndn_sim::Baseline::from_json(&std::fs::read_to_string(bpath)?)?;
            run_validation_against(&spec, &base)?
        }
        None => run_validation(&spec)?,
    };
    if let Some(out) = &record_baseline {
        std::fs::write(out, report.measured_baseline.to_json()?)?;
        eprintln!("recorded baseline → {}", out.display());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", report.summary());
    }
    if !report.passed {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(feature = "mavlink")]
#[allow(clippy::too_many_arguments)]
async fn cmd_fly(
    path: PathBuf,
    endpoint: String,
    record: Option<PathBuf>,
    base_sysid: u8,
    secs: Option<u64>,
    ref_lat: Option<f64>,
    ref_lon: Option<f64>,
    ref_alt: f64,
) -> Result<()> {
    use ndn_sim::mavlink::{GeoRef, MavlinkConfig, mavlink_source};

    let scenario = read_scenario(&path)?;
    // The real-time governor: real pace so a live autopilot feed lines up (clock mode B).
    let fabric = Arc::new(build_fabric(Some(scenario), RealTimeKernel::new()).await?);
    let reference = match (ref_lat, ref_lon) {
        (Some(lat_deg), Some(lon_deg)) => Some(GeoRef { lat_deg, lon_deg, alt_m: ref_alt }),
        _ => None,
    };
    let cfg = MavlinkConfig {
        endpoint: endpoint.clone(),
        reference,
        base_sysid,
        node_count: fabric.nodes(),
    };
    let (source, _reader) = mavlink_source(cfg)?;
    eprintln!(
        "ndn-lab: flying — MAVLink {endpoint}, {} node(s); {}",
        fabric.nodes(),
        match secs {
            Some(s) => format!("stopping in {s}s"),
            None => "Ctrl-C to stop".to_string(),
        }
    );

    let cancel = CancellationToken::new();
    let stopper = cancel.clone();
    tokio::spawn(async move {
        match secs {
            Some(s) => tokio::time::sleep(Duration::from_secs(s)).await,
            None => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        stopper.cancel();
    });

    let trace = fabric
        .drive_mobility(Box::new(source), Duration::from_millis(50), cancel)
        .await;
    fabric.shutdown().await;
    eprintln!(
        "ndn-lab: captured {} state(s) across {} node(s)",
        trace.states.len(),
        trace.into_models().len()
    );
    if let Some(rec) = record {
        std::fs::write(&rec, trace.to_json()?)?;
        eprintln!("ndn-lab: wrote trace → {}", rec.display());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_serve(
    scenario: Option<PathBuf>,
    addr: String,
    ws_addr: String,
    mavlink: Option<String>,
    launch: Option<String>,
    base_sysid: u8,
    telemetry_ms: u64,
    otlp: Option<String>,
    feed: Option<String>,
    record: Option<PathBuf>,
    require_signed: Option<PathBuf>,
) -> Result<()> {
    let scenario = scenario.as_ref().map(read_scenario).transpose()?;
    // Live co-sim rides the real-time governor (clock mode B); plain control uses wall-clock.
    let kernel: Arc<dyn SimKernel> = if mavlink.is_some() || feed.is_some() {
        RealTimeKernel::new()
    } else {
        Arc::new(WallClockKernel::new())
    };
    let fabric = Arc::new(build_fabric(scenario, kernel).await?);
    let control = ControlPlane::new(Arc::clone(&fabric));
    // Causal capture (axis 4): record radio delivery decisions so `explain` can answer "why".
    control.enable_radio_capture();

    // Require signed Interests on the NDN control surface (authenticated actuation).
    if let Some(ref path) = require_signed {
        let kc = ndn_security::KeyChain::open_or_create(path, "/ndn-lab/control")
            .map_err(|e| anyhow::anyhow!("open control keychain {path:?}: {e}"))?;
        eprintln!("ndn-lab: NDN control requires signed Interests (trust {})", kc.name());
        control.require_signed_control(Arc::new(kc.validator()));
    }

    // Journal every command so the session can be replayed deterministically.
    if record.is_some() {
        control.start_recording();
    }

    // Live telemetry (axis 4c): stream metric frames + optionally export to an OTLP collector.
    if telemetry_ms > 0 || otlp.is_some() {
        let interval = Duration::from_millis(if telemetry_ms > 0 { telemetry_ms } else { 1000 });
        control.spawn_telemetry(interval, otlp.clone());
        eprintln!(
            "ndn-lab: live telemetry every {}ms{}",
            interval.as_millis(),
            otlp.map(|a| format!(" → OTLP {a}")).unwrap_or_default()
        );
    }

    let bound = control.serve_tcp(&addr, CancellationToken::new()).await?;
    eprintln!("ndn-lab: control plane (JSON-RPC) on tcp://{bound}");
    let ws_bound = control.serve_ws(&ws_addr, CancellationToken::new()).await?;
    eprintln!("ndn-lab: control plane (JSON-RPC) on ws://{ws_bound}");

    // Also expose NDN-native control on node 0, if the fabric has one.
    if let Some(engine) = fabric.engine_of(NodeId(0)) {
        control.serve_ndn(&engine, CancellationToken::new());
        eprintln!("ndn-lab: NDN-native control on /localhop/sim/control (node 0)");
    }

    // Live bidirectional co-sim: launch the external sim, stream positions in, actuate out.
    let drive_cancel = CancellationToken::new();
    #[allow(unused_mut)]
    let mut child: Option<std::process::Child> = None;
    if let Some(endpoint) = mavlink {
        #[cfg(feature = "mavlink")]
        {
            use anyhow::Context;
            if let Some(cmd) = launch {
                eprintln!("ndn-lab: launching external sim: {cmd}");
                child = Some(
                    std::process::Command::new("sh")
                        .arg("-c")
                        .arg(&cmd)
                        .spawn()
                        .with_context(|| format!("launch external sim: {cmd}"))?,
                );
            }
            eprintln!("ndn-lab: live co-sim on MAVLink {endpoint} — Cosim commands fly the swarm");
            let (source, reader, actuator) = ndn_sim::mavlink::mavlink_link(
                ndn_sim::mavlink::MavlinkConfig {
                    endpoint,
                    reference: None,
                    base_sysid,
                    node_count: fabric.nodes(),
                },
            )?;
            control.set_actuator(std::sync::Arc::new(actuator));
            let df = Arc::clone(&fabric);
            let dc = drive_cancel.clone();
            tokio::spawn(async move {
                let _reader = reader; // keep the reader thread alive for the session
                df.drive_mobility(Box::new(source), Duration::from_millis(50), dc).await;
            });
        }
        #[cfg(not(feature = "mavlink"))]
        {
            let _ = (endpoint, launch, base_sysid);
            anyhow::bail!("--mavlink needs a build with `--features mavlink`");
        }
    }

    // A transport-agnostic JSON mobility feed (a Gazebo / Bevy / any-sim bridge writes to it).
    if let Some(endpoint) = feed {
        eprintln!("ndn-lab: JSON mobility feed on udp://{endpoint}");
        let (source, reader) = ndn_sim::udp_json_feed(&endpoint)?;
        let df = Arc::clone(&fabric);
        let dc = drive_cancel.clone();
        tokio::spawn(async move {
            let _reader = reader; // keep the feed thread alive for the session
            df.drive_mobility(Box::new(source), Duration::from_millis(50), dc).await;
        });
    }

    eprintln!("ndn-lab: {} node(s) up — Ctrl-C to stop", fabric.nodes());
    tokio::signal::ctrl_c().await?;
    eprintln!("ndn-lab: shutting down");
    drive_cancel.cancel();
    if let Some(mut c) = child {
        let _ = c.kill();
    }
    // Persist the session recording (if journaling was on) before tearing the fabric down.
    if let Some(path) = record {
        std::fs::write(&path, control.recording().to_json()?)?;
        eprintln!("ndn-lab: recording written to {path:?} — replay with `ndn-lab replay {}`", path.display());
    }
    fabric.shutdown().await;
    Ok(())
}

async fn cmd_mcp(scenario: Option<PathBuf>) -> Result<()> {
    let scenario = scenario.as_ref().map(read_scenario).transpose()?;
    let fabric = Arc::new(build_fabric(scenario, Arc::new(WallClockKernel::new())).await?);
    let control = ControlPlane::new(Arc::clone(&fabric));
    control.enable_radio_capture(); // so `explain_link` has evidence
    eprintln!("ndn-lab: MCP server on stdio ({} node(s))", fabric.nodes());
    SimMcp::new(control).serve_stdio().await?;
    fabric.shutdown().await;
    Ok(())
}

async fn cmd_replay(path: PathBuf) -> Result<()> {
    let recording = Recording::from_json(&std::fs::read_to_string(&path)?)?;
    let kernel: Arc<dyn SimKernel> = Arc::new(WallClockKernel::new());
    let fabric = Arc::new(build_fabric(recording.scenario.clone(), kernel).await?);
    let control = ControlPlane::new(Arc::clone(&fabric));

    recording.replay(&control, false).await?;
    eprintln!("ndn-lab: replayed {} command(s)", recording.len());
    println!("{}", serde_json::to_string_pretty(&fabric.topology())?);

    fabric.shutdown().await;
    Ok(())
}

/// Interactive DES stepping REPL (reads commands from stdin, deterministic + reproducible).
fn cmd_step(path: PathBuf) -> Result<()> {
    use std::io::BufRead;

    let scenario = read_scenario(&path)?;
    if !scenario.kernel.is_des() {
        eprintln!("ndn-lab: interactive stepping forces the DES kernel (the scenario's kernel is ignored)");
    }
    let stepper = Stepper::build(DesKernel::new(), scenario)?;
    println!(
        "ndn-lab step: {} node(s) on the DES event queue. Type 'help' for commands, 'quit' to exit.",
        stepper.fabric().topology().nodes.len()
    );
    print_clock(&stepper);

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        let mut parts = line.split_whitespace();
        let Some(cmd) = parts.next() else {
            print_clock(&stepper);
            continue;
        };
        let arg = parts.next();
        match cmd {
            "step" | "s" => {
                let n: u64 = arg.and_then(|a| a.parse().ok()).unwrap_or(1);
                for _ in 0..n {
                    stepper.step();
                }
                print_clock(&stepper);
            }
            "run" | "r" => {
                let ms: u64 = arg.and_then(|a| a.parse().ok()).unwrap_or(100);
                stepper.run_for_ms(ms);
                print_clock(&stepper);
            }
            "until" | "u" => {
                if let Some(ms) = arg.and_then(|a| a.parse::<u64>().ok()) {
                    stepper.run_until_ms(ms);
                } else {
                    println!("usage: until <ms-since-start>");
                }
                print_clock(&stepper);
            }
            "topo" | "t" => {
                println!("{}", serde_json::to_string_pretty(&stepper.fabric().topology())?);
            }
            "metrics" | "m" => {
                println!("{}", serde_json::to_string_pretty(&stepper.fabric().snapshot_metrics())?);
            }
            "where" | "w" => {
                for node in &stepper.fabric().scene_snapshot().nodes {
                    println!("  n{} @ ({:.1}, {:.1})", node.id, node.x, node.y);
                }
            }
            "help" | "h" | "?" => print_step_help(),
            "quit" | "q" => break,
            other => println!("unknown command '{other}' — try 'help'"),
        }
    }
    Ok(())
}

fn print_clock(stepper: &Stepper) {
    println!("t = {} ms (virtual)", stepper.elapsed_ms());
}

fn print_step_help() {
    println!(
        "commands:\n  \
         step [n]     advance n events (default 1)\n  \
         run  [ms]    advance ms of virtual time (default 100)\n  \
         until <ms>   advance to ms since start\n  \
         topo         print the topology (JSON)\n  \
         metrics      print per-node metrics (JSON)\n  \
         where        print node positions\n  \
         help | quit"
    );
}

/// Generate a topology and emit it as a scenario TOML.
#[allow(clippy::too_many_arguments)]
fn cmd_gen(
    shape: String,
    n: Option<usize>,
    rows: Option<usize>,
    cols: Option<usize>,
    branching: Option<usize>,
    depth: Option<usize>,
    prob: Option<f64>,
    seed: u64,
    toward: Option<String>,
    out: Option<PathBuf>,
) -> Result<()> {
    use anyhow::Context;

    let mut scenario = match shape.as_str() {
        "line" => topo::line(n.unwrap_or(3)),
        "ring" => topo::ring(n.unwrap_or(4)),
        "star" => topo::star(n.unwrap_or(5)),
        "grid" => topo::grid(rows.unwrap_or(3), cols.unwrap_or(3)),
        "mesh" | "full_mesh" => topo::full_mesh(n.unwrap_or(5)),
        "tree" => topo::tree(branching.unwrap_or(2), depth.unwrap_or(3)),
        "random" => topo::random(n.unwrap_or(20), prob.unwrap_or(0.15), seed),
        other => {
            anyhow::bail!("unknown shape '{other}' (line|ring|star|grid|mesh|tree|random)")
        }
    };
    if let Some(spec) = toward {
        let (prefix, dest) = spec
            .rsplit_once('@')
            .context("--toward must be PREFIX@NODE, e.g. /demo@0")?;
        let dest: usize = dest.parse().context("--toward node index")?;
        topo::add_routes_toward(&mut scenario, prefix, dest);
    }
    let toml = scenario.to_toml()?;
    match out {
        Some(path) => {
            std::fs::write(&path, &toml)?;
            eprintln!(
                "ndn-lab: wrote {} node(s) / {} link(s) / {} route(s) to {path:?}",
                scenario.nodes.len(),
                scenario.links.len(),
                scenario.routes.len()
            );
        }
        None => print!("{toml}"),
    }
    Ok(())
}
