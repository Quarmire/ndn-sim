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
    Scenario, SimKernel, SimMcp, Simulation, ValidationSpec, VirtualKernel, WallClockKernel,
    run_validation, run_validation_against,
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
    },
    /// Run the MCP server over stdio — point an MCP client (e.g. Claude) at this.
    Mcp { scenario: Option<PathBuf> },
    /// Rebuild the recorded scenario and replay its command journal, then print the topology.
    Replay { recording: PathBuf },
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
        Command::Run { scenario, secs } => cmd_run(scenario, secs),
        Command::Serve { scenario, addr, ws_addr, mavlink, launch, base_sysid } => {
            runtime()?.block_on(cmd_serve(scenario, addr, ws_addr, mavlink, launch, base_sysid))
        }
        Command::Mcp { scenario } => runtime()?.block_on(cmd_mcp(scenario)),
        Command::Replay { recording } => runtime()?.block_on(cmd_replay(recording)),
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

fn cmd_run(path: PathBuf, secs: u64) -> Result<()> {
    let scenario = read_scenario(&path)?;
    let dur = Duration::from_secs(secs);

    // A `virtual` scenario runs deterministically + faster-than-real on the VirtualKernel; a `des`
    // scenario runs on ndn-lab's own discrete-event executor (deterministic, no tokio clock);
    // anything else runs at real pace on a wall-clock runtime.
    let (topology, metrics) = if scenario.kernel.is_des() {
        let kernel = match scenario.kernel {
            KernelSpec::Des { epoch_ns: Some(ns) } => DesKernel::with_epoch_ns(ns),
            _ => DesKernel::new(),
        };
        kernel.run(move |k| async move {
            let fabric = scenario.build(k)?.start().await?;
            // Ambient-aware sleep advances the DES virtual clock (tokio::time would never fire here).
            ndn_app::rt::sleep(dur).await;
            let out = (fabric.topology(), fabric.snapshot_metrics());
            fabric.shutdown().await;
            anyhow::Ok(out)
        })?
    } else if scenario.kernel.is_virtual() {
        VirtualKernel::new().run(|k| async move {
            let fabric = scenario.build(k)?.start().await?;
            tokio::time::sleep(dur).await;
            let out = (fabric.topology(), fabric.snapshot_metrics());
            fabric.shutdown().await;
            anyhow::Ok(out)
        })?
    } else {
        runtime()?.block_on(async move {
            let fabric = build_fabric(Some(scenario), Arc::new(WallClockKernel::new())).await?;
            tokio::time::sleep(dur).await;
            let out = (fabric.topology(), fabric.snapshot_metrics());
            fabric.shutdown().await;
            anyhow::Ok(out)
        })?
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "topology": topology,
            "metrics": metrics,
        }))?
    );
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

async fn cmd_serve(
    scenario: Option<PathBuf>,
    addr: String,
    ws_addr: String,
    mavlink: Option<String>,
    launch: Option<String>,
    base_sysid: u8,
) -> Result<()> {
    let scenario = scenario.as_ref().map(read_scenario).transpose()?;
    // Live co-sim rides the real-time governor (clock mode B); plain control uses wall-clock.
    let kernel: Arc<dyn SimKernel> = if mavlink.is_some() {
        RealTimeKernel::new()
    } else {
        Arc::new(WallClockKernel::new())
    };
    let fabric = Arc::new(build_fabric(scenario, kernel).await?);
    let control = ControlPlane::new(Arc::clone(&fabric));

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

    eprintln!("ndn-lab: {} node(s) up — Ctrl-C to stop", fabric.nodes());
    tokio::signal::ctrl_c().await?;
    eprintln!("ndn-lab: shutting down");
    drive_cancel.cancel();
    if let Some(mut c) = child {
        let _ = c.kill();
    }
    fabric.shutdown().await;
    Ok(())
}

async fn cmd_mcp(scenario: Option<PathBuf>) -> Result<()> {
    let scenario = scenario.as_ref().map(read_scenario).transpose()?;
    let fabric = Arc::new(build_fabric(scenario, Arc::new(WallClockKernel::new())).await?);
    let control = ControlPlane::new(Arc::clone(&fabric));
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
