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
    ControlPlane, NodeId, Recording, RunningSimulation, Scenario, SimKernel, SimMcp, Simulation,
    VirtualKernel, WallClockKernel,
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
    /// Serve the control plane over TCP + WebSocket (JSON-RPC) + NDN-native control.
    Serve {
        scenario: Option<PathBuf>,
        /// TCP JSON-RPC bind address.
        #[arg(long, default_value = "127.0.0.1:6464")]
        addr: String,
        /// WebSocket bind address (for browser / Dioxus dashboard clients).
        #[arg(long, default_value = "127.0.0.1:6465")]
        ws_addr: String,
    },
    /// Run the MCP server over stdio — point an MCP client (e.g. Claude) at this.
    Mcp { scenario: Option<PathBuf> },
    /// Rebuild the recorded scenario and replay its command journal, then print the topology.
    Replay { recording: PathBuf },
}

fn main() -> Result<()> {
    init_tracing();
    match Cli::parse().command {
        Command::Run { scenario, secs } => cmd_run(scenario, secs),
        Command::Serve { scenario, addr, ws_addr } => {
            runtime()?.block_on(cmd_serve(scenario, addr, ws_addr))
        }
        Command::Mcp { scenario } => runtime()?.block_on(cmd_mcp(scenario)),
        Command::Replay { recording } => runtime()?.block_on(cmd_replay(recording)),
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

    // A `virtual` scenario runs deterministically + faster-than-real on the VirtualKernel;
    // anything else runs at real pace on a wall-clock runtime.
    let (topology, metrics) = if scenario.kernel.is_virtual() {
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

async fn cmd_serve(scenario: Option<PathBuf>, addr: String, ws_addr: String) -> Result<()> {
    let scenario = scenario.as_ref().map(read_scenario).transpose()?;
    let fabric = Arc::new(build_fabric(scenario, Arc::new(WallClockKernel::new())).await?);
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
    eprintln!("ndn-lab: {} node(s) up — Ctrl-C to stop", fabric.nodes());

    tokio::signal::ctrl_c().await?;
    eprintln!("ndn-lab: shutting down");
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
