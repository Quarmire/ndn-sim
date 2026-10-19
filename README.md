# ndn-sim — the **ndn-lab** simulation / emulation hub

In-process simulation and emulation of **real NDN forwarders**: multi-node networks of actual
[ndn-rs](https://github.com/Quarmire/ndn-rs) `ForwarderEngine`s run on a pluggable time kernel —
from a deterministic discrete-event queue (`DesKernel`, bit-reproducible replay) through a
faster-than-real virtual clock (`VirtualKernel`) to wall-clock and real-time kernels that host
live devices. The engine stays simulation-oblivious behind its `Face` + `Runtime` seams; nothing
is mocked above the link.

The crate is named `ndn-sim`; the tool it builds is **ndn-lab** — a CLI + control plane + MCP
server over one fabric.

## Layout

| Crate | What |
|-------|------|
| [`crates/ndn-sim`](crates/ndn-sim/) | **the core simulator** — kernels, fabric builder, faces, the named-radio face (`RadioBus`), scenarios, validation (`ndn-lab check`), control plane, MCP, bridge, the `ndn-lab` binary. Scenario and check TOMLs live in its `examples/`. |
| [`crates/ndn-sim-studies`](crates/ndn-sim-studies/) | **research studies on top of the core** (depends on `ndn-sim`, never the reverse; `publish = false`) — the in-sim IP plane + routing algorithms + NDN-vs-IP harness, the statistical Wi-Fi MAC, LoRa, the multi-radio PHY reference, the radio / MAC / coding / named-time study examples with their committed dashboards and `data/` CSVs, and the experiment-shaped tests. |

A plain `cargo build` / `cargo test` at the root covers the core only; build the studies with
`-p ndn-sim-studies` or `--workspace`.

## 60-second start

The `ndn-lab` binary is behind the `bin` feature (the library itself never pulls in clap/CLI
deps). From this repo's root:

```sh
# The doorway — subcommands: run / diff / serve / mcp / replay / step / gen / check
cargo run --features bin -p ndn-sim --bin ndn-lab -- --help

# A 3-node line (consumer ── relay ── producer) for 2 virtual seconds — near-instant,
# prints the topology + per-node metrics as JSON
cargo run --features bin -p ndn-sim --bin ndn-lab -- run crates/ndn-sim/examples/line.toml --secs 2

# A CI gate — paths inside a spec resolve relative to the spec file, so this works from any cwd
cargo run --features bin -p ndn-sim --bin ndn-lab -- check crates/ndn-sim/examples/checks/swarm-flight.toml
```

More scenarios live in [`crates/ndn-sim/examples/`](crates/ndn-sim/examples/) (wired `line.toml`,
deterministic `des-line.toml`, shared-medium `radio-mesh.toml`, validation specs under
`examples/checks/`, plus `.rs` examples for the library API).

## What you can do with it

| Doorway | What |
|---------|------|
| **Scenarios** (`ndn-lab run`) | a whole network as one diff-able TOML/JSON artifact — nodes, links, radio media, routes, declarative producer/consumer apps |
| **Generators** (`ndn-lab gen`) | line / ring / star / grid / mesh / tree / random topologies written as ready-to-run scenario TOML |
| **Step debugger** (`ndn-lab step`) | a REPL on the deterministic DES event queue — advance event-by-event, inspect topology/metrics between events |
| **Run diffing** (`ndn-lab run --capture` + `ndn-lab diff`) | capture two runs, then pinpoint and *explain* where they diverge |
| **CI gates** (`ndn-lab check`) | validation specs — scenario + fault schedule + property assertions + probes + seed sweeps + regression baselines; exits non-zero on failure |
| **Control plane** (`ndn-lab serve`) | one declarative JSON command/query surface over TCP + WebSocket JSON-RPC + NDN-native, with record/replay |
| **MCP for agents** (`ndn-lab mcp`) | the whole fabric as Model Context Protocol tools over stdio — an agent builds, inspects, drives, and gates a scenario directly |
| **Rust builder** (library) | `Simulation::new()` → `add_node`/`link`/`add_route` → `start()` → a live `Fabric` handle; see the crate docs |

Beyond the doorways: a spatial world with mobility, a named-radio face over a shared medium with an
802.11 airtime model (monitor vs managed — **logically faithful, not calibrated**: it gets the
relationships right, not measured absolute numbers), co-simulation with external vehicle
simulators, OTLP export, and a UDP bridge for over-the-wire interop with real forwarders
(NFD/ndnd). With the `keel` feature, telemetry also describes itself through render contracts (the
Keel). The IP plane for NDN-vs-IP benchmarks, LoRa and the multi-radio PHY reference live in
`ndn-sim-studies`.

**The real manual** is [`crates/ndn-sim/README.md`](crates/ndn-sim/README.md) and the crate-level
rustdoc in [`crates/ndn-sim/src/lib.rs`](crates/ndn-sim/src/lib.rs) (`cargo doc -p ndn-sim --open`).

## Sibling checkouts required

This repo builds by **path dependencies** on its siblings — check them out next to `ndn-sim/`
under one parent directory:

```
<workspace>/
├── ndn-rs/               # the core: packet, engine, faces, config, security, sync, time, …
├── ndn-ext/              # extensions: pipes, named-time runtime + sources
├── ndn-radio/            # ndn-coding (core tests), ndn-radio-cognition + ndn-strategy-reach (studies)
├── ndn-radio-drivers/    # ndn-frame-io (radio framing foundation, MCS tables)
├── ndn-repo/             # core tests only (dev-dependency)
├── flotilla/             # manifest / render-contract crates — compiled only with `--features keel`
└── ndn-sim/              # this repo
```

### The `keel` feature and `flotilla`

The Keel (self-describing telemetry: `ndn_sim::keel`, `#[derive(Manifest)]` on `FabricGauges` and
the scene types, the `keel-telemetry` / `keel-live` examples) is the off-by-default `keel` feature.
Without it nothing from `flotilla` is compiled or linked — `cargo tree -p ndn-sim -e normal` shows no
flotilla crate. `flotilla` is a private repository, and Cargo still *reads the manifests* of optional
path dependencies when it resolves the workspace, so the `flotilla/` checkout must exist on disk for
`cargo metadata` to succeed even with the feature off.

```sh
cargo build -p ndn-sim                       # core, no flotilla code
cargo run -p ndn-sim --features keel --example keel-telemetry
```

## License

MIT OR Apache-2.0, like the rest of the ndn-rs ecosystem.
