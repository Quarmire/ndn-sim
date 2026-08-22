# ndn-sim — the **ndn-lab** simulation / emulation hub

In-process simulation and emulation of **real NDN forwarders**: multi-node networks of actual
[ndn-rs](https://github.com/Quarmire/ndn-rs) `ForwarderEngine`s run on a pluggable time kernel —
from a deterministic discrete-event queue (`DesKernel`, bit-reproducible replay) through a
faster-than-real virtual clock (`VirtualKernel`) to wall-clock and real-time kernels that host
live devices. The engine stays simulation-oblivious behind its `Face` + `Runtime` seams; nothing
is mocked above the link.

The crate is named `ndn-sim`; the tool it builds is **ndn-lab** — a CLI + control plane + MCP
server over one fabric.

## 60-second start

The `ndn-lab` binary is behind the `bin` feature (the library itself never pulls in clap/CLI
deps). From this repo's root:

```sh
# The doorway — subcommands: run / diff / serve / mcp / replay / step / gen / check
cargo run --features bin -p ndn-sim --bin ndn-lab -- --help

# A 3-node line (consumer ── relay ── producer) for 2 virtual seconds — near-instant,
# prints the topology + per-node metrics as JSON
cargo run --features bin -p ndn-sim --bin ndn-lab -- run crates/ndn-sim/examples/line.toml --secs 2
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

Beyond the doorways: a spatial world with mobility, a faithful 802.11 MAC + pluggable multi-radio
PHY and LoRa, a deterministic in-sim **IP plane** for NDN-vs-IP benchmarks on identical
conditions, self-describing telemetry (the Keel) with OTLP export, co-simulation with external
vehicle simulators, and a UDP bridge for over-the-wire interop with real forwarders (NFD/ndnd).

**The real manual** is [`crates/ndn-sim/README.md`](crates/ndn-sim/README.md) and the crate-level
rustdoc in [`crates/ndn-sim/src/lib.rs`](crates/ndn-sim/src/lib.rs) (`cargo doc -p ndn-sim --open`).

## Sibling checkouts required

This repo builds by **path dependencies** on its siblings — check them out next to `ndn-sim/`
under one parent directory:

```
<workspace>/
├── ndn-rs/               # the core: packet, engine, faces, security, sync, …
├── ndn-ext/              # extensions: named-time runtime, coding, pipes, radio cognition
├── ndn-radio-drivers/    # ndn-frame-io (radio framing foundation)
├── ndn-repo/             # tests only (dev-dependency)
├── flotilla/             # manifest / render-contract crates (the Keel) — currently PRIVATE
└── ndn-sim/              # this repo
```

`flotilla` is a private repository; a feature gate that lets `ndn-sim` build without it is
planned (workspace decision ledger, ruling D7). Until then, all five siblings must be present
for `cargo metadata` to resolve.

## License

MIT OR Apache-2.0, like the rest of the ndn-rs ecosystem.
