# ndn-sim — the **ndn-lab** fabric

An in-process NDN network **simulation / emulation hub** (product name: *ndn-lab*). It runs
multi-node networks of *real* `ForwarderEngine`s on a pluggable time kernel, with a spatial world,
a named-radio face, one control + telemetry API, an MCP server, and a UDP bridge to real
forwarders — all behind the `Face` + `Runtime` seams, so the engine stays simulation-oblivious.

## The `ndn-lab` binary (the doorway)

```
cargo build -p ndn-sim --features bin

ndn-lab run   examples/line.toml --secs 2   # build + run, print topology + metrics (JSON)
ndn-lab serve examples/line.toml            # control plane over TCP JSON-RPC + NDN-native
ndn-lab mcp   [scenario.toml]               # MCP server over stdio (point Claude at it)
ndn-lab replay recording.json               # rebuild + replay a recorded session
```

`ndn-lab mcp` exposes the whole fabric to an MCP client (12 tools + a capability catalogue):
`spawn_node` / `connect` / `route` / `move_node` / `spawn_app` / `describe_topology` /
`query_metrics` / `why_did` / … — a model can compose and inspect a scenario directly.

## What's inside

| Piece | What |
|-------|------|
| **Kernels** | `WallClockKernel` (real time), `VirtualKernel` (deterministic, faster-than-real, bit-reproducible), `RealTimeKernel` (governor: real pace + logical clock, hosts real devices), `SteppableKernel` (pause / step / run-until) |
| **World** | `Position` + `MobilityModel` (static/linear/waypoint) + `Environment`, `WorldView` snapshots over a uniform spatial grid |
| **Medium / radio** | `WirelessMedium` (propagation + range) and `RadioBus` + `SimRadioFace` — the named-radio face with RSSI→MCS→per-frame delivery (`LinkModel`) + carrier-sense collisions |
| **Faces** | per-type behavioral catalogue (`FaceProfile`: udp/tcp/quic/ws/ethernet/multicast/shm/serial/ble/nan) — the engine sees each type's `FaceKind`/MTU/loss/ordering |
| **Control plane** | one declarative API (`SimCommand`/`SimQuery`) over three transports: in-proc, TCP JSON-RPC, and NDN-native `/localhop/sim/control` + a notification stream |
| **Apps** | declarative producers/consumers (`AppSpec`) — "a producer of /foo here, a consumer there" |
| **Scenarios** | a whole sim as one diff-able TOML/JSON artifact (`Scenario`) |
| **Record / replay** | journal live commands (`Recording`) → replay a session deterministically |
| **Telemetry** | Runtime-clocked metric gauges + OTLP spans; engine tracing captured on the virtual clock (`SpanLog`, causal `why_did`); OTLP/HTTP export |
| **GUI seam** | `SceneSnapshot` (`world_snapshot()`) + SVG renderers — headless; a GUI is a client of the control API |
| **Bridge** | real UDP faces on a node → external device / NFD / **ndnd** interop (validated over the wire) |
| **MCP** | `SimMcp` — MCP tools projecting the control plane + telemetry |

## Library quick start

```rust
use ndn_sim::{Simulation, LinkConfig};
use ndn_engine::builder::EngineConfig;

// async context:
let mut sim = Simulation::new();                 // default WallClockKernel
let a = sim.add_node(EngineConfig::default());
let b = sim.add_node(EngineConfig::default());
sim.link(a, b, LinkConfig::lan());
sim.add_route(a, "/prefix", b);
let fabric = sim.start().await?;
// interact via fabric.engine_of(a); live ops via the ControlPlane / MCP
fabric.shutdown().await;
```

Deterministic (bit-reproducible) runs go through the `VirtualKernel`; see `tests/determinism.rs`
for the replay gate. Design + roadmap:
`.claude/notes/sim-framework-design-v2-2026-06-24.md`.
