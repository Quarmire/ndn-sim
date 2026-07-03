# ndn-sim — the **ndn-lab** fabric

An in-process NDN network **simulation / emulation hub** (product name: *ndn-lab*). It runs
multi-node networks of *real* `ForwarderEngine`s on a pluggable time kernel, with a spatial world,
a named-radio face, one control + telemetry API, an MCP server, and a UDP bridge to real
forwarders — all behind the `Face` + `Runtime` seams, so the engine stays simulation-oblivious.

## The four capability axes

1. **Executor-agnostic core** — from a deterministic discrete-event queue (`DesKernel`,
   bit-reproducible replay) through the tokio paused-clock `VirtualKernel` to real-time
   (`RealTimeKernel`, hosts live devices).
2. **Validation platform** — `ValidationSpec` = scenario + fault schedule + property assertions +
   seed sweeps + regression baselines; `ndn-lab check` is a headless CI gate.
3. **Pluggable backends + co-simulation** — external simulators (ArduPilot SITL / Gazebo / Bevy)
   drive node motion; `cosim` commands actuate them back (bidirectional, NDN-native).
4. **Observability / analysis** — causal "why" over radio delivery (`explain_link`), cross-run diff
   (`diff_runs`), live telemetry streaming + OTLP/Jaeger export.

## The `ndn-lab` binary (the doorway)

```
cargo build -p ndn-sim --features bin           # add ,mavlink for ArduPilot SITL co-sim

ndn-lab run   examples/line.toml --secs 2       # build + run, print topology + metrics (JSON)
ndn-lab run   examples/line.toml --capture a.json   # capture a run for diffing
ndn-lab diff  a.json b.json                     # pinpoint + explain where two runs diverge
ndn-lab check examples/checks/line-convergence.toml # validate (faults + properties); CI-ready, exits non-zero on fail
ndn-lab gen   grid --rows 4 --cols 5 -o grid.toml   # generate a topology (line/ring/star/grid/mesh/tree/random)
ndn-lab step  examples/des-line.toml            # interactively step the DES event queue (deterministic debugger)
ndn-lab serve examples/line.toml                # control plane: TCP + WebSocket JSON-RPC + NDN-native
ndn-lab mcp   [scenario.toml]                   # MCP server over stdio (point Claude at it)
ndn-lab replay recording.json                   # rebuild + replay a recorded session
```

`ndn-lab gen <shape>` writes a ready-to-run scenario (add `--toward /demo@0` for shortest-path
routes toward a producer). `ndn-lab step <scenario>` opens a REPL on the deterministic DES event
queue — `step [n]` / `run [ms]` / `until <ms>` advance the clock event-by-event, `topo` / `metrics`
/ `where` inspect between events; fully reproducible.

`ndn-lab serve` extras: `--mavlink <ep>` (+ `--launch`) for the live bidirectional co-sim session,
`--feed <host:port>` for a JSON mobility feed, `--telemetry-ms`/`--otlp` for live/OTLP telemetry,
`--record <file>` to journal the session for replay, `--require-signed <keychain>` to demand signed
Interests on NDN control.

`ndn-lab mcp` exposes the whole fabric to an MCP client (**20 tools** + a capability catalogue):
build/inspect (`spawn_node` / `connect` / `route` / `move_node` / `spawn_app` / `set_strategy` /
`add_radio_route` / `describe_topology` / `query_metrics` / `scene_svg`), reason
(`explain_link` / `why_did`), actuate (`cosim`), record (`start_recording` / `get_recording`), and
validate (`run_validation`) — a model composes, inspects, drives, and gates a scenario directly.

## Building on it — debugging & ergonomics

- `fabric.explain_route(node, name)` — where an Interest goes and *why it might not arrive*: the
  matched FIB prefix, the strategy, each next-hop classified (link/radio/local-app), and a warning
  for the classic silent trap (two local app faces on one prefix under best-route → only one
  receives). The same trap is also flagged at start-time.
- `fabric.face_stats(node)` — per-face in/out/drops counters, classified, readable in a test
  (`recvs=0` → "12 Interests in, 0 Data out on the link toward node 3").
- `fabric.clock()` — a cheap `Clone` handle you capture in a task and read `.now_ns()`, instead of
  threading `Arc<dyn SimKernel>`.
- `sim.broadcast_segment(&[nodes], "/prefix")` — a collision-free all-hear-all bus for sync/discovery,
  with no geometry to reason about (a `PerfectPropagation` medium + no interference).
- `Strategy::Multicast` — typed, typo-proof; accepted anywhere a strategy name is (`add_strategy`,
  `set_strategy`) alongside the `"multicast"` string.
- `VirtualKernel::run_capped(max_virtual, f)` — a never-converging run becomes a clean timeout, not an
  output-less hang; plain `run` now carries a default virtual-time ceiling.

## What's inside

| Piece | What |
|-------|------|
| **Kernels** | `DesKernel` (from-scratch deterministic event queue; event-granular single-step), `VirtualKernel` (tokio paused clock; deterministic, faster-than-real, `run_capped` budget), `WallClockKernel` (real time), `RealTimeKernel` (governor: real pace + logical clock, hosts real devices), `SteppableKernel` (pause / step / run-until) |
| **World** | `Position` + `MobilityModel` (static/linear/waypoint) + `Environment`, `WorldView` snapshots over a uniform spatial grid |
| **Medium / radio** | `WirelessMedium` (propagation + range) and `RadioBus` + `SimRadioFace` — the named-radio face with RSSI→MCS→per-frame delivery (`LinkModel`) + carrier-sense collisions |
| **Faces** | per-type behavioral catalogue (`FaceProfile`: udp/tcp/quic/ws/ethernet/multicast/shm/serial/ble/nan) — the engine sees each type's `FaceKind`/MTU/loss/ordering |
| **Control plane** | one declarative API (`SimCommand`/`SimQuery`) over three transports: in-proc, TCP JSON-RPC, and NDN-native `/localhop/sim/control` + a notification stream |
| **Apps** | declarative producers/consumers (`AppSpec`) — "a producer of /foo here, a consumer there" |
| **Scenarios** | a whole sim as one diff-able TOML/JSON artifact (`Scenario`); `topo::{line,ring,star,grid,mesh,tree,random}` generators + shortest-path routing |
| **Stepping** | `Stepper` — drive a fabric on the DES event queue one event at a time, inspecting between steps (the deterministic debugger; `ndn-lab step`) |
| **Record / replay** | journal live commands (`Recording`) → replay a session deterministically |
| **Telemetry** | Runtime-clocked metric gauges + OTLP spans; engine tracing captured on the virtual clock (`SpanLog`, causal `why_did`); OTLP/HTTP export |
| **GUI seam** | `SceneSnapshot` (`world_snapshot()`) + SVG renderers — headless; a GUI is a client of the control API |
| **Bridge** | real UDP faces on a node → external device / NFD / **ndnd** interop (validated over the wire) |
| **MCP** | `SimMcp` — MCP tools projecting the control plane + telemetry |

## Library quick start

Import the everyday vocabulary from the [`prelude`](src/prelude.rs):

```rust
use ndn_sim::prelude::*;

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

Or declare the whole network as one `Scenario` TOML and `ndn-lab run`/`check` it (see
`examples/` and `examples/checks/`). Deterministic (bit-reproducible) runs go through the `DesKernel`
or `VirtualKernel`; see `tests/determinism.rs` for the replay gate.

## Known limitations

- **Scenario export from a live fabric is not yet available** — you can author a `Scenario` (TOML/JSON)
  and round-trip it (`to_toml`/`from_toml`) or generate one (`topo::*` / `ndn-lab gen`), but there is
  no `export-scenario` that reconstructs one from a running fabric built via MCP/RPC.
- **Backward seek (time-travel) isn't available** — `ndn-lab step` advances event-by-event
  (`step`/`run`/`until`) but can't rewind; that needs state checkpointing.
- **Per-node `EngineConfig` isn't serialized** in scenarios (nodes use the default engine config).
- **Mobility via live commands** covers static (`move_node`) and linear (`set_linear_mobility`);
  `WaypointMobility` exists as a model but isn't reachable through a command.
- **Co-simulation is not bit-reproducible while live** (real external input) — record the resulting
  `MobilityTrace` and replay it on `DesKernel` for a deterministic, gate-able run.

Design + roadmap: `.claude/notes/sim-framework-design-v2-2026-06-24.md`.
