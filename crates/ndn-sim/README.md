# ndn-sim — the **ndn-lab** fabric

An in-process NDN network **simulation / emulation hub** (product name: *ndn-lab*). It runs
multi-node networks of *real* `ForwarderEngine`s on a pluggable time kernel, with a spatial world,
a named-radio face, one control + telemetry API, an MCP server, and a UDP bridge to real
forwarders — all behind the `Face` + `Runtime` seams, so the engine stays simulation-oblivious.

It builds against sibling checkouts by path — `ndn-rs`, `ndn-ext`, `ndn-radio`,
`ndn-radio-drivers`, `ndn-repo` (tests), and `flotilla` (compiled only with the `keel` feature, but
its manifests must be on disk for Cargo to resolve) — laid out as in the
[repo README](../../README.md#sibling-checkouts-required).

## Fidelity: what runs for real, what is modelled

A sim result only predicts the fleet where the sim runs the fleet's code. Everything a deployed
`ndn-fwd` executes between "a datagram arrived" and "a datagram left" is production code here:

| Layer | In a sim node | Notes |
|-------|---------------|-------|
| Forwarding pipeline, PIT, CS, strategies, RIB | **production** (`ndn-engine`, `ndn-store`, `ndn-strategy`) | CS freshness, LP timers and SVS timers all read the kernel's clock, so virtual time ages them correctly |
| NDNLPv2 (fragmentation, reassembly, reliability, dedup) | **production** (`ndn-transport` `LpLinkService`) | `Simulation::link` defaults to `FaceProfile::udp()`: `FaceKind::Udp`, LP reliability on, `Permanent`, production UDP MTU |
| Startup from TOML (`EngineConfig`, `[[route]]` via RIB, `[[strategy]]`, `[security]` data path, `[cs]`) | **production** (`ndn_config::boot`, the same functions `ndn-fwd` calls) | `Simulation::add_node_from_config` / scenario `[[nodes]] config = "…" addr = "…"`; each `[[face]]` UDP peer resolving to another node's `addr` becomes a UDP face bound as `ndn_config::boot::udp_peer_binding` decides (the decision `ndn-fwd` realises) |
| UDP socket demux | **model** (`sim_udp`) | per node: listeners from `[[face]]`; a datagram goes to the connected face whose 4-tuple matches, else to the socket on its port, where the listener mints an on-demand face per unknown source, as `run_udp_listener` does. `RunningSimulation::start_udp_capture` records every datagram (the sim's `tcpdump`) |
| Transport (link, IP fragmentation) | **model** (`SimFace`) | per-IP-fragment loss (a datagram dies if any fragment dies), optional length-dependent bit-error loss (`with_loss_frame_bytes`), delay/jitter/bandwidth |
| Shared Wi-Fi airtime | **model** (`SharedChannel`) | serialises every member link's frames by airtime; bounded backlog tail-drops. Logical, not calibrated |
| Named-data radio | **model** (`RadioBus`) | see below |

Consequences worth knowing:

- `FaceProfile::internal()` (in-process, local scope, no LP) is for app↔forwarder faces only.
  Node↔node links on `internal()` skip the entire LP layer and local-scope checks, which is how
  earlier "passes in sim" results missed fleet bugs.
- `tests/fleet.rs` boots the four fleet forwarders from `tests/fixtures/fleet/*.toml` over a
  lossy shared channel. Each of these fleet bugs, when reintroduced, fails one of its
  assertions: LP retransmission re-condemnation, strategy choices not applied from config, the
  CanBePrefix+MustBeFresh CS lookup returning a non-freshest version, and peer faces bound to an
  ephemeral port (Round 15: two faces per neighbour; with the engine's same-node check also
  removed, 12 wire copies per Interest instead of 9, each extra one sent back to its origin).
- Still modelled, so not predictive: the IP stack beyond the socket demux (no ICMP, ARP or
  routing; a full receive queue back-pressures instead of dropping; `SO_REUSEPORT` flow-hashing
  between two unconnected sockets on one port is refused rather than guessed), kernel
  scheduling, and radio PHY numbers.

## Where the research went

This crate is the **core simulator** — what a fleet result has to be predicted by. The in-sim IP
plane (`IpNetwork`, the routing algorithms, `compare_ndn_vs_ip`), the statistical Wi-Fi MAC
(`Wifi`, Minstrel-HT, IBSS/AP/mesh operating modes), LoRa, the multi-radio PHY reference, the
`ndn-radio-cognition` bridge, the radio/MAC/coding/named-time study examples with their dashboards
and CSVs, and the experiment-shaped tests live in the sibling crate
[`ndn-sim-studies`](../ndn-sim-studies/), which depends on this one (never the reverse).

The radio this crate *does* carry: `RadioBus` + `SimRadioFace` over pluggable propagation /
interference / channel-leak models, with an 802.11 airtime model (`WifiMode::Monitor` = named-data
radio vs `Managed` = EDCA + ACK per unicast). That model is **logically faithful, not
calibrated**: the relationships (retries raise delivery and cost airtime, higher MCS is cheaper
airtime but needs more SNR, one broadcast serves every in-range receiver) are modelled; A-MPDU,
block-ACK and EDCA timing are reduced to textbook constants, not fitted to measured hardware.

## Telemetry that describes itself (the Keel — `keel` feature)

With the off-by-default `keel` feature, telemetry types carry `#[derive(Manifest)]` and describe
themselves; renderers publish **render contracts**; a deterministic matcher binds data + intent to
competing lenses, and selection at a fidelity floor picks between them — an exact SVG (Express), or
ASCII glyphs / a thumbnail / an OTLP gauge (Approximate, each loss a *named term*), depending on
what the surface can hold. No hand-written exporter integrations; every loss is auditable. See
`ndn_sim::keel` and `examples/keel-telemetry.rs`
(`cargo run -p ndn-sim --features keel --example keel-telemetry`). The feature compiles the
manifest / render-contract crates from the sibling `flotilla` checkout; without it none of that code
is built.

## The five capability axes

1. **Executor-agnostic core** — from a deterministic discrete-event queue (`DesKernel`,
   bit-reproducible replay) through the tokio paused-clock `VirtualKernel` to real-time
   (`RealTimeKernel`, hosts live devices).
2. **Validation platform** — `ValidationSpec` = scenario + fault schedule + property assertions +
   seed sweeps + regression baselines; `ndn-lab check` is a headless CI gate.
3. **Pluggable backends + co-simulation** — external simulators (ArduPilot SITL / Gazebo / Bevy)
   drive node motion; `cosim` commands actuate them back (bidirectional, NDN-native).
4. **Observability / analysis** — causal "why" over radio delivery (`explain_link`), cross-run diff
   (`diff_runs`), live telemetry streaming + OTLP/Jaeger export.
5. **Self-description** (`keel` feature) — telemetry described once (`#[derive(Manifest)]`),
   rendered through competing render contracts with deterministic selection and named, auditable
   losses (the Keel).

## Interop with other NDN stacks

ndn-lab interops **at the edge, by design** (`ndn_sim::bridge`): a real UDP face attaches to a
fabric node so any conformant forwarder — NFD, ndnd, NDNts, a phone — peers with the simulated
fabric over the real NDN wire, while the fabric interior stays deterministic. External endpoints
live on real time, so bridges require a `wall_clock`/`real_time` kernel (and are refused, loudly,
under `des`/`virtual` — validation runs stay hermetic).

Declare an external peer straight in a scenario:

```toml
[[bridges]]
node  = 0
local = "127.0.0.1:0"          # fixed port if the peer must dial back
peer  = "127.0.0.1:6363"       # e.g. a local NFD or ndnd
route = "/interop"             # optional FIB route over the bridge face
mtu   = 1200                   # optional send-MTU clamp (NDNLPv2-fragments above it)
```

A conformance suite validates the wire against a **real ndnd** (Go, named-data.net):
Interest/Data + MustBeFresh, foreign-signature parsing, NDNLPv2 fragmentation **in both
directions**, CanBePrefix discovery — plus one *documented divergence* (ndnd deliberately sends
no Nacks; an unrouted Interest surfaces here as a clean timeout). Run it with
`testbed/interop.sh` (builds ndnd from a checkout), or in CI via the opt-in `interop` job
(manual dispatch / weekly cron — never on PRs).

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

Paths *inside* a scenario or check spec (e.g. `mobility_trace = "swarm-flight.trace.json"`)
resolve relative to that file's directory, so every command above works from any working
directory.

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
| **World** | `Position` + `MobilityModel` (static/linear/waypoint/random-waypoint) + `Environment`, `WorldView` snapshots over a uniform spatial grid |
| **Medium / radio** | `RadioBus` + `SimRadioFace` — the named-radio face with RSSI→MCS→per-frame delivery (`LinkModel`), pluggable `PropagationModel` (range disc / Friis / obstacles) + `InterferenceModel` (carrier-sense collisions) + `ChannelModel` (side-band leakage), half-duplex, energy accounting |
| **802.11 airtime** | `WifiMode` Monitor-vs-Managed frame cost (EDCA + ACK/Block-ACK, A-MPDU) — logically faithful, not calibrated |
| **The Keel** (`keel` feature) | self-describing telemetry (`#[derive(Manifest)]`) through render contracts — competing lenses (`KeelView`/`SceneView`/`Surface`), deterministic selection, named losses |
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
