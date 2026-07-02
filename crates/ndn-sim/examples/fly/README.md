# Fly — live ArduPilot SITL co-simulation (axis 3, 3b)

`ndn-lab fly` drives the simulated World from a **live MAVLink telemetry stream** — a swarm flown in
ArduPilot SITL (real autopilot firmware + real flight dynamics). NDN forwarding, discovery, and the
named-radio stack run over the moving mesh on the real-time governor; positions are the autopilot's,
not a script's. The clock model is **B** (the autopilot is the clock master; the sim follows).

This needs the `mavlink` feature:

```
cargo build -p ndn-sim --features bin,mavlink
```

## 1. Fly a swarm in SITL

Run ArduPilot SITL with several vehicles, streaming telemetry to a GCS UDP port. For example, with
ArduPilot's `sim_vehicle.py`:

```
sim_vehicle.py -v ArduCopter --count 3 --auto-sysid --out=udp:127.0.0.1:14550
```

(or a Docker image / `mavproxy` fan-out to `udp:127.0.0.1:14550`). Arm and start a mission so the
vehicles move. System ids 1, 2, 3 map to nodes 0, 1, 2 (see `--base-sysid`).

## 2. Fly the co-simulation, recording the trace

```
ndn-lab fly examples/fly/swarm.toml \
    --mavlink udpin:0.0.0.0:14550 \
    --record flight.trace.json
```

Each vehicle's position streams into the World; the followers fetch `/swarm` from the lead over the
radio face; link quality tracks real separation. `Ctrl-C` (or `--secs N`) stops it and writes
`flight.trace.json`. Positions map to a local **ENU** frame — pass `--ref-lat/--ref-lon/--ref-alt`
to fix the origin, or omit them to adopt the first vehicle fix as the origin.

## 2b. Or: one interactive session that flies the swarm back (bidirectional)

`fly` above is capture-only (poses in). For the **single pane of glass** — poses in *and* commands
out, plus live NDN control, from one process — use `serve --mavlink`:

```
ndn-lab serve --mavlink udpin:0.0.0.0:14550 \
    --launch "sim_vehicle.py -v ArduCopter --count 3 --auto-sysid --out=udp:127.0.0.1:14550"
```

`--launch` makes ndn-lab spawn and supervise SITL, so this is literally one command. The session then
serves the control plane over TCP + WebSocket **and NDN** (`/localhop/sim/control`), while positions
stream in. A `Cosim` command — from the CLI, a dashboard, an MCP agent, or **an NDN Interest** — flies
a vehicle and you watch NDN react live:

```json
{"command": {"cmd": "cosim", "command": {"action": "goto", "node": 1, "x": 200, "y": 0, "z": 0}}}
```

(`action`: arm / disarm / takeoff / goto / velocity / land.) Because actuation is just a `SimCommand`,
it rides the NDN control surface for free — you fly the swarm *using the network you're validating*.

## 3. Replay deterministically and gate it (axis 2)

A live run is not bit-reproducible — so turn it into one. Point a validation scenario's
`mobility_trace` at the recording (see `examples/checks/swarm-flight.toml` for the shape), then:

```
ndn-lab check my-swarm-check.toml
```

The recorded flight replays as deterministic `SampledMobility` on the DES kernel, gated by property
and regression assertions. **Fly it live to discover the scenario; replay the trace to prove it in
CI, forever.**
