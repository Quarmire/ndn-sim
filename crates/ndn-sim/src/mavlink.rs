//! # ArduPilot SITL (MAVLink) mobility adapter — the co-simulation killer feature (axis 3, 3b)
//!
//! Feature-gated behind `mavlink` so the core build never pulls the MAVLink stack. This is the first
//! *external* [`MobilitySource`](crate::MobilitySource): it connects to a MAVLink telemetry stream
//! (ArduPilot SITL, a real autopilot, MAVProxy, …), maps each vehicle's position reports to
//! [`NodeState`](crate::NodeState)s, and feeds them into a [`ChannelSource`](crate::ChannelSource).
//! Ride it on the [`RealTimeKernel`](crate::RealTimeKernel) governor via
//! [`drive_mobility`](crate::RunningSimulation::drive_mobility) (clock mode B — the autopilot is the
//! clock master; the sim follows), record the [`MobilityTrace`](crate::MobilityTrace), and replay it
//! deterministically on DES to gate with the axis-2 validator.
//!
//! ## Frames
//! - `GLOBAL_POSITION_INT` (lat/lon/alt) → an ENU World position relative to a reference origin. If
//!   no origin is given, the **first fix becomes the origin** (the arena centers on the first
//!   vehicle) — so a swarm of vehicles at distinct homes lands in one shared coordinate frame.
//! - `LOCAL_POSITION_NED` (x=N, y=E, z=D metres) → ENU directly (no origin needed).
//!
//! ## Vehicle → node
//! Each MAVLink system id maps to a [`NodeId`]; the default is `sysid - base_sysid` (ArduPilot
//! vehicles are typically sysid 1..N), skipping the GCS (sysid 255).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Instant;

use anyhow::{Context, Result};
use mavlink::common::MavMessage;

use crate::cosim::{ChannelSource, CosimActuator, NodeState, VehicleCommand};
use crate::topology::NodeId;
use crate::world::Position;

/// A shared, bidirectional MAVLink connection — the reader thread and the actuator both use it
/// (`recv`/`send` take `&self`), so commands go back to the same peer the telemetry came from.
type MavConn = Arc<dyn mavlink::MavConnection<MavMessage> + Send + Sync>;

/// A geographic reference origin for the ENU frame that World positions live in.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GeoRef {
    pub lat_deg: f64,
    pub lon_deg: f64,
    pub alt_m: f64,
}

/// Configuration for a MAVLink co-sim source.
#[derive(Clone, Debug)]
pub struct MavlinkConfig {
    /// Connection string, e.g. `"udpin:0.0.0.0:14550"` (listen for SITL's telemetry).
    pub endpoint: String,
    /// ENU origin for `GLOBAL_POSITION_INT`. `None` ⇒ adopt the first received fix as the origin.
    pub reference: Option<GeoRef>,
    /// The MAVLink system id that maps to `NodeId(0)` (ArduPilot vehicles usually start at 1).
    pub base_sysid: u8,
    /// Number of scenario nodes — sysids mapping beyond this are ignored (don't pollute the world).
    pub node_count: usize,
}

/// WGS-84 equatorial radius (m) — the equirectangular approximation is exact enough for an arena.
const EARTH_R_M: f64 = 6_378_137.0;

/// Convert a geodetic position to a local **ENU** offset (east, north, up) from `origin`, as a World
/// [`Position`] (`x = east`, `y = north`, `z = up`). Equirectangular projection — sub-metre accurate
/// over the kilometre scales a swarm operates in.
pub fn geo_to_enu(lat_deg: f64, lon_deg: f64, alt_m: f64, origin: GeoRef) -> Position {
    let dlat = (lat_deg - origin.lat_deg).to_radians();
    let dlon = (lon_deg - origin.lon_deg).to_radians();
    let east = dlon * EARTH_R_M * origin.lat_deg.to_radians().cos();
    let north = dlat * EARTH_R_M;
    let up = alt_m - origin.alt_m;
    Position::xyz(east, north, up)
}

/// Map a MAVLink message to a World position + ENU velocity `[east, north, up]` m/s, given the ENU
/// `origin` (needed only for global positions). Returns `None` for non-position messages. Pure.
pub fn decode_position(msg: &MavMessage, origin: Option<GeoRef>) -> Option<(Position, [f64; 3])> {
    match msg {
        MavMessage::GLOBAL_POSITION_INT(d) => {
            let origin = origin?;
            let pos = geo_to_enu(
                d.lat as f64 / 1e7,
                d.lon as f64 / 1e7,
                d.alt as f64 / 1e3,
                origin,
            );
            // GLOBAL_POSITION_INT velocity is (vx=N, vy=E, vz=D) in cm/s.
            let vel = [d.vy as f64 / 100.0, d.vx as f64 / 100.0, -(d.vz as f64) / 100.0];
            Some((pos, vel))
        }
        MavMessage::LOCAL_POSITION_NED(d) => {
            // NED (x=N, y=E, z=D) metres → ENU.
            let pos = Position::xyz(d.y as f64, d.x as f64, -(d.z as f64));
            let vel = [d.vy as f64, d.vx as f64, -(d.vz as f64)];
            Some((pos, vel))
        }
        _ => None,
    }
}

/// Extract the geodetic fix from a `GLOBAL_POSITION_INT` (for adopting the first fix as the origin).
fn global_fix(msg: &MavMessage) -> Option<GeoRef> {
    match msg {
        MavMessage::GLOBAL_POSITION_INT(d) => Some(GeoRef {
            lat_deg: d.lat as f64 / 1e7,
            lon_deg: d.lon as f64 / 1e7,
            alt_m: d.alt as f64 / 1e3,
        }),
        _ => None,
    }
}

/// The default vehicle→node mapping: `sysid - base_sysid`, skipping the GCS (255) and sysids that
/// fall outside `[base_sysid, base_sysid + node_count)`.
pub fn default_node_of(cfg: &MavlinkConfig, sysid: u8) -> Option<NodeId> {
    if sysid == 255 || sysid < cfg.base_sysid {
        return None;
    }
    let idx = (sysid - cfg.base_sysid) as usize;
    (idx < cfg.node_count).then_some(NodeId(idx))
}

/// A running MAVLink reader — dropping it signals the reader thread to stop. The thread exits on its
/// next received frame (or when the [`ChannelSource`] it feeds is dropped); it is *not* joined,
/// because `recv()` blocks, so a silent feed must not hang the drop. `handle` is kept for callers
/// that want to join explicitly.
pub struct MavlinkReader {
    stop: Arc<AtomicBool>,
    pub handle: Option<JoinHandle<()>>,
}

impl MavlinkReader {
    /// Signal the reader to stop (idempotent). It winds down on its next frame.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for MavlinkReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Deliberately not joined: `recv()` blocks, so a silent feed would hang. The thread observes
        // `stop` on its next frame, or dies when the process exits.
    }
}

/// Open a bidirectional MAVLink connection to `endpoint` — shareable between a reader and an actuator.
pub fn mavlink_connect(endpoint: &str) -> Result<MavConn> {
    let conn = mavlink::connect::<MavMessage>(endpoint)
        .with_context(|| format!("connect MAVLink endpoint {endpoint:?}"))?;
    Ok(Arc::from(conn))
}

/// Spawn the blocking reader thread that decodes vehicle positions off `conn` into `tx`.
fn spawn_reader(
    conn: MavConn,
    cfg: MavlinkConfig,
    tx: tokio::sync::mpsc::UnboundedSender<NodeState>,
) -> Result<MavlinkReader> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("mavlink-reader".into())
        .spawn(move || {
            let start = Instant::now();
            let mut origin = cfg.reference;
            while !stop_thread.load(Ordering::Relaxed) {
                let (header, msg) = match conn.recv() {
                    Ok(x) => x,
                    Err(mavlink::error::MessageReadError::Parse(_)) => continue,
                    Err(mavlink::error::MessageReadError::Io(e))
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break, // socket gone
                };
                if origin.is_none() {
                    origin = global_fix(&msg);
                }
                let Some(node) = default_node_of(&cfg, header.system_id) else { continue };
                if let Some((position, vel)) = decode_position(&msg, origin) {
                    let state = NodeState {
                        node,
                        t_secs: start.elapsed().as_secs_f64(),
                        position,
                        velocity: Some(vel),
                    };
                    if tx.send(state).is_err() {
                        break; // the source was dropped — the run ended
                    }
                }
            }
        })
        .context("spawn MAVLink reader thread")?;
    Ok(MavlinkReader { stop, handle: Some(handle) })
}

/// Connect to `cfg.endpoint` and spawn a reader that pushes [`NodeState`]s into the returned
/// [`ChannelSource`] (positions IN only). For the bidirectional loop, use [`mavlink_link`].
///
/// The reader stamps each state with elapsed seconds since connect — a shared clock across vehicles,
/// which is exactly the frame the recorded trace replays against.
pub fn mavlink_source(cfg: MavlinkConfig) -> Result<(ChannelSource, MavlinkReader)> {
    let conn = mavlink_connect(&cfg.endpoint)?;
    let (tx, source) = ChannelSource::new();
    let reader = spawn_reader(conn, cfg, tx)?;
    Ok((source, reader))
}

/// The **bidirectional** entry point: one MAVLink link, a [`ChannelSource`] of incoming positions AND
/// a [`MavlinkActuator`] that commands the vehicles back over the same link. Wire the source to
/// [`drive_mobility`](crate::RunningSimulation::drive_mobility) and hand the actuator to the control
/// plane — then a `Cosim` command from anywhere (CLI, dashboard, MCP, an NDN Interest) flies the swarm.
pub fn mavlink_link(cfg: MavlinkConfig) -> Result<(ChannelSource, MavlinkReader, MavlinkActuator)> {
    let conn = mavlink_connect(&cfg.endpoint)?;
    let (tx, source) = ChannelSource::new();
    let reader = spawn_reader(Arc::clone(&conn), cfg.clone(), tx)?;
    let actuator = MavlinkActuator { conn, base_sysid: cfg.base_sysid };
    Ok((source, reader, actuator))
}

/// Sends [`VehicleCommand`]s to ArduPilot over MAVLink — the co-sim actuation back-channel. Node
/// index → system id is the inverse of the reader's mapping (`base_sysid + node`).
pub struct MavlinkActuator {
    conn: MavConn,
    base_sysid: u8,
}

impl MavlinkActuator {
    fn target(&self, node: usize) -> u8 {
        self.base_sysid.wrapping_add(node as u8)
    }

    fn send(&self, msg: &MavMessage) -> Result<()> {
        let header = mavlink::MavHeader { system_id: 255, component_id: 0, sequence: 0 };
        self.conn.send(&header, msg).context("send MAVLink command")?;
        Ok(())
    }

    fn command_long(
        &self,
        node: usize,
        command: mavlink::common::MavCmd,
        params: [f32; 7],
    ) -> MavMessage {
        MavMessage::COMMAND_LONG(mavlink::common::COMMAND_LONG_DATA {
            target_system: self.target(node),
            target_component: 1,
            command,
            confirmation: 0,
            param1: params[0],
            param2: params[1],
            param3: params[2],
            param4: params[3],
            param5: params[4],
            param6: params[5],
            param7: params[6],
        })
    }
}

impl CosimActuator for MavlinkActuator {
    fn command(&self, cmd: &VehicleCommand) -> Result<()> {
        use mavlink::common::MavCmd;
        let msg = match *cmd {
            VehicleCommand::Arm { node } => {
                self.command_long(node, MavCmd::MAV_CMD_COMPONENT_ARM_DISARM, [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
            }
            VehicleCommand::Disarm { node } => {
                self.command_long(node, MavCmd::MAV_CMD_COMPONENT_ARM_DISARM, [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
            }
            VehicleCommand::Takeoff { node, alt_m } => self.command_long(
                node,
                MavCmd::MAV_CMD_NAV_TAKEOFF,
                [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, alt_m as f32],
            ),
            VehicleCommand::Land { node } => {
                self.command_long(node, MavCmd::MAV_CMD_NAV_LAND, [0.0; 7])
            }
            // Guided-mode setpoints, ENU → NED (north = y_enu, east = x_enu, down = -z_enu).
            VehicleCommand::Goto { node, x, y, z } => setpoint_local_ned(
                self.target(node),
                Some([y as f32, x as f32, -z as f32]),
                None,
            ),
            VehicleCommand::Velocity { node, vx, vy, vz } => setpoint_local_ned(
                self.target(node),
                None,
                Some([vy as f32, vx as f32, -vz as f32]),
            ),
        };
        self.send(&msg)
    }
}

/// Build a `SET_POSITION_TARGET_LOCAL_NED` for a position and/or velocity setpoint (NED frame).
fn setpoint_local_ned(target: u8, pos_ned: Option<[f32; 3]>, vel_ned: Option<[f32; 3]>) -> MavMessage {
    use mavlink::common::{MavFrame, PositionTargetTypemask, SET_POSITION_TARGET_LOCAL_NED_DATA};
    // type_mask bits set = IGNORE. Ignore accel + yaw always; ignore position or velocity per setpoint.
    let mut ignore = PositionTargetTypemask::POSITION_TARGET_TYPEMASK_AX_IGNORE
        | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_AY_IGNORE
        | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_AZ_IGNORE
        | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_YAW_IGNORE
        | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_YAW_RATE_IGNORE;
    if pos_ned.is_none() {
        ignore |= PositionTargetTypemask::POSITION_TARGET_TYPEMASK_X_IGNORE
            | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_Y_IGNORE
            | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_Z_IGNORE;
    }
    if vel_ned.is_none() {
        ignore |= PositionTargetTypemask::POSITION_TARGET_TYPEMASK_VX_IGNORE
            | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_VY_IGNORE
            | PositionTargetTypemask::POSITION_TARGET_TYPEMASK_VZ_IGNORE;
    }
    let p = pos_ned.unwrap_or([0.0; 3]);
    let v = vel_ned.unwrap_or([0.0; 3]);
    MavMessage::SET_POSITION_TARGET_LOCAL_NED(SET_POSITION_TARGET_LOCAL_NED_DATA {
        time_boot_ms: 0,
        target_system: target,
        target_component: 1,
        coordinate_frame: MavFrame::MAV_FRAME_LOCAL_NED,
        type_mask: ignore,
        x: p[0],
        y: p[1],
        z: p[2],
        vx: v[0],
        vy: v[1],
        vz: v[2],
        afx: 0.0,
        afy: 0.0,
        afz: 0.0,
        yaw: 0.0,
        yaw_rate: 0.0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mavlink::common::{GLOBAL_POSITION_INT_DATA, LOCAL_POSITION_NED_DATA};

    #[test]
    fn enu_origin_maps_to_zero_and_east_north_are_right() {
        let origin = GeoRef { lat_deg: 47.0, lon_deg: 8.0, alt_m: 500.0 };
        let at_origin = geo_to_enu(47.0, 8.0, 500.0, origin);
        assert!(at_origin.x.abs() < 1e-6 && at_origin.y.abs() < 1e-6 && at_origin.z.abs() < 1e-6);
        // 0.001° north ≈ 111 m; east is scaled by cos(lat).
        let north = geo_to_enu(47.001, 8.0, 500.0, origin);
        assert!((north.y - 111.0).abs() < 2.0, "north ≈ 111 m, got {}", north.y);
        assert!(north.x.abs() < 1e-3, "no east component");
        let east = geo_to_enu(47.0, 8.001, 500.0, origin);
        assert!(east.x > 70.0 && east.x < 80.0, "east ≈ 111*cos(47°) ≈ 76 m, got {}", east.x);
        assert!(east.y.abs() < 1e-3, "no north component");
    }

    #[test]
    fn global_position_decodes_to_enu_relative_to_origin() {
        let origin = GeoRef { lat_deg: 47.0, lon_deg: 8.0, alt_m: 500.0 };
        let msg = MavMessage::GLOBAL_POSITION_INT(GLOBAL_POSITION_INT_DATA {
            time_boot_ms: 0,
            lat: 470010000, // 47.001°
            lon: 80000000,  // 8.0°
            alt: 510000,    // 510 m
            relative_alt: 10000,
            vx: 500,  // 5 m/s north
            vy: 0,
            vz: 0,
            hdg: 0,
        });
        let (pos, vel) = decode_position(&msg, Some(origin)).unwrap();
        assert!((pos.y - 111.0).abs() < 2.0, "north ≈ 111 m");
        assert!((pos.z - 10.0).abs() < 1e-6, "10 m up");
        assert!((vel[1] - 5.0).abs() < 1e-6, "5 m/s north");
    }

    #[test]
    fn local_ned_decodes_directly() {
        let msg = MavMessage::LOCAL_POSITION_NED(LOCAL_POSITION_NED_DATA {
            time_boot_ms: 0,
            x: 10.0, // north
            y: 20.0, // east
            z: -30.0, // down = -30 ⇒ 30 up
            vx: 1.0,
            vy: 2.0,
            vz: -3.0,
        });
        let (pos, vel) = decode_position(&msg, None).unwrap();
        assert_eq!(pos, Position::xyz(20.0, 10.0, 30.0));
        assert_eq!(vel, [2.0, 1.0, 3.0]);
    }

    #[test]
    fn sysid_maps_to_node_and_skips_gcs() {
        let cfg = MavlinkConfig {
            endpoint: String::new(),
            reference: None,
            base_sysid: 1,
            node_count: 3,
        };
        assert_eq!(default_node_of(&cfg, 1), Some(NodeId(0)));
        assert_eq!(default_node_of(&cfg, 3), Some(NodeId(2)));
        assert_eq!(default_node_of(&cfg, 4), None, "beyond node_count");
        assert_eq!(default_node_of(&cfg, 255), None, "GCS skipped");
    }
}
