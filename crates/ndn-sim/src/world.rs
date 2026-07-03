//! The spatial **world** (ndn-lab slice 3): *where* nodes are, *how* they move, and *what*
//! lies between them. Engine-oblivious — the fabric consults these models; the forwarder
//! never sees them.
//!
//! Three pluggable traits, each with a trivial default + textbook impls (the
//! `Face`/`Strategy` pattern):
//! - [`MobilityModel`] — a node's position as a pure `fn(t)` (deterministic, cheap).
//! - [`Environment`] — extra attenuation (walls/terrain) between two points.
//! - the [`World`] ties them together and produces an immutable [`WorldView`] **snapshot**
//!   per tick (no live lock → reproducible + parallel-friendly), backed by a [`SpatialGrid`]
//!   so range queries are local, never O(N²).
//!
//! Units: metres for distance, seconds for mobility time (`t` = seconds since the world
//! epoch). The wireless [`medium`](crate::medium) converts the engine's epoch-nanosecond
//! clock into these seconds.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::NodeId;

/// A position in 3-D space, metres. Use `z = 0` for 2-D scenarios.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Position {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Position {
    pub const ORIGIN: Position = Position {
        x: 0.0,
        y: 0.0,
        z: 0.0,
    };

    /// A 2-D position (`z = 0`).
    pub fn xy(x: f64, y: f64) -> Self {
        Self { x, y, z: 0.0 }
    }

    pub fn xyz(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    /// Euclidean distance in metres.
    pub fn distance(&self, other: Position) -> f64 {
        let dx = self.x - other.x;
        let dy = self.y - other.y;
        let dz = self.z - other.z;
        (dx * dx + dy * dy + dz * dz).sqrt()
    }
}

/// A node's position as a pure function of time (seconds since the world epoch). Analytic
/// models are deterministic and cheap; externally-driven mobility (co-sim / GUI drag) plugs
/// in later by swapping the model.
pub trait MobilityModel: Send + Sync {
    fn position(&self, t_secs: f64) -> Position;
}

/// A node that never moves.
pub struct StaticMobility(pub Position);
impl MobilityModel for StaticMobility {
    fn position(&self, _t: f64) -> Position {
        self.0
    }
}

/// Constant-velocity motion: `start + velocity · t` (velocity in m/s per axis).
pub struct LinearMobility {
    pub start: Position,
    pub velocity: (f64, f64, f64),
}
impl MobilityModel for LinearMobility {
    fn position(&self, t: f64) -> Position {
        Position {
            x: self.start.x + self.velocity.0 * t,
            y: self.start.y + self.velocity.1 * t,
            z: self.start.z + self.velocity.2 * t,
        }
    }
}

/// Piecewise-linear motion through timestamped waypoints (interpolated between, clamped at
/// the ends). Deterministic; the basis for scripted scenarios.
pub struct WaypointMobility {
    /// `(t_secs, position)` pairs, assumed sorted by time.
    pub waypoints: Vec<(f64, Position)>,
}
impl MobilityModel for WaypointMobility {
    fn position(&self, t: f64) -> Position {
        match self.waypoints.as_slice() {
            [] => Position::ORIGIN,
            [(_, p)] => *p,
            wps => {
                if t <= wps[0].0 {
                    return wps[0].1;
                }
                if t >= wps[wps.len() - 1].0 {
                    return wps[wps.len() - 1].1;
                }
                // Find the segment [i, i+1] containing t.
                let i = wps.partition_point(|(wt, _)| *wt <= t) - 1;
                let (t0, p0) = wps[i];
                let (t1, p1) = wps[i + 1];
                let frac = if t1 > t0 { (t - t0) / (t1 - t0) } else { 0.0 };
                Position {
                    x: p0.x + (p1.x - p0.x) * frac,
                    y: p0.y + (p1.y - p0.y) * frac,
                    z: p0.z + (p1.z - p0.z) * frac,
                }
            }
        }
    }
}

/// What lies between two points: extra attenuation from walls / terrain (dB), on top of the
/// propagation model's free-space loss.
pub trait Environment: Send + Sync {
    /// Excess attenuation in dB along the path `a → b` (≥ 0). `0.0` = nothing in the way.
    fn attenuation(&self, a: Position, b: Position) -> f64;
}

/// Open air — no obstacles (the default).
pub struct FreeSpace;
impl Environment for FreeSpace {
    fn attenuation(&self, _a: Position, _b: Position) -> f64 {
        0.0
    }
}

/// A constant excess attenuation everywhere (a crude "indoors" knob for tests/scenarios).
pub struct UniformAttenuation(pub f64);
impl Environment for UniformAttenuation {
    fn attenuation(&self, _a: Position, _b: Position) -> f64 {
        self.0
    }
}

/// The spatial world: each node's mobility model + the shared environment. Analytic, so a
/// [`snapshot`](World::snapshot) at any time is pure and reproducible.
///
/// **Live-mutable through `&self`** (interior `RwLock`s): [`place`](World::place) /
/// [`set_mobility`](World::set_mobility) / [`set_environment`](World::set_environment) can be
/// called on a shared `Arc<World>` while a fabric runs — the seam for GUI drag-to-move and the
/// control plane's live-world commands. A [`snapshot`](World::snapshot) takes a consistent
/// read; concurrent edits land on the next snapshot.
pub struct World {
    mobility: RwLock<HashMap<NodeId, Arc<dyn MobilityModel>>>,
    environment: RwLock<Arc<dyn Environment>>,
    grid_cell_m: f64,
    /// Bumped on every mutation so cached [`WorldView`]s (the medium/radio per-instant snapshot
    /// cache) invalidate when positions/mobility/environment change live.
    generation: AtomicU64,
}

impl Default for World {
    fn default() -> Self {
        Self::new()
    }
}

impl World {
    /// An empty world in free space, with a 100 m spatial-grid cell.
    pub fn new() -> Self {
        Self {
            mobility: RwLock::new(HashMap::new()),
            environment: RwLock::new(Arc::new(FreeSpace)),
            grid_cell_m: 100.0,
            generation: AtomicU64::new(0),
        }
    }

    /// A monotonic counter bumped on every mutation — cache key for per-instant snapshots.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    pub fn with_environment(env: Arc<dyn Environment>) -> Self {
        let w = Self::new();
        *w.environment.write().unwrap() = env;
        w
    }

    /// Set the spatial-grid cell size (metres). Pick ≈ the typical transmission range for the
    /// fewest cells scanned per query; correctness holds for any positive value.
    pub fn with_grid_cell(mut self, cell_m: f64) -> Self {
        self.grid_cell_m = cell_m.max(f64::MIN_POSITIVE);
        self
    }

    /// Place a node at a fixed position (shorthand for [`StaticMobility`]). Live: callable on a
    /// shared `Arc<World>`.
    pub fn place(&self, node: NodeId, position: Position) {
        self.mobility
            .write()
            .unwrap()
            .insert(node, Arc::new(StaticMobility(position)));
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// Give a node a mobility model. Live: callable on a shared `Arc<World>`.
    pub fn set_mobility(&self, node: NodeId, model: Arc<dyn MobilityModel>) {
        self.mobility.write().unwrap().insert(node, model);
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// Remove a node from the world (it becomes unplaced — heard by no radio).
    pub fn remove(&self, node: NodeId) {
        self.mobility.write().unwrap().remove(&node);
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// Swap the shared environment model live.
    pub fn set_environment(&self, env: Arc<dyn Environment>) {
        *self.environment.write().unwrap() = env;
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    /// The current environment model (cheap `Arc` clone).
    pub fn environment(&self) -> Arc<dyn Environment> {
        Arc::clone(&self.environment.read().unwrap())
    }

    /// An immutable snapshot of every node's position at `t_secs`, with a spatial index ready
    /// for range queries. Take one per event tick and query it without locking.
    pub fn snapshot(&self, t_secs: f64) -> WorldView {
        let positions: HashMap<NodeId, Position> = self
            .mobility
            .read()
            .unwrap()
            .iter()
            .map(|(id, m)| (*id, m.position(t_secs)))
            .collect();
        let grid = SpatialGrid::build(&positions, self.grid_cell_m);
        WorldView {
            positions,
            grid,
            t_secs,
        }
    }
}

/// An immutable, point-in-time view of the world. Pure to query.
pub struct WorldView {
    positions: HashMap<NodeId, Position>,
    grid: SpatialGrid,
    t_secs: f64,
}

impl WorldView {
    /// The snapshot time (seconds since the world epoch).
    pub fn t(&self) -> f64 {
        self.t_secs
    }

    pub fn position(&self, node: NodeId) -> Option<Position> {
        self.positions.get(&node).copied()
    }

    pub fn nodes(&self) -> usize {
        self.positions.len()
    }

    /// Every placed node within `radius` metres of `center`, sorted by [`NodeId`]
    /// (deterministic). Uses the spatial grid, so only nearby cells are scanned.
    pub fn within_range(&self, center: Position, radius: f64) -> Vec<NodeId> {
        let mut out = self.grid.query(center, radius, &self.positions);
        out.sort_by_key(|n| n.0);
        out
    }
}

/// A uniform 3-D grid bucketing nodes by cell, so a range query scans only the cells the
/// radius can reach — the single most important medium-scaling primitive (avoids O(N²)).
struct SpatialGrid {
    cell: f64,
    cells: HashMap<(i64, i64, i64), Vec<NodeId>>,
}

impl SpatialGrid {
    fn cell_of(cell: f64, p: Position) -> (i64, i64, i64) {
        (
            (p.x / cell).floor() as i64,
            (p.y / cell).floor() as i64,
            (p.z / cell).floor() as i64,
        )
    }

    fn build(positions: &HashMap<NodeId, Position>, cell: f64) -> Self {
        let mut cells: HashMap<(i64, i64, i64), Vec<NodeId>> = HashMap::new();
        for (id, p) in positions {
            cells.entry(Self::cell_of(cell, *p)).or_default().push(*id);
        }
        Self { cell, cells }
    }

    /// Candidate nodes within `radius` of `center`, filtered to the true Euclidean distance.
    fn query(
        &self,
        center: Position,
        radius: f64,
        positions: &HashMap<NodeId, Position>,
    ) -> Vec<NodeId> {
        let (cx, cy, cz) = Self::cell_of(self.cell, center);
        // Cells the radius can reach in each axis (round up).
        let reach = (radius / self.cell).ceil() as i64 + 1;
        let mut out = Vec::new();
        for i in (cx - reach)..=(cx + reach) {
            for j in (cy - reach)..=(cy + reach) {
                for k in (cz - reach)..=(cz + reach) {
                    let Some(bucket) = self.cells.get(&(i, j, k)) else {
                        continue;
                    };
                    for id in bucket {
                        if let Some(p) = positions.get(id)
                            && p.distance(center) <= radius
                        {
                            out.push(*id);
                        }
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linear_mobility_is_deterministic_fn_of_time() {
        let m = LinearMobility {
            start: Position::xy(0.0, 0.0),
            velocity: (1.0, 0.0, 0.0),
        };
        assert_eq!(m.position(0.0), Position::xy(0.0, 0.0));
        assert_eq!(m.position(10.0), Position::xy(10.0, 0.0));
        // Pure function: same t ⇒ same position, every call.
        assert_eq!(m.position(3.5), m.position(3.5));
    }

    #[test]
    fn waypoint_mobility_interpolates_and_clamps() {
        let m = WaypointMobility {
            waypoints: vec![
                (0.0, Position::xy(0.0, 0.0)),
                (10.0, Position::xy(100.0, 0.0)),
            ],
        };
        assert_eq!(
            m.position(-5.0),
            Position::xy(0.0, 0.0),
            "clamps before first"
        );
        assert_eq!(
            m.position(5.0),
            Position::xy(50.0, 0.0),
            "interpolates midpoint"
        );
        assert_eq!(
            m.position(99.0),
            Position::xy(100.0, 0.0),
            "clamps after last"
        );
    }

    #[test]
    fn spatial_query_finds_only_in_range_nodes() {
        let world = World::new().with_grid_cell(10.0);
        world.place(NodeId(0), Position::xy(0.0, 0.0));
        world.place(NodeId(1), Position::xy(5.0, 0.0)); // 5 m
        world.place(NodeId(2), Position::xy(50.0, 0.0)); // 50 m
        world.place(NodeId(3), Position::xy(0.0, 8.0)); // 8 m
        let view = world.snapshot(0.0);

        let near = view.within_range(Position::ORIGIN, 10.0);
        assert_eq!(
            near,
            vec![NodeId(0), NodeId(1), NodeId(3)],
            "sorted, range-filtered"
        );
        assert!(
            !near.contains(&NodeId(2)),
            "50 m node excluded at radius 10"
        );
    }

    #[test]
    fn snapshot_reflects_movement_over_time() {
        let world = World::new();
        world.set_mobility(
            NodeId(0),
            Arc::new(LinearMobility {
                start: Position::xy(0.0, 0.0),
                velocity: (10.0, 0.0, 0.0),
            }),
        );
        assert_eq!(
            world.snapshot(0.0).position(NodeId(0)),
            Some(Position::xy(0.0, 0.0))
        );
        assert_eq!(
            world.snapshot(5.0).position(NodeId(0)),
            Some(Position::xy(50.0, 0.0))
        );
    }
}
