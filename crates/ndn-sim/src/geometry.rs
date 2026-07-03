//! # Geometry-aware radio: line-of-sight obstruction (axis 3, slice 3c)
//!
//! A pluggable [`PropagationModel`](crate::medium::PropagationModel) backend that layers **line-of-
//! sight** on top of any base channel model: a frame whose transmitter→receiver path crosses an
//! obstacle (a building, a hill, terrain) is attenuated or blocked. Combined with co-simulated
//! mobility (an ArduPilot swarm from 3b), this is the realistic capstone — a drone flying behind a
//! building **loses its NDN link and regains it in the clear**, and the axis-2 validator can gate it.
//!
//! Obstacles are axis-aligned boxes. The base model still decides free-space delivery/RSSI; this
//! wrapper subtracts `obstruction_loss_db` per obstacle crossed and drops the frame once the result
//! falls below `min_rssi_dbm`. The default loss (200 dB) makes any obstacle a hard blocker; a small
//! loss models partial obstruction (foliage).

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::link_model::NOISE_FLOOR_DBM;
use crate::medium::{Delivery, DeliveryReason, PropagationModel, TxContext};
use crate::world::Position;

/// An axis-aligned box obstacle (a building / terrain block) that obstructs radio crossing it.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Obstacle {
    pub min: Position,
    pub max: Position,
}

impl Obstacle {
    /// A box spanning two opposite corners (in any order).
    pub fn from_corners(a: Position, b: Position) -> Self {
        Self {
            min: Position::xyz(a.x.min(b.x), a.y.min(b.y), a.z.min(b.z)),
            max: Position::xyz(a.x.max(b.x), a.y.max(b.y), a.z.max(b.z)),
        }
    }

    /// Does the segment `a → b` pass through this box? Slab method, clipped to the segment `[0, 1]`.
    pub fn blocks(&self, a: Position, b: Position) -> bool {
        let dir = [b.x - a.x, b.y - a.y, b.z - a.z];
        let orig = [a.x, a.y, a.z];
        let lo = [self.min.x, self.min.y, self.min.z];
        let hi = [self.max.x, self.max.y, self.max.z];
        let mut tmin = 0.0f64;
        let mut tmax = 1.0f64;
        for i in 0..3 {
            if dir[i].abs() < 1e-9 {
                // Segment parallel to this slab: it can only cross if it starts inside the slab.
                if orig[i] < lo[i] || orig[i] > hi[i] {
                    return false;
                }
            } else {
                let inv = 1.0 / dir[i];
                let mut t1 = (lo[i] - orig[i]) * inv;
                let mut t2 = (hi[i] - orig[i]) * inv;
                if t1 > t2 {
                    std::mem::swap(&mut t1, &mut t2);
                }
                tmin = tmin.max(t1);
                tmax = tmax.min(t2);
                if tmin > tmax {
                    return false;
                }
            }
        }
        true
    }
}

/// A [`PropagationModel`] that adds line-of-sight obstruction over a base model.
pub struct ObstructedPropagation {
    base: Arc<dyn PropagationModel>,
    obstacles: Vec<Obstacle>,
    /// Attenuation (dB) applied per obstacle the tx→rx path crosses.
    obstruction_loss_db: f64,
    /// RSSI floor (dBm): below this, an obstructed frame is dropped.
    min_rssi_dbm: f64,
}

impl ObstructedPropagation {
    /// Wrap `base` so `obstacles` obstruct it. Default: 200 dB/obstacle (a hard blocker) and a
    /// noise-floor RSSI cutoff.
    pub fn new(base: Arc<dyn PropagationModel>, obstacles: Vec<Obstacle>) -> Self {
        Self {
            base,
            obstacles,
            obstruction_loss_db: 200.0,
            min_rssi_dbm: NOISE_FLOOR_DBM,
        }
    }

    /// Set the per-obstacle attenuation (dB). A small value (e.g. 10) models partial obstruction.
    pub fn with_loss_db(mut self, loss_db: f64) -> Self {
        self.obstruction_loss_db = loss_db;
        self
    }

    /// Set the RSSI floor (dBm) below which an obstructed frame is dropped.
    pub fn with_min_rssi_dbm(mut self, min_rssi_dbm: f64) -> Self {
        self.min_rssi_dbm = min_rssi_dbm;
        self
    }
}

impl PropagationModel for ObstructedPropagation {
    fn deliver(&self, ctx: &TxContext) -> Delivery {
        let mut d = self.base.deliver(ctx);
        let crossed = self
            .obstacles
            .iter()
            .filter(|o| o.blocks(ctx.tx_pos, ctx.rx_pos))
            .count();
        if crossed > 0 {
            d.rssi_dbm -= self.obstruction_loss_db * crossed as f64;
            if d.rssi_dbm < self.min_rssi_dbm {
                d.delivered = false;
                d.reason = DeliveryReason::Obstructed;
            }
        }
        d
    }

    fn max_range_m(&self) -> f64 {
        // Obstruction only ever reduces range, so the base bound still holds.
        self.base.max_range_m()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::medium::RangeThreshold;

    fn box_10() -> Obstacle {
        // A 2 m-wide wall centred at x=5, spanning y∈[-5,5], tall.
        Obstacle::from_corners(Position::xyz(4.0, -5.0, 0.0), Position::xyz(6.0, 5.0, 10.0))
    }

    #[test]
    fn segment_through_box_is_blocked_and_around_is_clear() {
        let o = box_10();
        // Straight through the wall (0,0)→(10,0).
        assert!(o.blocks(Position::xy(0.0, 0.0), Position::xy(10.0, 0.0)));
        // Around the wall (y = 10, outside the wall's y-span).
        assert!(!o.blocks(Position::xy(0.0, 10.0), Position::xy(10.0, 10.0)));
        // Both endpoints on the same side — never reaches the wall.
        assert!(!o.blocks(Position::xy(0.0, 0.0), Position::xy(3.0, 0.0)));
    }

    #[test]
    fn obstruction_blocks_delivery_that_the_base_would_allow() {
        let base = Arc::new(RangeThreshold {
            range_m: 100.0,
            tx_power_dbm: 20.0,
        });
        let obstructed = ObstructedPropagation::new(base.clone(), vec![box_10()]);
        let env = crate::world::FreeSpace;
        let ctx = |rx: Position| TxContext {
            tx_pos: Position::xy(0.0, 0.0),
            rx_pos: rx,
            tx_power_dbm: 20.0,
            environment: &env,
            frame_len: 100,
        };
        // In range, clear path (rx off to the side, above the wall's y-span) → delivered.
        assert!(obstructed.deliver(&ctx(Position::xy(10.0, 20.0))).delivered);
        // In range, but the wall is directly between (0,0) and (10,0) → blocked.
        assert!(!obstructed.deliver(&ctx(Position::xy(10.0, 0.0))).delivered);
        // The base model alone would have delivered it.
        assert!(base.deliver(&ctx(Position::xy(10.0, 0.0))).delivered);
    }

    #[test]
    fn partial_loss_attenuates_without_blocking() {
        let base = Arc::new(RangeThreshold {
            range_m: 100.0,
            tx_power_dbm: 20.0,
        });
        let obstructed = ObstructedPropagation::new(base, vec![box_10()]).with_loss_db(10.0);
        let env = crate::world::FreeSpace;
        let d = obstructed.deliver(&TxContext {
            tx_pos: Position::xy(0.0, 0.0),
            rx_pos: Position::xy(10.0, 0.0),
            tx_power_dbm: 20.0,
            environment: &env,
            frame_len: 100,
        });
        // 10 dB of foliage loss doesn't drop the frame, but the RSSI reflects it.
        assert!(d.delivered, "10 dB partial loss should not block");
        assert!(d.rssi_dbm < 20.0, "RSSI attenuated by the obstruction");
    }
}
