//! A **pluggable multi-radio PHY** — channels, antennas, propagation, and interference as swappable
//! backends, so the fidelity of each can be raised (or a whole model replaced) independently and
//! iterated over time. Nothing here commits to one physics implementation: the traits are the
//! contract; the bundled types are a *reference* baseline.
//!
//! **Scope note (F7):** the on-air Wi-Fi path — [`RadioBus`](crate::RadioBus) — computes propagation and
//! SINR through [`crate::medium`]'s `PropagationModel`, **not** through this module's `RadioEnvironment` /
//! antenna / self-interference composition. Today `phy` backs the **LoRa** propagation ([`crate::lora`]
//! via `PropagationBackend`); the richer multi-radio/antenna model here is a reference not yet wired to
//! `RadioBus`, so `medium.rs` is the single source of truth for the simulated Wi-Fi radio face.
//!
//! A node is a [`RadioPlatform`] carrying **several** [`Radio`]s (multi-radio, multi-channel), each
//! with its own [`Channel`] and [`AntennaPlacement`]. A [`RadioEnvironment`] composes a
//! [`PropagationBackend`] (path loss + antenna gains → received power) and an [`InterferenceBackend`]
//! (how concurrent transmissions combine into interference) to compute the **SINR** at a victim
//! radio. The interference backend models the interactions that matter and are usually skipped:
//!
//! - **Adjacent/co-channel rejection** — orthogonal channels reject, but by a *finite* amount.
//! - **Self-interference** — a platform's own radios leak into each other **even on orthogonal
//!   channels** (finite TX↔RX isolation, PA nonlinearity), floored by a hardware cap.
//! - **Antenna coupling** — two co-located antennas couple; isolation falls as they get closer.
//!
//! Swap in a ray-tracer, a measured antenna pattern, or a full-duplex self-interference-cancellation
//! model by implementing the trait — the rest of the sim is unchanged.

use std::sync::Arc;

/// Speed of light (m/s).
const C: f64 = 299_792_458.0;

// ---------------------------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------------------------

/// A frequency channel: a centre and a bandwidth.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Channel {
    pub center_hz: f64,
    pub bandwidth_hz: f64,
}

impl Channel {
    /// A 20 MHz 2.4 GHz Wi-Fi channel (1..=14; ch14 special-cased to 2484 MHz).
    pub fn wifi_2g(ch: u8) -> Self {
        let center = if ch == 14 { 2_484e6 } else { 2_412e6 + (ch as f64 - 1.0) * 5e6 };
        Channel { center_hz: center, bandwidth_hz: 20e6 }
    }
    /// A 20 MHz 5 GHz Wi-Fi channel (non-DFS lower band approximation).
    pub fn wifi_5g(ch: u8) -> Self {
        Channel { center_hz: 5_000e6 + ch as f64 * 5e6, bandwidth_hz: 20e6 }
    }
    fn low(&self) -> f64 {
        self.center_hz - self.bandwidth_hz / 2.0
    }
    fn high(&self) -> f64 {
        self.center_hz + self.bandwidth_hz / 2.0
    }
    /// Spectral overlap (Hz) with another channel.
    pub fn overlap_hz(&self, other: &Channel) -> f64 {
        (self.high().min(other.high()) - self.low().max(other.low())).max(0.0)
    }
    /// Overlap as a fraction of the narrower channel (`0` orthogonal, `1` fully co-channel).
    pub fn overlap_fraction(&self, other: &Channel) -> f64 {
        let narrower = self.bandwidth_hz.min(other.bandwidth_hz);
        if narrower <= 0.0 { 0.0 } else { self.overlap_hz(other) / narrower }
    }
    /// Centre-frequency separation (Hz).
    pub fn separation_hz(&self, other: &Channel) -> f64 {
        (self.center_hz - other.center_hz).abs()
    }
}

// ---------------------------------------------------------------------------------------------
// Antennas
// ---------------------------------------------------------------------------------------------

/// A pluggable antenna radiation pattern. `gain_dbi` is the gain toward `(azimuth, elevation)`
/// (radians) in the antenna's local frame, where boresight is `(0, 0)`.
pub trait Antenna: Send + Sync + std::fmt::Debug {
    fn gain_dbi(&self, azimuth: f64, elevation: f64) -> f64;
    fn name(&self) -> &'static str;
}

/// An ideal isotropic radiator (constant gain everywhere).
#[derive(Clone, Copy, Debug)]
pub struct Isotropic {
    pub gain_dbi: f64,
}
impl Antenna for Isotropic {
    fn gain_dbi(&self, _az: f64, _el: f64) -> f64 {
        self.gain_dbi
    }
    fn name(&self) -> &'static str {
        "isotropic"
    }
}

/// A half-wave dipole: omnidirectional in azimuth, ~2.15 dBi peak at the horizon, nulls at the poles.
#[derive(Clone, Copy, Debug, Default)]
pub struct Dipole;
impl Antenna for Dipole {
    fn gain_dbi(&self, _az: f64, el: f64) -> f64 {
        // Pattern ∝ cos(el) about the horizontal plane; 2.15 dBi at el=0, deep null toward the poles.
        let c = el.cos().abs().max(1e-3);
        2.15 + 20.0 * c.log10()
    }
    fn name(&self) -> &'static str {
        "dipole"
    }
}

/// A directional antenna: a `peak_dbi` main lobe of half-power `beamwidth`, with a back-lobe floor.
#[derive(Clone, Copy, Debug)]
pub struct Directional {
    pub peak_dbi: f64,
    pub beamwidth_rad: f64,
    pub back_lobe_dbi: f64,
}
impl Antenna for Directional {
    fn gain_dbi(&self, az: f64, el: f64) -> f64 {
        // Angle off boresight (small-angle combine of az + el).
        let off = (az * az + el * el).sqrt();
        // −3 dB at half the beamwidth; cos^n roll-off, floored at the back lobe.
        let cos = (off).cos().max(0.0);
        let n = (0.5f64.log10()) / (self.beamwidth_rad / 2.0).cos().max(1e-3).log10();
        (self.peak_dbi + 10.0 * n * cos.max(1e-3).log10()).max(self.back_lobe_dbi)
    }
    fn name(&self) -> &'static str {
        "directional"
    }
}

/// An antenna mounted on a platform: an offset from the platform centre, a boresight orientation,
/// and the radiation pattern.
#[derive(Clone, Debug)]
pub struct AntennaPlacement {
    /// Offset (m) from the platform centre `[x, y, z]`.
    pub offset: [f64; 3],
    /// Boresight direction: azimuth + elevation (radians), in the platform frame.
    pub boresight_az: f64,
    pub boresight_el: f64,
    pub antenna: Arc<dyn Antenna>,
}

impl AntennaPlacement {
    pub fn omni(antenna: Arc<dyn Antenna>) -> Self {
        AntennaPlacement { offset: [0.0; 3], boresight_az: 0.0, boresight_el: 0.0, antenna }
    }
    /// Gain toward a world-frame direction `(az, el)` (accounts for the boresight orientation).
    pub fn gain_toward(&self, az: f64, el: f64) -> f64 {
        self.antenna.gain_dbi(az - self.boresight_az, el - self.boresight_el)
    }
}

// ---------------------------------------------------------------------------------------------
// Radios + platforms
// ---------------------------------------------------------------------------------------------

/// A transceiver: a channel, a transmit power, and a mounted antenna.
#[derive(Clone, Debug)]
pub struct Radio {
    pub id: usize,
    pub channel: Channel,
    pub tx_power_dbm: f64,
    pub antenna: AntennaPlacement,
}

/// A node platform carrying one or more radios (multi-radio, multi-channel).
#[derive(Clone, Debug)]
pub struct RadioPlatform {
    pub position: [f64; 3],
    /// Platform heading (yaw, radians) — rotates every antenna's boresight.
    pub yaw: f64,
    pub radios: Vec<Radio>,
}

impl RadioPlatform {
    /// World-frame position of a radio's antenna (platform centre + rotated offset).
    fn antenna_world_pos(&self, radio: &Radio) -> [f64; 3] {
        let [ox, oy, oz] = radio.antenna.offset;
        let (s, c) = self.yaw.sin_cos();
        [self.position[0] + c * ox - s * oy, self.position[1] + s * ox + c * oy, self.position[2] + oz]
    }
}

/// Azimuth + elevation (radians) of `to` as seen from `from`.
fn az_el(from: [f64; 3], to: [f64; 3]) -> (f64, f64) {
    let d = [to[0] - from[0], to[1] - from[1], to[2] - from[2]];
    let az = d[1].atan2(d[0]);
    let horiz = (d[0] * d[0] + d[1] * d[1]).sqrt();
    let el = d[2].atan2(horiz.max(1e-9));
    (az, el)
}

fn distance(a: [f64; 3], b: [f64; 3]) -> f64 {
    ((a[0] - b[0]).powi(2) + (a[1] - b[1]).powi(2) + (a[2] - b[2]).powi(2)).sqrt()
}

// ---------------------------------------------------------------------------------------------
// Propagation backend (pluggable)
// ---------------------------------------------------------------------------------------------

/// The geometry + gains of one tx→rx path, handed to a [`PropagationBackend`].
#[derive(Clone, Copy, Debug)]
pub struct PathContext {
    pub distance_m: f64,
    pub freq_hz: f64,
    pub tx_power_dbm: f64,
    pub tx_gain_dbi: f64,
    pub rx_gain_dbi: f64,
}

/// Computes received power (dBm) for a path. Swap FreeSpace for a two-ray, log-distance, or
/// ray-traced model without touching the rest of the sim.
pub trait PropagationBackend: Send + Sync {
    fn rx_power_dbm(&self, ctx: &PathContext) -> f64;
    fn name(&self) -> &'static str;
}

/// Friis free-space: `Prx = Ptx + Gtx + Grx − FSPL(d, f)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct FreeSpace;
impl PropagationBackend for FreeSpace {
    fn rx_power_dbm(&self, ctx: &PathContext) -> f64 {
        let d = ctx.distance_m.max(1.0);
        let fspl = 20.0 * d.log10() + 20.0 * ctx.freq_hz.log10() - 147.55;
        ctx.tx_power_dbm + ctx.tx_gain_dbi + ctx.rx_gain_dbi - fspl
    }
    fn name(&self) -> &'static str {
        "free-space"
    }
}

/// Log-distance path loss: `PL = ref_loss + 10·n·log10(d/ref_dist)` — a tunable environment
/// (n≈2 free space, ≈3–4 urban/indoor).
#[derive(Clone, Copy, Debug)]
pub struct LogDistance {
    pub exponent: f64,
    pub ref_loss_db: f64,
    pub ref_dist_m: f64,
}
impl PropagationBackend for LogDistance {
    fn rx_power_dbm(&self, ctx: &PathContext) -> f64 {
        let d = ctx.distance_m.max(self.ref_dist_m);
        let pl = self.ref_loss_db + 10.0 * self.exponent * (d / self.ref_dist_m).log10();
        ctx.tx_power_dbm + ctx.tx_gain_dbi + ctx.rx_gain_dbi - pl
    }
    fn name(&self) -> &'static str {
        "log-distance"
    }
}

// ---------------------------------------------------------------------------------------------
// Interference backend (pluggable) — the interactions usually skipped
// ---------------------------------------------------------------------------------------------

/// Models how a transmission interferes with a victim radio: cross-channel rejection, on-platform
/// self-interference (finite even for orthogonal channels), and co-located antenna coupling. Swap in
/// a full-duplex cancellation model, measured coupling matrices, etc.
pub trait InterferenceBackend: Send + Sync {
    /// Rejection (dB) of an interferer on `interferer`'s channel by a receiver tuned to `victim`'s.
    /// 0 dB = fully co-channel; large = well-separated (but never infinite for a real filter).
    fn channel_rejection_db(&self, victim: &Channel, interferer: &Channel) -> f64;
    /// TX↔RX isolation (dB) between two radios on the **same platform** — the self-interference path.
    /// Finite even on orthogonal channels (leakage + PA nonlinearity), capped by hardware.
    fn self_isolation_db(&self, victim: &Radio, aggressor: &Radio, platform: &RadioPlatform) -> f64;
    /// Isolation (dB) from physical antenna coupling between two co-located antennas at `freq_hz`.
    fn antenna_coupling_db(&self, a: &AntennaPlacement, b: &AntennaPlacement, freq_hz: f64) -> f64;
    fn name(&self) -> &'static str;
}

/// A reasonable baseline interference model. Every figure is a knob for iteration.
#[derive(Clone, Copy, Debug)]
pub struct DefaultInterference {
    /// Adjacent-channel rejection per channel-bandwidth of separation (dB) — filter roll-off.
    pub adjacent_reject_db_per_bw: f64,
    /// Baseline on-board TX↔RX isolation (dB) before channel filtering + antenna separation.
    pub base_self_isolation_db: f64,
    /// The hardware floor: self-isolation cannot exceed this however orthogonal the channels are
    /// (PA nonlinearity, phase noise, ADC spurs) — why orthogonal channels still self-interfere.
    pub self_isolation_cap_db: f64,
}

impl Default for DefaultInterference {
    fn default() -> Self {
        DefaultInterference {
            adjacent_reject_db_per_bw: 25.0,
            base_self_isolation_db: 40.0,
            self_isolation_cap_db: 65.0,
        }
    }
}

impl InterferenceBackend for DefaultInterference {
    fn channel_rejection_db(&self, victim: &Channel, interferer: &Channel) -> f64 {
        let overlap = victim.overlap_fraction(interferer);
        if overlap >= 1.0 {
            return 0.0; // fully co-channel
        }
        // Rejection grows with centre separation (in victim bandwidths), reduced by any overlap.
        let bws = victim.separation_hz(interferer) / victim.bandwidth_hz.max(1.0);
        (self.adjacent_reject_db_per_bw * bws) * (1.0 - overlap)
    }
    fn self_isolation_db(&self, victim: &Radio, aggressor: &Radio, platform: &RadioPlatform) -> f64 {
        // Total isolation = board isolation + channel-filter rejection + antenna coupling isolation,
        // but never more than the hardware cap (the crux: orthogonal ≠ infinite isolation).
        let reject = self.channel_rejection_db(&victim.channel, &aggressor.channel);
        let coupling =
            self.antenna_coupling_db(&victim.antenna, &aggressor.antenna, victim.channel.center_hz);
        let _ = platform;
        (self.base_self_isolation_db + reject + coupling).min(self.self_isolation_cap_db)
    }
    fn antenna_coupling_db(&self, a: &AntennaPlacement, b: &AntennaPlacement, freq_hz: f64) -> f64 {
        // Free-space-ish isolation between two nearby antennas: ~22 + 20·log10(d/λ). Closer antennas
        // couple more (less isolation). Clamp so co-located antennas still have *some* isolation.
        let sep = distance(a.offset, b.offset).max(1e-3);
        let lambda = C / freq_hz.max(1.0);
        (22.0 + 20.0 * (sep / lambda).log10()).clamp(0.0, 80.0)
    }
    fn name(&self) -> &'static str {
        "default-interference"
    }
}

// ---------------------------------------------------------------------------------------------
// The environment: compose backends → SINR
// ---------------------------------------------------------------------------------------------

/// A transmitting radio on its platform.
#[derive(Clone, Copy)]
pub struct TxRef<'a> {
    pub platform: &'a RadioPlatform,
    pub radio: &'a Radio,
}

/// Composes a propagation + interference backend + a noise floor to compute link SINR.
pub struct RadioEnvironment {
    pub propagation: Arc<dyn PropagationBackend>,
    pub interference: Arc<dyn InterferenceBackend>,
    pub noise_floor_dbm: f64,
}

impl RadioEnvironment {
    pub fn new(
        propagation: Arc<dyn PropagationBackend>,
        interference: Arc<dyn InterferenceBackend>,
    ) -> Self {
        RadioEnvironment { propagation, interference, noise_floor_dbm: -95.0 }
    }

    /// Received power (dBm) of `tx`'s signal at `victim` (on `victim_platform`), accounting for
    /// distance, both antennas' gains, and cross-channel rejection.
    pub fn rx_power_dbm(
        &self,
        victim: &Radio,
        victim_platform: &RadioPlatform,
        tx: TxRef,
    ) -> f64 {
        let tx_pos = tx.platform.antenna_world_pos(tx.radio);
        let rx_pos = victim_platform.antenna_world_pos(victim);
        let (az_t, el_t) = az_el(tx_pos, rx_pos);
        let (az_r, el_r) = az_el(rx_pos, tx_pos);
        let ctx = PathContext {
            distance_m: distance(tx_pos, rx_pos),
            freq_hz: victim.channel.center_hz,
            tx_power_dbm: tx.radio.tx_power_dbm,
            tx_gain_dbi: tx.radio.antenna.gain_toward(az_t - tx.platform.yaw, el_t),
            rx_gain_dbi: victim.antenna.gain_toward(az_r - victim_platform.yaw, el_r),
        };
        self.propagation.rx_power_dbm(&ctx)
            - self.interference.channel_rejection_db(&victim.channel, &tx.radio.channel)
    }

    /// SINR (dB) at `victim` receiving `signal`, with a set of `concurrent` interferers (including,
    /// if listed, other radios on the victim's own platform — self-interference).
    pub fn sinr_db(
        &self,
        victim: &Radio,
        victim_platform: &RadioPlatform,
        signal: TxRef,
        concurrent: &[TxRef],
    ) -> f64 {
        let signal_mw = dbm_to_mw(self.rx_power_dbm(victim, victim_platform, signal));
        let noise_mw = dbm_to_mw(self.noise_floor_dbm);
        let mut interf_mw = 0.0;
        for tx in concurrent {
            let same_platform = std::ptr::eq(tx.platform, victim_platform);
            let i_dbm = if same_platform {
                // Self-interference: the aggressor's power minus the platform's TX↔RX isolation.
                tx.radio.tx_power_dbm
                    - self.interference.self_isolation_db(victim, tx.radio, victim_platform)
            } else {
                self.rx_power_dbm(victim, victim_platform, *tx)
            };
            interf_mw += dbm_to_mw(i_dbm);
        }
        10.0 * (signal_mw / (noise_mw + interf_mw)).log10()
    }
}

fn dbm_to_mw(dbm: f64) -> f64 {
    10f64.powf(dbm / 10.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn platform(pos: [f64; 3], radios: Vec<Radio>) -> RadioPlatform {
        RadioPlatform { position: pos, yaw: 0.0, radios }
    }
    fn radio(id: usize, ch: u8, offset: [f64; 3]) -> Radio {
        Radio {
            id,
            channel: Channel::wifi_2g(ch),
            tx_power_dbm: 20.0,
            antenna: AntennaPlacement {
                offset,
                boresight_az: 0.0,
                boresight_el: 0.0,
                antenna: Arc::new(Isotropic { gain_dbi: 0.0 }),
            },
        }
    }

    #[test]
    fn channels_overlap_and_separate() {
        let c1 = Channel::wifi_2g(1);
        let c6 = Channel::wifi_2g(6); // 25 MHz away, 20 MHz BW ⇒ non-overlapping
        let c3 = Channel::wifi_2g(3); // 10 MHz away ⇒ overlaps
        assert_eq!(c1.overlap_fraction(&c1), 1.0);
        assert!(c1.overlap_fraction(&c6) == 0.0, "1 and 6 don't overlap");
        assert!(c1.overlap_fraction(&c3) > 0.0, "1 and 3 overlap");
    }

    #[test]
    fn directional_antenna_gain_peaks_on_boresight() {
        let d = Directional { peak_dbi: 12.0, beamwidth_rad: 0.5, back_lobe_dbi: -10.0 };
        let on = d.gain_dbi(0.0, 0.0);
        let off = d.gain_dbi(1.2, 0.0); // well off boresight
        assert!(on > off + 5.0, "gain peaks on boresight ({on} ≫ {off})");
        assert!((on - 12.0).abs() < 0.01, "boresight ≈ peak");
    }

    #[test]
    fn orthogonal_channels_still_self_interfere() {
        // Two radios on ONE platform, on non-overlapping channels 1 and 11.
        let victim = radio(0, 1, [0.0, 0.0, 0.0]);
        let aggressor = radio(1, 11, [0.05, 0.0, 0.0]); // 5 cm apart
        let plat = platform([0.0, 0.0, 0.0], vec![victim.clone(), aggressor.clone()]);
        let itf = DefaultInterference::default();
        let iso = itf.self_isolation_db(&victim, &aggressor, &plat);
        // Isolation is capped (hardware floor) ⇒ the aggressor's 20 dBm leaks in well above noise.
        assert!(iso <= itf.self_isolation_cap_db, "orthogonal channels don't give infinite isolation");
        let self_interf_dbm = aggressor.tx_power_dbm - iso;
        assert!(self_interf_dbm > -95.0, "self-interference sits above the noise floor ({self_interf_dbm} dBm)");
    }

    #[test]
    fn antenna_coupling_rises_as_antennas_approach() {
        let itf = DefaultInterference::default();
        let far = AntennaPlacement::omni(Arc::new(Isotropic { gain_dbi: 0.0 }));
        let a = AntennaPlacement { offset: [0.5, 0.0, 0.0], ..far.clone() };
        let b = AntennaPlacement { offset: [0.02, 0.0, 0.0], ..far.clone() };
        let origin = AntennaPlacement { offset: [0.0, 0.0, 0.0], ..far };
        let iso_far = itf.antenna_coupling_db(&origin, &a, 2.4e9);
        let iso_near = itf.antenna_coupling_db(&origin, &b, 2.4e9);
        assert!(iso_near < iso_far, "closer antennas couple more (less isolation): {iso_near} < {iso_far}");
    }

    #[test]
    fn sinr_drops_when_an_interferer_is_added() {
        let env = RadioEnvironment::new(Arc::new(FreeSpace), Arc::new(DefaultInterference::default()));
        let rx = radio(0, 1, [0.0; 3]);
        let rx_plat = platform([0.0, 0.0, 0.0], vec![rx.clone()]);
        let tx = radio(0, 1, [0.0; 3]);
        let tx_plat = platform([100.0, 0.0, 0.0], vec![tx.clone()]);
        let itf = radio(0, 1, [0.0; 3]);
        let itf_plat = platform([120.0, 0.0, 0.0], vec![itf.clone()]);

        let clean = env.sinr_db(&rx, &rx_plat, TxRef { platform: &tx_plat, radio: &tx }, &[]);
        let jammed = env.sinr_db(
            &rx,
            &rx_plat,
            TxRef { platform: &tx_plat, radio: &tx },
            &[TxRef { platform: &itf_plat, radio: &itf }],
        );
        assert!(jammed < clean - 3.0, "a co-channel interferer lowers SINR ({jammed} < {clean})");
    }
}
