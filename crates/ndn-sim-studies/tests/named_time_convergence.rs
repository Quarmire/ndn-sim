//! Multi-node named-time convergence (design §9), end-to-end.
//!
//! Six nodes with disparate physical clocks — one GNSS reference and five
//! free-running oscillators scattered over ±9 ms and drifting — exchange **real**
//! signed-beacon payloads ([`ndn_timekeeper::beacon_wire`]) over a lossy
//! broadcast medium, each running a **real** [`Timekeeper`]. On a virtual clock
//! we watch the ensemble converge to the reference and hold there despite drift
//! and 40 % packet loss.
//!
//! This drives the actual named-time runtime + wire codec end-to-end across
//! nodes. It models the beacon **medium** (broadcast + loss) rather than routing
//! each beacon as signed Data through ndn-sim's forwarding kernel — the
//! full-stack carriage (beacons as `SafeData` over SVS through real engines) is
//! the remaining integration; the convergence behaviour it would exercise is
//! exactly what this proves. Everything is deterministic (a fixed-seed LCG
//! drives the loss), so the run is reproducible and the assertions cannot flake.

use ndn_time::provenance::{Authenticity, KeyId, MeasurementProvenance, PathId};
use ndn_time::{ClockCapability, Discipline, TimeInterval, TimePolicy};
use ndn_time_sources::Reading;
use ndn_timekeeper::{Timekeeper, beacon_wire};

/// A node's physical clock: it reads true time offset by `offset_ns` and running
/// fast/slow by `drift_ppb`. The discipline loop steers `offset_ns`; `drift_ppb`
/// is the intrinsic error the loop must keep tracking out.
#[derive(Clone, Copy)]
struct PhysClock {
    offset_ns: i64,
    drift_ppb: i64,
}

impl PhysClock {
    /// Wall reading at relative true time `t_ns` (the sim runs in relative time
    /// from 0 to keep drift·t within i64).
    fn wall(&self, t_ns: i64) -> i64 {
        t_ns + self.offset_ns + self.drift_ppb * t_ns / 1_000_000_000
    }

    /// Apply a discipline action over `dt_ns` of elapsed time.
    fn steer(&mut self, d: Discipline, dt_ns: i64) {
        match d {
            Discipline::Step { correction_ns } => self.offset_ns += correction_ns,
            Discipline::Slew { rate_ppb } => self.offset_ns += rate_ppb * dt_ns / 1_000_000_000,
            // Track (a reference clock) and Withhold do not steer.
            Discipline::Track { .. } | Discipline::Withhold { .. } => {}
        }
    }
}

/// A tiny deterministic PRNG (LCG) so packet loss is reproducible.
struct Lcg(u64);
impl Lcg {
    fn drops(&mut self, loss_pct: u64) -> bool {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) % 100 < loss_pct
    }
}

/// Reception provenance for a peer's beacon: authenticated by the sender's key
/// over its own path (path-diverse), network (not distance-bounded).
fn peer_prov(sender: usize) -> MeasurementProvenance {
    MeasurementProvenance {
        distance_bounded: false,
        replay_protected: true,
        authenticity: Authenticity::AuthenticatedDomainPeer(KeyId(sender as u64)),
        path: PathId(sender as u32 + 1),
    }
}

struct Node {
    phys: PhysClock,
    tk: Timekeeper,
    cap: ClockCapability,
    self_unc_ns: u64,
    /// The uncertainty this node currently advertises (its last fix, or its raw
    /// clock before it has one).
    pub_unc_ns: u64,
    seq: u64,
}

#[test]
fn six_nodes_converge_to_the_gnss_reference_over_a_lossy_medium() {
    const N: usize = 6;
    const CADENCE_NS: i64 = 1_000_000_000; // 1 s beacon cadence
    const ROUNDS: usize = 30;
    const LOSS_PCT: u64 = 40;

    let policy = TimePolicy::default(); // step_threshold 1 ms, required 1 ms

    // Node 0 is the GNSS reference (offset 0, no drift, ±50 ns, reference clock).
    // Nodes 1..5 are free-running oscillators: scattered offsets, sub-ppm drift,
    // and an honest ±20 ms self-uncertainty (they do not know the time well).
    let osc_offsets = [8_000_000i64, -6_000_000, 4_000_000, -9_000_000, 5_000_000];
    let osc_drifts = [300i64, -250, 350, -200, 400]; // ppb, all < max_slew (500)

    let mut nodes: Vec<Node> = Vec::with_capacity(N);
    nodes.push(Node {
        phys: PhysClock {
            offset_ns: 0,
            drift_ppb: 0,
        },
        tk: Timekeeper::new(0, KeyId(0), ClockCapability::gnss_disciplined(), policy),
        cap: ClockCapability::gnss_disciplined(),
        self_unc_ns: 50,
        pub_unc_ns: 50,
        seq: 0,
    });
    for (i, (&off, &drift)) in osc_offsets.iter().zip(&osc_drifts).enumerate() {
        let id = (i + 1) as u64;
        nodes.push(Node {
            phys: PhysClock {
                offset_ns: off,
                drift_ppb: drift,
            },
            tk: Timekeeper::new(id, KeyId(id), ClockCapability::oscillator_tcxo(), policy),
            cap: ClockCapability::oscillator_tcxo(),
            self_unc_ns: 20_000_000,
            pub_unc_ns: 20_000_000,
            seq: 0,
        });
    }

    let initial_spread = osc_offsets.iter().map(|o| o.unsigned_abs()).max().unwrap();
    let mut rng = Lcg(0x1234_5678_9abc_def0);
    let mut max_err_by_round = Vec::with_capacity(ROUNDS);

    println!(
        "\nnamed-time convergence: {N} nodes (1 GNSS + 5 oscillators), \
         {LOSS_PCT}% loss, {ROUNDS} rounds\n\
         initial oscillator spread: {:.3} ms\n",
        initial_spread as f64 / 1e6
    );
    println!("  round │ max err │ mean err │ nodes synced (<100µs)");
    println!("  ──────┼─────────┼──────────┼──────────────────────");

    for r in 0..ROUNDS {
        let t = r as i64 * CADENCE_NS;

        // 1. Every node publishes a beacon of its current belief (its physical
        //    wall — already reflecting prior steers) at its advertised uncertainty.
        let published: Vec<(u64, i64, u64, ClockCapability)> = nodes
            .iter_mut()
            .map(|nd| {
                nd.seq += 1;
                (nd.seq, nd.phys.wall(t), nd.pub_unc_ns, nd.cap)
            })
            .collect();

        // 2. Broadcast over the lossy medium: node j ingests node i's beacon
        //    (i != j) unless the medium drops it. Real encode → decode → ingest.
        for (i, &(seq, wall, unc, cap)) in published.iter().enumerate() {
            let bytes = beacon_wire::encode(seq, wall, unc, &cap);
            for (j, nd) in nodes.iter_mut().enumerate() {
                if i == j || rng.drops(LOSS_PCT) {
                    continue;
                }
                let Some(dec) = beacon_wire::decode(&bytes) else {
                    continue;
                };
                let beacon = dec.into_beacon(t as u64, peer_prov(i));
                nd.tk.ingest_beacon(i as u64, &beacon);
            }
        }

        // 3. Each node folds in its own clock, disciplines, and steers.
        for nd in nodes.iter_mut() {
            let local_wall = nd.phys.wall(t);
            let reading = Reading {
                wall: TimeInterval::new(local_wall, nd.self_unc_ns),
                cap: nd.cap,
                captured_mono_ns: t as u64,
            };
            nd.tk.ingest_local_reading(&reading);
            let out = nd.tk.tick(t as u64, local_wall);
            nd.phys.steer(out.discipline, CADENCE_NS);
            if out.correction.admitted {
                nd.pub_unc_ns = out.correction.uncertainty_ns;
            }
        }

        // 4. Measure each oscillator's residual error vs true time (post-steer).
        let errs: Vec<u64> = (1..N)
            .map(|i| (nodes[i].phys.wall(t) - t).unsigned_abs())
            .collect();
        let max_err = *errs.iter().max().unwrap();
        let mean_err = errs.iter().sum::<u64>() / errs.len() as u64;
        let synced = errs.iter().filter(|&&e| e < 100_000).count();
        max_err_by_round.push(max_err);

        if r < 8 || r % 5 == 0 || r == ROUNDS - 1 {
            println!(
                "  {r:>5} │ {:>6.1}µs │ {:>7.1}µs │ {synced}/5",
                max_err as f64 / 1e3,
                mean_err as f64 / 1e3,
            );
        }
    }

    let final_err = *max_err_by_round.last().unwrap();
    let tail_max = *max_err_by_round[ROUNDS - 10..].iter().max().unwrap();
    println!(
        "\nfinal max error {:.1}µs; worst over last 10 rounds {:.1}µs\n",
        final_err as f64 / 1e3,
        tail_max as f64 / 1e3
    );

    // The scatter was real…
    assert!(
        initial_spread > 1_000_000,
        "oscillators started >1 ms apart ({initial_spread} ns)"
    );
    // …and named-time pulled them in and held them there despite drift + loss.
    assert!(
        final_err < 100_000,
        "ensemble should converge to <100µs, got {final_err} ns"
    );
    assert!(
        tail_max < 200_000,
        "converged ensemble should hold <200µs, worst tail was {tail_max} ns"
    );
}
