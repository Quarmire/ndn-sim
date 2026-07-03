//! Slice-2 tests (ndn-lab): the `VirtualKernel` — deterministic, faster-than-real-time
//! virtual scheduling. These are plain `#[test]`s (the kernel owns its own paused runtime;
//! a `#[tokio::test]` would nest runtimes and panic).
//!
//! Security note (same as the fabric tests): default node config keeps a real accept-all
//! validator — signatures are still verified; nothing is disabled.

use std::time::{Duration, Instant};

use ndn_app::EngineAppExt;
use ndn_engine::builder::EngineConfig;
use ndn_packet::encode::InterestBuilder;
use ndn_sim::{LinkConfig, SimKernel, Simulation, VirtualKernel};
use tokio_util::sync::CancellationToken;

/// Outcome of one virtual run: the fetched payload, the virtual time it took, and the
/// tracer's event projection — all of which must be identical across runs of the same
/// scenario under the virtual kernel.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    payload: Vec<u8>,
    virtual_elapsed_ns: u64,
    events: Vec<(usize, Option<u32>, String, u64)>,
}

/// A fixed scenario: consumer (A) fetches `/app/ping` from a producer (B) across a link with
/// `delay` each way. Runs entirely in virtual time on the given kernel.
async fn scenario(kernel: std::sync::Arc<dyn SimKernel>, delay: Duration) -> Outcome {
    let mut sim = Simulation::new().kernel(kernel.clone());
    let a = sim.add_node(EngineConfig::default());
    let b = sim.add_node(EngineConfig::default());
    sim.link(
        a,
        b,
        LinkConfig {
            delay,
            jitter: Duration::ZERO,
            loss_rate: 0.0,
            bandwidth_bps: 0,
        },
    );
    sim.add_route(a, "/app", b);
    let fabric = sim.start().await.unwrap();

    let producer = fabric
        .engine_of(b)
        .unwrap()
        .register_producer("/app", CancellationToken::new());
    tokio::spawn(async move {
        let _ = producer
            .serve(|interest, responder| async move {
                let _ = responder
                    .respond((*interest.name).clone(), bytes::Bytes::from_static(b"pong"))
                    .await;
            })
            .await;
    });

    let clock = kernel.runtime();
    let t0 = clock.unix_nanos();

    let mut consumer = fabric
        .engine_of(a)
        .unwrap()
        .app_consumer(CancellationToken::new());
    // Explicit long lifetime so a large virtual link delay never trips the PIT timeout.
    let builder = InterestBuilder::new("/app/ping".parse::<ndn_packet::Name>().unwrap())
        .lifetime(Duration::from_secs(30));
    let data = consumer.fetch_with(builder).await.expect("fetch");

    let virtual_elapsed_ns = clock.unix_nanos().saturating_sub(t0);

    let mut events: Vec<(usize, Option<u32>, String, u64)> = fabric
        .tracer()
        .events()
        .iter()
        .map(|e| (e.node, e.face, e.kind.to_string(), e.timestamp_us))
        .collect();
    events.sort();

    fabric.shutdown().await;
    Outcome {
        payload: data.content().map(|c| c.to_vec()).unwrap_or_default(),
        virtual_elapsed_ns,
        events,
    }
}

/// Virtual-time end-to-end: the exchange completes and virtual time advances by ~the round
/// trip (2 × link delay), even though wall-clock time barely moves.
#[test]
fn virtual_kernel_runs_exchange_in_virtual_time() {
    let kernel = VirtualKernel::new();
    let out = kernel.run(|k| scenario(k, Duration::from_millis(100)));
    assert_eq!(
        out.payload, b"pong",
        "exchange completed under virtual time"
    );
    // RTT = 2 × 100ms = 200ms of virtual time, give or take processing.
    assert!(
        out.virtual_elapsed_ns >= 200_000_000,
        "virtual time advanced through the round-trip link delay, got {} ns",
        out.virtual_elapsed_ns
    );
}

/// The headline guarantee: the same scenario + seed replays **identically** — same payload,
/// same virtual duration, same event timeline (down to virtual timestamps).
#[test]
fn virtual_kernel_is_bit_reproducible() {
    let first = VirtualKernel::new().run(|k| scenario(k, Duration::from_millis(100)));
    let second = VirtualKernel::new().run(|k| scenario(k, Duration::from_millis(100)));
    assert_eq!(
        first, second,
        "identical scenario must replay identically under virtual time"
    );
}

/// Faster-than-real-time: a scenario with seconds of virtual link delay finishes in
/// milliseconds of wall-clock time (the paused runtime jumps idle time).
#[test]
fn virtual_kernel_is_faster_than_real_time() {
    let wall_start = Instant::now();
    let out = VirtualKernel::new().run(|k| scenario(k, Duration::from_secs(3)));
    let wall = wall_start.elapsed();

    assert_eq!(out.payload, b"pong");
    assert!(
        out.virtual_elapsed_ns >= 6_000_000_000,
        "≥6 s of virtual time elapsed (2 × 3 s), got {} ns",
        out.virtual_elapsed_ns
    );
    assert!(
        wall < Duration::from_secs(2),
        "but it ran in well under wall-clock real time, took {wall:?}"
    );
}

/// A convergence predicate that never holds no longer hangs forever: `run_capped` returns a clean
/// timeout once the virtual-time budget elapses (the sleeping loop advances the clock to the cap).
#[test]
fn run_capped_turns_a_hang_into_a_clean_timeout() {
    let kernel = ndn_sim::VirtualKernel::new();
    let result: Result<(), _> =
        kernel.run_capped(std::time::Duration::from_secs(30), |_k| async move {
            // Never converges — just keeps waiting.
            loop {
                ndn_app::rt::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    assert!(
        result.is_err(),
        "the never-ending run bailed at the virtual-time cap"
    );
    assert_eq!(result.unwrap_err().cap, std::time::Duration::from_secs(30));
}

/// A run that DOES finish returns its value through the (now capped) `run`.
#[test]
fn capped_run_returns_the_value_when_it_finishes() {
    let kernel = ndn_sim::VirtualKernel::new();
    let out = kernel.run_capped(std::time::Duration::from_secs(60), |_k| async move {
        ndn_app::rt::sleep(std::time::Duration::from_secs(2)).await;
        7u32
    });
    assert_eq!(out.unwrap(), 7);
}
