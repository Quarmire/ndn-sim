//! App lifecycle (ndn-lab follow-on): declarative **apps** on a node, so the palette MCP/GUI and
//! scenarios draw from is more than `{forwarder}`. An [`AppSpec`] says "a producer of `/foo`
//! here, a consumer of `/foo` there"; the fabric spawns it on the node's real engine and tracks
//! it as an [`AppHandle`] you can stop.
//!
//! Every app records a protocol-neutral [`FlowStats`] (sent / received / lost / bytes / RTT /
//! throughput) — the same shape the (future) IP flow apps populate, so a benchmark reads latency,
//! loss, and goodput the same way regardless of the stack under test. A `Producer` serves a prefix;
//! a `Consumer` and a [`TrafficPattern`]-driven `TrafficSource` fetch and *measure*.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::ForwarderEngine;
use ndn_packet::Name;
use ndn_packet::encode::InterestBuilder;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::NodeId;

/// Protocol-neutral per-flow metrics — the shape both the NDN apps here and (later) the in-sim IP
/// flow apps populate, so an NDN-vs-IP benchmark reads latency / loss / goodput identically.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct FlowStats {
    /// Requests issued (Interests expressed).
    pub sent: u64,
    /// Replies received (Data fetched / served).
    pub received: u64,
    /// Requests that timed out.
    pub lost: u64,
    /// Content bytes received.
    pub bytes: u64,
    /// Round-trip time min / max / sum (ns), over received replies.
    pub rtt_min_ns: u64,
    pub rtt_max_ns: u64,
    pub rtt_sum_ns: u64,
    /// Virtual-clock stamps of the first and last reply — the throughput measurement window.
    pub first_recv_ns: u64,
    pub last_recv_ns: u64,
}

impl FlowStats {
    /// Replies received (alias for the benchmark vocabulary).
    pub fn delivered(&self) -> u64 {
        self.received
    }
    /// Fraction of requests that timed out (`0` if none sent).
    pub fn loss_rate(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { self.lost as f64 / self.sent as f64 }
    }
    /// Mean round-trip time (ms) over received replies (`0` if none).
    pub fn mean_rtt_ms(&self) -> f64 {
        if self.received == 0 { 0.0 } else { (self.rtt_sum_ns as f64 / self.received as f64) / 1e6 }
    }
    /// Min / max RTT (ms).
    pub fn min_rtt_ms(&self) -> f64 {
        self.rtt_min_ns as f64 / 1e6
    }
    pub fn max_rtt_ms(&self) -> f64 {
        self.rtt_max_ns as f64 / 1e6
    }
    /// Goodput in bits/sec over the receive window (`0` if fewer than two replies).
    pub fn throughput_bps(&self) -> f64 {
        let span = self.last_recv_ns.saturating_sub(self.first_recv_ns);
        if span == 0 { 0.0 } else { (self.bytes as f64 * 8.0) / (span as f64 / 1e9) }
    }
}

/// Atomic accumulator behind a live app; snapshot into a [`FlowStats`].
#[derive(Default)]
pub(crate) struct FlowStatsInner {
    sent: AtomicU64,
    received: AtomicU64,
    lost: AtomicU64,
    bytes: AtomicU64,
    rtt_min_ns: AtomicU64, // u64::MAX sentinel = unset
    rtt_max_ns: AtomicU64,
    rtt_sum_ns: AtomicU64,
    first_recv_ns: AtomicU64, // 0 sentinel = unset
    last_recv_ns: AtomicU64,
}

impl FlowStatsInner {
    fn new() -> Arc<Self> {
        let s = Self::default();
        s.rtt_min_ns.store(u64::MAX, Ordering::Relaxed);
        Arc::new(s)
    }
    fn on_sent(&self) {
        self.sent.fetch_add(1, Ordering::Relaxed);
    }
    fn on_lost(&self) {
        self.lost.fetch_add(1, Ordering::Relaxed);
    }
    /// Record a received reply: bump counters, fold in the RTT, and mark the receive window.
    fn on_recv(&self, rtt_ns: u64, bytes: usize, now_ns: u64) {
        self.rtt_sum_ns.fetch_add(rtt_ns, Ordering::Relaxed);
        self.rtt_min_ns.fetch_min(rtt_ns, Ordering::Relaxed);
        self.rtt_max_ns.fetch_max(rtt_ns, Ordering::Relaxed);
        self.on_served(bytes, now_ns);
    }
    /// A reply received without an RTT to fold in (a producer serving Data).
    fn on_served(&self, bytes: usize, now_ns: u64) {
        self.received.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        let _ = self.first_recv_ns.compare_exchange(0, now_ns, Ordering::Relaxed, Ordering::Relaxed);
        self.last_recv_ns.store(now_ns, Ordering::Relaxed);
    }
    fn snapshot(&self) -> FlowStats {
        let rtt_min = self.rtt_min_ns.load(Ordering::Relaxed);
        FlowStats {
            sent: self.sent.load(Ordering::Relaxed),
            received: self.received.load(Ordering::Relaxed),
            lost: self.lost.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            rtt_min_ns: if rtt_min == u64::MAX { 0 } else { rtt_min },
            rtt_max_ns: self.rtt_max_ns.load(Ordering::Relaxed),
            rtt_sum_ns: self.rtt_sum_ns.load(Ordering::Relaxed),
            first_recv_ns: self.first_recv_ns.load(Ordering::Relaxed),
            last_recv_ns: self.last_recv_ns.load(Ordering::Relaxed),
        }
    }
    fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
}

/// A traffic-arrival process for a [`AppSpec::TrafficSource`] — the workload shape a benchmark
/// varies. All are deterministic given the seed (reproducible under the DES/virtual kernels).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "pattern", rename_all = "snake_case")]
pub enum TrafficPattern {
    /// Constant bit rate: one request every `interval_ms`.
    Cbr { interval_ms: u64 },
    /// A Poisson process: exponentially-distributed inter-arrivals with the given mean (ms).
    Poisson {
        mean_interval_ms: u64,
        #[serde(default)]
        seed: u64,
    },
    /// Bursty: `burst` requests `interval_ms` apart, then an idle `gap_ms`, repeating.
    Bursty {
        burst: u64,
        gap_ms: u64,
        #[serde(default = "default_burst_interval")]
        interval_ms: u64,
    },
}

fn default_burst_interval() -> u64 {
    5
}

impl TrafficPattern {
    /// The wait before request number `i` (0-based), advancing `rng` for the Poisson case.
    fn next_delay(&self, i: u64, rng: &mut SplitMix64) -> Duration {
        match *self {
            TrafficPattern::Cbr { interval_ms } => Duration::from_millis(interval_ms),
            TrafficPattern::Poisson { mean_interval_ms, .. } => {
                // Exponential inter-arrival: -mean * ln(1 - U), U ∈ [0,1).
                let u = rng.next_f64();
                let ms = -(mean_interval_ms as f64) * (1.0 - u).max(f64::MIN_POSITIVE).ln();
                Duration::from_secs_f64(ms / 1000.0)
            }
            TrafficPattern::Bursty { burst, gap_ms, interval_ms } => {
                let burst = burst.max(1);
                if i % burst == burst - 1 {
                    Duration::from_millis(gap_ms)
                } else {
                    Duration::from_millis(interval_ms)
                }
            }
        }
    }
}

/// A tiny deterministic PRNG (splitmix64) for the Poisson process — no `rand` dependency.
pub(crate) struct SplitMix64 {
    state: u64,
}
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

/// Stable id for a spawned app.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AppId(pub usize);

/// A declarative app — carried in scenarios and control commands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "app", rename_all = "snake_case")]
pub enum AppSpec {
    /// Serve `prefix`, answering every Interest under it with `content` (default `"ndn-lab"`).
    Producer {
        prefix: String,
        #[serde(default)]
        content: Option<String>,
        /// `FreshnessPeriod` (ms) stamped on served Data (default 4000). A positive freshness is
        /// what makes forwarders admit the Data into their Content Store — NFD's default admission
        /// policy (and ndn-rs's) rejects `FreshnessPeriod = 0`. Set `0` to opt a producer out of
        /// on-path caching.
        #[serde(default)]
        freshness_ms: Option<u64>,
    },
    /// Fetch `prefix/<i>` for `i = 0..` — `count` times (`0` = until stopped), `interval_ms`
    /// between fetches. Counts successful fetches (a constant-rate flow; see [`FlowStats`]).
    Consumer {
        prefix: String,
        #[serde(default)]
        count: u64,
        #[serde(default)]
        interval_ms: u64,
        /// Per-Interest lifetime (ms, default 4000) — this single-shot consumer waits it out on a
        /// lost segment before moving on, so a shorter lifetime makes a lossy link converge faster.
        #[serde(default)]
        lifetime_ms: Option<u64>,
    },
    /// A measured workload: fetch `prefix/<i>` for `count` requests (`0` = until stopped) with
    /// inter-arrivals from a [`TrafficPattern`] (CBR / Poisson / bursty), recording RTT, loss, and
    /// goodput into [`FlowStats`]. The benchmark workload generator.
    TrafficSource {
        prefix: String,
        pattern: TrafficPattern,
        #[serde(default)]
        count: u64,
        #[serde(default)]
        lifetime_ms: Option<u64>,
    },
}

impl AppSpec {
    pub fn kind(&self) -> &'static str {
        match self {
            AppSpec::Producer { .. } => "producer",
            AppSpec::Consumer { .. } => "consumer",
            AppSpec::TrafficSource { .. } => "traffic_source",
        }
    }
    pub fn prefix(&self) -> &str {
        match self {
            AppSpec::Producer { prefix, .. }
            | AppSpec::Consumer { prefix, .. }
            | AppSpec::TrafficSource { prefix, .. } => prefix,
        }
    }
}

/// A live app: cancel it via [`stop`](AppHandle::stop); read its progress via
/// [`successes`](AppHandle::successes) (Data served / fetched) or the full [`stats`](AppHandle::stats)
/// ([`FlowStats`]: RTT, loss, goodput).
pub struct AppHandle {
    id: AppId,
    node: NodeId,
    kind: &'static str,
    cancel: CancellationToken,
    stats: Arc<FlowStatsInner>,
}

impl AppHandle {
    pub fn id(&self) -> AppId {
        self.id
    }
    pub fn node(&self) -> NodeId {
        self.node
    }
    pub fn kind(&self) -> &'static str {
        self.kind
    }
    /// Data served (producer) or fetched (consumer/traffic-source) so far.
    pub fn successes(&self) -> u64 {
        self.stats.received()
    }
    /// The full protocol-neutral flow metrics (sent/received/lost/bytes/RTT/goodput).
    pub fn stats(&self) -> FlowStats {
        self.stats.snapshot()
    }
    /// Stop the app (cancels its tasks; the engine drops its app face).
    pub fn stop(&self) {
        self.cancel.cancel();
    }
}

/// Spawn `spec` on `engine` (the engine of `node`), returning a handle. Validates the prefix.
pub(crate) fn spawn_app(
    engine: &ForwarderEngine,
    id: AppId,
    node: NodeId,
    spec: &AppSpec,
) -> anyhow::Result<AppHandle> {

    let cancel = CancellationToken::new();
    let stats = FlowStatsInner::new();
    let prefix: Name = spec
        .prefix()
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid app prefix {:?}: {e}", spec.prefix()))?;
    let clock = engine.runtime();

    match spec {
        AppSpec::Producer { content, freshness_ms, .. } => {
            let producer = engine.register_producer(prefix, cancel.clone());
            let bytes = Bytes::from(content.clone().unwrap_or_else(|| "ndn-lab".to_string()));
            let served = Arc::clone(&stats);
            let clock = Arc::clone(&clock);
            // Real producers stamp a FreshnessPeriod; without one, forwarders won't cache the Data
            // (DefaultAdmissionPolicy rejects freshness=0, as NFD does). Default 4 s.
            let freshness = Duration::from_millis(freshness_ms.unwrap_or(4000));
            // rt::spawn rides the ambient runtime (virtual / discrete-event) when one is set.
            ndn_app::rt::spawn(async move {
                let _ = producer
                    .serve(move |interest, responder| {
                        let bytes = bytes.clone();
                        let served = Arc::clone(&served);
                        let clock = Arc::clone(&clock);
                        async move {
                            let wire = ndn_packet::encode::DataBuilder::new(
                                (*interest.name).clone(),
                                &bytes,
                            )
                            .freshness(freshness)
                            .build();
                            let n = bytes.len();
                            if responder.respond_bytes(wire).await.is_ok() {
                                served.on_served(n, clock.unix_nanos());
                            }
                        }
                    })
                    .await;
            });
            Ok(AppHandle { id, node, kind: "producer", cancel, stats })
        }
        AppSpec::Consumer { prefix: pfx, count, interval_ms, lifetime_ms } => {
            // Unbounded consumers get a default 50 ms pace so they don't busy-loop.
            let interval = match (*interval_ms, *count) {
                (0, 0) => Duration::from_millis(50),
                (ms, _) => Duration::from_millis(ms),
            };
            spawn_fetch_loop(
                engine,
                cancel.clone(),
                Arc::clone(&stats),
                clock,
                pfx.clone(),
                *count,
                lifetime_ms.unwrap_or(4000),
                move |_i, _rng| interval,
            );
            Ok(AppHandle { id, node, kind: "consumer", cancel, stats })
        }
        AppSpec::TrafficSource { prefix: pfx, pattern, count, lifetime_ms } => {
            let pattern = *pattern;
            spawn_fetch_loop(
                engine,
                cancel.clone(),
                Arc::clone(&stats),
                clock,
                pfx.clone(),
                *count,
                lifetime_ms.unwrap_or(4000),
                move |i, rng| pattern.next_delay(i, rng),
            );
            Ok(AppHandle { id, node, kind: "traffic_source", cancel, stats })
        }
    }
}

/// The shared measured-fetch loop behind `Consumer` and `TrafficSource`: express `prefix/<i>`,
/// time the round trip into `stats`, then wait `delay(i, rng)` before the next. `count == 0` runs
/// until cancelled. Seeded PRNG (id-independent here; the pattern carries its own seed).
#[allow(clippy::too_many_arguments)]
fn spawn_fetch_loop(
    engine: &ForwarderEngine,
    cancel: CancellationToken,
    stats: Arc<FlowStatsInner>,
    clock: Arc<dyn ndn_runtime::Runtime>,
    prefix: String,
    count: u64,
    lifetime_ms: u64,
    delay: impl Fn(u64, &mut SplitMix64) -> Duration + Send + 'static,
) {
    let mut consumer = engine.app_consumer(cancel.clone());
    let lifetime = Duration::from_millis(lifetime_ms);
    // Seed the Poisson clock from the prefix so distinct sources draw distinct (reproducible) streams.
    let seed = prefix.bytes().fold(0xcbf2_9ce4_8422_2325u64, |h, b| (h ^ b as u64).wrapping_mul(0x1000_0000_01b3));
    ndn_app::rt::spawn(async move {
        let mut rng = SplitMix64::new(seed);
        let mut i = 0u64;
        while !cancel.is_cancelled() && (count == 0 || i < count) {
            if let Ok(name) = format!("{prefix}/{i}").parse::<Name>() {
                let builder = InterestBuilder::new(name).lifetime(lifetime);
                stats.on_sent();
                let t0 = clock.unix_nanos();
                match consumer.fetch_with(builder).await {
                    Ok(data) => {
                        let t1 = clock.unix_nanos();
                        let bytes = data.content().map(|c| c.len()).unwrap_or(0);
                        stats.on_recv(t1.saturating_sub(t0), bytes, t1);
                    }
                    Err(_) => stats.on_lost(),
                }
            }
            i += 1;
            let wait = delay(i.saturating_sub(1), &mut rng);
            if !wait.is_zero() {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = ndn_app::rt::sleep(wait) => {}
                }
            }
        }
    });
}
