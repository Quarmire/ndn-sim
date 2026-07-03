//! App lifecycle (ndn-lab follow-on): declarative **apps** on a node, so the palette MCP/GUI and
//! scenarios draw from is more than `{forwarder}`. An [`AppSpec`] says "a producer of `/foo`
//! here, a consumer of `/foo` there"; the fabric spawns it on the node's real engine and tracks
//! it as an [`AppHandle`] you can stop. This is the missing half of the tool's "test my apps"
//! pitch — previously you had to write Rust against the engine handle (what the tests do).
//!
//! Apps are intentionally simple + observable (counters), not a general app framework: a
//! `Producer` serves a prefix with fixed content; a `Consumer` fetches `prefix/<i>` a bounded or
//! unbounded number of times and counts successes. Richer apps compose on the same engine API.

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
    /// between fetches. Counts successful fetches.
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
}

impl AppSpec {
    pub fn kind(&self) -> &'static str {
        match self {
            AppSpec::Producer { .. } => "producer",
            AppSpec::Consumer { .. } => "consumer",
        }
    }
    pub fn prefix(&self) -> &str {
        match self {
            AppSpec::Producer { prefix, .. } | AppSpec::Consumer { prefix, .. } => prefix,
        }
    }
}

/// A live app: cancel it via [`stop`](AppHandle::stop); read its progress via
/// [`successes`](AppHandle::successes) (Data served / fetched).
pub struct AppHandle {
    id: AppId,
    node: NodeId,
    kind: &'static str,
    cancel: CancellationToken,
    successes: Arc<AtomicU64>,
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
    /// Data served (producer) or fetched (consumer) so far.
    pub fn successes(&self) -> u64 {
        self.successes.load(Ordering::Relaxed)
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
    let successes = Arc::new(AtomicU64::new(0));
    let prefix: Name = spec
        .prefix()
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid app prefix {:?}: {e}", spec.prefix()))?;

    match spec {
        AppSpec::Producer {
            content,
            freshness_ms,
            ..
        } => {
            let producer = engine.register_producer(prefix, cancel.clone());
            let bytes = Bytes::from(content.clone().unwrap_or_else(|| "ndn-lab".to_string()));
            let served = Arc::clone(&successes);
            // Real producers stamp a FreshnessPeriod; without one, forwarders won't cache the Data
            // (DefaultAdmissionPolicy rejects freshness=0, as NFD does). Default 4 s.
            let freshness = Duration::from_millis(freshness_ms.unwrap_or(4000));
            // rt::spawn rides the ambient runtime (virtual / discrete-event) when one is set.
            ndn_app::rt::spawn(async move {
                let _ = producer
                    .serve(move |interest, responder| {
                        let bytes = bytes.clone();
                        let served = Arc::clone(&served);
                        async move {
                            let wire = ndn_packet::encode::DataBuilder::new(
                                (*interest.name).clone(),
                                &bytes,
                            )
                            .freshness(freshness)
                            .build();
                            if responder.respond_bytes(wire).await.is_ok() {
                                served.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    })
                    .await;
            });
            Ok(AppHandle {
                id,
                node,
                kind: "producer",
                cancel,
                successes,
            })
        }
        AppSpec::Consumer {
            prefix: pfx,
            count,
            interval_ms,
            lifetime_ms,
        } => {
            let mut consumer = engine.app_consumer(cancel.clone());
            let pfx = pfx.clone();
            let count = *count;
            // Unbounded consumers get a default 50 ms pace so they don't busy-loop.
            let interval = match (*interval_ms, count) {
                (0, 0) => Duration::from_millis(50),
                (ms, _) => Duration::from_millis(ms),
            };
            let lifetime = Duration::from_millis(lifetime_ms.unwrap_or(4000));
            let fetched = Arc::clone(&successes);
            let cancel2 = cancel.clone();
            ndn_app::rt::spawn(async move {
                let mut i = 0u64;
                while !cancel2.is_cancelled() && (count == 0 || i < count) {
                    if let Ok(name) = format!("{pfx}/{i}").parse::<Name>() {
                        let builder = InterestBuilder::new(name).lifetime(lifetime);
                        if consumer.fetch_with(builder).await.is_ok() {
                            fetched.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    i += 1;
                    if !interval.is_zero() {
                        // rt::sleep is ambient-runtime-aware (virtual under the DES kernel).
                        tokio::select! {
                            _ = cancel2.cancelled() => break,
                            _ = ndn_app::rt::sleep(interval) => {}
                        }
                    }
                }
            });
            Ok(AppHandle {
                id,
                node,
                kind: "consumer",
                cancel,
                successes,
            })
        }
    }
}
