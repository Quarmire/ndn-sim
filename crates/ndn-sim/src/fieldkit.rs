//! Field-failure scenario kit — the reusable pieces behind the three **silent-stall** failure
//! classes an application in the field found and the pre-existing suites structurally could
//! not (skyfall `FIELD-REPORT.md` §3/§6, ledgered there as NS-6/NS-7/NS-8):
//!
//! 1. **Reorder** (NS-6): links that drop but never reorder can only produce *timeouts* — a
//!    *late reply* to an already-timed-out request is unreachable. The fault lives in the sim
//!    core: [`HoldRule`](crate::HoldRule) + [`RunningSimulation::hold_link`] delay a matching
//!    frame without dropping it. This module adds the consumer-side probes.
//! 2. **Burst scale** (NS-7): suites that replicate a handful of Blocks never fill ndn-sync's
//!    bounded channels (update = 256 / ack = 64), so the `svs_task` ↔ consumer mutual stall
//!    under a several-hundred-Block catch-up is invisible. [`publish_backlog`] builds the
//!    backlog; [`TwoPhaseReplica`] + [`naive_catchup`] are the two-phase consumer;
//!    [`drive_until_or_stall`] detects the wedge *as a wedge* (progress frozen while virtual
//!    time flows) instead of a generic timeout.
//! 3. **Restart / lagging peer** (NS-8): single-boot suites never have a peer that is behind a
//!    publisher whose process restarted — the case where the stock per-boot SVS data plane
//!    starves the peer forever. [`RestartablePublisher`] models the restart (fresh app faces,
//!    fresh SVS instance, empty `DataStore`, seq space reset).
//!
//! These are **acceptance-gate** primitives: a fault or scenario that cannot turn a known-bad
//! implementation red is a shell, so each one ships with a self-test in
//! `tests/field_faults.rs` that drives the *stock* stack and observes the documented failure.
//! Fix sessions (ndn-app pairing, ndn-sync channel geometry, the history-serving story) run
//! the same scenario and flip the assertion — red → green, not reasoned.
//!
//! Everything here assumes the [`VirtualKernel`](crate::VirtualKernel) (probes sleep on tokio
//! time, which that kernel virtualizes); wall-clock use works but wastes real seconds.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use ndn_app::{Consumer, EngineAppExt, Publisher, PublisherConfig};
use ndn_packet::{Interest, Name};
use ndn_sync::{
    DataStore, MemoryStore, SvsConfig, SyncHandle, join_svs_group, svs_data_name,
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::topology::{NodeId, RunningSimulation};

/// Let the fabric settle for `d` of (virtual) time — route installation, face registration,
/// first sync rounds. Sugar over `tokio::time::sleep`, which the
/// [`VirtualKernel`](crate::VirtualKernel) virtualizes.
pub async fn settle(d: Duration) {
    tokio::time::sleep(d).await;
}

/// A monotone progress counter shared between a scenario's worker task and the driving test —
/// the seam [`drive_until_or_stall`] watches. Clone freely (all clones share the count).
#[derive(Clone, Debug, Default)]
pub struct Progress(Arc<AtomicU64>);

impl Progress {
    pub fn new() -> Self {
        Self::default()
    }
    /// Record one unit of progress.
    pub fn incr(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
    /// The count so far.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// What [`drive_until_or_stall`] observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatchupOutcome {
    /// Progress reached `target`.
    Reached(u64),
    /// Progress froze at `at` for the whole stall window while virtual time kept flowing —
    /// the silent-stall signature (distinct from "slow": nothing moved at all).
    Stalled {
        /// The progress count the run froze at.
        at: u64,
    },
}

impl CatchupOutcome {
    /// True if the run wedged short of its target.
    pub fn is_stalled(&self) -> bool {
        matches!(self, Self::Stalled { .. })
    }
}

/// Watch `progress` until it reaches `target`, or declare a **stall**: no progress at all for
/// `stall_window` of (virtual) time. The stall verdict is what distinguishes the NS-7 wedge
/// from mere slowness — a healthy-but-slow catch-up keeps ticking and never trips it.
pub async fn drive_until_or_stall(
    progress: &Progress,
    target: u64,
    stall_window: Duration,
) -> CatchupOutcome {
    let tick = (stall_window / 10).max(Duration::from_millis(10));
    let mut last = progress.get();
    let mut idle = Duration::ZERO;
    loop {
        tokio::time::sleep(tick).await;
        let now = progress.get();
        if now >= target {
            return CatchupOutcome::Reached(now);
        }
        if now == last {
            idle += tick;
            if idle >= stall_window {
                return CatchupOutcome::Stalled { at: now };
            }
        } else {
            last = now;
            idle = Duration::ZERO;
        }
    }
}

/// Publish `count` payloads through a [`Publisher`] back to back — the burst backlog that makes
/// one catch-up advertise hundreds of seqs (the NS-7 precondition; ≤5-Block suites never fill
/// the sync layer's bounded channels). `payload(i)` supplies the `i`-th body (0-based; SVS
/// assigns seqs `1..=count`).
pub async fn publish_backlog(
    publisher: &Publisher,
    count: usize,
    payload: impl Fn(usize) -> Vec<u8>,
) -> Result<()> {
    for i in 0..count {
        publisher
            .put(payload(i))
            .await
            .map_err(|e| anyhow::anyhow!("backlog publish {i}: {e:?}"))?;
    }
    Ok(())
}

/// The **two-phase replication plane** on one fabric node, hand-wired the way a chain
/// replicator rides it: `join_svs_group` with `auto_ack: false` (the state vector advances only
/// on [`SyncHandle::ack`]) pumped over a real app face, plus a consumer face for per-seq
/// fetches. The stock geometry is preserved on purpose — bounded update/ack channels and all —
/// because that geometry is exactly what the burst scenario must be able to wedge.
pub struct TwoPhaseReplica {
    /// The live two-phase handle: `recv()` advertised gaps, `ack()` validated-and-stored seqs.
    pub handle: SyncHandle,
    consumer: tokio::sync::Mutex<Consumer>,
    group: Name,
}

impl TwoPhaseReplica {
    /// Attach to `node`'s engine: register the sync group on a fresh app face, join with
    /// `auto_ack: false` and `sync_interval`, and pump sync Interests both ways. The caller
    /// owns route/strategy setup (group prefix routed node↔peers, multicast where a node holds
    /// several group faces).
    pub async fn attach(
        fabric: &RunningSimulation,
        node: NodeId,
        group: &Name,
        local: &Name,
        sync_interval: Duration,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        let engine = fabric
            .engine_of(node)
            .context("no engine for replica node")?;

        // The sync plane: one app face; peers' sync Interests route here, ours leave here.
        let app = engine.app_node(cancel.child_token());
        let conn = app.connection();
        conn.register_prefix(group)
            .await
            .map_err(|e| anyhow::anyhow!("register group prefix: {e:?}"))?;

        let (core_out_tx, mut core_out_rx) = mpsc::channel::<Bytes>(256);
        let (core_in_tx, core_in_rx) = mpsc::channel::<Bytes>(256);
        let cfg = SvsConfig {
            auto_ack: false, // two-phase: merges deferred, acks advance the vector
            sync_interval,
            jitter_ms: 0,
            ..SvsConfig::default()
        };
        let handle = join_svs_group(group.clone(), local.clone(), core_out_tx, core_in_rx, cfg);

        // Outbound pump: the core's sync Interests → the face → the fabric.
        {
            let conn = Arc::clone(&conn);
            let cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        pkt = core_out_rx.recv() => match pkt {
                            Some(p) => {
                                let _ = conn.send(p).await;
                            }
                            None => break,
                        },
                    }
                }
            });
        }
        // Inbound pump: sync Interests off the face → the core (the same classification the
        // SvSync demux applies: group-prefixed Interest whose next component is version 2).
        {
            let conn = Arc::clone(&conn);
            let group = group.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let group_len = group.components().len();
                loop {
                    let wire = tokio::select! {
                        _ = cancel.cancelled() => break,
                        w = conn.recv() => match w {
                            Some(w) => w,
                            None => break,
                        },
                    };
                    if wire.first() != Some(&0x05) {
                        continue;
                    }
                    let Ok(interest) = Interest::decode(wire.clone()) else {
                        continue;
                    };
                    let comps = interest.name.components();
                    let is_sync = interest.name.has_prefix(&group)
                        && comps.len() > group_len
                        && comps[group_len].as_version() == Some(2);
                    if is_sync {
                        let _ = core_in_tx.send(wire).await;
                    }
                }
            });
        }

        Ok(Self {
            handle,
            consumer: tokio::sync::Mutex::new(engine.app_consumer(cancel.child_token())),
            group: group.clone(),
        })
    }

    /// Fetch one advertised publication `(publisher_base, seq)` over the real data plane (an
    /// Interest for the canonical SVS data name, answered by the publisher's store across the
    /// fabric). Returns the publication's content bytes, `None` on timeout / no route.
    pub async fn fetch(&self, publisher_base: &Name, seq: u64) -> Option<Bytes> {
        let name = svs_data_name(publisher_base, &self.group, seq);
        let data = self.consumer.lock().await.fetch(name).await.ok()?;
        data.content().cloned()
    }
}

// The durable history-serving member is no longer an ndn-sync `HistoryServer` (that fork was
// retired in favor of ndn-repo's two-phase mode — see field_faults.rs `RepoNode`). The general
// `serve_all_stored` SvSync knob it needed remains in ndn-sync and is consumed by ndn-repo.

/// The **pre-fix consumer shape** (deliberately naive — this is the known-bad reference the
/// burst scenario must wedge, kept exportable so fix sessions can run naive-vs-fixed against
/// the identical scenario): one loop, `recv` an update, then fetch + **ack inline** per
/// advertised seq — re-acking already-stored seqs the way the transport layer's idempotence
/// path does. Under a several-hundred-Block backlog this consumer and the stock `svs_task`
/// wedge each other: the task blocks delivering to the full update channel (and stops draining
/// acks), the consumer blocks sending to the full ack channel (and stops draining updates) —
/// the NS-7 mutual stall. `progress` counts *distinct* stored seqs.
pub async fn naive_catchup(mut replica: TwoPhaseReplica, progress: Progress) {
    let mut stored: HashSet<(String, u64)> = HashSet::new();
    while let Some(update) = replica.handle.recv().await {
        for seq in update.low_seq..=update.high_seq {
            if replica.fetch(&update.name, seq).await.is_some() {
                let _ = replica.handle.ack(&update.publisher, seq).await;
                if stored.insert((update.publisher.clone(), seq)) {
                    progress.incr();
                }
            }
        }
    }
}

/// A publisher that can model a **process restart** (the NS-8 shape): stopping cancels the
/// instance's app faces and drops its SVS data plane; starting again is a *fresh boot* — new app
/// faces, a new SVS instance, no memory of what the previous boot advertised on the wire.
///
/// **Persistence across the boot (N-13/N-15).** The `DataStore` is held HERE, by the
/// `RestartablePublisher`, not by the per-boot instance — the in-process analogue of a
/// disk-backed store surviving the process. On restart it is handed to the fresh instance via
/// [`PublisherConfig::store`], so `SvSync::join` recovers the sequence high-water from it and the
/// new boot **serves its prior history from the store**: a peer that fell behind fetches the
/// missing Block straight from disk, no `O(history)` genesis-first re-announce. Construct with
/// [`new`](Self::new) (persistent — the fixed regime) or [`new_ephemeral`](Self::new_ephemeral)
/// (a fresh empty store per boot — the stock starvation the NS-8 gate pins).
pub struct RestartablePublisher {
    engine: ndn_engine::ForwarderEngine,
    group: Name,
    local: Name,
    parent: CancellationToken,
    current: Option<(Publisher, CancellationToken)>,
    /// The served-history store. `Some` = one store retained across boots (persistent);
    /// `None` = a fresh empty store minted per boot (the stock per-boot data plane).
    store: Option<Arc<dyn DataStore>>,
}

impl RestartablePublisher {
    /// Bind to `node`'s engine with a **persistent** store retained across boots (the N-13 fix).
    pub fn new(
        fabric: &RunningSimulation,
        node: NodeId,
        group: &Name,
        local: &Name,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        let mut this = Self::new_ephemeral(fabric, node, group, local, cancel)?;
        this.store = Some(Arc::new(MemoryStore::new()));
        Ok(this)
    }

    /// Bind to `node`'s engine with a **fresh empty store per boot** — the stock per-boot data
    /// plane that starves a lagging peer after a restart (the pinned NS-8 shape).
    pub fn new_ephemeral(
        fabric: &RunningSimulation,
        node: NodeId,
        group: &Name,
        local: &Name,
        cancel: &CancellationToken,
    ) -> Result<Self> {
        Ok(Self {
            engine: fabric
                .engine_of(node)
                .context("no engine for publisher node")?,
            group: group.clone(),
            local: local.clone(),
            parent: cancel.clone(),
            current: None,
            store: None,
        })
    }

    /// Start a fresh instance (a new boot): new app faces, new SVS instance. With a persistent
    /// store (see [`new`](Self::new)) the instance recovers its seq and serves prior history from
    /// it; ephemeral, it boots empty with seq reset. Stops any running instance first.
    pub async fn start(&mut self) -> Result<&Publisher> {
        self.stop();
        let instance_cancel = self.parent.child_token();
        let app = self.engine.app_node(instance_cancel.child_token());
        let config = PublisherConfig {
            store: self.store.clone(),
            ..PublisherConfig::default()
        };
        let publisher = app
            .publish_with_config(self.group.clone(), self.local.clone(), config)
            .await
            .map_err(|e| anyhow::anyhow!("start publisher: {e:?}"))?;
        self.current = Some((publisher, instance_cancel));
        Ok(&self.current.as_ref().unwrap().0)
    }

    /// Kill the running instance — the process exits: its faces are cancelled, its SVS data
    /// plane (store + sync task) is dropped. History published under this boot is no longer
    /// served by anything.
    pub fn stop(&mut self) {
        if let Some((publisher, token)) = self.current.take() {
            drop(publisher);
            token.cancel();
        }
    }

    /// The running instance, if started.
    pub fn publisher(&self) -> Option<&Publisher> {
        self.current.as_ref().map(|(p, _)| p)
    }
}
