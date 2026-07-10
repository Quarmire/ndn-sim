//! NS-11 — multi-hop persistent-Interest subscriptions die PERMANENTLY at ~2× the
//! `SubscriptionRequest` budget after a SINGLE Data loss adjacent to a budget boundary.
//!
//! Field signature (skyfall Slice-2, read out of `ndn-engine/src/stages/pit.rs`): per-hop
//! `data_count_remaining` pools desync on one lost Data — the hop behind the loss exhausts and
//! reaps its PIT entry while the hop in front keeps leftover credit; the consumer's re-express
//! then AGGREGATES at the surviving hop (`persistent && !upstream_lost` was never re-forwarded),
//! refreshing the survivor while the reaped hop behind stays unreachable. First boundary recovers
//! (hops reap in lockstep); the second meets the first in-flight loss; after that, never — the
//! stock engine dies at 2×1024−1 = 2047 Data.
//!
//! THE FIX (pit.rs, `PitCheckStage`): a persistent (subscription-flavored) re-express (1) ALWAYS
//! re-forwards — a standing subscription must reach every hop, so a reaped hop is always revived —
//! and (2) RESETS the subscriber's in-record (replaces the same-face record) so every hop's credit
//! pool renews in lockstep, re-syncing the pools. Re-forward alone recovers the first boundary but
//! still dies at the second (~2× budget) because the survivor keeps its depleted pool; the reset is
//! what closes it. This gate uses a small budget so the cliff lands in a few virtual seconds.
//!
//! VERIFIED red-capable (this file, against the stock engine): the flow permanently stalls at the
//! first budget boundary and never reaches TARGET; with the fix it sails past 2× budget. So the
//! bug IS visible in virtual time — once the right fault is injected (a single Data dropped on the
//! UPSTREAM direction at a boundary, which desyncs the pools asymmetrically). The field's original
//! harness missed it only for lack of that fault, not because virtual time hides it.
//!
//! §5 doctrine (recommended follow-on): a real-socket twin (localhost UDP) as belt-and-suspenders
//! for timing-dependent variants — NOT built here; the virtual gate already reproduces the death.

use std::time::Duration;

use ndn_app::{EngineAppExt, SubscribeOptions};
use ndn_engine::builder::EngineConfig;
use ndn_packet::Name;
use ndn_packet::encode::DataBuilder;
use ndn_sim::{FrameMatcher, HoldRule, LinkConfig, Simulation, VirtualKernel};
use tokio_util::sync::CancellationToken;

const PREFIX: &str = "/push";
const BUDGET: u32 = 8; // small so the ~2× cliff (16) lands in a few virtual seconds
const TARGET: u64 = 2 * BUDGET as u64 + 4; // must sail comfortably PAST 2× budget

fn n(s: &str) -> Name {
    s.parse().unwrap()
}

/// Two hops (C — R — P), one persistent subscription, a single Data dropped adjacent to the first
/// budget boundary. Returns the count of distinct pushed Blocks the subscriber received before it
/// stalled or reached `TARGET`. Stock engine: stalls at ~2× budget. Fixed engine: reaches TARGET.
#[test]
fn persistent_subscription_survives_single_loss_past_2x_budget() {
    fastrand::seed(0x11);
    let kernel = VirtualKernel::new();
    let received = kernel.run(|k| async move {
        let mut sim = Simulation::new().kernel(k).seed(11);
        let c = sim.add_node(EngineConfig::default()); // consumer
        let r = sim.add_node(EngineConfig::default()); // relay — the 2nd hop
        let p = sim.add_node(EngineConfig::default()); // producer
        sim.link(c, r, LinkConfig::lan());
        sim.link(r, p, LinkConfig::lan());
        // The subscription Interest for /push routes C → R → P; pushed Data follows the PIT
        // reverse path P → R → C.
        sim.add_route(c, PREFIX, r);
        sim.add_route(r, PREFIX, p);
        let fabric = sim.start().await.unwrap();

        let cancel = CancellationToken::new();

        // Producer P: registers /push and pushes /push/<seq> onto the standing persistent entry.
        let producer = fabric
            .engine_of(p)
            .unwrap()
            .register_producer(n(PREFIX), cancel.child_token());
        ndn_sim::fieldkit::settle(Duration::from_millis(200)).await;

        // Consumer C: subscribe /push with a SMALL budget and a short staleness (so a stalled
        // subscriber re-expresses promptly — the budget/staleness re-express the field describes).
        let consumer = fabric.engine_of(c).unwrap().app_consumer(cancel.child_token());
        let mut sub = consumer
            .subscribe(
                n(PREFIX),
                SubscribeOptions {
                    max_data_count: BUDGET,
                    lifetime: Duration::from_secs(600),
                    staleness: Some(Duration::from_millis(300)),
                },
            )
            .await
            .expect("subscribe");
        ndn_sim::fieldkit::settle(Duration::from_millis(200)).await;

        // THE FAULT: drop a single Data on the UPSTREAM (P → R) direction adjacent to the first
        // budget boundary (the BUDGET-th Data crossing, 0-indexed BUDGET-1). This is the loss that
        // desyncs the per-hop pools asymmetrically: P forwards it (decrements + reaps) while R
        // never receives it (keeps credit) — so R survives and P behind it dies. (Dropping on
        // R → C instead reaps both hops symmetrically and does not exercise the aggregation bug.)
        // A hold with an effectively infinite delay is a drop that reaches only that one frame.
        fabric
            .hold_link(
                p,
                r,
                HoldRule::nth(FrameMatcher::Data, (BUDGET - 1) as u64, Duration::from_secs(86_400)),
            )
            .unwrap();

        // Producer pushes an UNBOUNDED stream of fresh Data until cancelled — so the ONLY reason
        // the subscriber stops receiving new Blocks is a *permanent* protocol stall (NS-11), never
        // running out of pushes. (Persistent push delivers only ~budget per re-arm cycle, so a
        // bounded producer would drop ~half during dead windows regardless of the bug.)
        {
            let producer = producer;
            let cancel = cancel.clone();
            tokio::spawn(async move {
                let mut seq: u64 = 0;
                while !cancel.is_cancelled() {
                    let name = n(PREFIX).append(seq.to_string());
                    let wire = DataBuilder::new(name, &seq.to_le_bytes())
                        .freshness(Duration::from_secs(4))
                        .build();
                    let _ = producer.publish(wire).await;
                    seq += 1;
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            });
        }

        // Drain the subscription, counting DISTINCT pushed Blocks (by seq). A live flow keeps
        // yielding new seqs (even if only ~budget per re-arm cycle), so it reaches TARGET; a
        // permanently stalled flow (NS-11) yields nothing new for a full window and breaks short.
        use std::collections::HashSet;
        let mut seen: HashSet<u64> = HashSet::new();
        // Loop ends on the first Err/timeout (a permanent stall or a closed subscription).
        while let Ok(Ok(data)) = tokio::time::timeout(Duration::from_secs(4), sub.recv()).await {
            if let Some(c) = data.content() {
                let mut b = [0u8; 8];
                let k = 8.min(c.len());
                b[..k].copy_from_slice(&c[..k]);
                seen.insert(u64::from_le_bytes(b));
            }
            if seen.len() as u64 >= TARGET {
                break;
            }
        }

        cancel.cancel();
        let got = seen.len() as u64;
        fabric.shutdown().await;
        got
    });

    assert!(
        received >= TARGET,
        "NS-11: a multi-hop persistent subscription must survive a single Data loss and progress \
         PAST 2× budget ({}); got {received} (stock engine stalls at ~2× budget = {})",
        TARGET,
        2 * BUDGET
    );
}
