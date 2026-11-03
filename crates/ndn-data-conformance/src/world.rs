//! The world a case runs in: devices on a real ndn-sim fabric ([`Net`]) and their data layers
//! ([`World`]).
//!
//! Topology: every device is a forwarder linked to one hub forwarder (the network between
//! devices). Devices route everything to the hub; the hub multicasts to every device, so any
//! device can reach any name another device serves. Going offline cuts a device's link; every
//! device has its own wall clock, which a case can set wrong at any time.

use std::cell::{Cell, RefCell};
use std::sync::Arc;
use std::time::Duration;

use ndn_data::{DataLayer, Timestamp};
use ndn_sim::{
    ClockSkew, Fabric, FaceKind, LinkConfig, NodeId, NodeProfile, SimKernel, Simulation,
};

use crate::case::Failure;
use crate::provider::{DeviceSpec, NodeRole, Provider, Tally};
use crate::report::{Cost, Measure};

/// A device of a [`Plan`], by position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Dev(pub usize);

#[derive(Clone, Debug)]
struct Planned {
    person: String,
    device: String,
    /// A thief: holds a copy of this device's key.
    stolen_from: Option<Dev>,
}

/// The devices a case needs, declared before the fabric starts.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    devices: Vec<Planned>,
}

impl Plan {
    /// An empty plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add `person`'s `device` (e.g. `"alice"`, `"laptop"`). The person is a namespace of any
    /// number of components, written without its leading slash (`"home/bob"` is `/home/bob`).
    pub fn device(&mut self, person: &str, device: &str) -> Dev {
        self.devices.push(Planned {
            person: person.to_owned(),
            device: device.to_owned(),
            stolen_from: None,
        });
        Dev(self.devices.len() - 1)
    }

    /// Add a thief's node holding a copy of `victim`'s key.
    pub fn thief(&mut self, victim: Dev) -> Dev {
        self.devices.push(Planned {
            person: "thief".to_owned(),
            device: format!("with-{}", self.devices[victim.0].device),
            stolen_from: Some(victim),
        });
        Dev(self.devices.len() - 1)
    }

    /// The number of devices.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Whether the plan has no devices.
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

/// Link counters summed over the fabric, for [`Cost`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wire {
    /// Interests the devices sent onto their links.
    pub device_interests: u64,
    /// Bytes every node sent onto links.
    pub bytes: u64,
}

/// The devices of a case on a running fabric, without any data layer.
pub struct Net {
    fabric: Fabric,
    hub: NodeId,
    specs: Vec<DeviceSpec>,
}

impl Net {
    /// Start the fabric on `kernel`: a hub with profile `hub`, and one device per spec of `plan`
    /// with the profile `profile` gives it. Every device gets its own (adjustable) wall clock.
    pub async fn start(
        kernel: Arc<dyn SimKernel>,
        plan: &Plan,
        hub: NodeProfile,
        mut profile: impl FnMut(&DeviceSpec) -> NodeProfile,
    ) -> anyhow::Result<Net> {
        let mut sim = Simulation::new().kernel(kernel);
        let hub_node = sim.add_node_profile(hub);
        sim.add_strategy(hub_node, "/", "multicast");
        let mut specs = Vec::with_capacity(plan.devices.len());
        for (i, p) in plan.devices.iter().enumerate() {
            let spec = DeviceSpec {
                person: format!("/{}", p.person).parse()?,
                device: p.device.clone(),
                // The hub is node 0; devices follow in plan order.
                node: NodeId(i + 1),
            };
            let mut node_profile = profile(&spec);
            node_profile.clock_skew.get_or_insert(ClockSkew::NONE);
            let node = sim.add_node_profile(node_profile);
            debug_assert_eq!(node, spec.node);
            sim.link(node, hub_node, LinkConfig::lan());
            sim.add_route(node, "/", hub_node);
            sim.add_route(hub_node, "/", node);
            specs.push(spec);
        }
        Ok(Net {
            fabric: sim.start().await?,
            hub: hub_node,
            specs,
        })
    }

    /// The running fabric.
    pub fn fabric(&self) -> &Fabric {
        &self.fabric
    }

    /// The device's spec.
    pub fn spec(&self, d: Dev) -> &DeviceSpec {
        &self.specs[d.0]
    }

    /// Cut the device's link: it is offline until [`online`](Self::online).
    pub fn offline(&self, d: Dev) {
        self.fabric
            .set_link_up(self.specs[d.0].node, self.hub, false)
            .expect("every device is linked to the hub");
    }

    /// Restore the device's link.
    pub fn online(&self, d: Dev) {
        self.fabric
            .set_link_up(self.specs[d.0].node, self.hub, true)
            .expect("every device is linked to the hub");
    }

    /// Step the device's wall clock to `skew` from now on.
    pub fn set_clock(&self, d: Dev, skew: ClockSkew) {
        self.fabric
            .set_clock_skew(self.specs[d.0].node, skew)
            .expect("every device has its own clock");
    }

    /// The date the device's own clock shows now.
    pub fn date(&self, d: Dev) -> Timestamp {
        let clock = self
            .fabric
            .node_clock(self.specs[d.0].node)
            .expect("every device is a node");
        Timestamp(clock.now_ns() / 1_000_000)
    }

    /// The true date (the fabric's clock), for comparing with what devices claim.
    pub fn true_date(&self) -> Timestamp {
        Timestamp(self.fabric.clock().now_ns() / 1_000_000)
    }

    /// Link counters summed over the fabric now.
    pub fn wire(&self) -> Wire {
        let mut w = Wire::default();
        let nodes = std::iter::once(self.hub).chain(self.specs.iter().map(|s| s.node));
        for node in nodes {
            for f in self.fabric.face_stats(node).unwrap_or_default() {
                if matches!(f.kind, FaceKind::Link { .. }) {
                    w.bytes += f.out_bytes;
                    if node != self.hub {
                        w.device_interests += f.out_interests;
                    }
                }
            }
        }
        w
    }

    /// One device's link counters now: the Interests it sent and the bytes it received.
    pub fn device_wire(&self, d: Dev) -> DeviceWire {
        let mut w = DeviceWire::default();
        for f in self
            .fabric
            .face_stats(self.specs[d.0].node)
            .unwrap_or_default()
        {
            if matches!(f.kind, FaceKind::Link { .. }) {
                w.interests += f.out_interests;
                w.in_bytes += f.in_bytes;
            }
        }
        w
    }
}

/// One device's link counters, for [`Net::device_wire`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceWire {
    /// Interests the device sent onto its links.
    pub interests: u64,
    /// Bytes the device received from its links.
    pub in_bytes: u64,
}

impl std::ops::Sub for DeviceWire {
    type Output = DeviceWire;
    fn sub(self, before: DeviceWire) -> DeviceWire {
        DeviceWire {
            interests: self.interests - before.interests,
            in_bytes: self.in_bytes - before.in_bytes,
        }
    }
}

/// What the cost counters read at one moment.
#[derive(Clone, Copy, Debug)]
pub struct Mark {
    wire: Wire,
    tally: Tally,
}

/// A case's world: the [`Net`] plus each device's data layer from the provider.
pub struct World {
    net: Net,
    layers: Vec<Arc<dyn DataLayer>>,
    provider: Arc<dyn Provider>,
    gestures: Cell<u64>,
    converge: Cell<Option<Duration>>,
    reported_from: Cell<Option<Mark>>,
    measured: RefCell<Vec<Measure>>,
}

impl World {
    /// Start `plan` on `kernel` and attach `provider`'s data layer to every device (a thief's
    /// with the victim's key).
    pub async fn build(
        kernel: Arc<dyn SimKernel>,
        plan: &Plan,
        provider: Arc<dyn Provider>,
    ) -> anyhow::Result<World> {
        let net = Net::start(kernel, plan, provider.node_profile(NodeRole::Hub), |spec| {
            provider.node_profile(NodeRole::Device(spec))
        })
        .await?;
        provider.prepare(&net.fabric, net.hub, &net.specs).await?;
        let mut layers = Vec::with_capacity(plan.devices.len());
        for (i, p) in plan.devices.iter().enumerate() {
            let spec = &net.specs[i];
            let layer = match p.stolen_from {
                Some(victim) => {
                    provider
                        .attach_stolen(&net.fabric, &net.specs[victim.0], spec)
                        .await?
                }
                None => provider.attach(&net.fabric, spec).await?,
            };
            layers.push(layer);
        }
        Ok(World {
            net,
            layers,
            provider,
            gestures: Cell::new(0),
            converge: Cell::new(None),
            reported_from: Cell::new(None),
            measured: RefCell::new(Vec::new()),
        })
    }

    /// The devices and their links.
    pub fn net(&self) -> &Net {
        &self.net
    }

    /// The device's data layer.
    pub fn at(&self, d: Dev) -> Arc<dyn DataLayer> {
        Arc::clone(&self.layers[d.0])
    }

    /// Record one person gesture: pointing at data, pointing at someone, throwing away.
    pub fn gesture(&self) {
        self.gestures.set(self.gestures.get() + 1);
    }

    /// `by`, holding the namespace's authority, revokes `device`'s key (see
    /// [`Provider::revoke`]).
    pub async fn revoke(&self, by: Dev, device: Dev) -> Result<(), Failure> {
        self.provider
            .revoke(&self.net.fabric, self.net.spec(by), self.net.spec(device))
            .await
            .map_err(|e| Failure::new(format!("revoke failed: {e:#}")))
    }

    /// Let `d` of virtual time pass.
    pub async fn sleep(&self, d: Duration) {
        tokio::time::sleep(d).await;
    }

    /// Let `d` of virtual time pass at once, as for a world whose devices all slept through it:
    /// every timer due within `d` fires once, at its end, instead of every periodic tick in
    /// between being simulated. For long absences (months) whose ticks a case does not observe —
    /// an idle fabric costs its forwarders' housekeeping ticks, about 2 minutes of real time per
    /// virtual day. Nothing that would have happened in `d` is asserted by such a case.
    pub async fn skip(&self, d: Duration) {
        tokio::time::advance(d).await;
    }

    /// Wait until `check` holds, polling every 100 ms of virtual time, for at most `limit`;
    /// returns how long it took.
    pub async fn until<F, Fut>(
        &self,
        what: &str,
        limit: Duration,
        mut check: F,
    ) -> Result<Duration, Failure>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<bool, Failure>>,
    {
        let start = tokio::time::Instant::now();
        loop {
            if check().await? {
                return Ok(start.elapsed());
            }
            if start.elapsed() >= limit {
                return Err(Failure::new(format!(
                    "{what}: not reached within {limit:?} of virtual time"
                )));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Like [`until`](Self::until), and record the time taken as the case's time to converge.
    pub async fn converge<F, Fut>(
        &self,
        what: &str,
        limit: Duration,
        check: F,
    ) -> Result<Duration, Failure>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<bool, Failure>>,
    {
        let took = self.until(what, limit, check).await?;
        self.converged(took);
        Ok(took)
    }

    /// Record one quantity the case measured for an open question it answers.
    pub fn measure(&self, what: impl Into<String>, value: u64, unit: &'static str) {
        self.measured.borrow_mut().push(Measure {
            what: what.into(),
            value,
            unit,
        });
    }

    /// What the case measured.
    pub fn measured(&self) -> Vec<Measure> {
        self.measured.borrow().clone()
    }

    /// Record `took` as the case's time to converge.
    pub fn converged(&self, took: Duration) {
        self.converge.set(Some(took));
    }

    /// The cost counters now.
    pub fn mark(&self) -> Mark {
        Mark {
            wire: self.net.wire(),
            tally: self.provider.tally(),
        }
    }

    /// Report the case's cost from `mark` on rather than from its start: for a case whose setup
    /// (populating thousands of notes, say) is not the workload it measures.
    pub fn report_from(&self, mark: Mark) {
        self.reported_from.set(Some(mark));
    }

    /// What the case reports it cost: since the mark it chose ([`Self::report_from`]), else
    /// since `start`.
    pub fn reported_cost(&self, start: Mark) -> Cost {
        self.cost_since(self.reported_from.get().unwrap_or(start))
    }

    /// What the case cost since `start`.
    pub fn cost_since(&self, start: Mark) -> Cost {
        let now = self.mark();
        Cost {
            round_trips: Some(now.wire.device_interests - start.wire.device_interests),
            bytes: Some(now.wire.bytes - start.wire.bytes),
            signatures: Some(now.tally.signatures - start.tally.signatures),
            copies: Some(now.tally.copies),
            converge_ms: self.converge.get().map(|d| d.as_millis() as u64),
            gestures: Some(self.gestures.get()),
        }
    }

    /// Shut the fabric down.
    pub async fn shutdown(self) {
        self.net.fabric.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ndn_app::EngineAppExt;
    use ndn_packet::encode::InterestBuilder;
    use ndn_sim::{ClockSkew, NodeProfile, VirtualKernel};
    use tokio_util::sync::CancellationToken;

    use super::*;

    const WEEK: Duration = Duration::from_secs(7 * 24 * 3600);

    /// Two of Alice's devices on the harness topology, with plain (fail-closed) forwarders.
    async fn two_devices(kernel: Arc<dyn SimKernel>) -> (Net, Dev, Dev) {
        let mut plan = Plan::new();
        let laptop = plan.device("alice", "laptop");
        let phone = plan.device("alice", "phone");
        let net = Net::start(kernel, &plan, NodeProfile::new("hub"), |s| {
            NodeProfile::new(s.device.clone())
        })
        .await
        .unwrap();
        (net, laptop, phone)
    }

    /// Serve `/alice/laptop` on the laptop (digest-signed Data, which fail-closed nodes accept).
    fn serve(net: &Net, d: Dev) {
        let producer = net
            .fabric()
            .engine_of(net.spec(d).node)
            .unwrap()
            .register_producer(net.spec(d).name(), CancellationToken::new());
        tokio::spawn(async move {
            let _ = producer
                .serve(|interest, responder| async move {
                    let _ = responder
                        .respond((*interest.name).clone(), bytes::Bytes::from_static(b"here"))
                        .await;
                })
                .await;
        });
    }

    async fn reaches(net: &Net, from: Dev, to: Dev) -> bool {
        let mut consumer = net
            .fabric()
            .engine_of(net.spec(from).node)
            .unwrap()
            .app_consumer(CancellationToken::new());
        let name = net.spec(to).name().append("ping");
        consumer
            .fetch_with(InterestBuilder::new(name).lifetime(Duration::from_secs(1)))
            .await
            .is_ok()
    }

    #[test]
    fn a_device_offline_is_unreachable_until_it_is_online_again() {
        VirtualKernel::new().run(|k| async move {
            let (net, laptop, phone) = two_devices(k).await;
            serve(&net, laptop);
            assert!(
                reaches(&net, phone, laptop).await,
                "devices reach each other via the hub"
            );
            net.offline(laptop);
            assert!(
                !reaches(&net, phone, laptop).await,
                "an offline device is unreachable"
            );
            net.online(laptop);
            assert!(
                reaches(&net, phone, laptop).await,
                "back online, it is reachable again"
            );
            net.fabric().shutdown().await;
        });
    }

    #[test]
    fn every_device_keeps_its_own_wall_clock() {
        VirtualKernel::new().run(|k| async move {
            let (net, laptop, phone) = two_devices(k).await;
            assert_eq!(net.date(laptop), net.true_date());
            net.set_clock(laptop, ClockSkew::behind(WEEK));
            let week_ms = WEEK.as_millis() as u64;
            assert_eq!(net.date(laptop).0, net.true_date().0 - week_ms);
            assert_eq!(
                net.date(phone),
                net.true_date(),
                "other devices are unaffected"
            );
            tokio::time::sleep(Duration::from_secs(60)).await;
            assert_eq!(
                net.date(laptop).0,
                net.true_date().0 - week_ms,
                "an offset, no drift"
            );
            net.fabric().shutdown().await;
        });
    }

    #[test]
    fn wire_counters_follow_traffic() {
        VirtualKernel::new().run(|k| async move {
            let (net, laptop, phone) = two_devices(k).await;
            serve(&net, laptop);
            let before = net.wire();
            assert!(reaches(&net, phone, laptop).await);
            let after = net.wire();
            assert!(after.device_interests > before.device_interests);
            assert!(after.bytes > before.bytes);
            net.fabric().shutdown().await;
        });
    }
}
