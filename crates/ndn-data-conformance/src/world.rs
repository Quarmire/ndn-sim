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

use ndn_data::{DataLayer, Name, Timestamp, VersionId};
use ndn_sim::{
    ClockSkew, Fabric, FaceKind, LinkConfig, NodeId, NodeProfile, SimKernel, Simulation,
};

use crate::case::Failure;
use crate::provider::{Certs, DeviceSpec, NodeRole, Provider, Tally, Tamper};
use crate::report::{Cost, Measure};

/// A device of a [`Plan`], by position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Dev(pub usize);

#[derive(Clone, Debug)]
struct Planned {
    person: String,
    device: String,
    /// A thief: takes this device, key and storage ([`World::steal`]).
    stolen_from: Option<Dev>,
    /// A holder of its person's collections.
    holds: bool,
}

/// The devices a case needs, declared before the fabric starts.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    devices: Vec<Planned>,
    /// Count each device's packets by name, to this many name components
    /// ([`Plan::count_names`]).
    names: Option<usize>,
}

impl Plan {
    /// An empty plan.
    pub fn new() -> Self {
        Self::default()
    }

    /// Count every packet on every link by name, its first `components` name components, so a
    /// case can tell which named packets reached a device ([`Net::received`]). It decodes each
    /// frame, so only the cases that need it ask.
    pub fn count_names(&mut self, components: usize) {
        self.names = Some(components);
    }

    /// Add `person`'s `device` (e.g. `"alice"`, `"laptop"`). The person is a namespace of any
    /// number of components, written without its leading slash (`"home/bob"` is `/home/bob`).
    pub fn device(&mut self, person: &str, device: &str) -> Dev {
        self.add(person, device, false)
    }

    /// Add `person`'s `device` as a holder: it keeps the collections of its person's namespace
    /// for their owners under custody leases (a home repo, a vault).
    pub fn holder(&mut self, person: &str, device: &str) -> Dev {
        self.add(person, device, true)
    }

    fn add(&mut self, person: &str, device: &str, holds: bool) -> Dev {
        self.devices.push(Planned {
            person: person.to_owned(),
            device: device.to_owned(),
            stolen_from: None,
            holds,
        });
        Dev(self.devices.len() - 1)
    }

    /// Add a thief's node, which takes `victim`'s device — key and storage — when the case
    /// says so ([`World::steal`]).
    pub fn thief(&mut self, victim: Dev) -> Dev {
        self.devices.push(Planned {
            person: "thief".to_owned(),
            device: format!("with-{}", self.devices[victim.0].device),
            stolen_from: Some(victim),
            holds: false,
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
    /// Each device's forwarder label, as the fabric's name counters know it.
    labels: Vec<String>,
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
        if let Some(components) = plan.names {
            sim = sim.with_prefix_accounting(components);
        }
        let hub_node = sim.add_node_profile(hub);
        sim.add_strategy(hub_node, "/", "multicast");
        let mut specs = Vec::with_capacity(plan.devices.len());
        let mut labels = Vec::with_capacity(plan.devices.len());
        for (i, p) in plan.devices.iter().enumerate() {
            let spec = DeviceSpec {
                person: format!("/{}", p.person).parse()?,
                device: p.device.clone(),
                // The hub is node 0; devices follow in plan order.
                node: NodeId(i + 1),
                holds: p.holds,
            };
            let mut node_profile = profile(&spec);
            node_profile.clock_skew.get_or_insert(ClockSkew::NONE);
            labels.push(node_profile.label.clone());
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
            labels,
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

    /// One device's link counters now: the packets and bytes it sent and received.
    pub fn device_wire(&self, d: Dev) -> DeviceWire {
        let mut w = DeviceWire::default();
        for f in self
            .fabric
            .face_stats(self.specs[d.0].node)
            .unwrap_or_default()
        {
            if matches!(f.kind, FaceKind::Link { .. }) {
                w.interests += f.out_interests;
                w.data += f.out_data;
                w.out_bytes += f.out_bytes;
                w.in_interests += f.in_interests;
                w.in_data += f.in_data;
                w.in_bytes += f.in_bytes;
            }
        }
        w
    }

    /// Every forwarder (the hub's and each device's) evicts what its content store caches under
    /// `prefix`, as caches do under load or on restart: from then on a packet under `prefix` is
    /// found only at a device that serves it. Returns how many cached packets were evicted.
    pub async fn forget_cached(&self, prefix: &Name) -> usize {
        let mut evicted = 0;
        let nodes = std::iter::once(self.hub).chain(self.specs.iter().map(|s| s.node));
        for node in nodes {
            if let Some(engine) = self.fabric.engine_of(node) {
                evicted += engine.cs().evict_prefix_erased(prefix, None).await;
            }
        }
        evicted
    }

    /// How many Data packets named `name` reached `d` over its links so far, whether or not its
    /// data layer kept them. Needs the plan to count names ([`Plan::count_names`]) to at least
    /// `name`'s length; a longer name is counted with every other name sharing its first
    /// components.
    pub fn received(&self, d: Dev, name: &Name) -> u64 {
        let stats = self
            .fabric
            .prefix_stats()
            .expect("a case reading names received plans to count them (Plan::count_names)");
        let group = ndn_sim::netstat::group_prefix(&name.to_string(), stats.grouping());
        stats
            .get(&self.labels[d.0], &group)
            .map_or(0, |c| c.in_data)
    }
}

/// One device's link counters, for [`Net::device_wire`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceWire {
    /// Interests the device sent onto its links.
    pub interests: u64,
    /// Data packets the device sent onto its links.
    pub data: u64,
    /// Bytes the device sent onto its links.
    pub out_bytes: u64,
    /// Interests the device received from its links.
    pub in_interests: u64,
    /// Data packets the device received from its links.
    pub in_data: u64,
    /// Bytes the device received from its links.
    pub in_bytes: u64,
}

impl std::ops::Sub for DeviceWire {
    type Output = DeviceWire;
    fn sub(self, before: DeviceWire) -> DeviceWire {
        DeviceWire {
            interests: self.interests - before.interests,
            data: self.data - before.data,
            out_bytes: self.out_bytes - before.out_bytes,
            in_interests: self.in_interests - before.in_interests,
            in_data: self.in_data - before.in_data,
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
    /// Each device's data layer; a thief has one once it takes the stolen device
    /// ([`World::steal`]).
    layers: RefCell<Vec<Option<Arc<dyn DataLayer>>>>,
    /// For each device, the device it holds a stolen key of (a thief).
    victims: Vec<Option<Dev>>,
    provider: Arc<dyn Provider>,
    gestures: Cell<u64>,
    converge: Cell<Option<Duration>>,
    reported_from: Cell<Option<Mark>>,
    measured: RefCell<Vec<Measure>>,
}

impl World {
    /// Start `plan` on `kernel` and attach `provider`'s data layer to every device but the
    /// thieves (see [`steal`](Self::steal)).
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
            let layer = match p.stolen_from {
                Some(_) => None,
                None => Some(provider.attach(&net.fabric, &net.specs[i]).await?),
            };
            layers.push(layer);
        }
        Ok(World {
            net,
            layers: RefCell::new(layers),
            victims: plan.devices.iter().map(|p| p.stolen_from).collect(),
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
    ///
    /// # Panics
    ///
    /// For a thief that has not taken the stolen device yet ([`steal`](Self::steal)).
    pub fn at(&self, d: Dev) -> Arc<dyn DataLayer> {
        let layers = self.layers.borrow();
        let layer = layers[d.0].as_ref().unwrap_or_else(|| {
            panic!(
                "device {} is a thief without a data layer until it steals the device",
                d.0
            )
        });
        Arc::clone(layer)
    }

    /// Record one person gesture: pointing at data, pointing at someone, throwing away.
    pub fn gesture(&self) {
        self.gestures.set(self.gestures.get() + 1);
    }

    /// `by`, holding the namespace's authority, revokes `device`'s key with a cut at what `by`
    /// holds (see [`Provider::revoke`]), and the new trust-context version reaches every node
    /// ([`spread_all`](Self::spread_all)).
    pub async fn revoke(&self, by: Dev, device: Dev) -> Result<(), Failure> {
        self.revoke_at(by, device).await?;
        self.spread_all().await
    }

    /// As [`revoke`](Self::revoke), but the new version stays on `by`'s node until
    /// [`spread`](Self::spread) carries it further: the revocation has not reached the others
    /// yet.
    pub async fn revoke_at(&self, by: Dev, device: Dev) -> Result<(), Failure> {
        self.provider
            .revoke(&self.net.fabric, self.net.spec(by), self.net.spec(device))
            .await
            .map_err(|e| Failure::new(format!("revoke failed: {e:#}")))
    }

    /// The newest trust-context versions reach `d`'s node (see [`Provider::spread`]).
    pub async fn spread(&self, d: Dev) -> Result<(), Failure> {
        self.spread_to(self.net.spec(d).node).await
    }

    /// The newest trust-context versions reach the hub and every device but the thieves': a
    /// thief's node is the adversary's, which adopts nothing that would stop it.
    pub async fn spread_all(&self) -> Result<(), Failure> {
        self.spread_to(self.net.hub).await?;
        for (i, victim) in self.victims.iter().enumerate() {
            if victim.is_none() {
                self.spread_to(self.net.specs[i].node).await?;
            }
        }
        Ok(())
    }

    async fn spread_to(&self, node: NodeId) -> Result<(), Failure> {
        self.provider
            .spread(&self.net.fabric, node)
            .await
            .map_err(|e| Failure::new(format!("a trust-context version did not spread: {e:#}")))
    }

    /// `by`, holding the namespace's authority, re-admits version `id` of `collection` exactly
    /// as `from` holds it refused (see [`Provider::readmit`]), and the new trust-context version
    /// reaches every node.
    pub async fn readmit(
        &self,
        by: Dev,
        from: Dev,
        collection: &Name,
        id: &VersionId,
    ) -> Result<(), Failure> {
        self.provider
            .readmit(
                &self.net.fabric,
                self.net.spec(by),
                self.net.spec(from),
                collection,
                id,
            )
            .await
            .map_err(|e| Failure::new(format!("readmit failed: {e:#}")))?;
        self.spread_all().await
    }

    /// The thief `thief` takes the device whose key it holds, storage and all (see
    /// [`Provider::steal`]): [`at`](Self::at) answers its data layer from now on.
    pub async fn steal(&self, thief: Dev) -> Result<(), Failure> {
        let victim = self.victims[thief.0]
            .unwrap_or_else(|| panic!("device {} of the plan is no thief", thief.0));
        let layer = self
            .provider
            .steal(
                &self.net.fabric,
                self.net.spec(victim),
                self.net.spec(thief),
            )
            .await
            .map_err(|e| Failure::new(format!("cannot steal the device: {e:#}")))?;
        self.layers.borrow_mut()[thief.0] = Some(layer);
        Ok(())
    }

    /// `d` renews its certificate (see [`Provider::renew`]).
    pub async fn renew(&self, d: Dev) -> Result<(), Failure> {
        self.provider
            .renew(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("renew failed: {e:#}")))
    }

    /// `which` certificates of `d`'s key expire (see [`Provider::expire`]).
    pub async fn expire(&self, d: Dev, which: Certs) -> Result<(), Failure> {
        self.provider
            .expire(&self.net.fabric, self.net.spec(d), which)
            .await
            .map_err(|e| Failure::new(format!("cannot let the certificates expire: {e:#}")))
    }

    /// `by` makes a recovery kit for its namespace (see [`Provider::recovery_kit`]), and the new
    /// trust-context version reaches every node.
    pub async fn recovery_kit(&self, by: Dev) -> Result<(), Failure> {
        self.provider
            .recovery_kit(&self.net.fabric, self.net.spec(by))
            .await
            .map_err(|e| Failure::new(format!("making a recovery kit failed: {e:#}")))?;
        self.spread_all().await
    }

    /// `by` recovers its namespace with the kit after its root was compromised (see
    /// [`Provider::recover`]), and the new trust-context versions reach every node.
    pub async fn recover(&self, by: Dev) -> Result<(), Failure> {
        self.provider
            .recover(&self.net.fabric, self.net.spec(by))
            .await
            .map_err(|e| Failure::new(format!("recovery failed: {e:#}")))?;
        self.spread_all().await
    }

    /// `d`'s host drops its own copies of the large payload pieces under `name` (a version's name
    /// or a collection), leaving them to the holders (see [`Provider::release`]); returns how
    /// many pieces it dropped.
    pub async fn release(&self, d: Dev, name: &Name) -> Result<u64, Failure> {
        self.provider
            .release(&self.net.fabric, self.net.spec(d), name)
            .await
            .map_err(|e| Failure::new(format!("release failed: {e:#}")))
    }

    /// `d`'s storage silently loses every `every`-th stored piece of `collection` (1 = all), in
    /// name order (see [`Provider::lose`]); returns how many it lost.
    pub fn lose(&self, d: Dev, collection: &Name, every: u32) -> u64 {
        self.provider.lose(self.net.spec(d), collection, every)
    }

    /// The octets of the pieces `d` stores under `prefix`, a collection or a version's name (see
    /// [`Provider::stored`]).
    pub fn stored(&self, d: Dev, prefix: &Name) -> u64 {
        self.provider.stored(self.net.spec(d), prefix)
    }

    /// From now on `d` answers audits by relaying each asked piece from the network instead of
    /// from its store (see [`Provider::relay_audits`]).
    pub async fn relay_audits(&self, d: Dev) -> Result<(), Failure> {
        self.provider
            .relay_audits(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("cannot relay audits: {e:#}")))
    }

    /// The signatures `d`'s data layer has made, cumulative (see [`Provider::signed_by`]).
    pub fn signed_by(&self, d: Dev) -> u64 {
        self.provider.signed_by(self.net.spec(d))
    }

    /// `d`, a malicious holder, replaces the packet of block `version` in its store as `how`
    /// says, keeping its signature bytes (see [`Provider::tamper`]).
    pub fn tamper(&self, d: Dev, version: &Name, how: Tamper) -> Result<(), Failure> {
        self.provider
            .tamper(self.net.spec(d), version, how)
            .map_err(|e| Failure::new(format!("cannot tamper: {e:#}")))
    }

    /// From now on `d`'s node answers Interests under `prefix` with the packet that answers it
    /// now, fetched fresh: a replaying cache (see [`Provider::replay`]).
    pub async fn replay(&self, d: Dev, prefix: &Name) -> Result<(), Failure> {
        self.provider
            .replay(&self.net.fabric, self.net.spec(d), prefix)
            .await
            .map_err(|e| Failure::new(format!("cannot replay: {e:#}")))
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
        // MustBeFresh: the answer is stale at once, so a cache on the way (which now admits
        // every Data, as NFD's does) never answers for the device; only the device itself can.
        consumer
            .fetch_with(
                InterestBuilder::new(name)
                    .must_be_fresh()
                    .lifetime(Duration::from_secs(1)),
            )
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
