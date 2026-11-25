//! The world a case runs in: devices on a real ndn-sim fabric ([`Net`]) and their data layers
//! ([`World`]).
//!
//! Topology: every device is a forwarder linked to one hub forwarder (the network between
//! devices). Devices route everything to the hub; the hub multicasts to every device, so any
//! device can reach any name another device serves. Going offline cuts a device's link; every
//! device has its own wall clock, which a case can set wrong at any time.

use std::cell::{Cell, RefCell};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Connection, EngineAppExt, ForwarderEngine};
use ndn_heap::{Name, Timestamp};
use ndn_packet::encode::InterestBuilder;
use ndn_security::Signer;
use ndn_sim::{
    ClockSkew, Fabric, FaceKind, FaceProfile, Faults, LinkConfig, NodeId, NodeProfile,
    PrefixSample, SimKernel, Simulation,
};
use ndn_surface::signal::Signals;
use tokio_util::sync::CancellationToken;

use crate::case::Failure;
use crate::invite::{
    GrantLog, InviteCode, InviteFailure, InviteJoined, InviteOffer, InviteShort, InviteShortError,
    JoinedList, LinkCall,
};
use crate::provider::{Certs, DeviceSpec, Grants, Image, NodeRole, Provider, SignalKeyPair, Tally};
use crate::report::{Cost, Measure};
use crate::spaces::{SpaceEntry, Spaces};

/// A device of a [`Plan`], by position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Dev(pub usize);

/// How long [`World::retry_later`] asks again while a verb answers a `RetryLater` next step: as
/// long as a case waits for anything to arrive.
pub const AGAIN_FOR: Duration = Duration::from_secs(120);

/// The virtual time [`World::retry_later`] lets pass between two asks.
pub const AGAIN_PAUSE: Duration = Duration::from_millis(500);

#[derive(Clone, Debug)]
struct Planned {
    person: String,
    /// The device's role in the person's namespace, if it has one (`guest`).
    role: Option<String>,
    device: String,
    /// A thief: takes this device, key and storage ([`World::steal`]).
    stolen_from: Option<Dev>,
    /// The person's genesis root key, for a self-certifying person ([`Plan::self_certifying`]).
    genesis: Option<[u8; 32]>,
    /// Its host's introductions make link grants ([`Plan::no_link_grants`]).
    link_grants: bool,
}

/// The devices a case needs, declared before the fabric starts.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    devices: Vec<Planned>,
    /// Count each device's packets by name, to this many name components
    /// ([`Plan::count_names`]).
    names: Option<usize>,
    /// Every person a stranger to the others ([`Plan::strangers`]).
    strangers: bool,
    /// The fault profile every packet arriving at a device meets ([`Plan::faults`]).
    faults: Option<Faults>,
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

    /// Make every person a stranger to the others: each device's node holds its own person's
    /// trust context and certificates only, so it validates nothing of another person until an
    /// introduction ([`World::join`]) adopts that person's anchor.
    pub fn strangers(&mut self) {
        self.strangers = true;
    }

    /// Run the case on a faulty network: every packet arriving at a device from its link is
    /// dropped, duplicated, forged, delayed or reordered as `faults` says (ndf's per-arrival
    /// fault layer; see [`ndn_sim::Faults`]). What the hub receives is not faulted, so every
    /// packet from one device to another meets the profile exactly once, on its way into the
    /// receiving device, as on a direct connection under ndf's layer. The device links are then
    /// the face ndf's layer sits on, an ndn-link QUIC stream face: whole packets meet the faults
    /// (no NDNLPv2 fragments), and no LP reliability resends a dropped one. Each link draws from
    /// its own stream,
    /// seeded by `faults.seed` and the link, so the case replays identically alone and in a
    /// suite. A case that sets this keeps it under the runner's faulty mode, whose
    /// `--fault-seed` replaces only its seed ([`crate::runner::Network`]).
    pub fn faults(&mut self, faults: Faults) {
        self.faults = Some(faults);
    }

    /// The fault profile the case runs under, if any ([`faults`](Self::faults)).
    pub fn fault_profile(&self) -> Option<Faults> {
        self.faults
    }

    /// Add `person`'s `device` (e.g. `"alice"`, `"laptop"`). The person is a namespace of any
    /// number of components, written without its leading slash (`"home/bob"` is `/home/bob`).
    pub fn device(&mut self, person: &str, device: &str) -> Dev {
        self.add(person, device)
    }

    /// Add a guest of `person`'s namespace: a friend's device `<person>/guest/<who>`, certified
    /// by `person` as a guest (a role whose data, once its certificate lapsed, needs a cut).
    pub fn guest(&mut self, person: &str, who: &str) -> Dev {
        let d = self.add(person, who);
        self.devices[d.0].role = Some("guest".to_owned());
        d
    }

    /// Add a role-named device of `person`'s namespace as `ndn-fwd init` names them: a member's
    /// device `<person>/member/<who>`, certified by `person` as a member (a role whose data,
    /// once its certificate lapsed without a renewal, needs a cut as a guest's does). The
    /// plain [`device`](Self::device) `<person>/<device>` has no role: no rule of the context's
    /// DataRequiresCut applies to its key.
    pub fn member(&mut self, person: &str, who: &str) -> Dev {
        let d = self.add(person, who);
        self.devices[d.0].role = Some("member".to_owned());
        d
    }

    /// `d`'s host makes no link grants: its `IntroPolicy::grant_for` is zero.
    pub fn no_link_grants(&mut self, d: Dev) {
        self.devices[d.0].link_grants = false;
    }

    /// Add `device` of the self-certifying person whose root key is the Ed25519 secret
    /// `genesis`: the person is named by that key alone, `/user/<0xA1: SHA-256 of its public
    /// key>` (ndn-cert's `GenesisKey`), and its trust context's version 1 is signed by it. The
    /// person's namespace, as the case names it: [`self_certifying_person`].
    pub fn self_certifying(&mut self, genesis: [u8; 32], device: &str) -> Dev {
        let person = self_certifying_person(&genesis).to_string();
        let d = self.add(person.trim_start_matches('/'), device);
        self.devices[d.0].genesis = Some(genesis);
        d
    }

    fn add(&mut self, person: &str, device: &str) -> Dev {
        self.devices.push(Planned {
            person: person.to_owned(),
            role: None,
            device: device.to_owned(),
            stolen_from: None,
            genesis: None,
            link_grants: true,
        });
        Dev(self.devices.len() - 1)
    }

    /// Add a thief's node, which takes `victim`'s device — key and storage — when the case
    /// says so ([`World::steal`]).
    pub fn thief(&mut self, victim: Dev) -> Dev {
        self.devices.push(Planned {
            person: "thief".to_owned(),
            role: None,
            device: format!("with-{}", self.devices[victim.0].device),
            stolen_from: Some(victim),
            genesis: None,
            link_grants: true,
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

/// The namespace of the self-certifying person whose root key is the Ed25519 secret `genesis`
/// ([`Plan::self_certifying`]): `/user/<0xA1: SHA-256 of its public key>`.
pub fn self_certifying_person(genesis: &[u8; 32]) -> Name {
    ndn_cert::GenesisKey::from_seed(*genesis).namespace()
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
    /// The fault profile every packet arriving at a device meets, if any ([`Plan::faults`]).
    faults: Option<Faults>,
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
            let person = match &p.genesis {
                Some(genesis) => self_certifying_person(genesis),
                None => format!("/{}", p.person).parse()?,
            };
            let spec = DeviceSpec {
                person,
                role: p.role.clone(),
                device: p.device.clone(),
                // The hub is node 0; devices follow in plan order.
                node: NodeId(i + 1),
                stranger: plan.strangers,
                genesis: p.genesis,
                link_grants: p.link_grants,
            };
            let mut node_profile = profile(&spec);
            node_profile.clock_skew.get_or_insert(ClockSkew::NONE);
            labels.push(node_profile.label.clone());
            let node = sim.add_node_profile(node_profile);
            debug_assert_eq!(node, spec.node);
            match plan.faults {
                None => sim.link(node, hub_node, LinkConfig::lan()),
                // ndf's direct connection is an ndn-link QUIC stream face, and its fault layer
                // sits on that face: whole packets meet the faults, none is cut into NDNLPv2
                // fragments, and no LP reliability resends what the layer drops. A faulty link
                // is that face, so a large Data is dropped, held or forged once, as there; on
                // the UDP face each fragment would meet the profile, and LP reliability would
                // resend nearly every drop (the device's Acks travel the clean way). It is
                // wired permanent, as the clean link is: the faults are what arrives on it, not
                // its life, so a case's long absence ([`World::skip`]) does not leave the hub
                // removing it as an idle on-demand face that nothing dials again.
                Some(_) => sim.link_profiled(
                    node,
                    hub_node,
                    FaceProfile::quic()
                        .with_link(LinkConfig::lan())
                        .with_persistency(ndn_transport::FacePersistency::Permanent),
                ),
            }
            sim.add_route(node, "/", hub_node);
            sim.add_route(hub_node, "/", node);
            specs.push(spec);
        }
        let fabric = sim.start().await?;
        if let Some(faults) = plan.faults {
            // What arrives at each device from its link; the hub's side stays clean, so a packet
            // between two devices meets the profile once.
            for spec in &specs {
                fabric.set_link_faults(hub_node, spec.node, Some(faults))?;
            }
        }
        Ok(Net {
            fabric,
            hub: hub_node,
            specs,
            labels,
            faults: plan.faults,
        })
    }

    /// The running fabric.
    pub fn fabric(&self) -> &Fabric {
        &self.fabric
    }

    /// The fault profile every packet arriving at a device meets, if any ([`Plan::faults`]).
    pub fn faults(&self) -> Option<Faults> {
        self.faults
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

    /// A passer-by on the network: an app on the hub's own node asks once for the packet named
    /// exactly `name`, so the hub forwards whatever answers through its validation and its
    /// content store, as a forwarder on any device's path would. Returns whether a packet came
    /// back within two seconds of virtual time (one the hub's validation refused does not).
    pub async fn ask_at_hub(&self, name: &Name) -> bool {
        let Some(engine) = self.fabric.engine_of(self.hub) else {
            return false;
        };
        let mut consumer = engine.app_consumer(tokio_util::sync::CancellationToken::new());
        consumer
            .fetch_with(InterestBuilder::new(name.clone()).lifetime(Duration::from_secs(2)))
            .await
            .is_ok()
    }

    /// An app of `d`'s own on its node: a raw face to its forwarder, for packets a case makes
    /// by hand (a push Interest it injects, as a hostile program on the device would).
    pub fn app_face(&self, d: Dev) -> Arc<dyn Connection> {
        self.fabric
            .engine_of(self.specs[d.0].node)
            .expect("every device is a node")
            .app_face(CancellationToken::new())
    }

    /// A tap on the hub, the relay between every two devices: from now on it receives a copy of
    /// every Interest the hub forwards under `prefix`, as the relay forwards it. The hub reaches
    /// every device under `prefix` as before (its route there names every device's link beside
    /// the tap, as its default route does), so the tap changes nothing the devices receive.
    pub async fn tap(&self, prefix: &Name) -> Tap {
        let engine = self.fabric.engine_of(self.hub).expect("the hub is a node");
        for spec in &self.specs {
            let link = self
                .fabric
                .face_between(self.hub, spec.node)
                .expect("every device is linked to the hub");
            engine.fib().add_nexthop(prefix, link, 0);
        }
        let conn = engine.app_face(CancellationToken::new());
        conn.register_prefix(prefix)
            .await
            .expect("an in-process face routes any prefix");
        let seen: Arc<Mutex<Vec<Bytes>>> = Arc::default();
        let into = Arc::clone(&seen);
        let task = tokio::spawn(async move {
            while let Some(wire) = conn.recv().await {
                into.lock().expect("the tap's lock").push(bare(wire));
            }
        });
        Tap { seen, task }
    }

    /// The name of every packet any forwarder's content store (the hub's and each device's)
    /// holds now.
    pub async fn cached(&self) -> Vec<Name> {
        let mut names = Vec::new();
        let now = self.fabric.clock().now_ns();
        let nodes = std::iter::once(self.hub).chain(self.specs.iter().map(|s| s.node));
        for node in nodes {
            let Some(engine) = self.fabric.engine_of(node) else {
                continue;
            };
            let cs = engine.cs();
            let mut after: Option<Name> = None;
            loop {
                let page = cs
                    .list_erased(&Name::root(), after.as_ref(), 1024, now)
                    .await;
                names.extend(page.entries.iter().map(|e| (*e.name).clone()));
                match page.entries.last() {
                    Some(last) if page.more => after = Some((*last.name).clone()),
                    _ => break,
                }
            }
        }
        names
    }

    /// Every node's traffic so far by name, as the plan counts it ([`Plan::count_names`]).
    pub fn traffic(&self) -> Vec<PrefixSample> {
        self.fabric
            .prefix_stats()
            .expect("a case reading traffic by name plans to count names (Plan::count_names)")
            .snapshot()
    }

    /// From now on `d` reaches nothing under `prefix` (another device's name: its records, its
    /// summaries): its node routes `prefix` to a face that answers nothing, while everything
    /// else — every Interest it pushes or receives — flows. Until the [`CutOff`] is restored or
    /// dropped. A hold on the link would not do: on the faulty fabric's ordered link face a held
    /// packet holds every packet behind it.
    pub async fn cut_off(&self, d: Dev, prefix: &Name) -> CutOff {
        let engine = self
            .fabric
            .engine_of(self.specs[d.0].node)
            .expect("every device is a node");
        let sink = engine.app_face(CancellationToken::new());
        sink.register_prefix(prefix)
            .await
            .expect("an in-process face routes any prefix");
        let task = tokio::spawn(async move { while sink.recv().await.is_some() {} });
        CutOff {
            engine,
            prefix: prefix.clone(),
            task,
        }
    }
}

/// A device cut off from a prefix ([`Net::cut_off`]).
pub struct CutOff {
    engine: ForwarderEngine,
    prefix: Name,
    task: tokio::task::JoinHandle<()>,
}

impl CutOff {
    /// The device reaches the prefix again, by its routes from before.
    pub fn restore(self) {}
}

impl Drop for CutOff {
    fn drop(&mut self) {
        self.engine.fib().remove_prefix(&self.prefix);
        self.task.abort();
    }
}

/// A tap on the relay ([`Net::tap`]).
pub struct Tap {
    seen: Arc<Mutex<Vec<Bytes>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Tap {
    /// Every Interest the relay forwarded under the tapped prefix so far, as it forwarded it.
    pub fn interests(&self) -> Vec<Bytes> {
        self.seen.lock().expect("the tap's lock").clone()
    }
}

impl Drop for Tap {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A frame as its packet: an NDNLPv2 packet's fragment, or the frame itself.
fn bare(wire: Bytes) -> Bytes {
    if wire.first() == Some(&0x64)
        && let Ok(lp) = ndn_packet::LpPacket::decode(wire.clone())
        && let Some(fragment) = lp.fragment
    {
        return fragment;
    }
    wire
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
    /// Each device's spaces; a thief has them once it takes the stolen device
    /// ([`World::steal`]), a device stopped none until it starts again.
    spaces: RefCell<Vec<Option<Arc<dyn Spaces>>>>,
    /// For each device, the device it holds a stolen key of (a thief).
    victims: Vec<Option<Dev>>,
    provider: Arc<dyn Provider>,
    gestures: Cell<u64>,
    converge: Cell<Option<Duration>>,
    reported_from: Cell<Option<Mark>>,
    measured: RefCell<Vec<Measure>>,
    /// Each device's signals once started ([`World::signals`]), shut down with the world.
    signals: RefCell<Vec<Option<Signals>>>,
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
        let mut spaces = Vec::with_capacity(plan.devices.len());
        for (i, p) in plan.devices.iter().enumerate() {
            let attached = match p.stolen_from {
                Some(_) => None,
                None => Some(provider.attach(&net.fabric, &net.specs[i]).await?),
            };
            spaces.push(attached);
        }
        Ok(World {
            net,
            spaces: RefCell::new(spaces),
            victims: plan.devices.iter().map(|p| p.stolen_from).collect(),
            provider,
            gestures: Cell::new(0),
            converge: Cell::new(None),
            reported_from: Cell::new(None),
            measured: RefCell::new(Vec::new()),
            signals: RefCell::new(vec![None; plan.devices.len()]),
        })
    }

    /// The devices and their links.
    pub fn net(&self) -> &Net {
        &self.net
    }

    /// The device's spaces: the neutral surface every case drives.
    ///
    /// # Panics
    ///
    /// For a thief that has not taken the stolen device yet ([`steal`](Self::steal)), and for a
    /// device that is stopped ([`stop`](Self::stop)) until it starts again.
    pub fn spaces(&self, d: Dev) -> Arc<dyn Spaces> {
        let spaces = self.spaces.borrow();
        let attached = spaces[d.0].as_ref().unwrap_or_else(|| {
            panic!(
                "device {} runs no data layer: a thief before it steals the device, or a device \
                 stopped until it restarts",
                d.0
            )
        });
        Arc::clone(attached)
    }

    /// Record one person gesture: pointing at data, pointing at someone, throwing away.
    pub fn gesture(&self) {
        self.gestures.set(self.gestures.get() + 1);
    }

    /// The owner reports `device` lost at `since` (by `by`'s clock), and `by`, the namespace's
    /// root device, suspects its key from now on (see [`Provider::suspect`]).
    pub async fn suspect(&self, by: Dev, device: Dev, since: Timestamp) -> Result<(), Failure> {
        self.provider
            .suspect(
                &self.net.fabric,
                self.net.spec(by),
                self.net.spec(device),
                since,
            )
            .await
            .map_err(|e| Failure::new(format!("suspect failed: {e:#}")))
    }

    /// `by`, holding the namespace's authority, revokes `device`'s key with a cut at what `by`
    /// first verified before `lost` (see [`Provider::revoke`]), and the new trust-context
    /// version reaches every node ([`spread_all`](Self::spread_all)). Returns the entries of the
    /// key `by` held but left out of the cut, by full name.
    pub async fn revoke(
        &self,
        by: Dev,
        device: Dev,
        lost: Timestamp,
    ) -> Result<Vec<Name>, Failure> {
        let left_out = self.revoke_at(by, device, lost).await?;
        self.spread_all().await?;
        Ok(left_out)
    }

    /// As [`revoke`](Self::revoke), but the new version stays on `by`'s node until
    /// [`spread`](Self::spread) carries it further: the revocation has not reached the others
    /// yet.
    pub async fn revoke_at(
        &self,
        by: Dev,
        device: Dev,
        lost: Timestamp,
    ) -> Result<Vec<Name>, Failure> {
        self.provider
            .revoke(
                &self.net.fabric,
                self.net.spec(by),
                self.net.spec(device),
                lost,
            )
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

    /// `by`, holding the namespace's authority, re-admits exactly the packet `full` (see
    /// [`Provider::readmit_name`]), and the new trust-context version reaches every node.
    pub async fn readmit_name(&self, by: Dev, full: &Name) -> Result<(), Failure> {
        self.provider
            .readmit_name(&self.net.fabric, self.net.spec(by), full)
            .await
            .map_err(|e| Failure::new(format!("readmit failed: {e:#}")))?;
        self.spread_all().await
    }

    /// `by`, the namespace's root device, ends the keys whose authority over data ended without
    /// a revocation (see [`Provider::end_keys`]), and the new trust-context versions reach every
    /// node. Returns the keys it ended.
    pub async fn end_keys(&self, by: Dev) -> Result<Vec<Name>, Failure> {
        let ended = self
            .provider
            .end_keys(&self.net.fabric, self.net.spec(by))
            .await
            .map_err(|e| Failure::new(format!("ending lapsed keys failed: {e:#}")))?;
        self.spread_all().await?;
        Ok(ended)
    }

    /// `d`'s data layer stops, keeping what it stored (see [`Provider::stop`]);
    /// [`spaces`](Self::spaces) and [`at`](Self::at) have none for it until
    /// [`restart`](Self::restart).
    pub async fn stop(&self, d: Dev) -> Result<(), Failure> {
        self.provider
            .stop(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("cannot stop the data layer: {e:#}")))?;
        self.spaces.borrow_mut()[d.0] = None;
        self.signals.borrow_mut()[d.0] = None;
        Ok(())
    }

    /// `d`'s stopped data layer starts again on what it stored (see [`Provider::restart`]);
    /// [`spaces`](Self::spaces) answers the new run's spaces, which this returns.
    pub async fn restart(&self, d: Dev) -> Result<Arc<dyn Spaces>, Failure> {
        let started = self
            .provider
            .restart(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("cannot restart the data layer: {e:#}")))?;
        self.spaces.borrow_mut()[d.0] = Some(Arc::clone(&started));
        Ok(started)
    }

    /// The thief `thief` takes the device whose key it holds, storage and all (see
    /// [`Provider::steal`]): [`spaces`](Self::spaces) answers its spaces from now on.
    pub async fn steal(&self, thief: Dev) -> Result<(), Failure> {
        let victim = self.victims[thief.0]
            .unwrap_or_else(|| panic!("device {} of the plan is no thief", thief.0));
        let stolen = self
            .provider
            .steal(
                &self.net.fabric,
                self.net.spec(victim),
                self.net.spec(thief),
            )
            .await
            .map_err(|e| Failure::new(format!("cannot steal the device: {e:#}")))?;
        self.spaces.borrow_mut()[thief.0] = Some(stolen);
        Ok(())
    }

    /// `d` crashes and starts again on what its store kept (see [`Provider::crash`]);
    /// [`spaces`](Self::spaces) answers the new run's spaces, which this returns.
    pub async fn crash(&self, d: Dev) -> Result<Arc<dyn Spaces>, Failure> {
        self.signals.borrow_mut()[d.0] = None;
        let started = self
            .provider
            .crash(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("cannot crash the device: {e:#}")))?;
        self.spaces.borrow_mut()[d.0] = Some(Arc::clone(&started));
        Ok(started)
    }

    /// A copy of what `d`'s store holds now (see [`Provider::image`]).
    pub async fn image(&self, d: Dev) -> Result<Image, Failure> {
        self.provider
            .image(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("cannot image the store: {e:#}")))
    }

    /// `d` starts again on `image` in place of its store (see [`Provider::restore`]);
    /// [`spaces`](Self::spaces) answers the new run's spaces, which this returns.
    pub async fn restore(&self, d: Dev, image: Image) -> Result<Arc<dyn Spaces>, Failure> {
        self.signals.borrow_mut()[d.0] = None;
        let started = self
            .provider
            .restore(&self.net.fabric, self.net.spec(d), image)
            .await
            .map_err(|e| Failure::new(format!("cannot restore the store: {e:#}")))?;
        self.spaces.borrow_mut()[d.0] = Some(Arc::clone(&started));
        Ok(started)
    }

    /// `d`'s store holds its flush (`on`) or lets it return again (see [`Provider::block_flush`]).
    pub async fn block_flush(&self, d: Dev, on: bool) -> Result<(), Failure> {
        self.provider
            .block_flush(&self.net.fabric, self.net.spec(d), on)
            .await
            .map_err(|e| Failure::new(format!("cannot hold the flush: {e:#}")))
    }

    /// `d`'s process is killed and starts again on what its store accepted, flushed or not (see
    /// [`Provider::kill`]); [`spaces`](Self::spaces) answers the new run's spaces, which this
    /// returns.
    pub async fn kill(&self, d: Dev) -> Result<Arc<dyn Spaces>, Failure> {
        self.signals.borrow_mut()[d.0] = None;
        let started = self
            .provider
            .kill(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("cannot kill the device: {e:#}")))?;
        self.spaces.borrow_mut()[d.0] = Some(Arc::clone(&started));
        Ok(started)
    }

    /// `d`'s store fails every flush with `reason`, or flushes again with `None` (see
    /// [`Provider::fail_flush`]).
    pub async fn fail_flush(&self, d: Dev, reason: Option<&str>) -> Result<(), Failure> {
        self.provider
            .fail_flush(&self.net.fabric, self.net.spec(d), reason)
            .await
            .map_err(|e| Failure::new(format!("cannot fail the flush: {e:#}")))
    }

    /// `d`, a copy of a key, signs `bytes` at `path` of `space` as its entry number `seq` (see
    /// [`Provider::sign_at`]).
    pub async fn sign_at(
        &self,
        d: Dev,
        space: &Name,
        path: &Name,
        bytes: Bytes,
        seq: u64,
    ) -> Result<SpaceEntry, Failure> {
        self.provider
            .sign_at(&self.net.fabric, self.net.spec(d), space, path, bytes, seq)
            .await
            .map_err(|e| Failure::new(format!("cannot sign at seq {seq}: {e:#}")))
    }

    /// `by`, holding the namespace's authority, re-admits `entry` of `from`'s log exactly (see
    /// [`Provider::readmit_entry`]), and the new trust-context version reaches every node.
    pub async fn readmit_entry(
        &self,
        by: Dev,
        from: Dev,
        entry: &SpaceEntry,
    ) -> Result<(), Failure> {
        self.provider
            .readmit_entry(
                &self.net.fabric,
                self.net.spec(by),
                self.net.spec(from),
                entry,
            )
            .await
            .map_err(|e| Failure::new(format!("readmit failed: {e:#}")))?;
        self.spread_all().await
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

    /// `by` makes a one-use offer of `space` and returns its code (see [`Provider::offer`]).
    /// One gesture: the owner offers.
    pub async fn offer(
        &self,
        by: Dev,
        space: &Name,
        offer: InviteOffer,
    ) -> Result<InviteCode, Failure> {
        self.gesture();
        self.provider
            .offer(&self.net.fabric, self.net.spec(by), space, offer)
            .await
            .map_err(|e| Failure::new(format!("offer failed: {e:#}")))
    }

    /// `by`, the device that made `offer`, closes it (see [`Provider::close_offer`]). One
    /// gesture: the owner closes.
    pub async fn close_offer(&self, by: Dev, offer: &Name) -> Result<(), Failure> {
        self.gesture();
        self.provider
            .close_offer(&self.net.fabric, self.net.spec(by), offer)
            .await
            .map_err(|e| Failure::new(format!("close_offer failed: {e:#}")))
    }

    /// `d` joins by `code` (its link, its words or its short line; see [`Provider::join`]): one
    /// gesture, the joiner's. A refusal by `d`'s device is answered as an [`InviteFailure`], for
    /// a case that expects one.
    pub async fn join(
        &self,
        d: Dev,
        code: &str,
    ) -> Result<Result<InviteJoined, InviteFailure>, Failure> {
        self.gesture();
        match self
            .provider
            .join(&self.net.fabric, self.net.spec(d), code)
            .await
        {
            Ok(joined) => Ok(Ok(joined)),
            Err(e) => match e.downcast_ref::<InviteFailure>() {
                Some(refusal) => Ok(Err(refusal.clone())),
                None => Err(Failure::new(format!("join failed: {e:#}"))),
            },
        }
    }

    /// `d` joins by `code`, as [`join`](Self::join) — one gesture — joining again while the
    /// refusal's next step is `"RetryLater"` (the inviter's device not reached yet), as a host
    /// does what the refusal says, every [`AGAIN_PAUSE`] for at most [`AGAIN_FOR`] of virtual
    /// time. Any other refusal is answered at once.
    pub async fn join_again(
        &self,
        d: Dev,
        code: &str,
    ) -> Result<Result<InviteJoined, InviteFailure>, Failure> {
        self.gesture();
        let start = tokio::time::Instant::now();
        loop {
            match self
                .provider
                .join(&self.net.fabric, self.net.spec(d), code)
                .await
            {
                Ok(joined) => return Ok(Ok(joined)),
                Err(e) => match e.downcast_ref::<InviteFailure>() {
                    Some(refusal) if refusal.retry_later() && start.elapsed() < AGAIN_FOR => {
                        tokio::time::sleep(AGAIN_PAUSE).await;
                    }
                    Some(refusal) => return Ok(Err(refusal.clone())),
                    None => return Err(Failure::new(format!("join failed: {e:#}"))),
                },
            }
        }
    }

    /// `verb`, done again while it fails with next step `"RetryLater"`
    /// ([`Failure::retry_later`]) — a host does what the refusal says — every [`AGAIN_PAUSE`]
    /// for at most [`AGAIN_FOR`] of virtual time; then, or at any other failure, the failure as
    /// it came. Asking again is liveness only: what the verb answers when it succeeds is judged
    /// by the device as on a first try.
    pub async fn retry_later<T, F, Fut>(&self, mut verb: F) -> Result<T, Failure>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, Failure>>,
    {
        let start = tokio::time::Instant::now();
        loop {
            match verb().await {
                Err(e) if e.retry_later() && start.elapsed() < AGAIN_FOR => {
                    tokio::time::sleep(AGAIN_PAUSE).await;
                }
                answer => return answer,
            }
        }
    }

    /// `d` writes `bytes` at `path` of `space` ([`Spaces::put`]), writing again while the device
    /// answers `"RetryLater"` ([`retry_later`](Self::retry_later)): a writer whose device has not
    /// yet received the members record admitting it is told so, and writes once it has. The
    /// neutral twin of [`put_op`](Self::put_op).
    pub async fn space_put(
        &self,
        d: Dev,
        space: &Name,
        path: &Name,
        bytes: Bytes,
    ) -> Result<SpaceEntry, Failure> {
        let spaces = self.spaces(d);
        self.retry_later(|| spaces.put(space, path, bytes.clone()))
            .await
    }

    /// `d`'s host adopts the anchor link `link` (see [`Provider::adopt`]): one gesture, the
    /// adopter's. A refusal of the link is answered as why, for a case that expects one. An
    /// adoption of the same namespace already in progress on the node (the data layer follows a
    /// space of a person it does not hold and adopts her for it on its own) says to wait for it
    /// and retry: the host does, as [`retry_later`](Self::retry_later) does, for at most
    /// [`AGAIN_FOR`] of virtual time.
    pub async fn adopt(&self, d: Dev, link: &str) -> Result<Result<(), String>, Failure> {
        self.gesture();
        let start = tokio::time::Instant::now();
        loop {
            let adopted = self
                .provider
                .adopt(&self.net.fabric, self.net.spec(d), link)
                .await;
            match adopted {
                Ok(()) => return Ok(Ok(())),
                Err(e) => match e.downcast_ref::<ndn_cert::AdoptError>() {
                    Some(ndn_cert::AdoptError::InProgress(_)) if start.elapsed() < AGAIN_FOR => {
                        tokio::time::sleep(AGAIN_PAUSE).await;
                    }
                    Some(refusal) => return Ok(Err(refusal.to_string())),
                    None => return Err(Failure::new(format!("adopt failed: {e:#}"))),
                },
            }
        }
    }

    /// What `at`'s forwarder — its node's validator, which judges every packet it forwards —
    /// says of the packet `from` stores under `name` (see [`Provider::forwarder_verdict`]):
    /// `Ok` when it accepts it, else why not. Looking costs no gesture.
    pub async fn forwarder_verdict(
        &self,
        at: Dev,
        from: Dev,
        name: &Name,
    ) -> Result<Result<(), String>, Failure> {
        self.provider
            .forwarder_verdict(
                &self.net.fabric,
                self.net.spec(at),
                self.net.spec(from),
                name,
            )
            .await
            .map_err(|e| Failure::new(format!("cannot ask the forwarder: {e:#}")))
    }

    /// The octets of the pieces `d` stores under `prefix`, a collection or a version's name (see
    /// [`Provider::stored`]).
    pub fn stored(&self, d: Dev, prefix: &Name) -> u64 {
        self.provider.stored(self.net.spec(d), prefix)
    }

    /// How many pieces of `version` (chunks and manifest nodes, not its log entry) `d` stores
    /// (see [`Provider::pieces_stored`]).
    pub fn pieces_stored(&self, d: Dev, version: &Name) -> u64 {
        self.provider.pieces_stored(self.net.spec(d), version)
    }

    /// The signatures `d`'s data layer has made, cumulative (see [`Provider::signed_by`]).
    pub fn signed_by(&self, d: Dev) -> u64 {
        self.provider.signed_by(self.net.spec(d))
    }

    /// The seal-key grants `d`'s data layer has asked for and answered, cumulative (see
    /// [`Provider::grants`]).
    pub fn grants(&self, d: Dev) -> Grants {
        self.provider.grants(self.net.spec(d))
    }

    /// What `d`'s host was told of its link grants, and what its layer lists now (see
    /// [`Provider::link_grants`]). A read, not a gesture.
    pub async fn link_grants(&self, d: Dev) -> Result<GrantLog, Failure> {
        self.provider
            .link_grants(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("link_grants failed: {e:#}")))
    }

    /// The folders `d`'s layer lists as joined, and the generation of that list (see
    /// [`Provider::joined_folders`]). A read, not a gesture.
    pub async fn joined_folders(&self, d: Dev) -> Result<JoinedList, Failure> {
        self.provider
            .joined_folders(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("joined_folders failed: {e:#}")))
    }

    /// The digest of `d`'s own key, which a grant to `d` names (see [`Provider::link_key`]).
    pub async fn link_key(&self, d: Dev) -> Result<[u8; 32], Failure> {
        self.provider
            .link_key(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("link_key failed: {e:#}")))
    }

    /// What `d`'s host was asked of its link layer in introductions, in order (see
    /// [`Provider::link_calls`]). A read, not a gesture.
    pub async fn link_calls(&self, d: Dev) -> Result<Vec<LinkCall>, Failure> {
        self.provider
            .link_calls(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("link_calls failed: {e:#}")))
    }

    /// `d`, a person let go of `space`, takes the members record `record` its inviter told it
    /// of (see [`Provider::take_departure`]): one gesture, the person's host; `from` is the
    /// device that told it (the inviter's host). A refusal by `d`'s device is answered as an
    /// [`InviteFailure`], for a case that expects one.
    pub async fn take_departure(
        &self,
        d: Dev,
        from: Dev,
        space: &Name,
        record: &Name,
    ) -> Result<Result<(), InviteFailure>, Failure> {
        self.gesture();
        match self
            .provider
            .take_departure(
                &self.net.fabric,
                self.net.spec(d),
                self.net.spec(from),
                space,
                record,
            )
            .await
        {
            Ok(()) => Ok(Ok(())),
            Err(e) => match e.downcast_ref::<InviteFailure>() {
                Some(refusal) => Ok(Err(refusal.clone())),
                None => Err(Failure::new(format!("take_departure failed: {e:#}"))),
            },
        }
    }

    /// `d`'s host ends the grant of `key` for `space` (see [`Provider::end_grant_in`]): whether
    /// there was an entry to end. A read of the host's own state, not a gesture.
    pub async fn end_grant_in(
        &self,
        d: Dev,
        key: &[u8; 32],
        space: &Name,
    ) -> Result<bool, Failure> {
        self.provider
            .end_grant_in(&self.net.fabric, self.net.spec(d), key, space)
            .await
            .map_err(|e| Failure::new(format!("end_grant_in failed: {e:#}")))
    }

    /// `d`'s host ends every grant of `key` (see [`Provider::end_grant`]): whether there was an
    /// entry to end.
    pub async fn end_grant(&self, d: Dev, key: &[u8; 32]) -> Result<bool, Failure> {
        self.provider
            .end_grant(&self.net.fabric, self.net.spec(d), key)
            .await
            .map_err(|e| Failure::new(format!("end_grant failed: {e:#}")))
    }

    /// What the short code `line` reads as (see [`Provider::short_read`]); pure, asks no
    /// device.
    pub fn short_read(&self, line: &str) -> Result<InviteShort, InviteShortError> {
        self.provider.short_read(line)
    }

    /// The line a short code is written as (see [`Provider::short_write`]).
    pub fn short_write(&self, short: &InviteShort) -> Result<String, InviteShortError> {
        self.provider.short_write(short)
    }

    /// From now on `d`'s node answers Interests under `prefix` with the packet that answers it
    /// now, fetched fresh, its last octet (its signature's) flipped (see
    /// [`Provider::replay_altered`]). Every forwarder's cache is then emptied under `prefix`, so
    /// the genuine copy `d` fetched answers nobody.
    pub async fn replay_altered(&self, d: Dev, prefix: &Name) -> Result<(), Failure> {
        self.provider
            .replay_altered(&self.net.fabric, self.net.spec(d), prefix)
            .await
            .map_err(|e| Failure::new(format!("cannot replay an altered packet: {e:#}")))?;
        self.net.forget_cached(prefix).await;
        Ok(())
    }

    /// `d`'s host's signals (see [`Provider::signals`]), started on first ask.
    pub async fn signals(&self, d: Dev) -> Result<Signals, Failure> {
        if let Some(signals) = &self.signals.borrow()[d.0] {
            return Ok(signals.clone());
        }
        let signals = self
            .provider
            .signals(&self.net.fabric, self.net.spec(d))
            .await
            .map_err(|e| Failure::new(format!("cannot start signals: {e:#}")))?;
        self.signals.borrow_mut()[d.0] = Some(signals.clone());
        Ok(signals)
    }

    /// `d`'s host routes the sync group `group` to its signals too, as an eavesdropper on its
    /// own node does (see [`Provider::listen`]).
    pub async fn listen(&self, d: Dev, group: &Name) -> Result<(), Failure> {
        self.provider
            .listen(&self.net.fabric, self.net.spec(d), group)
            .await
            .map_err(|e| Failure::new(format!("cannot listen to {group}: {e:#}")))
    }

    /// The signal keys `d` holds for `space` to seal with and open by, newest epoch's first, as
    /// (id, key) (see [`Provider::signal_keys`]).
    pub fn signal_keys(&self, d: Dev, space: &Name) -> Result<Vec<SignalKeyPair>, Failure> {
        self.provider
            .signal_keys(self.net.spec(d), space)
            .map_err(|e| Failure::new(format!("no signal keys: {e:#}")))
    }

    /// A run header signed by `d`'s key for `space` (see [`Provider::signal_header`]).
    pub fn signal_header(
        &self,
        d: Dev,
        space: &Name,
        run_id: &[u8; 16],
        body: &[u8],
    ) -> Result<Bytes, Failure> {
        self.provider
            .signal_header(self.net.spec(d), space, run_id, body)
            .map_err(|e| Failure::new(format!("no run header: {e:#}")))
    }

    /// Whether `d` holds `key` a member of `space` now (see [`Provider::signal_member`]).
    pub fn signal_member(&self, d: Dev, space: &Name, key: &Name) -> Result<bool, Failure> {
        self.provider
            .signal_member(self.net.spec(d), space, key)
            .map_err(|e| Failure::new(format!("no member verdict: {e:#}")))
    }

    /// `d`'s own signing key, as a hostile program on it holds it (see [`Provider::signer`]).
    pub fn signer(&self, d: Dev) -> Result<Arc<dyn Signer>, Failure> {
        self.provider
            .signer(self.net.spec(d))
            .map_err(|e| Failure::new(format!("no key: {e:#}")))
    }

    /// The name of every packet `d`'s data layer stores (see [`Provider::stored_names`]).
    pub fn stored_names(&self, d: Dev) -> Result<Vec<Name>, Failure> {
        self.provider
            .stored_names(self.net.spec(d))
            .map_err(|e| Failure::new(format!("cannot list the store: {e:#}")))
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

    /// Let what is still in flight at this instant finish before the cost is read: every task that
    /// can run does, and every blocking job (a store flush, a signature, an evaluation, each on a
    /// real thread) ends. A paused clock never advances while a blocking job runs, so one
    /// millisecond of virtual time passes only when the executor is idle and none is left. Without
    /// it, whether a notice a device was about to send went out before the cost was read depended
    /// on how fast a real thread finished against a task that needed it, and a loaded machine
    /// measured one Interest more than an idle one (case `a3`, 2 against 3 round trips).
    pub async fn settle(&self) {
        tokio::time::sleep(Duration::from_millis(1)).await;
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

    /// Shut the device's signals and the fabric down.
    pub async fn shutdown(self) {
        for signals in self.signals.borrow().iter().flatten() {
            signals.shutdown();
        }
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
