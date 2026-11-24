//! The recording core of the stand-in host a device's introductions run against, independent of
//! the crate that implements them.
//!
//! A host is asked of its link layer during an introduction: to dial the inviter by a link hint
//! or by the one address a short code names, to take a link down, and it is told of the grants,
//! departures and ends of grants the layer makes. In the simulated world the forwarders already
//! route every name through the hub, so the stand-in has no real link: a dial answers at once
//! for a device that listens at the address (and proves the key) it dials, and for no other.
//!
//! [`IntroduceCore`] is that stand-in's memory and decision, in plain types
//! ([`GrantEvent`](crate::invite::GrantEvent), [`LinkCall`](crate::invite::LinkCall)): what the
//! host was told, in order, across restarts of its layer; what it was asked, in order; who
//! listens where. Each provider wraps one core in its crate's host trait
//! (`ndn_data::Introducer` for `ndn-data`, `ndn_invite::Host` for `ndn-invite`), converts that
//! crate's types at the edge, and adds what is the crate's own (the anchor, adopting a person,
//! routing what a first contact's link carries).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use ndn_data::Name;
use ndn_sim::NodeId;

use crate::invite::{GrantEvent, InviteDeparture, InviteGrant, LinkCall};

/// The port every device's link socket listens on.
pub const LINK_PORT: u16 = 4433;

/// Where `node`'s host listens: an address of the documentation range 192.0.2.0/24 (RFC 5737),
/// the node's number as its last octet, so every device has its own and it is the same in every
/// run.
pub fn link_address(node: NodeId) -> anyhow::Result<SocketAddr> {
    let octet = u8::try_from(node.0).with_context(|| format!("{node} has no 192.0.2.x address"))?;
    Ok(SocketAddr::from(([192, 0, 2, octet], LINK_PORT)))
}

/// The addresses the devices of a case listen at and the keys they prove there: shared by the
/// cores of one case.
pub type Listening = Arc<Mutex<HashMap<SocketAddr, [u8; 32]>>>;

/// What one device's host was told and asked, and how its link layer answers.
pub struct IntroduceCore {
    /// What the host was told of grants, oldest first.
    told: Mutex<Vec<GrantEvent>>,
    /// What the host was asked of its link layer, oldest first.
    dialled: Mutex<Vec<LinkCall>>,
    /// The first-contact links up, by the inviter's device and the address dialled.
    firsts: Mutex<Vec<(Name, SocketAddr)>>,
    /// Who listens where, in this case.
    listening: Listening,
    /// Where this host listens.
    address: SocketAddr,
    /// The key this host's link proves.
    key: [u8; 32],
}

impl IntroduceCore {
    /// The core of a host that listens at `address` and proves `key` there, which `listening`
    /// from now on says.
    pub fn new(listening: Listening, address: SocketAddr, key: [u8; 32]) -> Self {
        listening
            .lock()
            .expect("the host's lock")
            .insert(address, key);
        Self {
            told: Mutex::new(Vec::new()),
            dialled: Mutex::new(Vec::new()),
            firsts: Mutex::new(Vec::new()),
            listening,
            address,
            key,
        }
    }

    /// Where this host listens: the address it gives in its link hint.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The key this host's link proves: the key its link hint names.
    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    /// The key the device that listens at `addr` proves, if one does.
    fn proves(&self, addr: &SocketAddr) -> Option<[u8; 32]> {
        self.listening
            .lock()
            .expect("the host's lock")
            .get(addr)
            .copied()
    }

    /// The host is asked to dial the inviter `inviter` by a hint naming `key`, at `candidates`:
    /// recorded, and answered when a device listens at one of them and proves `key`, as a
    /// handshake would; no other address or key makes a link.
    pub fn dial(&self, inviter: &Name, key: [u8; 32], candidates: &[SocketAddr]) -> bool {
        let answered = candidates.iter().any(|a| self.proves(a) == Some(key));
        self.dialled
            .lock()
            .expect("the host's lock")
            .push(LinkCall::Dial {
                inviter: inviter.clone(),
                key,
                candidates: candidates.to_vec(),
                answered,
            });
        answered
    }

    /// The host is asked to dial the inviter's one first-contact address `addr`, with no key to
    /// expect: recorded, and answered with the key of the device that listens there, which a
    /// handshake proves; an address nobody listens at does not answer. An answered dial is a
    /// first-contact link, kept until [`undial`](Self::undial) takes it down.
    pub fn dial_first(&self, inviter: &Name, addr: SocketAddr) -> Option<[u8; 32]> {
        let proved = self.proves(&addr);
        self.dialled
            .lock()
            .expect("the host's lock")
            .push(LinkCall::DialFirst {
                inviter: inviter.clone(),
                addr,
                answered: proved.is_some(),
            });
        if proved.is_some() {
            self.firsts
                .lock()
                .expect("the host's lock")
                .push((inviter.clone(), addr));
        }
        proved
    }

    /// The host is asked to take down what a dial of `inviter` by `key` at `candidates` made:
    /// recorded. Returns whether a first-contact link ([`dial_first`](Self::dial_first), the
    /// hint's candidate being the address dialled first) was taken down, so the host stops
    /// carrying what that link carried.
    pub fn undial(&self, inviter: &Name, key: [u8; 32], candidates: &[SocketAddr]) -> bool {
        self.dialled
            .lock()
            .expect("the host's lock")
            .push(LinkCall::Undial {
                inviter: inviter.clone(),
                key,
                candidates: candidates.to_vec(),
            });
        let mut firsts = self.firsts.lock().expect("the host's lock");
        let Some(at) = firsts.iter().position(|(device, addr)| {
            device == inviter && candidates.contains(addr) && self.proves(addr) == Some(key)
        }) else {
            return false;
        };
        firsts.remove(at);
        true
    }

    /// The host is told of a grant.
    pub fn granted(&self, grant: InviteGrant) {
        self.told
            .lock()
            .expect("the host's lock")
            .push(GrantEvent::Granted(grant));
    }

    /// The host is told a held record let a person go.
    pub fn departed(&self, departure: InviteDeparture) {
        self.told
            .lock()
            .expect("the host's lock")
            .push(GrantEvent::Departed(departure));
    }

    /// The host is told the grant of `key` for `space` ended.
    pub fn revoked(&self, key: [u8; 32], space: &Name) {
        self.told
            .lock()
            .expect("the host's lock")
            .push(GrantEvent::Revoked {
                key,
                space: space.clone(),
            });
    }

    /// What the host was told of grants, oldest first.
    pub fn told(&self) -> Vec<GrantEvent> {
        self.told.lock().expect("the host's lock").clone()
    }

    /// What the host was asked of its link layer, oldest first.
    pub fn calls(&self) -> Vec<LinkCall> {
        self.dialled.lock().expect("the host's lock").clone()
    }
}
