//! `ndn-invite`'s introductions as the neutral surface of [`crate::invite`]: the conversions that
//! let the neutral cases run on the second provider, and the stand-in host a device's
//! [`Invites`](ndn_invite::Invites) run against.
//!
//! The conversions mirror [`old_invite`](crate::old_invite): each turns an `ndn_invite` type into
//! the plain type of the same meaning (or, for the offer and the short code, the other way), a
//! space being what `ndn-invite` still calls a folder in its grants, departures and joined
//! spaces, and an [`InviteError`] being an [`InviteFailure`] with its next step and kind as
//! strings, its reason apart and, for a refused introduction, why.
//!
//! [`Stand`] is the second provider's host: it wraps the same provider-independent
//! [`IntroduceCore`] as the old one (what the host was told and asked, who listens where) in
//! `ndn_invite::Host`, and adds what is the crate's own: the anchor it gives, adopting a person
//! through its node's engine, and carrying what a dialled link carries.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use ndn_cert::AnchorLink;
use ndn_data::Name;
use ndn_heap::{HeapError, NextStep, Timestamp};
use ndn_invite::{
    Adopting, Code, Contact, Departure, Dialing, FirstDialing, Grant, Host, IntroRefusal,
    InviteError, Joined, JoinedFolder, LinkHint, Offer, Role, ShortCode, ShortError, hint_name,
    hint_token, introduction_prefixes, parse_offer_name,
};
use ndn_security::{Validator, anchor_fingerprint};
use ndn_trust_envelope::words::WORD_COUNT as WORDS_FORM_WORDS;
use ndn_trust_envelope::{IntroWords, TrustEnvelope};

use crate::host::IntroduceCore;
use crate::invite::{
    InviteCode, InviteDeparture, InviteFailure, InviteGrant, InviteJoined, InviteJoinedSpace,
    InviteOffer, InviteRefusal, InviteRole, InviteShort, InviteShortError, ShortFault,
};
use crate::world_common::Route;

/// The neutral role of `role`.
pub fn role(role: Role) -> InviteRole {
    match role {
        Role::Reader => InviteRole::Reader,
        Role::Writer => InviteRole::Writer,
    }
}

/// `ndn-invite`'s offer of `offer`.
pub fn offer(offer: &InviteOffer) -> Offer {
    Offer {
        role: match offer.role {
            InviteRole::Reader => Role::Reader,
            InviteRole::Writer => Role::Writer,
        },
        until: Timestamp(offer.until),
        tries: offer.tries,
    }
}

/// The neutral code of `code`, an offer of the device `device`: the name of the hint record that
/// device serves for the code's secret is read from the code's link.
pub fn code(code: Code, device: &Name) -> anyhow::Result<InviteCode> {
    let TrustEnvelope::Intro(intro) = TrustEnvelope::from_uri(&code.link)
        .with_context(|| format!("the offer's link {} does not read", code.link))?
    else {
        anyhow::bail!("the offer's link {} is not an introduction link", code.link);
    };
    Ok(InviteCode {
        hint: hint_name(device, &hint_token(&intro.secret)),
        offer: code.offer,
        link: code.link,
        words: code.words,
        short: code.short,
        short_why: code.short_why,
    })
}

/// The neutral join of `joined`.
pub fn joined(joined: Joined) -> InviteJoined {
    InviteJoined {
        space: joined.space,
        role: role(joined.role),
        inviter: joined.inviter,
    }
}

/// The neutral refusal of `why`.
pub fn refusal(why: &IntroRefusal) -> InviteRefusal {
    match why {
        IntroRefusal::Unknown => InviteRefusal::Unknown,
        IntroRefusal::Used => InviteRefusal::Used,
        IntroRefusal::Expired => InviteRefusal::Expired,
        IntroRefusal::Closed => InviteRefusal::Closed,
        IntroRefusal::WrongProof { left } => InviteRefusal::WrongProof { left: *left },
        IntroRefusal::Forged => InviteRefusal::Forged,
        IntroRefusal::Conflict => InviteRefusal::Conflict,
        IntroRefusal::InviterConflict { inviter, why } => InviteRefusal::InviterConflict {
            inviter: inviter.clone(),
            why: why.clone(),
        },
        IntroRefusal::Hint { why } => InviteRefusal::Hint { why: why.clone() },
        IntroRefusal::HintMismatch { why } => InviteRefusal::HintMismatch { why: why.clone() },
        IntroRefusal::GoneUnproven { why } => InviteRefusal::GoneUnproven { why: why.clone() },
    }
}

/// The name of a next step, as [`Failure`](crate::case::Failure) names it.
pub fn next_name(next: NextStep) -> &'static str {
    match next {
        NextStep::None => "None",
        NextStep::RetryLater => "RetryLater",
        NextStep::AskOwner => "AskOwner",
        NextStep::UseOwnerDevice => "UseOwnerDevice",
        NextStep::FixLocal => "FixLocal",
        NextStep::FixName => "FixName",
        NextStep::FixRequest => "FixRequest",
    }
}

/// The kind of a data-layer failure, by its variant's name.
pub fn heap_kind(e: &HeapError) -> &'static str {
    match e {
        HeapError::Unavailable { .. } => "Unavailable",
        HeapError::NotReady { .. } => "NotReady",
        HeapError::BadName { .. } => "BadName",
        HeapError::TooLarge { .. } => "TooLarge",
        HeapError::NotAllowed { .. } => "NotAllowed",
        HeapError::Sealed { .. } => "Sealed",
        HeapError::NotOwner { .. } => "NotOwner",
        HeapError::Refused { .. } => "Refused",
        HeapError::BadRequest { .. } => "BadRequest",
        HeapError::Local { .. } => "Local",
    }
}

/// The neutral failure of `e`: its next step and kind by name, its reason alone, and the refusal
/// when it is one of an introduction.
pub fn failure(e: &InviteError) -> InviteFailure {
    let kind = match e {
        InviteError::Heap(h) => heap_kind(h),
        InviteError::Refused(_) => "Introduction",
        InviteError::NotReady { .. } => "NotReady",
        InviteError::BadRequest { .. } => "BadRequest",
        InviteError::Local { .. } => "Local",
    };
    let why = match e {
        InviteError::NotReady { why, .. } | InviteError::BadRequest { why } => why.clone(),
        InviteError::Heap(
            HeapError::NotReady { why, .. }
            | HeapError::BadRequest { why }
            | HeapError::BadName { why, .. },
        ) => why.clone(),
        InviteError::Refused(why) => why.to_string(),
        other => other.to_string(),
    };
    InviteFailure {
        detail: e.to_string(),
        why,
        next: next_name(e.next()),
        kind,
        retry: e.retry(),
        refusal: e.refusal().map(refusal),
    }
}

/// `e`, as the error of a provider verb: an [`InviteFailure`].
pub fn error(e: InviteError) -> anyhow::Error {
    anyhow::Error::new(failure(&e))
}

/// The neutral grant of `grant`.
pub fn grant(grant: &Grant) -> InviteGrant {
    InviteGrant {
        key: grant.key,
        namespaces: grant.namespaces.clone(),
        space: grant.folder.clone(),
        role: role(grant.role),
        until: grant.until.map(|t| t.0),
    }
}

/// The neutral departure of `departure`.
pub fn departure(departure: &Departure) -> InviteDeparture {
    InviteDeparture {
        key: departure.key,
        namespaces: departure.namespaces.clone(),
        space: departure.folder.clone(),
        record: departure.record.clone(),
        until: departure.until.0,
    }
}

/// The neutral joined space of `folder`.
pub fn joined_space(folder: &JoinedFolder) -> InviteJoinedSpace {
    InviteJoinedSpace {
        inviter: folder.inviter,
        owner: folder.owner.clone(),
        space: folder.folder.clone(),
        role: role(folder.role),
        writers: folder.writers.clone(),
    }
}

fn short_error(e: &ShortError) -> InviteShortError {
    InviteShortError {
        fault: match e {
            ShortError::Words(n) => ShortFault::Words(*n),
            ShortError::UnknownWord(i) => ShortFault::UnknownWord(*i),
            ShortError::Checksum => ShortFault::Checksum,
            _ => ShortFault::Other,
        },
        text: e.to_string(),
    }
}

/// The short code `line` reads as (every word on the list, the checksum matching); a relay
/// contact has no neutral form and is refused. A loopback or link-local first contact is not
/// read, as a device's policy leaves it.
pub fn short_read(line: &str) -> Result<InviteShort, InviteShortError> {
    let read = ShortCode::parse(line, false).map_err(|e| short_error(&e))?;
    let address = match read.contact {
        Some(Contact::Address(addr)) => Some(addr),
        None => None,
        Some(Contact::Relay(relay)) => {
            return Err(InviteShortError {
                fault: ShortFault::Other,
                text: format!("the code names the relay {relay}, which the cases do not use"),
            });
        }
    };
    Ok(InviteShort {
        device: read.device,
        address,
        secret: read.secret,
        fingerprint: read.fingerprint,
    })
}

/// The line `short` is written as.
pub fn short_write(short: &InviteShort) -> Result<String, InviteShortError> {
    ShortCode {
        device: short.device.clone(),
        contact: short.address.map(Contact::Address),
        secret: short.secret,
        fingerprint: short.fingerprint.clone(),
    }
    .encode()
    .map_err(|e| short_error(&e))
}

/// The addresses of a hint's candidates, in order.
fn addresses(hint: &LinkHint) -> Vec<SocketAddr> {
    hint.candidates.iter().map(|c| c.addr).collect()
}

/// The inviter's device a code names, whatever its form (a link, the words, a short code), if it
/// names one: what a join is about to fetch from, by name when no link carries the fetch.
pub fn inviter_of(code: &str) -> Option<Name> {
    let code = code.trim();
    if code.starts_with('/') {
        if ShortCode::word_count(code) != WORDS_FORM_WORDS {
            return ShortCode::parse(code, true).ok().map(|s| s.device);
        }
        let words = IntroWords::parse(code).ok()?;
        return parse_offer_name(&words.offer.parse().ok()?).map(|(device, _)| device);
    }
    let TrustEnvelope::Intro(intro) = TrustEnvelope::from_uri(code).ok()? else {
        return None;
    };
    parse_offer_name(&intro.offer.parse().ok()?).map(|(device, _)| device)
}

/// What a join of `code` has the node's forwarder carry in transit, unvalidated, while it runs:
/// the introduction prefixes of the inviter's device. The world's hub stands for the network and
/// its relays and routes every name, so a joiner reaches the inviter by name; its own forwarder
/// holds no trust of the inviter's namespace yet and would refuse what the inviter signs (the
/// offer, the answer, a hint record), which a link layer's carrying of an introduction link
/// prevents ([`Stand::carry`]) and a join that goes by name leaves to the host's forwarder. The
/// join judges all of it against the code.
pub fn carried_by_name(code: &str) -> Vec<Name> {
    inviter_of(code).map_or_else(Vec::new, |device| introduction_prefixes(&device).to_vec())
}

/// What a device's host does for introductions (`Invites::start`'s host): it gives its
/// namespace's signed trust context as its anchor, and adopts another person's anchor link into
/// its node's validator through its node's engine, as the daemon does
/// (`ndn_identity::adopt_anchor_link_via_engine`): an inline context checked against the link's
/// expected fingerprint, a self-certifying namespace not held adopted by name (its inline version
/// 1 only compared with the fetched one) — after which its node carries that person's sync group
/// and routes it over its link to the hub, as a daemon's link library does on the trust event.
/// Its link layer is the stand-in of [`IntroduceCore`].
pub struct Stand {
    /// The newest signed version of its namespace's trust context when the layer started.
    pub anchor: Bytes,
    /// Its node's validator.
    pub validator: Arc<Validator>,
    /// Its node's engine, the network an adoption fetches over.
    pub engine: ndn_app::ForwarderEngine,
    /// Carry and route a newly adopted person's sync group.
    pub route: Route,
    /// What the host was told and asked, and how its link layer answers, across restarts of its
    /// layer.
    pub core: Arc<IntroduceCore>,
    /// The hint the host gives for an offer's code: its device's key and the address it
    /// listens at.
    pub hint: LinkHint,
    /// The links up that carry an inviter's introduction prefixes in transit, by the inviter's
    /// device and the key the link proved, one entry for each link a dial made.
    pub carried: Mutex<Vec<(Name, [u8; 32])>>,
}

impl Host for Stand {
    fn anchor(&self) -> Option<Bytes> {
        Some(self.anchor.clone())
    }

    /// The host's link layer is this stand-in: the world already routes every name through the
    /// hub, so a dial that answers is a link by name. It gives the hint of the device's own
    /// key at the address it listens at.
    fn link_hint(&self) -> Option<LinkHint> {
        Some(self.hint.clone())
    }

    /// Answers when a device listens at one of the candidates and proves the hint's key, as a
    /// handshake would; no other address or key makes a link. The link carries the inviter's
    /// introduction prefixes, whatever it answers ([`Stand::carry`]).
    fn dial<'a>(&'a self, hint: &'a LinkHint, inviter: &'a Name, _within: Duration) -> Dialing<'a> {
        let answered = self.core.dial(inviter, hint.key, &addresses(hint));
        if answered {
            self.carry(inviter, hint.key);
        }
        Box::pin(async move {
            if answered {
                Ok(())
            } else {
                Err(format!(
                    "no address of the hint answered with the key it names (tried {} of them)",
                    hint.candidates.len()
                ))
            }
        })
    }

    /// Answers with the key of the device that listens at `addr`, which a handshake proves;
    /// an address nobody listens at does not answer. The link carries the inviter's
    /// introduction prefixes, signed by a namespace this node does not hold yet, as ndn-link's
    /// first-contact link does (it routes them whatever answers): the node's forwarder takes
    /// those names in transit, unvalidated, until the link is taken down.
    fn dial_first<'a>(
        &'a self,
        inviter: &'a Name,
        addr: SocketAddr,
        _within: Duration,
    ) -> FirstDialing<'a> {
        let proved = self.core.dial_first(inviter, addr);
        if let Some(key) = proved {
            self.carry(inviter, key);
        }
        Box::pin(async move { proved.ok_or_else(|| format!("nothing answers at {addr}")) })
    }

    fn undial(&self, hint: &LinkHint, inviter: &Name) {
        self.core.undial(inviter, hint.key, &addresses(hint));
        self.drop_carry(inviter, hint.key);
    }

    fn grant(&self, grant_: &Grant) {
        self.core.granted(grant(grant_));
    }

    fn departure(&self, departure_: &Departure) {
        self.core.departed(departure(departure_));
    }

    fn revoke_grant(&self, key: &[u8; 32], folder: &Name) {
        self.core.revoked(*key, folder);
    }

    fn adopt<'a>(&'a self, link: &'a TrustEnvelope) -> Adopting<'a> {
        Box::pin(async move {
            let TrustEnvelope::Anchor {
                namespace: Some(ns),
                fingerprint: Some(fingerprint),
                ..
            } = link
            else {
                return Err("not an anchor link naming its namespace and fingerprint".into());
            };
            let ns: Name = ns
                .parse()
                .map_err(|_| format!("the anchor link names {ns}, which is no name"))?;
            let keyring = self.validator.keyring();
            match keyring
                .contexts()
                .into_iter()
                .find(|c| *c.namespace() == ns)
            {
                Some(held)
                    if held
                        .anchors()
                        .iter()
                        .any(|a| anchor_fingerprint(a.value()) == *fingerprint) =>
                {
                    Ok(())
                }
                Some(_) => Err(format!(
                    "this node trusts {ns} under another anchor than the link's"
                )),
                None => {
                    let link = AnchorLink::from_envelope(link).map_err(|e| e.to_string())?;
                    ndn_identity::adopt_anchor_link_via_engine(&self.engine, keyring, &link)
                        .await
                        .map_err(|e| e.to_string())?;
                    (self.route)(&ns);
                    Ok(())
                }
            }
        })
    }
}

impl Stand {
    /// A link that proved `key` is up to `inviter`: it carries `inviter`'s introduction
    /// prefixes (the offer, the ask and its answer, the hint records) in transit. The node holds
    /// no trust of the inviter's namespace yet, so its forwarder would refuse them otherwise;
    /// they are checked by the join, against the code. A namespace this node holds is never in
    /// transit, so what the join adopted is validated from then on.
    fn carry(&self, inviter: &Name, key: [u8; 32]) {
        for prefix in introduction_prefixes(inviter) {
            self.engine.transit().add(&prefix, || {});
        }
        self.carried
            .lock()
            .expect("the host's lock")
            .push((inviter.clone(), key));
    }

    /// The link to `inviter` that proved `key` is taken down: it carries nothing more.
    fn drop_carry(&self, inviter: &Name, key: [u8; 32]) {
        let mut carried = self.carried.lock().expect("the host's lock");
        let Some(at) = carried
            .iter()
            .position(|(device, k)| device == inviter && *k == key)
        else {
            return;
        };
        carried.remove(at);
        for prefix in introduction_prefixes(inviter) {
            self.engine.transit().remove(&prefix, || {});
        }
    }
}
