//! The neutral surface of introductions, as the cases drive it: a one-use offer of a space, its
//! code, a join by that code, the grants a host is told of, the spaces a device joined and the
//! calls its host's link layer was asked, in plain data.
//!
//! Every type here is plain data (`Clone + Debug + PartialEq`): what a provider answers is
//! compared and kept by the cases without knowing which crate's types it came from; `new_invite`
//! converts `ndn-invite`'s at the edge.
//! A refusal a verb answers is an [`InviteFailure`] carried as the source of the verb's
//! `anyhow::Error` (the cases get it back with [`World::join`](crate::world::World::join) and the
//! like): its `next` names the next step by kind (`"AskOwner"`, `"RetryLater"`, `"FixRequest"`,
//! `"FixLocal"`, …) and its `kind` the kind of refusal (`"Introduction"`, `"NotReady"`,
//! `"BadRequest"`, …), as strings, as [`Failure`] does for [`Spaces`](crate::spaces::Spaces).

use std::net::SocketAddr;

use ndn_heap::Name;

use crate::case::Failure;

/// What a joiner is granted by an offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InviteRole {
    /// The joiner reads the space.
    Reader,
    /// The joiner reads and writes the space.
    Writer,
}

/// A one-use offer of a space ([`Provider::offer`](crate::provider::Provider::offer)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteOffer {
    /// What it grants.
    pub role: InviteRole,
    /// Its expiry in milliseconds, judged by the offering device's clock.
    pub until: u64,
    /// How many wrong tries of one asker (one key) close it to that asker (at least one).
    pub tries: u32,
}

/// What an offer is shown as: the forms of one code, and the name of the record the inviter
/// serves for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteCode {
    /// The offer's name, which [`World::close_offer`](crate::world::World::close_offer) takes.
    pub offer: Name,
    /// The compact full link (`ndn-trust://intro/<base64url>`), at most one QR.
    pub link: String,
    /// The offer's words.
    pub words: String,
    /// The short code: one line a person can read aloud or type. `None` when
    /// [`short_why`](Self::short_why) says why.
    pub short: Option<String>,
    /// Why there is no short code, when `short` is `None`.
    pub short_why: Option<String>,
    /// The name of the hint record (`<device>/32=hint/<token>`) the inviter's device serves for
    /// this code's secret, which a device given only the short line fetches.
    pub hint: Name,
}

impl InviteCode {
    /// What to show: the short code when there is one, else the link.
    pub fn share(&self) -> &str {
        self.short.as_deref().unwrap_or(&self.link)
    }
}

/// What a join brought ([`World::join`](crate::world::World::join)).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteJoined {
    /// The space the device now reads (and writes, as a writer).
    pub space: Name,
    /// What the offer granted.
    pub role: InviteRole,
    /// The inviter's namespace, adopted.
    pub inviter: Name,
}

/// Why an introduction was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InviteRefusal {
    /// The offering device holds no such offer.
    Unknown,
    /// Another key joined with this offer.
    Used,
    /// It expired by the offering device's clock.
    Expired,
    /// Too many wrong tries, or closed by its maker: refused for good, even with the right
    /// secret.
    Closed,
    /// The proof of the secret is wrong; it counted as a wrong try of this asker.
    WrongProof {
        /// Wrong tries this asker has left before the offer closes to it.
        left: u32,
    },
    /// What answered for the inviter proves neither the code's secret nor its anchor.
    Forged,
    /// The asker's namespace overlaps one the inviter's device trusts, or is one no introduction
    /// brings; or its credentials do not hold under it.
    Conflict,
    /// The inviter's namespace, judged by the joiner, overlaps one its device already trusts or
    /// is its own, or is one no introduction brings. Nothing of it was adopted.
    InviterConflict {
        /// The inviter's namespace.
        inviter: Name,
        /// What it overlaps, and how.
        why: String,
    },
    /// What answered at a short code's first contact came damaged, or does not prove it is the
    /// inviter's.
    Hint {
        /// Which check failed.
        why: String,
    },
    /// A hint record that verifies but is not the one this code names.
    HintMismatch {
        /// Which check failed.
        why: String,
    },
    /// A gone mark that does not prove itself.
    GoneUnproven {
        /// Which check failed.
        why: String,
    },
}

/// A refusal of an introduction verb, or of a verb a host asks of a device in one: what the
/// device says, what to do about it, and, for a refused introduction, why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteFailure {
    /// What the device said, whole.
    pub detail: String,
    /// The reason alone, without the name of what was asked: the `why` of a not-ready, a bad
    /// request or a hint, the refusal's text of a refused introduction, else the whole text.
    pub why: String,
    /// The next step the device named, by its kind (`"AskOwner"`, `"RetryLater"`, …).
    pub next: &'static str,
    /// The kind of refusal (`"Introduction"`, `"NotReady"`, `"BadRequest"`, …).
    pub kind: &'static str,
    /// Whether the same call, unchanged, can succeed later.
    pub retry: bool,
    /// Why an introduction was refused, when it was (`kind` is `"Introduction"`).
    pub refusal: Option<InviteRefusal>,
}

impl InviteFailure {
    /// Whether the device named `next` as the next step.
    pub fn next_is(&self, next: &str) -> bool {
        self.next == next
    }

    /// Whether the device says to ask again later.
    pub fn retry_later(&self) -> bool {
        self.next_is("RetryLater")
    }

    /// Whether the refusal is of this kind.
    pub fn kind_is(&self, kind: &str) -> bool {
        self.kind == kind
    }
}

impl std::fmt::Display for InviteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for InviteFailure {}

impl From<InviteFailure> for Failure {
    fn from(e: InviteFailure) -> Self {
        Failure::answered(
            format!("verb failed: {} (next step: {})", e.detail, e.next),
            e.next,
            e.kind,
        )
    }
}

/// A link grant (`Introducer::grant` / `Host::grant`): the host's link layer may link with the
/// device holding `key` as a person of `namespaces`, for as long as the members record in force
/// for `space` lists the person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteGrant {
    /// The asker's key's public-key digest: what a link's handshake proves.
    pub key: [u8; 32],
    /// The namespaces the person may be identified in.
    pub namespaces: Vec<Name>,
    /// The space the offer admitted the person to.
    pub space: Name,
    /// The person's role in the space now, from the members record in force.
    pub role: InviteRole,
    /// A date, in milliseconds by the inviter's clock, after which the grant is over; `None`: it
    /// lasts while a held record lists the person.
    pub until: Option<u64>,
}

/// What a person who was let go is told: a held members record left a granted person out of
/// `space`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteDeparture {
    /// The person's device key (the grant's key).
    pub key: [u8; 32],
    /// The namespaces the grant admitted the key in.
    pub namespaces: Vec<Name>,
    /// The space the person was let go of.
    pub space: Name,
    /// The log entry name of the held members record that leaves the person out:
    /// `<signer device>/32=log/…`.
    pub record: Name,
    /// By the inviter's clock, in milliseconds: the mark is no longer served after it.
    pub until: u64,
}

/// A space a device joined, and what its link to the inviter must route for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteJoinedSpace {
    /// The inviter's device key's digest: the mirror grant's key.
    pub inviter: [u8; 32],
    /// The space's owner, which is the inviter's namespace.
    pub owner: Name,
    /// The space the offer admitted this device to.
    pub space: Name,
    /// This device's role in the members record in force now.
    pub role: InviteRole,
    /// The namespaces of the other writers the record in force lists (never this device's own
    /// namespace or one above or below it, never the inviter's), sorted, at most sixteen.
    pub writers: Vec<Name>,
}

/// What a host was told of a grant, in the order it was told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GrantEvent {
    /// `grant`.
    Granted(InviteGrant),
    /// `departure`: a held record let the person go.
    Departed(InviteDeparture),
    /// `revoke_grant`, with the key and the space whose grant ended.
    Revoked {
        /// The person's device key.
        key: [u8; 32],
        /// The space whose grant ended.
        space: Name,
    },
}

/// A device's grants: what its host was told, and what its layer lists now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrantLog {
    /// Every call of the host's `grant`, `departure` and `revoke_grant`, oldest first.
    pub told: Vec<GrantEvent>,
    /// The grants in force now.
    pub now: Vec<InviteGrant>,
    /// The departures listed now.
    pub departures: Vec<InviteDeparture>,
}

/// One call a device's host was made of its link layer during an introduction, in the order it
/// was made ([`Provider::link_calls`](crate::provider::Provider::link_calls)): the dials the
/// joiner's layer asks for and the links it takes down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkCall {
    /// `dial_first`: the one address a short code names, no key to expect.
    DialFirst {
        /// The inviter's device the code names.
        inviter: Name,
        /// The address dialled.
        addr: SocketAddr,
        /// Whether a device answered there: a link was made.
        answered: bool,
    },
    /// `dial`: by a link hint (a compact link's, or the hint record's) that names the key to
    /// prove.
    Dial {
        /// The inviter's device.
        inviter: Name,
        /// The key the link must prove.
        key: [u8; 32],
        /// The addresses tried, in order.
        candidates: Vec<SocketAddr>,
        /// Whether a candidate answered with the key: a link was made.
        answered: bool,
    },
    /// `undial`: a failed join takes down what its dial made.
    Undial {
        /// The inviter's device.
        inviter: Name,
        /// The key of the link taken down.
        key: [u8; 32],
        /// The addresses the dial was made at.
        candidates: Vec<SocketAddr>,
    },
}

/// The spaces a device joined, as its layer lists them, and the generation of that list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct JoinedList {
    /// What the device's link layer routes for each space it was let into, derived from the
    /// record in force.
    pub spaces: Vec<InviteJoinedSpace>,
    /// The generation of the list: it moves (and never repeats) whenever the list changed.
    pub generation: u64,
}

/// A short code, read or to be written
/// ([`Provider::short_read`](crate::provider::Provider::short_read)).
#[derive(Clone, PartialEq, Eq)]
pub struct InviteShort {
    /// The inviter's device name.
    pub device: Name,
    /// The address of the first contact; `None` when the code names none.
    pub address: Option<SocketAddr>,
    /// The offer's secret.
    pub secret: [u8; 16],
    /// The anchor's fingerprint as the code carries it.
    pub fingerprint: Vec<u8>,
}

impl std::fmt::Debug for InviteShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteShort")
            .field("device", &self.device)
            .field("address", &self.address)
            .field("secret", &"<secret>")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

/// What is wrong with a short code that does not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShortFault {
    /// The code has this many words after its device name and first contact: not 20 or 36.
    Words(usize),
    /// The word at this position (from 1, among the words) is not on the list.
    UnknownWord(usize),
    /// Every word is on the list but the checksum does not match.
    Checksum,
    /// Any other fault: the first contact, the placeholder, a loopback address.
    Other,
}

/// Why a short code could not be read or written: the fault, and the text a join of that line
/// is refused with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteShortError {
    /// What is wrong.
    pub fault: ShortFault,
    /// What the device says of it.
    pub text: String,
}

impl std::fmt::Display for InviteShortError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

impl std::error::Error for InviteShortError {}
