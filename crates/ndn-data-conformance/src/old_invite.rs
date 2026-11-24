//! `ndn-data`'s introductions as the neutral surface of [`crate::invite`]: the conversions that
//! let the neutral cases run on the old provider until it leaves the suite (deleted with
//! `old_spaces` at stage 9).
//!
//! Each function turns an `ndn_data` type into the plain type of the same meaning (or, for the
//! offer and the short code, the other way), keeping what the cases compare and dropping nothing
//! they read: a folder is a space, a [`DataError`] is an [`InviteFailure`] with its next step and
//! kind as strings, its reason apart, and, for a refused introduction, why.

use anyhow::Context;
use ndn_data::intro::{Contact, ShortCode, ShortError, hint_name, hint_token};
use ndn_data::{
    Code, DataError, Departure, Grant, IntroRefusal, Joined, JoinedFolder, Name, Offer, Role,
    Timestamp,
};
use ndn_trust_envelope::TrustEnvelope;

use crate::case::Failure;
use crate::invite::{
    InviteCode, InviteDeparture, InviteFailure, InviteGrant, InviteJoined, InviteJoinedSpace,
    InviteOffer, InviteRefusal, InviteRole, InviteShort, InviteShortError, ShortFault,
};

/// The neutral role of `role`.
pub fn role(role: Role) -> InviteRole {
    match role {
        Role::Reader => InviteRole::Reader,
        Role::Writer => InviteRole::Writer,
    }
}

/// `ndn-data`'s offer of `offer`.
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
        space: joined.folder,
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

/// The neutral failure of `e`: its next step and kind by name (as [`Failure`] names them), its
/// reason alone, and the refusal when it is one of an introduction.
pub fn failure(e: &DataError) -> InviteFailure {
    let named = Failure::from(e.clone());
    let why = match e {
        DataError::NotReady { why, .. }
        | DataError::BadRequest { why, .. }
        | DataError::BadName { why, .. } => why.clone(),
        DataError::Introduction { why, .. } => why.to_string(),
        other => other.to_string(),
    };
    InviteFailure {
        detail: e.to_string(),
        why,
        next: named.next.expect("a DataError names a next step"),
        kind: named.kind.expect("a DataError names a kind"),
        retry: e.retry(),
        refusal: match e {
            DataError::Introduction { why, .. } => Some(refusal(why)),
            _ => None,
        },
    }
}

/// `e`, as the error of a provider verb: the [`InviteFailure`] a refused introduction is, any
/// other failure as itself.
pub fn error(e: DataError) -> anyhow::Error {
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
/// contact has no neutral form and is refused.
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
