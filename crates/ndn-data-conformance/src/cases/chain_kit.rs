//! What the chain, fold and grant cases (`q1`…`q6`) share beyond [`super::kit`]: the epoch a set of
//! devices holds, what a device that may not read answers, and a watch drained without failing on
//! the refusal a removed reader's feed ends with.
//!
//! Everything here speaks the neutral types of [`crate::spaces`].

use std::time::Duration;

use bytes::Bytes;
use ndn_data::Name;

use super::kit::item;
use crate::case::Failure;
use crate::spaces::{SpaceChanges, SpaceEpoch, SpaceEvent, Spaces};

/// The epoch `spaces` holds in force over `space`; `None` while it holds none, or while the device
/// answers `"RetryLater"` (a members record not received yet).
pub async fn epoch_now(spaces: &dyn Spaces, space: &Name) -> Result<Option<SpaceEpoch>, Failure> {
    match spaces.epoch(space).await {
        Ok(epoch) => Ok(epoch),
        Err(e) if e.retry_later() => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether every device holds the same epoch in force over `space` and it is complete: the
/// writers of the space seal in one epoch, and no owner device has anything left to repair.
pub async fn one_complete_epoch(spaces: &[&dyn Spaces], space: &Name) -> Result<bool, Failure> {
    let mut first: Option<SpaceEpoch> = None;
    let mut agree = true;
    for s in spaces {
        match epoch_now(*s, space).await? {
            Some(e) if e.complete => match &first {
                None => first = Some(e),
                Some(f) => agree &= *f == e,
            },
            _ => agree = false,
        }
    }
    Ok(agree)
}

/// The octets `spaces` reads at `path` of `space`; `None` when it reads nothing there, whether
/// because nothing is written, the key is on its way (`"RetryLater"`), or the device is refused
/// the space (`Sealed`, `NotAllowed`): a device that fails closed opens nothing.
pub async fn opens(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
) -> Result<Option<Bytes>, Failure> {
    match item(spaces, space, path).await {
        Ok(item) => Ok(item.map(|i| i.bytes)),
        Err(e) if e.kind_is("Sealed") || e.kind_is("NotAllowed") => Ok(None),
        Err(e) => Err(e),
    }
}

/// Whether `spaces` reads exactly the octets of `want` at `path` of `space`.
pub async fn reads(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
    want: &str,
) -> Result<bool, Failure> {
    Ok(opens(spaces, space, path).await?.as_deref() == Some(want.as_bytes()))
}

/// Whether `spaces` refuses the reader at `path` of `space` the way a device must that is no
/// reader: an answer of kind `Sealed` or `NotAllowed` whose next step is `AskOwner`. `false` while
/// the device answers anything that is no refusal (nothing, a wait); a value it reads is a failure
/// of the case.
pub async fn refuses_the_reader(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
) -> Result<bool, Failure> {
    match spaces.get(space, path).await {
        Ok(Some(item)) => Err(Failure::new(format!(
            "a device that is no reader of {space} reads {:?} at {path}",
            String::from_utf8_lossy(&item.bytes)
        ))),
        Ok(None) => Ok(false),
        Err(e) if e.kind_is("Sealed") || e.kind_is("NotAllowed") => {
            if e.next_is("AskOwner") {
                Ok(true)
            } else {
                Err(Failure::new(format!(
                    "the refusal at {path} of {space} names next step {:?}, not AskOwner: {e}",
                    e.next
                )))
            }
        }
        Err(e) if e.retry_later() => Ok(false),
        Err(e) => Err(e),
    }
}

/// Everything `stream` reports within `window` of virtual time. A feed that ends in a refusal
/// (the reader it served was removed since it opened) ends the drain: what it reported before is
/// what a removed reader's device saw, which is all a case asks of it.
pub async fn drain_quiet(stream: &mut dyn SpaceChanges, window: Duration) -> Vec<SpaceEvent> {
    let deadline = tokio::time::Instant::now() + window;
    let mut seen = Vec::new();
    while let Ok(Some(Ok(event))) = tokio::time::timeout_at(deadline, stream.next()).await {
        seen.push(event);
    }
    seen
}
