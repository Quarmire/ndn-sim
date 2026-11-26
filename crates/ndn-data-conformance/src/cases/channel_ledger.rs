//! What a sender emitted, in order, and the check of what a receiver was given against it: every
//! message is one the sender emitted, from the sender's device, delivered at most once, and (per
//! path) never older than one delivered before it.
//!
//! A payload is `<stem>#<n>`: the stem names a run of emissions at a path, `n` counts them. A
//! ledger lists the runs of each path in the order the sender made them, so a message's place in
//! the sender's order is (its run's position, `n`), and what a `Latest` channel promises is that a
//! receiver's messages at one path rise in that order.
//!
//! Beside it, [`refused_ask`]: a device asks a channel until the answer says, with a reason, that
//! it will not be given one.

use bytes::Bytes;
use ndn_heap::Name;

use super::channel_kit::Listener;
use super::kit::{LIMIT, n};
use crate::case::Failure;
use crate::channel::{ChannelEvent, Channels};
use crate::ensure;
use crate::world::{AGAIN_PAUSE, World};

/// The runs a sender emits, in order.
#[derive(Default)]
pub struct Ledger {
    runs: Vec<(Name, &'static str)>,
}

impl Ledger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// The sender goes on to emit run `stem` at `path`, after the runs listed so far.
    pub fn run(mut self, path: &str, stem: &'static str) -> Self {
        self.runs.push((n(path), stem));
        self
    }

    /// `<stem>#<n>`, the payload of the `n`th emission of a run.
    pub fn payload(stem: &str, n: u64) -> Bytes {
        Bytes::from(format!("{stem}#{n}"))
    }

    /// Checks everything `listener` was given of the sender `from`. Returns how many messages
    /// it was given.
    pub fn check(&self, listener: &Listener, from: &Name) -> Result<usize, Failure> {
        self.scan(listener, from, false)
    }

    /// [`check`](Self::check) for a listener of several senders: only what it was given from
    /// `from` is judged (a message of another sender is no failure here).
    pub fn check_of(&self, listener: &Listener, from: &Name) -> Result<usize, Failure> {
        self.scan(listener, from, true)
    }

    fn scan(&self, listener: &Listener, from: &Name, only: bool) -> Result<usize, Failure> {
        let mut last: Vec<(Name, (usize, u64))> = Vec::new();
        let mut given = 0;
        for event in &listener.events {
            let ChannelEvent::Message {
                path,
                bytes,
                writer,
            } = event
            else {
                continue;
            };
            if only && writer != from {
                continue;
            }
            ensure!(
                writer == from,
                "device {} was given {path} from {writer}, not from the sender's device {from}",
                listener.dev.0
            );
            let key = self.place(path, bytes)?;
            match last.iter_mut().find(|(p, _)| p == path) {
                Some((_, held)) => {
                    ensure!(
                        key > *held,
                        "device {} was given {path} {:?} (run {}, emission {}) after run {}, \
                         emission {}: delivered twice or older than a delivery before it",
                        listener.dev.0,
                        String::from_utf8_lossy(bytes),
                        key.0,
                        key.1,
                        held.0,
                        held.1
                    );
                    *held = key;
                }
                None => last.push((path.clone(), key)),
            }
            given += 1;
        }
        Ok(given)
    }

    /// The place of `payload` at `path` in the sender's order: its run's position and its count.
    fn place(&self, path: &Name, payload: &Bytes) -> Result<(usize, u64), Failure> {
        let text = std::str::from_utf8(payload).ok();
        let split = text.and_then(|t| t.rsplit_once('#'));
        let found = split.and_then(|(stem, count)| {
            let at = self
                .runs
                .iter()
                .position(|(p, s)| p == path && *s == stem)?;
            Some((at, count.parse::<u64>().ok()?))
        });
        found.ok_or_else(|| {
            Failure::new(format!(
                "a message at {path} reached a receiver as {payload:?}, which the sender never \
                 emitted there"
            ))
        })
    }
}

/// Whether `e` says that a sender or a device will not give this device a channel, and why: the
/// sender lists no such member, the device may not use channels, the sender that answered is no
/// writer, or the forwarder refused its answer because its key is revoked.
fn refusal(e: &Failure) -> bool {
    [
        "does not answer this device's ask",
        "may not use channels",
        "is no writer of it by the entries held here",
        "the signer's certificate was revoked",
    ]
    .iter()
    .any(|text| e.detail.contains(text))
}

/// `who` asks `from`'s channel over `space` until a refusal says why it is given none: an ask a
/// lossy network lost, or one made before the record is held, is asked again. A session given
/// is a failure.
pub async fn refused_ask(
    w: &World,
    ch: &dyn Channels,
    who: &str,
    space: &Name,
    from: &Name,
) -> Result<(), Failure> {
    let start = tokio::time::Instant::now();
    loop {
        match ch.ask(space, from).await {
            Ok(id) => {
                return Err(Failure::new(format!(
                    "{who}'s ask of {from}'s channel over {space} was answered with channel \
                     {id:016x}: a session was given to a device that is not to have one"
                )));
            }
            Err(e) if refusal(&e) => return Ok(()),
            Err(e) if e.retry_later() => {
                ensure!(
                    start.elapsed() < LIMIT,
                    "{who}'s ask over {space} was never refused with a reason within {LIMIT:?} \
                     of virtual time; the last answer: {e}"
                );
                w.sleep(AGAIN_PAUSE).await;
            }
            Err(e) => return Err(e),
        }
    }
}
