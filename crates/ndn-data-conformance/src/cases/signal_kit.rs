//! The kit the signal cases (`e1`…`e19`) share: a device's part in a space's signals, the signals
//! it delivered and sent, and the counters a case waits on. A signal's scope is a space, so a
//! case drives the spaces of [`Spaces`] beside the signals of `ndn_surface::signal`, which only
//! the `ndn-heap` provider runs ([`Feature::Signals`]).
//!
//! The signals of a space are pushed into its one sync group ([`group`]), `<O>/32=sync/<rest of
//! the space>` for the space `<O>/32=data/<rest>`: every member's devices hear them there.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_data::Name;
use ndn_heap::NextStep;
use ndn_packet::NameComponent;
use ndn_surface::signal::{Signal, SignalError, SignalRun, SignalStats};
use sha2::Digest;

use super::kit::LIMIT;
use crate::case::Failure;
use crate::ensure;
use crate::provider::SignalKeyPair;
use crate::signal;
use crate::spaces::SpaceShare;
use crate::world::{Dev, World};

/// How long a sender waits before sending its final value again while a receiver has not yet
/// acknowledged it, as a host re-sends its latest presence or cursor until it is seen.
pub const RESEND: Duration = Duration::from_millis(250);
/// One frame at 60 Hz.
pub const FRAME: Duration = Duration::from_micros(16_667);
/// What a final value's payload starts with: a receiver acknowledges each one it delivers.
pub const FINAL: &str = "final:";

/// A space every one of `people` writes and reads, sealed to them (the owner reads and writes
/// beside them).
pub fn sealed_to(people: &[&str]) -> SpaceShare {
    SpaceShare {
        anyone: false,
        readers: super::kit::people(people),
        writers: super::kit::people(people),
    }
}

/// The sync group of `space`: where its members push signals for each other's devices.
pub fn group(space: &Name) -> Name {
    ndn_heap::wire::sync_group_of(space)
        .unwrap_or_else(|| panic!("{space} is no space name (<owner>/32=data/<1 to 4 components>)"))
}

/// The prefix every push Interest into `space`'s group has: `<group>/32=signal`.
pub fn pushes(space: &Name) -> Name {
    group(space).append_component(NameComponent::new(32, Bytes::from_static(b"signal")))
}

/// Why a signal verb failed, as a case failure.
pub fn refused(what: &str, e: SignalError) -> Failure {
    Failure::new(format!("{what}: {e} (next step: {:?})", e.next()))
}

/// `verb` asked again while it answers [`NextStep::RetryLater`] (no record or epoch key held
/// yet), as a host does what the refusal says, every [`crate::world::AGAIN_PAUSE`] for at most
/// [`crate::world::AGAIN_FOR`]; then, or at any other refusal, the answer as it came.
pub async fn signal_again<T, F, Fut>(mut verb: F) -> Result<T, SignalError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, SignalError>>,
{
    let start = tokio::time::Instant::now();
    loop {
        match verb().await {
            Err(e)
                if e.next() == NextStep::RetryLater
                    && start.elapsed() < crate::world::AGAIN_FOR =>
            {
                tokio::time::sleep(crate::world::AGAIN_PAUSE).await;
            }
            answer => return answer,
        }
    }
}

/// The device whose key signed a signal's run header: the key's name without `KEY/<id>`.
pub fn sender_of(s: &Signal) -> Name {
    let comps = s.sender.components();
    match comps.len().checked_sub(2) {
        Some(d) if d >= 1 && comps[d].value.as_ref() == b"KEY" => {
            Name::from_components(comps[..d].iter().cloned())
        }
        _ => s.sender.clone(),
    }
}

/// The payload acknowledging the final `payload`: `seen:` and the final, which is no final
/// itself, so acknowledgements are never acknowledged.
pub fn acknowledging(payload: &[u8]) -> Vec<u8> {
    [b"seen:".as_slice(), payload].concat()
}

/// The address a receiver acknowledges `sender`'s final at `address` on:
/// `seen/<12 hex digits of SHA-256(sender ‖ address)>`, so acknowledgements of finals of other
/// senders or addresses keep their own latest.
pub fn ack_address(sender: &Name, address: &[u8]) -> Vec<u8> {
    let mut h = sha2::Sha256::new();
    h.update(sender.encode_to_tlv());
    h.update(address);
    let digest = h.finalize();
    let mut out = b"seen/".to_vec();
    for b in &digest[..6] {
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    out
}

/// A run, shared by its device's sends and its inbox's acknowledgements.
pub type Run = Arc<futures::lock::Mutex<SignalRun>>;
/// What one device sent: (address, payload).
pub type Ledger = Arc<Mutex<BTreeSet<(Vec<u8>, Vec<u8>)>>>;

/// Send one signal on `run` and note it in `ledger`, as a host does what a refusal says: past
/// the run's rate (`RateLimited`) after `retry_after`, and again while the next step is retry
/// later (a new epoch's key not held yet) every [`crate::world::AGAIN_PAUSE`], for at most
/// [`crate::world::AGAIN_FOR`]. Returns its sequence.
pub async fn send_on(
    run: &Run,
    ledger: &Ledger,
    address: &[u8],
    payload: &[u8],
) -> Result<u64, SignalError> {
    let start = tokio::time::Instant::now();
    loop {
        let sent = run.lock().await.send(address, payload).await;
        match sent {
            Err(SignalError::RateLimited { retry_after }) => tokio::time::sleep(retry_after).await,
            Err(e)
                if e.next() == NextStep::RetryLater
                    && start.elapsed() < crate::world::AGAIN_FOR =>
            {
                tokio::time::sleep(crate::world::AGAIN_PAUSE).await;
            }
            Err(e) => return Err(e),
            Ok(seq) => {
                ledger
                    .lock()
                    .expect("the ledger's lock")
                    .insert((address.to_vec(), payload.to_vec()));
                return Ok(seq);
            }
        }
    }
}

/// One device's part in a signal case: its device following the space, its run, the signals its
/// subscriber delivered (in order) and what it sent. Its inbox acknowledges on its run every
/// final of another sender it delivers ([`ack_address`]).
pub struct Peer {
    pub who: String,
    pub me: Name,
    pub scope: Name,
    pub run: Run,
    pub sent: Ledger,
    got: Arc<Mutex<Vec<Signal>>>,
    inbox: tokio::task::JoinHandle<()>,
}

impl Peer {
    /// `d` takes part in `space`'s signals: its device follows the space (its members record and
    /// epoch keys arrive), and its host's signals subscribe to it and open a run, each asked
    /// again while refused with retry later (the record or the epoch key not held yet).
    pub async fn join(w: &World, d: Dev, space: &Name) -> Result<Peer, Failure> {
        let me = w.net().spec(d).name();
        let who = me.to_string();
        let spaces = w.spaces(d);
        w.retry_later(|| spaces.open(space)).await?;
        let signals = w.signals(d).await?;
        let mut sub = signal_again(|| signals.subscribe(space))
            .await
            .map_err(|e| refused(&format!("{who} subscribes to {space}"), e))?;
        let run: Run = Arc::new(futures::lock::Mutex::new(
            signal_again(|| signals.open(space))
                .await
                .map_err(|e| refused(&format!("{who} opens a run in {space}"), e))?,
        ));
        let sent = Ledger::default();
        let got = Arc::new(Mutex::new(Vec::new()));
        let inbox = {
            let (me, run, sent, got) = (me.clone(), run.clone(), sent.clone(), got.clone());
            tokio::spawn(async move {
                while let Some(s) = sub.next().await {
                    let from = sender_of(&s);
                    let ack = (from != me && s.payload.starts_with(FINAL.as_bytes()))
                        .then(|| (ack_address(&from, &s.address), acknowledging(&s.payload)));
                    got.lock().expect("the inbox's lock").push(s);
                    // A lost acknowledgement is made good by the next one: the sender sends its
                    // final again until it sees one.
                    if let Some((address, payload)) = ack {
                        let _ = send_on(&run, &sent, &address, &payload).await;
                    }
                }
            })
        };
        Ok(Peer {
            who,
            me,
            scope: space.clone(),
            run,
            sent,
            got,
            inbox,
        })
    }

    /// Send one signal now.
    pub async fn send(&self, address: &str, payload: &str) -> Result<u64, Failure> {
        send_on(
            &self.run,
            &self.sent,
            address.as_bytes(),
            payload.as_bytes(),
        )
        .await
        .map_err(|e| refused(&format!("{} sends at {address}", self.who), e))
    }

    /// Send `payload` (a [`FINAL`]) at `address` until every one of `to` acknowledged it,
    /// again every [`RESEND`], for at most [`LIMIT`]. Returns how many times it was sent.
    pub async fn send_final(
        &self,
        address: &str,
        payload: &str,
        to: &[&Peer],
    ) -> Result<u32, Failure> {
        debug_assert!(payload.starts_with(FINAL));
        let ack = ack_address(&self.me, address.as_bytes());
        let start = tokio::time::Instant::now();
        let mut sends = 0;
        loop {
            let seen = to.iter().all(|p| {
                self.latest(p, &ack)
                    .is_some_and(|s| s.payload == acknowledging(payload.as_bytes()))
            });
            if seen {
                return Ok(sends);
            }
            if start.elapsed() >= LIMIT {
                return Err(Failure::new(format!(
                    "{}'s final {payload:?} at {address} was not seen by every receiver within \
                     {LIMIT:?} of virtual time, sent {sends} times",
                    self.who
                )));
            }
            self.send(address, payload).await?;
            sends += 1;
            tokio::time::sleep(RESEND).await;
        }
    }

    /// Every signal its subscriber delivered so far, in order.
    pub fn all(&self) -> Vec<Signal> {
        self.got.lock().expect("the inbox's lock").clone()
    }

    /// The last signal it delivered from `from` at `address`.
    pub fn latest(&self, from: &Peer, address: &[u8]) -> Option<Signal> {
        self.got
            .lock()
            .expect("the inbox's lock")
            .iter()
            .rev()
            .find(|s| sender_of(s) == from.me && s.address == address)
            .cloned()
    }

    /// How many signals it delivered whose payload contains `part`.
    pub fn delivered(&self, part: &str) -> usize {
        self.got
            .lock()
            .expect("the inbox's lock")
            .iter()
            .filter(|s| contains(&s.payload, part.as_bytes()))
            .count()
    }

    /// What every delivery must be, whatever the network did: of its scope, from one of
    /// `peers` and something that peer sent, from the network (no ring), each (sender, run, seq)
    /// once, and per (sender, address) never older than one delivered before it.
    pub fn check(&self, peers: &[&Peer]) -> Result<(), Failure> {
        let got = self.all();
        let mut once = BTreeSet::new();
        let mut newest: BTreeMap<(Name, Bytes), u64> = BTreeMap::new();
        for s in &got {
            let from = sender_of(s);
            let Some(peer) = peers.iter().find(|p| p.me == from) else {
                return Err(Failure::new(format!(
                    "{} delivered a signal from {}, no sender of the case: {s:?}",
                    self.who, s.sender
                )));
            };
            ensure!(
                s.scope == self.scope,
                "{} delivered a signal of {} on its subscription to {}",
                self.who,
                s.scope,
                self.scope
            );
            ensure!(
                peer.sent
                    .lock()
                    .expect("the ledger's lock")
                    .contains(&(s.address.to_vec(), s.payload.to_vec())),
                "{} delivered {:?} at {:?} as {from}'s, which {from} never sent",
                self.who,
                String::from_utf8_lossy(&s.payload),
                String::from_utf8_lossy(&s.address)
            );
            ensure!(
                from == self.me || !s.local,
                "{} delivered {from}'s signal off a local ring: every device is its own host",
                self.who
            );
            ensure!(
                once.insert((from.clone(), s.run.0, s.seq)),
                "{} delivered {from}'s signal seq {} of its run twice",
                self.who,
                s.seq
            );
            let last = newest.entry((from.clone(), s.address.clone())).or_insert(0);
            ensure!(
                s.seq > *last,
                "{} delivered {from}'s seq {} at {:?} after seq {}: an older signal after a \
                 newer one for the same sender and address",
                self.who,
                s.seq,
                String::from_utf8_lossy(&s.address),
                *last
            );
            *last = s.seq;
        }
        Ok(())
    }

    /// What its run sends: the run's id.
    pub async fn run_id(&self) -> [u8; 16] {
        self.run.lock().await.id().0
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.inbox.abort();
    }
}

/// Whether `part` appears in `bytes`.
pub fn contains(bytes: &[u8], part: &[u8]) -> bool {
    super::kit::contains(bytes, part)
}

/// `d`'s signal counters now.
pub async fn stats(w: &World, d: Dev) -> Result<SignalStats, Failure> {
    Ok(w.signals(d).await?.stats())
}

/// How many packets (or signals) `s` counts as dropped, whatever the reason.
pub fn dropped(s: &SignalStats) -> u64 {
    s.stale
        + s.replayed
        + s.expired
        + s.not_member
        + s.bad_signature
        + s.unknown_run
        + s.unknown_key
        + s.flood
        + s.malformed
        + s.unsubscribed
}

/// Wait until `rose` holds of `d`'s signal counters, for at most [`LIMIT`]; while it does not,
/// `again` is done every [`RESEND`] (a packet sent again, as the packet that should raise the
/// counter may be lost on its way).
pub async fn until_counted<F, Fut>(
    w: &World,
    d: Dev,
    what: &str,
    rose: impl Fn(&SignalStats) -> bool,
    mut again: F,
) -> Result<SignalStats, Failure>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), Failure>>,
{
    let start = tokio::time::Instant::now();
    loop {
        let now = stats(w, d).await?;
        if rose(&now) {
            return Ok(now);
        }
        if start.elapsed() >= LIMIT {
            return Err(Failure::new(format!(
                "{what}: not counted within {LIMIT:?} of virtual time ({now:?})"
            )));
        }
        again().await?;
        tokio::time::sleep(RESEND).await;
    }
}

/// The signal key `d` holds for `space` to seal with now (newest epoch), as (id, key).
pub fn signal_key(w: &World, d: Dev, space: &Name) -> Result<SignalKeyPair, Failure> {
    w.signal_keys(d, space)?.into_iter().next().ok_or_else(|| {
        Failure::new(format!(
            "{} holds no signal key of {space}: it is no sealed space there",
            w.net().spec(d).name()
        ))
    })
}

/// The SignalBody of the sealed packet a push Interest `wire` carries, opened with `key`.
pub fn opened(wire: &Bytes, key: &[u8; 32]) -> Option<signal::Body> {
    let (_, packet) = signal::pushed(wire)?;
    let body = signal::open(&signal::sealed(&packet)?, key)?;
    signal::parse_body(&body)
}
