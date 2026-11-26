//! What the channel cases share: a device that takes a space's live messages, asks a sender for
//! its channel and keeps what its stream told it, and a sender that emits until its receivers
//! have what it sent.
//!
//! A `Latest` channel loses frames on a faulty network, by contract; a case never waits for one
//! frame, it emits again (a new value, a new frame) until what it wants to see has arrived, as a
//! host that wants a value seen does.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use ndn_heap::Name;

use super::kit::{LIMIT, holds_key, known, n};
use crate::case::Failure;
use crate::channel::{ChannelEvent, ChannelItems, ChannelTrust, Channels};
use crate::ensure;
use crate::world::{Dev, Fwd, World};

/// How often a sender emits again while a receiver has not seen its value.
pub const EMIT_EVERY: Duration = Duration::from_millis(250);

/// How far past the sequence a sender takes next a forged frame that is meant to be exposed by
/// the sender's next frames sits. A sender that is idle queues an empty checkpoint every 5 s, and
/// a checkpoint takes a sequence like a frame: the sequence read from the sender is the next one
/// only until then. A few above it is reached by the sender's next few messages (each takes a
/// sequence, and so does the checkpoint that follows it) and is never behind what the sender has
/// already had checkpointed.
pub const NEAR: u64 = 3;

/// The space the channel cases live in: Alice's, public (a channel needs no reading key: it is
/// sealed under its own).
pub fn space() -> Name {
    n("/alice/32=data/live")
}

/// Whether a stream's end `why` is one a lossy or slow network makes, and a host answers by
/// asking again: `NoPath` (the first `Keep` was lost or the session held up, so the sender
/// dropped its `HELLO`; channel.md 13.12 item 27) and `Unverifiable` (a frame was accepted after
/// the checkpoint that covers it, and no later checkpoint came within 3 s: channel.md 13.12
/// item 2). Every other end is a refusal.
pub fn transient(why: &str) -> bool {
    why.starts_with("NoPath") || why.contains("Unverifiable")
}

/// A device that takes the live messages of the space and keeps everything its stream told it.
pub struct Listener {
    /// Which device.
    pub dev: Dev,
    /// Its channels.
    pub ch: Arc<dyn Channels>,
    trust: ChannelTrust,
    /// The stream: `None` only while a receiver that released it asks again.
    items: Option<Box<dyn ChannelItems>>,
    /// What the stream told it so far, in order.
    pub events: Vec<ChannelEvent>,
    /// The space it takes live.
    pub space: Name,
    /// The channel it asked last.
    pub channel: u64,
    /// Every channel it asked, by the sender's device, in the order it asked them.
    pub channels: Vec<(Dev, u64)>,
    /// The devices it asks, in the order it first asked them.
    senders: Vec<Dev>,
}

impl Listener {
    /// `dev` opens the space, waits for its members record and epoch key, and takes it live
    /// with `trust`; it has asked no sender yet.
    pub async fn prepare(w: &World, dev: Dev, trust: ChannelTrust) -> Result<Listener, Failure> {
        Listener::prepare_in(w, dev, trust, &space()).await
    }

    /// [`prepare`](Self::prepare) for `space` instead of [`space()`].
    pub async fn prepare_in(
        w: &World,
        dev: Dev,
        trust: ChannelTrust,
        space: &Name,
    ) -> Result<Listener, Failure> {
        let spaces = w.spaces(dev);
        w.retry_later(|| spaces.open(space)).await?;
        w.until("the members record", LIMIT, || known(&*spaces, space))
            .await?;
        w.until("the epoch key", LIMIT, || holds_key(&*spaces, space))
            .await?;
        let ch = w.channels(dev).await?;
        let items = Some(ch.live(space, trust).await?);
        Ok(Listener {
            dev,
            ch,
            trust,
            items,
            events: Vec::new(),
            space: space.clone(),
            channel: 0,
            channels: Vec::new(),
            senders: Vec::new(),
        })
    }

    /// One ask of `sender`'s device for its channel; returns the channel's id.
    pub async fn ask(&self, w: &World, sender: Dev) -> Result<u64, Failure> {
        let from = w.net().spec(sender).name();
        self.ch.ask(&self.space, &from).await
    }

    /// [`prepare`](Self::prepare), then [`establish`](Self::establish) a channel from `sender`'s
    /// device.
    pub async fn join(
        w: &World,
        dev: Dev,
        trust: ChannelTrust,
        sender: Dev,
    ) -> Result<Listener, Failure> {
        let mut listener = Listener::prepare(w, dev, trust).await?;
        listener.establish(w, sender).await?;
        Ok(listener)
    }

    /// Asks `sender`'s device for its channel (again while the answer is "retry later") and
    /// waits for the sender's `HELLO`, which says the path works. On a network that holds the
    /// session Data back for longer than a stream frame waits for its route, or loses the first
    /// `Keep`, the `HELLO` is dropped and the stream says `NoPath` 2 s after the session
    /// (channel.md 13.12 item 27); the receiver then does what a host does and asks again
    /// ([`restart`](Self::restart)). That notice is not kept among `events`. Sets
    /// [`channel`](Self::channel).
    pub async fn establish(&mut self, w: &World, sender: Dev) -> Result<(), Failure> {
        if !self.senders.contains(&sender) {
            self.senders.push(sender);
        }
        let start = tokio::time::Instant::now();
        let mut asked = vec![sender];
        loop {
            for s in asked.drain(..) {
                let channel = w.retry_later(|| self.ask(w, s)).await?;
                self.channels.retain(|(d, _)| *d != s);
                self.channels.push((s, channel));
                if s == sender {
                    self.channel = channel;
                }
            }
            loop {
                w.sleep(Duration::from_millis(100)).await;
                self.pump();
                if self.hello() {
                    return Ok(());
                }
                if self.lapsed() {
                    self.events
                        .retain(|e| !matches!(e, ChannelEvent::Ended { why } if transient(why)));
                    self.restart(w).await?;
                    asked.clone_from(&self.senders);
                    break;
                }
                ensure!(
                    start.elapsed() < LIMIT,
                    "device {} heard no HELLO of {}'s channel within {LIMIT:?} of virtual time: \
                     {:?}; {}",
                    self.dev.0,
                    sender.0,
                    self.events,
                    channel_state(
                        w,
                        self.channel,
                        &[Fwd::Device(self.dev), Fwd::Hub, Fwd::Device(sender)]
                    )
                );
            }
        }
    }

    /// Read what the stream has queued now.
    pub fn pump(&mut self) {
        if let Some(items) = self.items.as_mut() {
            let told = items.drain();
            self.events.extend(told);
        }
    }

    /// Whether the sender's `HELLO` came.
    pub fn hello(&self) -> bool {
        self.items.as_ref().is_some_and(|items| items.hello())
    }

    /// The messages delivered so far, as `(path, payload)`, in order.
    pub fn messages(&self) -> Vec<(Name, Bytes)> {
        self.events
            .iter()
            .filter_map(|e| match e {
                ChannelEvent::Message { path, bytes, .. } => Some((path.clone(), bytes.clone())),
                _ => None,
            })
            .collect()
    }

    /// Whether `payload` was delivered at `path`.
    pub fn has(&self, path: &Name, payload: &[u8]) -> bool {
        self.messages()
            .iter()
            .any(|(p, b)| p == path && b[..] == *payload)
    }

    /// Whether a message at `path` was delivered whose payload begins with `stem`.
    pub fn has_stem(&self, path: &Name, stem: &[u8]) -> bool {
        self.messages()
            .iter()
            .any(|(p, b)| p == path && b.starts_with(stem))
    }

    /// Fail unless the stream so far is only messages, lags and retractions the case expects:
    /// a session that ended for a cause the case did not provoke is a refusal. The ends a lossy
    /// or slow network makes (see [`transient`]) are not: a host asks again.
    pub fn alive(&self, who: &str) -> Result<(), Failure> {
        for e in &self.events {
            if let ChannelEvent::Ended { why } = e
                && !transient(why)
            {
                return Err(Failure::new(format!("{who}'s live stream ended: {why}")));
            }
        }
        Ok(())
    }

    /// Whether the stream told that a session ended for a cause a lossy or slow network makes
    /// ([`transient`]) and the receiver has not asked again since.
    pub fn lapsed(&self) -> bool {
        self.events
            .iter()
            .any(|e| matches!(e, ChannelEvent::Ended { why } if transient(why)))
    }

    /// The receiver lets the stream go (the channel is released: an `Unsub` leaves) and takes the
    /// space live again after [`QUIET`]: the network holds or reorders a datagram for less, so
    /// that no `Unsub` of the session let go is still on its way when the next ask installs a
    /// session and its first `Keep` (an `Unsub` that overtook it would remove the new sink).
    pub async fn restart(&mut self, w: &World) -> Result<(), Failure> {
        self.items = None;
        w.sleep(QUIET).await;
        self.items = Some(self.ch.live(&self.space, self.trust).await?);
        Ok(())
    }

    /// What a host does when the stream says a session ended for a cause a lossy or slow network
    /// makes: ask again. Does nothing when none did. Returns whether it asked again. The notice
    /// is not kept among `events`.
    pub async fn heal(&mut self, w: &World) -> Result<bool, Failure> {
        self.heal_with(w, &mut []).await
    }

    /// [`heal`](Self::heal) for a receiver whose device holds `companions`, other streams over
    /// the same session (a second `Items` of the node): the session is let go when the last of
    /// them is, and a session not let go is renewed with no new `HELLO`, so they are let go with
    /// it and take the space live again after it asked.
    pub async fn heal_with(
        &mut self,
        w: &World,
        companions: &mut [&mut Listener],
    ) -> Result<bool, Failure> {
        self.pump();
        for c in companions.iter_mut() {
            c.pump();
        }
        if !self.lapsed() && !companions.iter().any(|c| c.lapsed()) {
            return Ok(false);
        }
        if self.senders.is_empty() {
            return Ok(false);
        }
        let senders = self.senders.clone();
        self.events
            .retain(|e| !matches!(e, ChannelEvent::Ended { why } if transient(why)));
        for c in companions.iter_mut() {
            c.settle_lapse();
            c.items = None;
        }
        self.restart(w).await?;
        for sender in senders {
            self.establish(w, sender).await?;
        }
        for c in companions.iter_mut() {
            c.items = Some(c.ch.live(&c.space, c.trust).await?);
        }
        Ok(true)
    }

    /// Drops the notice of an end that another receiver of the same device answered. Returns
    /// whether there was one.
    pub fn settle_lapse(&mut self) -> bool {
        self.pump();
        let before = self.events.len();
        self.events
            .retain(|e| !matches!(e, ChannelEvent::Ended { why } if transient(why)));
        self.events.len() != before
    }
}

/// `sender` emits `payload` at `path`, and again every [`EMIT_EVERY`] with a new tail, until
/// every listener has delivered a message at `path` whose payload begins with `payload`'s
/// stem; returns the payload each of them got last. For at most [`LIMIT`].
pub async fn emit_until_seen(
    w: &World,
    sender: &Arc<dyn Channels>,
    path: &Name,
    stem: &str,
    listeners: &mut [&mut Listener],
) -> Result<Vec<Bytes>, Failure> {
    let start = tokio::time::Instant::now();
    let mut round = 0u64;
    loop {
        let payload = format!("{stem}#{round}");
        sender
            .emit(&space(), path, Bytes::from(payload.clone()))
            .await?;
        round += 1;
        w.sleep(EMIT_EVERY).await;
        let mut seen = Vec::new();
        for l in listeners.iter_mut() {
            l.heal(w).await?;
            l.pump();
            let last = l
                .messages()
                .into_iter()
                .rev()
                .find(|(p, b)| p == path && b.starts_with(stem.as_bytes()));
            seen.push(last.map(|(_, b)| b));
        }
        if seen.iter().all(Option::is_some) {
            return Ok(seen.into_iter().flatten().collect());
        }
        ensure!(
            start.elapsed() < LIMIT,
            "after {round} emissions of {path} over {LIMIT:?} of virtual time, not every receiver \
             had a message of {stem:?}"
        );
    }
}

/// How long the network is left to deliver what it holds before a case reads a counter it
/// compares later: past the longest a faulty link holds a packet back (delay, reorder, block).
pub const QUIET: Duration = Duration::from_secs(3);

/// How long a forged frame is sent again before the sender's sequence is read anew: past it the
/// sender may have taken more than [`NEAR`] sequences (an idle sender's checkpoint takes one
/// every 5 s), and a frame below what the sender has had checkpointed is never judged.
pub const FORGE_WINDOW: Duration = Duration::from_secs(4);

/// `holder`, a member that holds the channel's key like every receiver, turns hostile. It asks
/// `sender`'s device again (a renewal queues nothing) to read the sequence the sender takes next
/// (plus `ahead`), seals a frame of one message, `payload` at `path`, at that sequence, and the
/// relay it runs sends it over its link to `watch`'s device (again every [`EMIT_EVERY`]) until
/// `watch`, a receiver that takes frames as they come, has been given it. The sender emits
/// nothing meanwhile, and must emit soon after: a receiver that took a frame no checkpoint has
/// listed yet waits only so long for one. Returns the frame's sequence and its octets, or `None`
/// when the frame did not land within [`FORGE_WINDOW`] or `watch`'s session ended on the way
/// (the sequence may be stale, and a frame a session that ended held is gone): the caller heals
/// and tries again.
pub async fn forge_ahead(
    w: &World,
    sender: Dev,
    holder: &Listener,
    watch: &mut Listener,
    path: &Name,
    payload: &str,
    ahead: u64,
) -> Result<Option<(u64, Bytes)>, Failure> {
    // The checkpoint the sender queued after its last frame has taken its sequence by now.
    w.sleep(EMIT_EVERY).await;
    let space = space();
    let from = w.net().spec(sender).name();
    let ch = holder.ch.clone();
    w.retry_later(|| ch.ask(&space, &from)).await?;
    let seq = holder.ch.next_seq(holder.channel)? + ahead;
    let frame = holder
        .ch
        .forge_data(holder.channel, seq, path, payload.as_bytes())?;
    let start = tokio::time::Instant::now();
    loop {
        w.net()
            .relay_inject(watch.dev, frame.clone(), false)
            .await?;
        w.sleep(EMIT_EVERY).await;
        watch.pump();
        if watch.has(path, payload.as_bytes()) {
            return Ok(Some((seq, frame)));
        }
        if watch.lapsed() || start.elapsed() >= FORGE_WINDOW {
            return Ok(None);
        }
    }
}

/// The relay `listener`'s link runs sends `frame` (a stream frame when `stream`) over it, again
/// every [`EMIT_EVERY`], until `landed` says it had its effect, for at most [`LIMIT`]. A frame
/// is tried against the session the receiver holds: when the session ended on the way (a frame
/// accepted after the checkpoint that covers it, nothing after it for 3 s, channel.md 13.12
/// item 2) the receiver asks again first.
pub async fn inject_until(
    w: &World,
    listener: &mut Listener,
    frame: &Bytes,
    stream: bool,
    landed: impl Fn(&Listener) -> bool,
) -> Result<(), Failure> {
    let start = tokio::time::Instant::now();
    loop {
        listener.heal(w).await?;
        w.net()
            .relay_inject(listener.dev, frame.clone(), stream)
            .await?;
        w.sleep(EMIT_EVERY).await;
        listener.pump();
        if landed(listener) {
            return Ok(());
        }
        ensure!(
            start.elapsed() < LIMIT,
            "the frame had no effect on device {} within {LIMIT:?} of virtual time",
            listener.dev.0
        );
    }
}

/// Wait until the relay holds a sink for at least each of `sinks` receivers of `channel` (a
/// device that has the space live asks a channel an announce told it of, so there may be more
/// than the case asked for) and every one of `listeners` has seen the sender's `HELLO`. When it
/// does not, the failure says where setup stopped: each forwarder's route and counters, and
/// which receivers heard a `HELLO`.
pub async fn until_ready(
    w: &World,
    listeners: &[&Listener],
    channel: u64,
    sinks: usize,
) -> Result<(), Failure> {
    w.until("every receiver's route and HELLO", LIMIT, || async {
        Ok(w.net()
            .side_route(Fwd::Hub, channel)
            .is_some_and(|(_, held)| held >= sinks)
            && listeners.iter().all(|l| l.hello()))
    })
    .await
    .map(drop)
    .map_err(|e| {
        let mut at = vec![Fwd::Hub];
        at.extend(listeners.iter().map(|l| Fwd::Device(l.dev)));
        let heard: Vec<(usize, bool)> = listeners.iter().map(|l| (l.dev.0, l.hello())).collect();
        Failure::new(format!(
            "{e}; HELLO heard {heard:?}; {}",
            channel_state(w, channel, &at)
        ))
    })
}

/// Where `channel` stands at each forwarder of `at`: its route, the faces that are its sinks and
/// what the side table counted: what a failure says so that it can be read without a rerun.
pub fn channel_state(w: &World, channel: u64, at: &[Fwd]) -> String {
    at.iter()
        .map(|f| {
            format!(
                "{f:?}: route {:?} with sink faces {:?}, {:?}",
                w.net().side_route(*f, channel),
                w.net().side_sink_faces(*f, channel),
                w.net().side_counts(*f)
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// What `ch`'s device's receiver counted under `name` (0 when it counts nothing of that name).
pub fn rx_count(ch: &Arc<dyn Channels>, name: &str) -> u64 {
    ch.rx_counters()
        .into_iter()
        .find_map(|(n, v)| (n == name).then_some(v))
        .unwrap_or(0)
}

/// The counters of `ch`'s device's receiver that are not zero, for a failure to say.
pub fn rx_state(ch: &Arc<dyn Channels>) -> String {
    ch.rx_counters()
        .into_iter()
        .filter(|(_, v)| *v > 0)
        .map(|(n, v)| format!("{n}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The receiver's counters at the phases of a case, in virtual time: what a failure says so that
/// it can be read without a rerun.
pub struct Marks {
    t0: tokio::time::Instant,
    said: Vec<String>,
}

impl Marks {
    pub fn new() -> Marks {
        Marks {
            t0: tokio::time::Instant::now(),
            said: Vec::new(),
        }
    }

    /// `what` happened now; `ch`'s device's receiver counted [`rx_state`].
    pub fn at(&mut self, what: &str, ch: &Arc<dyn Channels>) {
        self.said.push(format!(
            "{what}@{}ms [{}]",
            self.t0.elapsed().as_millis(),
            rx_state(ch)
        ));
    }

    pub fn said(&self) -> String {
        self.said.join("; ")
    }
}
