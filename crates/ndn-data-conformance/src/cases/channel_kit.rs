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
    /// The channel it asked.
    pub channel: u64,
}

impl Listener {
    /// `dev` opens the space, waits for its members record and epoch key, and takes it live
    /// with `trust`; it has asked no sender yet.
    pub async fn prepare(w: &World, dev: Dev, trust: ChannelTrust) -> Result<Listener, Failure> {
        let spaces = w.spaces(dev);
        let space = space();
        w.retry_later(|| spaces.open(&space)).await?;
        w.until("the members record", LIMIT, || known(&*spaces, &space))
            .await?;
        w.until("the epoch key", LIMIT, || holds_key(&*spaces, &space))
            .await?;
        let ch = w.channels(dev).await?;
        let items = Some(ch.live(&space, trust).await?);
        Ok(Listener {
            dev,
            ch,
            trust,
            items,
            events: Vec::new(),
            channel: 0,
        })
    }

    /// One ask of `sender`'s device for its channel; returns the channel's id.
    pub async fn ask(&self, w: &World, sender: Dev) -> Result<u64, Failure> {
        let from = w.net().spec(sender).name();
        self.ch.ask(&space(), &from).await
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
    /// session Data back for longer than a stream frame waits for its route, the `HELLO` is
    /// dropped and the stream says `NoPath` 2 s after the session; the receiver then does what
    /// a host does: it lets the stream go (the channel is released), takes the space live again
    /// and asks anew. That notice is not kept among `events`. Sets [`channel`](Self::channel).
    pub async fn establish(&mut self, w: &World, sender: Dev) -> Result<(), Failure> {
        let start = tokio::time::Instant::now();
        loop {
            self.channel = w.retry_later(|| self.ask(w, sender)).await?;
            loop {
                w.sleep(Duration::from_millis(100)).await;
                self.pump();
                if self.hello() {
                    return Ok(());
                }
                if let Some(no_path) = self.events.iter().position(
                    |e| matches!(e, ChannelEvent::Ended { why } if why.starts_with("NoPath")),
                ) {
                    self.events.remove(no_path);
                    self.items = None;
                    let (dev, channel) = (self.dev, self.channel);
                    w.until("the released route to go", LIMIT, || async move {
                        Ok(w.net().side_route(Fwd::Device(dev), channel).is_none())
                    })
                    .await
                    .map_err(|e| {
                        Failure::new(format!(
                            "{e}; the stream said {:?}; {}",
                            self.events,
                            channel_state(w, channel, &[Fwd::Device(dev), Fwd::Hub])
                        ))
                    })?;
                    self.items = Some(self.ch.live(&space(), self.trust).await?);
                    break;
                }
                ensure!(
                    start.elapsed() < LIMIT,
                    "device {} heard no HELLO of {}'s channel within {LIMIT:?} of virtual time: \
                     {:?}",
                    self.dev.0,
                    sender.0,
                    self.events
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
    /// a session that ended is a refusal the case did not provoke.
    pub fn alive(&self, who: &str) -> Result<(), Failure> {
        for e in &self.events {
            if let ChannelEvent::Ended { why } = e {
                return Err(Failure::new(format!("{who}'s live stream ended: {why}")));
            }
        }
        Ok(())
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

/// `holder`, a member that holds the channel's key like every receiver, turns hostile. It asks
/// `sender`'s device again (a renewal queues nothing) to read the sequence the sender takes next
/// (plus `ahead`), seals a frame of one message, `payload` at `path`, at that sequence, and the
/// relay it runs sends it over its link to `watch`'s device (again every [`EMIT_EVERY`]) until
/// `watch`, a receiver that takes frames as they come, has been given it. The sender emits
/// nothing meanwhile, and must emit soon after: a receiver that took a frame no checkpoint has
/// listed yet waits only so long for one. Returns the frame's sequence and its octets.
pub async fn forge_ahead(
    w: &World,
    sender: Dev,
    holder: &Listener,
    watch: &mut Listener,
    path: &Name,
    payload: &str,
    ahead: u64,
) -> Result<(u64, Bytes), Failure> {
    w.sleep(QUIET).await;
    let space = space();
    let from = w.net().spec(sender).name();
    let ch = holder.ch.clone();
    w.retry_later(|| ch.ask(&space, &from)).await?;
    let seq = holder.ch.next_seq(holder.channel)? + ahead;
    let frame = holder
        .ch
        .forge_data(holder.channel, seq, path, payload.as_bytes())?;
    let to = watch.dev;
    inject_until(w, to, &frame, false, || {
        watch.pump();
        watch.has(path, payload.as_bytes())
    })
    .await
    .map_err(|e| Failure::new(format!("the forged frame at sequence {seq}: {e}")))?;
    Ok((seq, frame))
}

/// The relay `to`'s link runs sends `frame` (a stream frame when `stream`) over it, again every
/// [`EMIT_EVERY`], until `landed` says it had its effect, for at most [`LIMIT`].
pub async fn inject_until(
    w: &World,
    to: Dev,
    frame: &Bytes,
    stream: bool,
    mut landed: impl FnMut() -> bool,
) -> Result<(), Failure> {
    let start = tokio::time::Instant::now();
    loop {
        w.net().relay_inject(to, frame.clone(), stream).await?;
        w.sleep(EMIT_EVERY).await;
        if landed() {
            return Ok(());
        }
        ensure!(
            start.elapsed() < LIMIT,
            "the frame had no effect on device {} within {LIMIT:?} of virtual time",
            to.0
        );
    }
}

/// What tells that a frame of `channel` the relay sent over `to`'s link reached `to`'s forwarder
/// when it has no other visible effect: its route counted one more, or the route is gone (a
/// checkpoint the sender did not sign ends the session the route belonged to, and the route
/// with it). For a frame no genuine traffic of the channel meets: the sender is quiet.
pub fn route_took<'w>(w: &'w World, to: Dev, channel: u64) -> impl FnMut() -> bool + 'w {
    let route = move || w.net().side_route(Fwd::Device(to), channel);
    let before = route();
    move || match (before, route()) {
        (Some((was, _)), Some((now, _))) => now > was,
        (Some(_), None) => true,
        _ => false,
    }
}

/// Wait until the relay holds a sink for each of `sinks` receivers of `channel` and every one of
/// `listeners` has seen the sender's `HELLO`. When it does not, the failure says where setup
/// stopped: each forwarder's route and counters, and which receivers heard a `HELLO`.
pub async fn until_ready(
    w: &World,
    listeners: &[&Listener],
    channel: u64,
    sinks: usize,
) -> Result<(), Failure> {
    w.until("every receiver's route and HELLO", LIMIT, || async {
        Ok(w.net()
            .side_route(Fwd::Hub, channel)
            .is_some_and(|(_, held)| held == sinks)
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
