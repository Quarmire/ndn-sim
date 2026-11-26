//! The live data of a space, as the channel cases drive it: a device emits ephemeral messages
//! into a space and the devices that asked its channel receive them, through the forwarders
//! between them (the hub is the relay); a receiver may insist that a signed checkpoint list every
//! frame before it is given it; a device reports the evidence it made when a checkpoint exposed a
//! frame the sender did not send.
//!
//! The neutral types speak in plain octets, names and numbers so a case asserts what a receiver
//! saw, never how a provider arrived at it. The last group of verbs ([`Channels::forge_data`]
//! and its kin) is what a **member holding the channel key** can do beside the public verbs: it
//! is never available to a device that is not a member and holds no session, and a provider that
//! cannot do it says so.

use bytes::Bytes;
use ndn_heap::Name;

use crate::case::Failure;

/// What a receiver waits for before it is given a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelTrust {
    /// Frames are delivered as they come; a signed checkpoint that later contradicts one says so
    /// ([`ChannelEvent::Retracted`]).
    Prompt,
    /// A frame is delivered only once a signed checkpoint of the sender lists it; one no
    /// checkpoint lists is never delivered.
    Verified,
}

/// One thing a receiver's stream told it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelEvent {
    /// A message of a sender's channel.
    Message {
        /// Its path, relative to the space.
        path: Name,
        /// Its payload.
        bytes: Bytes,
        /// The sender's device.
        writer: Name,
    },
    /// Messages were missed (dropped by the mode, or held frames no checkpoint listed in time).
    Lagged {
        /// How many.
        missed: u64,
    },
    /// A signed checkpoint contradicted messages already delivered: those with sequences from
    /// `from` to `to` (inclusive) are not what the sender sent.
    Retracted {
        /// The sender's device.
        writer: Name,
        /// The first retracted sequence.
        from: u64,
        /// The last retracted sequence.
        to: u64,
    },
    /// The live part of the stream ended, and why.
    Ended {
        /// What the stream said.
        why: String,
    },
}

/// What a signed checkpoint showed a device: a frame a holder of the channel key made.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelEvidence {
    /// `"mismatch"` (a frame the sender's checkpoint does not list), `"conflict"` (two authentic
    /// frames at one sequence) or `"bad-checkpoint"` (a checkpoint the sender did not sign).
    pub kind: &'static str,
    /// The channel.
    pub channel: u64,
    /// The sender's device.
    pub sender: Name,
    /// The first sequence of the frame.
    pub seq0: u64,
    /// The face, at this device's forwarder, the frame came over.
    pub ingress: u64,
    /// The frame as it came.
    pub frame: Bytes,
    /// What contradicts it: the signed checkpoint (empty for a bad checkpoint).
    pub proof: Bytes,
}

/// A receiver's stream of live messages.
pub trait ChannelItems: Send {
    /// Everything the stream has queued now, in order, without waiting.
    fn drain(&mut self) -> Vec<ChannelEvent>;

    /// Whether the sender's `HELLO` came: the path to a sender works.
    fn hello(&self) -> bool;
}

/// A device's live channels.
#[async_trait::async_trait]
pub trait Channels: Send + Sync {
    /// Take the live messages of `space` as they arrive, for `trust`. Ask a sender's channel
    /// ([`ask`](Self::ask)) to have it send to this stream.
    async fn live(
        &self,
        space: &Name,
        trust: ChannelTrust,
    ) -> Result<Box<dyn ChannelItems>, Failure>;

    /// Ask the device `sender` for its channel over `space` (a signed ask, judged as the setup
    /// says) and hold the session it answers. Returns the channel's id.
    async fn ask(&self, space: &Name, sender: &Name) -> Result<u64, Failure>;

    /// Emit `bytes` at `path` of `space` on this device's newest-per-path channel, to every
    /// receiver that asked. A sender with no receiver sends nothing.
    async fn emit(&self, space: &Name, path: &Name, bytes: Bytes) -> Result<(), Failure>;

    /// The evidence this device made so far, oldest first.
    fn evidence(&self) -> Vec<ChannelEvidence>;

    /// The sequence the sender's next message took when this device last asked `channel`: where
    /// this device's frames begin. A member holding a session of `channel` reads it; a device
    /// with none is refused.
    fn next_seq(&self, channel: u64) -> Result<u64, Failure>;

    /// A frame of one message, `bytes` at `path`, sealed under `channel`'s key as this device
    /// holds it, with first sequence `seq0`: **what a member that turned hostile makes**. It
    /// holds the key, not the sender's signing key. Returns the frame's octets; sending it, and
    /// where, is the caller's.
    fn forge_data(
        &self,
        channel: u64,
        seq0: u64,
        path: &Name,
        bytes: &[u8],
    ) -> Result<Bytes, Failure>;

    /// A checkpoint of `listed` (frames as they travelled) over `[lo, hi)` at sequence `seq`,
    /// sealed under `channel`'s key and signed with **this device's own key**: what a hostile
    /// member makes of a checkpoint. The receivers refuse it as the sender's.
    fn forge_checkpoint(
        &self,
        channel: u64,
        seq: u64,
        lo: u64,
        hi: u64,
        listed: &[Bytes],
    ) -> Result<Bytes, Failure>;

    /// What this device's receiver counted so far, as `(name, count)` (every channel of the
    /// device): frames taken (`accepted`), frames no checkpoint judged (`unchecked`),
    /// checkpoints read and verified, frames they contradicted (`mismatches`). A case reads
    /// them to say what happened to a frame it made, never to time anything.
    fn rx_counters(&self) -> Vec<(&'static str, u64)>;
}
