//! `ndn-heap`'s channels as [`Channels`]: `Heap::emit` and `Heap::live` over a node attached to
//! its forwarder's side table, and the `adversary` seam a member holding a channel's key forges
//! with.

use std::sync::Arc;

use bytes::Bytes;
use futures::FutureExt;
use ndn_heap::{
    EmitOptions, EvidenceKind, GetNotice, GetOptions, Heap, Items, Name, Node, Select, Trust,
};

use crate::case::Failure;
use crate::channel::{ChannelEvent, ChannelEvidence, ChannelItems, ChannelTrust, Channels};
use crate::new_invite::next_name;

/// The name id the forged frames bind their path under: one the genuine sender, which numbers its
/// names from 1, never reaches in a case.
const FORGED_NAME_ID: u64 = 4000;

/// One device's channels: its node, attached to its forwarder.
pub(crate) struct NewChannels {
    node: Arc<Node>,
}

impl NewChannels {
    /// The channels of `node`, which sends and receives channel frames through its forwarder.
    pub(crate) fn attach(node: Arc<Node>) -> anyhow::Result<Arc<dyn Channels>> {
        node.attach_forwarder()
            .map_err(|e| anyhow::anyhow!("{e} (next step: {:?})", e.next()))?;
        Ok(Arc::new(Self { node }))
    }

    /// The space `space` of this node, opened (followed) on first use.
    async fn heap(&self, space: &Name) -> Result<Heap, Failure> {
        if let Some(heap) = self.node.space(space) {
            return Ok(heap);
        }
        self.node.open(space).await.map_err(|e| {
            Failure::answered(
                format!("{space} cannot be opened: {e} (next step: {:?})", e.next()),
                next_name(e.next()),
                "Space",
            )
        })
    }
}

/// `what` failed with `e`, whose next step is `next`.
fn refused(what: &str, e: &dyn std::fmt::Display, next: ndn_heap::NextStep) -> Failure {
    Failure::answered(
        format!("{what}: {e} (next step: {next:?})"),
        next_name(next),
        "Channel",
    )
}

/// A receiver's `Items` as the neutral stream.
struct NewItems(Items);

impl ChannelItems for NewItems {
    fn drain(&mut self) -> Vec<ChannelEvent> {
        let mut told = Vec::new();
        while let Some(Some(next)) = self.0.next().now_or_never() {
            told.push(match next {
                Ok(got) => ChannelEvent::Message {
                    path: got.path,
                    bytes: got.bytes,
                    writer: got.writer,
                },
                Err(GetNotice::Lagged { missed }) => ChannelEvent::Lagged { missed },
                Err(GetNotice::Retracted { writer, from, to }) => {
                    ChannelEvent::Retracted { writer, from, to }
                }
                Err(GetNotice::LiveEnded(end)) => ChannelEvent::Ended {
                    why: format!("{end:?}"),
                },
            });
        }
        told
    }

    fn hello(&self) -> bool {
        self.0.hello_seen()
    }
}

#[async_trait::async_trait]
impl Channels for NewChannels {
    async fn live(
        &self,
        space: &Name,
        trust: ChannelTrust,
    ) -> Result<Box<dyn ChannelItems>, Failure> {
        let heap = self.heap(space).await?;
        let opts = GetOptions {
            trust: match trust {
                ChannelTrust::Prompt => Trust::Prompt,
                ChannelTrust::Verified => Trust::Verified,
            },
            ..GetOptions::default()
        };
        let items = heap
            .live(Select::Prefix(Name::root()), opts)
            .map_err(|e| refused(&format!("{space} cannot be taken live"), &e, e.next()))?;
        Ok(Box::new(NewItems(items)))
    }

    async fn ask(&self, space: &Name, sender: &Name) -> Result<u64, Failure> {
        self.node
            .ask_channel(space, sender)
            .await
            .map(|info| info.channel)
            .map_err(|e| {
                refused(
                    &format!("the ask of {sender}'s channel in {space}"),
                    &e,
                    e.next(),
                )
            })
    }

    async fn emit(&self, space: &Name, path: &Name, bytes: Bytes) -> Result<(), Failure> {
        self.heap(space)
            .await?
            .emit(path, bytes, EmitOptions::latest())
            .await
            .map_err(|e| refused(&format!("the emission at {path} of {space}"), &e, e.next()))
    }

    fn evidence(&self) -> Vec<ChannelEvidence> {
        self.node
            .channel_evidence()
            .into_iter()
            .map(|e| ChannelEvidence {
                kind: match e.kind {
                    EvidenceKind::Mismatch => "mismatch",
                    EvidenceKind::Conflict => "conflict",
                    EvidenceKind::BadCheckpoint => "bad-checkpoint",
                    _ => "other",
                },
                channel: e.channel,
                sender: e.sender,
                seq0: e.seq0,
                ingress: e.ingress.0,
                frame: e.frame,
                proof: e.proof,
            })
            .collect()
    }

    fn next_seq(&self, channel: u64) -> Result<u64, Failure> {
        self.node.adversary_next_seq(channel).ok_or_else(|| {
            Failure::new(format!(
                "this device holds no session of channel {channel:016x}"
            ))
        })
    }

    fn forge_data(
        &self,
        channel: u64,
        seq0: u64,
        path: &Name,
        bytes: &[u8],
    ) -> Result<Bytes, Failure> {
        self.node
            .adversary_data_frame(channel, seq0, FORGED_NAME_ID, path, bytes)
            .ok_or_else(|| {
                Failure::new(format!(
                    "this device holds no usable session of channel {channel:016x} to seal under"
                ))
            })
    }

    fn forge_checkpoint(
        &self,
        channel: u64,
        seq: u64,
        lo: u64,
        hi: u64,
        listed: &[Bytes],
    ) -> Result<Bytes, Failure> {
        self.node
            .adversary_checkpoint_frame(channel, seq, lo, hi, listed)
            .ok_or_else(|| {
                Failure::new(format!(
                    "this device holds no usable session of channel {channel:016x} to seal under"
                ))
            })
    }

    fn rx_counters(&self) -> Vec<(&'static str, u64)> {
        self.node.adversary_rx_counters()
    }
}
