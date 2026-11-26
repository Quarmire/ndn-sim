//! A tap on the relay for channel frames: what the relay between the devices forwards of one
//! channel, as it forwards it, and what a case may do with a genuine frame it holds.
//!
//! A channel's frames are not NDN packets: [`Net::tap`](crate::world::Net::tap) sees none of
//! them. The hub's side table fans a frame out to every sink of the channel's route, so the tap
//! is one more sink: a face of an app on the hub's own node, installed on the route the way a
//! receiver's link is. It sees every frame the hub forwards, before the faulty network between
//! the hub and a device meets it (the faults act on what arrives at a device).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::EngineAppExt;
use ndn_engine::side::SideId;
use ndn_sim::NodeId;
use tokio_util::sync::CancellationToken;

use crate::case::Failure;
use crate::world::World;

/// How long a sink the tap installed lasts before the tap installs it again: under the side
/// table's longest ttl, so the route never drops it while the tap lives.
const REFRESH: Duration = Duration::from_secs(60);

/// The longest ttl the tap asks for (the side table clamps it to its own bound).
const TTL: Duration = Duration::from_secs(300);

/// The first octet a side frame starts with.
pub const MARKER: u8 = 0x00;

/// The second octet of a `DATA` frame on a datagram (`ver 1`, class 0, kind 0).
pub const DATA_DATAGRAM: u8 = 0x20;

/// The tap: the frames of one channel the relay forwarded since it was installed.
pub struct FrameTap {
    seen: Arc<Mutex<Vec<Bytes>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FrameTap {
    /// Taps `channel` at the hub. The hub must already hold the channel's route (a receiver
    /// asked and was answered: [`until_ready`](super::channel_kit::until_ready)).
    pub fn on(w: &World, channel: u64) -> Result<FrameTap, Failure> {
        // The hub is the first node of the fabric.
        let engine = w
            .net()
            .fabric()
            .engine_of(NodeId(0))
            .ok_or_else(|| Failure::new("the fabric has no hub to tap"))?;
        let route = engine
            .side()
            .list()
            .into_iter()
            .find(|r| r.id == channel)
            .ok_or_else(|| {
                Failure::new(format!(
                    "the relay holds no route of channel {channel:016x} to tap"
                ))
            })?;
        let before = engine.faces().face_ids();
        let conn = engine.app_face(CancellationToken::new());
        let face = engine
            .faces()
            .face_ids()
            .into_iter()
            .find(|id| !before.contains(id))
            .ok_or_else(|| Failure::new("the tap's face is not in the hub's face table"))?;
        let side = engine.side();
        side.install(SideId(channel), route.source, face, TTL)
            .map_err(|e| Failure::new(format!("the relay took no tap on {channel:016x}: {e:?}")))?;
        let seen: Arc<Mutex<Vec<Bytes>>> = Arc::default();
        let into = Arc::clone(&seen);
        let source = route.source;
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    got = conn.recv_side() => {
                        let Some((frame, _)) = got else { return };
                        into.lock().expect("the tap's lock").push(frame);
                    }
                    () = tokio::time::sleep(REFRESH) => {
                        // A route that went away takes the tap with it: the case sees no more.
                        let _ = side.install(SideId(channel), source, face, TTL);
                    }
                }
            }
        });
        Ok(FrameTap { seen, task })
    }

    /// Every frame forwarded so far, oldest first.
    pub fn frames(&self) -> Vec<Bytes> {
        self.seen.lock().expect("the tap's lock").clone()
    }

    /// The `DATA` frames sent on the datagram class so far, oldest first.
    pub fn data(&self) -> Vec<Bytes> {
        self.frames()
            .into_iter()
            .filter(|f| f.len() >= 46 && f[0] == MARKER && f[1] == DATA_DATAGRAM)
            .collect()
    }
}

impl Drop for FrameTap {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// `frame` with its `seq0` moved up by `by`: the header is authenticated, so no key holder's
/// tag covers the new one. What a party that holds no key makes of a frame it saw: a frame that
/// reads like the sender's and cannot open.
pub fn moved(frame: &Bytes, by: u64) -> Bytes {
    let mut out = frame.to_vec();
    let seq0 = u64::from_be_bytes(out[11..19].try_into().expect("eight octets of seq0"));
    out[11..19].copy_from_slice(&(seq0 + by).to_be_bytes());
    Bytes::from(out)
}
