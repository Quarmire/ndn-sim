//! Name-aware **per-prefix traffic accounting** on the fabric — the per-prefix
//! half of the network-viz feed.
//!
//! The fabric's [`FaceStats`](crate::FaceStats) give per-face TOTALS (counters,
//! no names); `SimLink`s shuttle opaque frames. This decodes each frame's L3
//! name (NDNLPv2-aware) and counts bytes/packets per `(node, prefix)`, so a
//! console can answer "who is talking about *what*" without decoding the wire
//! itself.
//!
//! # Lifted from a real consumer
//!
//! A deployment (miniMUAS) hand-rolled this as a UDP-bridge tap
//! (`muas-sim/src/nettap.rs`), forced to sit at the bridge seam because names
//! were *not visible inside the fabric*. Enabling accounting here makes the
//! fabric itself the source — no bridge tap needed. The stat surface
//! ([`PrefixSample`] / [`PrefixCounters`]) matches that feed's `net` message
//! `prefixes` key, so the console maps it through directly.
//!
//! # Scope & attribution
//!
//! Counting happens on **wired [`SimFace`](crate::SimFace)s**: a face's `send`
//! is its owning node's emission (`out_*`, counted before the loss roll — the
//! node *emitted* it), its `recv` is a delivery (`in_*`). A relay node's faces
//! therefore show forwarded traffic as both in and out — honest, per-face truth.
//! Radio delivery is broadcast and out of scope (the never-synthesize rule),
//! matching the source tap's coverage.
//!
//! # Prefix grouping
//!
//! [`group_prefix`] keeps the first `max_components` name components (the fabric
//! defaults to 3 — the network-viz `net`-message default). Undecodable datagrams
//! (LP continuation fragments, junk) count under `"(unparsed)"` so bytes never
//! silently vanish. App-specific grouping (e.g. a semantic 4th component) stays
//! the *console's* policy, layered on the raw names — not baked into the fabric.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use ndn_packet::lp::LpPacket;
use ndn_packet::{Data, Interest};

/// Cumulative counters for one `(node, prefix)` pair. `out_*` = emitted by the
/// labeled node toward the fabric; `in_*` = delivered to it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrefixCounters {
    pub out_bytes: u64,
    pub in_bytes: u64,
    pub out_interests: u64,
    pub out_data: u64,
    pub in_interests: u64,
    pub in_data: u64,
}

/// One snapshot row: a node's cumulative counters for one name prefix.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrefixSample {
    pub node: String,
    pub prefix: String,
    #[serde(flatten)]
    pub counters: PrefixCounters,
}

/// Shared per-prefix counter table: every tapped face writes into it; a console
/// reads it on a cadence. Cheap to clone (`Arc`), lock-per-observation. Carries
/// its own name-grouping depth so runtime-added links account consistently.
pub struct PrefixStats {
    inner: Mutex<HashMap<(String, String), PrefixCounters>>,
    grouping: usize,
}

impl PrefixStats {
    /// A table grouping names to 3 components (the network-viz default).
    pub fn new() -> Arc<Self> {
        Self::with_grouping(3)
    }

    /// A table grouping names to `max_components`.
    pub fn with_grouping(max_components: usize) -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(HashMap::new()), grouping: max_components.max(1) })
    }

    /// The name-grouping depth this table counts at.
    pub fn grouping(&self) -> usize {
        self.grouping
    }

    fn count(&self, node: &str, prefix: &str, outbound: bool, kind: WireKind, bytes: usize) {
        let mut map = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let c = map.entry((node.to_string(), prefix.to_string())).or_default();
        if outbound {
            c.out_bytes += bytes as u64;
            match kind {
                WireKind::Interest => c.out_interests += 1,
                WireKind::Data => c.out_data += 1,
                WireKind::Other => {}
            }
        } else {
            c.in_bytes += bytes as u64;
            match kind {
                WireKind::Interest => c.in_interests += 1,
                WireKind::Data => c.in_data += 1,
                WireKind::Other => {}
            }
        }
    }

    /// Deterministically ordered snapshot of every `(node, prefix)` row.
    pub fn snapshot(&self) -> Vec<PrefixSample> {
        let map = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rows: Vec<PrefixSample> = map
            .iter()
            .map(|((node, prefix), counters)| PrefixSample {
                node: node.clone(),
                prefix: prefix.clone(),
                counters: *counters,
            })
            .collect();
        rows.sort_by(|a, b| (&a.node, &a.prefix).cmp(&(&b.node, &b.prefix)));
        rows
    }

    /// The row for one `(node, prefix)`, or `None` if it was never seen.
    pub fn get(&self, node: &str, prefix: &str) -> Option<PrefixCounters> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&(node.to_string(), prefix.to_string()))
            .copied()
    }
}

/// A per-face tap: classifies + counts one node's frames into a shared
/// [`PrefixStats`]. Installed on a [`SimFace`](crate::SimFace) by the fabric when
/// prefix accounting is enabled.
#[derive(Clone)]
pub struct PrefixTap {
    stats: Arc<PrefixStats>,
    node: String,
    max_components: usize,
}

impl PrefixTap {
    pub(crate) fn new(stats: Arc<PrefixStats>, node: impl Into<String>, max_components: usize) -> Self {
        Self { stats, node: node.into(), max_components: max_components.max(1) }
    }

    /// Observe one frame on this face: `outbound` = the node is emitting it.
    pub(crate) fn observe(&self, wire: &[u8], outbound: bool) {
        let (kind, name) = classify(wire);
        let prefix = name
            .as_deref()
            .map(|n| group_prefix(n, self.max_components))
            .unwrap_or_else(|| "(unparsed)".into());
        self.stats.count(&self.node, &prefix, outbound, kind, wire.len());
    }
}

/// L3 packet classification for the counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WireKind {
    Interest,
    Data,
    Other,
}

/// Decode one datagram far enough to learn its kind and name. LP packets are
/// unwrapped one level: the first fragment carries the inner L3 header (name
/// included); continuations are unattributable by design (counted as bytes only).
fn classify(wire: &[u8]) -> (WireKind, Option<String>) {
    match wire.first() {
        Some(0x05) => match Interest::decode(bytes::Bytes::copy_from_slice(wire)) {
            Ok(i) => (WireKind::Interest, Some(i.name.to_string())),
            Err(_) => (WireKind::Other, None),
        },
        Some(0x06) => match Data::decode(bytes::Bytes::copy_from_slice(wire)) {
            Ok(d) => (WireKind::Data, Some(d.name.to_string())),
            Err(_) => (WireKind::Other, None),
        },
        Some(0x64) => match LpPacket::decode(bytes::Bytes::copy_from_slice(wire)) {
            // Only the FIRST fragment carries the inner header; later fragments
            // count as unparsed bytes (never dropped from totals, never
            // mis-attributed to a name).
            Ok(lp) if lp.frag_index.unwrap_or(0) == 0 => match lp.fragment {
                Some(inner) => classify(&inner),
                None => (WireKind::Other, None),
            },
            _ => (WireKind::Other, None),
        },
        _ => (WireKind::Other, None),
    }
}

/// Group a name URI into its accounting prefix: the first `max_components`
/// components. A generic default (the fabric passes 3); app-semantic grouping is
/// the console's own policy over the raw names.
pub fn group_prefix(uri: &str, max_components: usize) -> String {
    let comps: Vec<&str> = uri.split('/').filter(|c| !c.is_empty()).collect();
    if comps.is_empty() {
        return "/".into();
    }
    let take = comps.len().min(max_components.max(1));
    format!("/{}", comps[..take].join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndn_packet::Name;
    use ndn_packet::encode::{encode_data_unsigned, encode_interest};

    #[test]
    fn group_prefix_keeps_the_first_n_components() {
        assert_eq!(group_prefix("/edu/ucla/data/seg/0", 3), "/edu/ucla/data");
        assert_eq!(group_prefix("/a/b", 3), "/a/b"); // shorter than n: no pad, no panic
        assert_eq!(group_prefix("/muas/v3/iuas-01/telemetry/live", 4), "/muas/v3/iuas-01/telemetry");
        assert_eq!(group_prefix("/", 3), "/");
        assert_eq!(group_prefix("/x", 1), "/x");
    }

    #[test]
    fn classify_reads_names_through_lp_wrapping() {
        let name: Name = "/svc/telemetry/live".parse().expect("name");
        let interest = encode_interest(&name, None);
        assert_eq!(classify(&interest), (WireKind::Interest, Some("/svc/telemetry/live".into())));

        let data = encode_data_unsigned(&name, b"payload");
        assert_eq!(classify(&data), (WireKind::Data, Some("/svc/telemetry/live".into())));

        // Hand-rolled LPv2 wrap: LP_PACKET(0x64) { Fragment(0x50) { data } }.
        let mut lp = vec![0x64, (data.len() + 2) as u8, 0x50, data.len() as u8];
        lp.extend_from_slice(&data);
        assert_eq!(classify(&lp), (WireKind::Data, Some("/svc/telemetry/live".into())));

        // Junk is unattributable, never panics.
        assert_eq!(classify(&[0xff, 0x00]).0, WireKind::Other);
        assert_eq!(classify(&[]).0, WireKind::Other);
    }

    #[test]
    fn tap_counts_per_node_and_prefix() {
        let name: Name = "/svc/a/x".parse().unwrap();
        let stats = PrefixStats::new();
        let tap = PrefixTap::new(stats.clone(), "node#1", 3);
        tap.observe(&encode_interest(&name, None), true); // emission
        tap.observe(&encode_data_unsigned(&name, b"y"), false); // delivery
        let c = stats.get("node#1", "/svc/a/x").expect("row");
        assert_eq!((c.out_interests, c.in_data), (1, 1));
        assert!(c.out_bytes > 0 && c.in_bytes > 0);
    }
}
