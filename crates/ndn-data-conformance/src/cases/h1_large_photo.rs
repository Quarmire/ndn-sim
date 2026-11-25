//! Slice 3, h1 — a photo of hundreds of pieces.
//!
//! Alice's phone saves a 1.6 MB photo into her photos. No packet carries that: the write is a
//! small signed record naming the value's size and the root of a manifest of its pieces, and the
//! value travels as pieces under the record's name, each verified against the manifest. A reader
//! device that reads the photo fetches the pieces, verifies each, opens the seal and returns
//! exactly the bytes written; the pieces it fetched stay in its store, so it holds what it
//! would serve to a peer.

use std::time::Duration;

use super::kit::{IMAGE, LIMIT, item, n, people, picture, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::SpaceMembers;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "h1",
    title: "A photo of hundreds of pieces",
    slice: 3,
    needs: &[Feature::Log, Feature::LargePayloads],
    model: &[],
    guards: "A payload larger than a packet travels in pieces under its version's name, each \
             verified against the version's signed manifest: a reader learns its size without \
             fetching it, reading it returns exactly the bytes written, and it stays sealed to \
             its audience all the way.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);

/// The most octets one packet of the network carries (the largest NDN packet): a value of
/// [`IMAGE`] octets travels in at least `IMAGE / PACKET_MAX` pieces whatever the provider cuts
/// them to.
const PACKET_MAX: usize = 8800;

/// Alice's phone (`Dev(0)`, which writes the photos) and her laptop (`Dev(1)`, a reader).
fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "phone");
    p.device("alice", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let photos = n("/alice/32=data/photos");
        let beach = n("/beach.jpg");
        let alice = n("/alice");
        let (phone, laptop) = (w.spaces(PHONE), w.spaces(LAPTOP));
        // Her photos are for her alone: the audience the pieces stay sealed to.
        phone.create(&photos, private(&[], &[])).await?;
        let image = picture("beach.jpg", IMAGE);
        w.gesture();
        let written = phone.put(&photos, &beach, image.clone()).await?;

        // The laptop follows the space and reads the photo whole: it fetches every piece,
        // verifies it and opens the seal. What the read cost it on its links is the measure.
        let before = w.net().device_wire(LAPTOP);
        let start = tokio::time::Instant::now();
        w.retry_later(|| laptop.open(&photos)).await?;
        w.until("the laptop reads the photo whole", LIMIT, || async {
            match item(&*laptop, &photos, &beach).await? {
                Some(read) if read.bytes == image => Ok(true),
                Some(read) => Err(Failure::new(format!(
                    "the laptop read {} octets at {beach}, not the {IMAGE} that were written \
                     (or other octets of the same length)",
                    read.bytes.len()
                ))),
                None => Ok(false),
            }
        })
        .await?;
        w.converged(start.elapsed());
        let spent = w.net().device_wire(LAPTOP) - before;
        w.measure(
            "the laptop reads the photo whole: Interests",
            spent.interests,
            "round trips",
        );
        w.measure(
            "the laptop reads the photo whole: bytes received",
            spent.in_bytes,
            "bytes",
        );

        let read = item(&*laptop, &photos, &beach)
            .await?
            .ok_or_else(|| Failure::new("the photo the laptop read is gone".to_string()))?;
        ensure!(
            read.entry() == written && read.by == alice,
            "the laptop's photo is the entry {:?} by {}, not the one the phone signed ({:?})",
            read.entry(),
            read.by,
            written
        );

        // The audience is still Alice alone (the seal's side of the photo).
        let members = w.retry_later(|| laptop.members(&photos)).await?;
        let alone = SpaceMembers::new(&alice, people(&[]), people(&[]), false);
        ensure!(
            members == alone,
            "the photos space's members are {members:?}; they must stay {alone:?}"
        );

        // The photo travelled in pieces: what the laptop stores under the entry's name is at
        // least the octets written, in more pieces than one packet carries (`pieces_stored` counts
        // the packets that carry the value under the entry, apart from the signed entry itself:
        // the pieces of a blob; `stored` counts the octets of the entry and its pieces).
        let pieces = w.pieces_stored(LAPTOP, &written.name);
        ensure!(
            pieces >= IMAGE.div_ceil(PACKET_MAX) as u64,
            "the laptop stores {pieces} pieces of the {IMAGE}-octet photo; a packet carries at \
             most {PACKET_MAX} octets"
        );
        let held = w.stored(LAPTOP, &written.name);
        ensure!(
            held >= IMAGE as u64,
            "the laptop stores {held} octets under the photo's entry, fewer than the {IMAGE} it \
             read"
        );
        w.measure("photo: pieces", pieces, "pieces");
        Ok(())
    })
}
