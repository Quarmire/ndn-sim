//! Slice 3, h1 — a photo of hundreds of pieces.
//!
//! Alice's phone saves a 1.6 MB photo into her photos. No packet carries that: the version is a
//! small signed record naming the payload's size and the digest of a manifest tree, and the
//! payload travels as chunks under the version's name, each verified against the manifest. A
//! reader is told the photo's size without fetching it; reading the version's name fetches the
//! pieces, verifies each, opens the seal and returns exactly the bytes written.

use std::time::Duration;

use ndn_data::wire::{CHUNK, FANOUT, INLINE_MAX};

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

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
    plan: custody_plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(2);

/// The pieces of a payload of `size` octets: its chunks and its manifest nodes (fan-out
/// [`FANOUT`], depth the smallest that lists every chunk).
fn pieces(size: u64) -> u64 {
    let chunks = size.div_ceil(CHUNK as u64);
    let mut nodes = 0;
    let mut level = chunks;
    loop {
        level = level.div_ceil(FANOUT as u64);
        nodes += level;
        if level <= 1 {
            return chunks + nodes;
        }
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let photos = n("/alice/32=data/photos");
        let (phone, laptop) = (w.at(PHONE), w.at(LAPTOP));
        let readers = [person("/alice")];
        phone
            .share(&photos, members(Rule::Log, &["/alice"], &readers))
            .await?;
        let beach = picture("beach.jpg", IMAGE);
        w.gesture();
        let id = phone
            .put(&photos, beach.clone(), photo(Keep::Forever))
            .await?;

        // The laptop is told of the photo, its size and its seal, not its bytes.
        let mut feed = laptop.watch(&photos, &Frontier::new()).await?;
        let mut seen = Vec::new();
        drain_until(
            &mut feed,
            &mut seen,
            "the laptop's watch delivers the photo",
            LIMIT,
            |c| version(c, &id).is_some(),
        )
        .await?;
        let v = version(&seen, &id).expect("drained until it arrived");
        let size = large(v).ok_or_else(|| {
            Failure::new(format!(
                "the laptop's watch delivered the {IMAGE}-octet photo {}, not as a payload in \
                 pieces (Payload::Large)",
                match &v.payload {
                    Payload::Block(_) => "as a block",
                    _ => "inline",
                }
            ))
        })?;
        ensure!(
            size > INLINE_MAX as u64 && size >= IMAGE as u64,
            "the photo of {IMAGE} octets is listed as {size} octets"
        );
        ensure!(
            v.seal.any_of == readers,
            "the photo's seal is {:?}; it must stay {:?}",
            v.seal.any_of,
            readers
        );
        let name = v.name.clone();
        w.measure("photo: pieces", pieces(size), "pieces");

        // Reading the version's name fetches every piece, verifies it and opens the seal.
        let start = tokio::time::Instant::now();
        read_whole(w, LAPTOP, &name, &beach, "the laptop reads the photo whole").await?;
        w.converged(start.elapsed());
        Ok(())
    })
}
