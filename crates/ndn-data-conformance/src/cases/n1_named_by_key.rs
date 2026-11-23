//! Names by key, n1 — two people named by their keys share a space, each adopting the other by
//! name alone.
//!
//! Alice and Bob are each named by their genesis root key alone: `/user/<0xA1: SHA-256 of the
//! key>`. They are strangers: neither node holds the other's trust context. Bob tells Alice his
//! name and nothing more — no fingerprint, no context. First a version 1 for Bob's name, made and
//! signed by another key, reaches Alice's device inline in an anchor link: it is refused, and
//! nothing of it is held (else Bob's genuine version 1 would be refused later as a fork). Then
//! Alice's device adopts Bob's namespace by its name alone — version 1 fetched from Bob's device
//! and checked as signed by the key the name hashes — and Bob's device adopts Alice's the same
//! way. Alice adds Bob to her notebook space as a writer; Bob reads her cover and writes a page,
//! and Alice reads his page. Mirrors ndf's personal names (`record::personal_root`).

use std::time::Duration;

use bytes::Bytes;
use ndn_data::Name;
use ndn_security::{SecurityManager, SignedTrustContext};
use ndn_trust_envelope::TrustEnvelope;

use super::kit::{DAY, LIMIT, n, octets};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::{SpaceChange, SpaceShare, Spaces};
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "n1",
    title: "Two people named by their keys share a folder, adopting each other by name alone",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::SelfCertifying,
    ],
    model: &[],
    guards: "A namespace named by its genesis root key is adopted by its name alone — version 1 \
             fetched and checked as signed by the key the name hashes — and a version 1 for that \
             name signed by another key is refused, leaving nothing held; once each person's \
             device adopted the other's name, a folder shared with the other is read and written \
             both ways.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const BOB: Dev = Dev(1);

/// Alice's and Bob's genesis root keys (Ed25519 secrets), and the forger's.
const ALICE_KEY: [u8; 32] = [0xa1; 32];
const BOB_KEY: [u8; 32] = [0xb0; 32];
const FORGER_KEY: [u8; 32] = [0xf0; 32];

/// Alice's laptop and Bob's phone, each person named by their key: strangers to each other.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.self_certifying(ALICE_KEY, "laptop");
    p.self_certifying(BOB_KEY, "phone");
    p.strangers();
    p
}

/// `ns` followed by the components of `rest`.
pub(super) fn under(ns: &Name, rest: &str) -> Name {
    Name::from_components(
        ns.components()
            .iter()
            .chain(n(rest).components().iter())
            .cloned(),
    )
}

/// The anchor link naming `ns` alone, as `ndn-fwd init --self-certifying` prints it.
pub(super) fn by_name(ns: &Name) -> String {
    TrustEnvelope::Anchor {
        namespace: Some(ns.to_string()),
        fingerprint: None,
        version: None,
        context_data: None,
        context_content: None,
    }
    .to_uri()
}

/// An anchor link carrying a version 1 of `ns`'s trust context that the forger's key signs and
/// anchors, under the name `ns`'s root key has (`<ns>/KEY/ns`): a genesis the name does not hash.
fn forged_genesis(ns: &Name) -> Result<String, Failure> {
    let forged = |e: &dyn std::fmt::Display| Failure::new(format!("forging a genesis: {e}"));
    let mgr = SecurityManager::new();
    let key = mgr
        .generate_ed25519_from_seed(ns.clone().append("KEY").append("ns"), &FORGER_KEY)
        .map_err(|e| forged(&e))?;
    let signer = mgr.get_signer_sync(&key).map_err(|e| forged(&e))?;
    let public = signer
        .public_key()
        .ok_or_else(|| forged(&"an Ed25519 key without its public key"))?;
    let anchor = mgr
        .issue_self_signed(&key, public, DAY.as_millis() as u64)
        .map_err(|e| forged(&e))?;
    let ctx = SignedTrustContext::hierarchical(ns.clone()).with_version(1);
    ensure!(
        ctx.add_anchor(anchor),
        "the forger's anchor is not valid now"
    );
    let data = ctx
        .sign_into_data(signer.as_ref())
        .map_err(|e| forged(&e))?;
    Ok(TrustEnvelope::Anchor {
        namespace: Some(ns.to_string()),
        fingerprint: None,
        version: Some(1),
        context_data: Some(data.raw().clone()),
        context_content: None,
    }
    .to_uri())
}

/// `d` adopts `link`, which must succeed.
pub(super) async fn adopts(w: &World, d: Dev, link: &str, what: &str) -> Result<(), Failure> {
    w.adopt(d, link).await?.map_err(|why| {
        Failure::new(format!(
            "{} could not adopt {what}: {why}",
            w.net().spec(d).name()
        ))
    })
}

/// Whether `spaces` reads the octets of `text` at `path` of `space` now. A device that has not
/// received what it needs (the record, the keys) reads nothing yet.
pub(super) async fn reads(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
    text: &str,
) -> Result<bool, Failure> {
    match spaces.get(space, path).await {
        Ok(Some(read)) => Ok(read.bytes == Bytes::copy_from_slice(text.as_bytes())),
        Ok(None) => Ok(false),
        Err(e) if e.retry_later() || e.kind_is("Sealed") => Ok(false),
        Err(e) => Err(e),
    }
}

/// Whether `spaces` cannot read anything at `path` of `space` now: sealed to it, refused, or
/// nothing held.
pub(super) async fn shut_out(
    spaces: &dyn Spaces,
    space: &Name,
    path: &Name,
) -> Result<bool, Failure> {
    Ok(!matches!(spaces.get(space, path).await, Ok(Some(_))))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let alice_ns = w.net().spec(ALICE).person.clone();
        let bob_ns = w.net().spec(BOB).person.clone();
        let space = under(&alice_ns, "/32=data/notebook");
        let cover = n("/cover");
        let alice = w.spaces(ALICE);
        let bob = w.spaces(BOB);
        // Alice alone writes and reads her notebook.
        alice.create(&space, SpaceShare::default()).await?;
        alice.put(&space, &cover, octets("cover by alice")).await?;
        ensure!(
            shut_out(&*bob, &space, &cover).await?,
            "bob reads alice's notebook before adopting her name"
        );

        // A genesis for Bob's name that his key did not sign.
        let forged = w.adopt(ALICE, &forged_genesis(&bob_ns)?).await?;
        ensure!(
            forged.is_err(),
            "alice's device adopted a version 1 of {bob_ns} signed by a key the name does not \
             hash"
        );

        // Each adopts the other by name alone.
        let start = tokio::time::Instant::now();
        adopts(w, ALICE, &by_name(&bob_ns), "bob's namespace by its name").await?;
        let took = start.elapsed();
        w.measure("adoption by name alone", took.as_millis() as u64, "ms");
        adopts(w, BOB, &by_name(&alice_ns), "alice's namespace by its name").await?;

        // Alice adds Bob to the space as a writer and a reader.
        alice
            .change(
                &space,
                SpaceChange {
                    add_writers: vec![bob_ns.clone()],
                    add_readers: vec![bob_ns.clone()],
                    remove: Vec::new(),
                },
            )
            .await?;
        let start = tokio::time::Instant::now();
        w.retry_later(|| bob.open(&space)).await?;
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &space, &cover, "cover by alice")
        })
        .await?;
        let page = n("/page-bob");
        w.space_put(BOB, &space, &page, octets("a page by bob"))
            .await?;
        w.until("alice reads bob's page", LIMIT, || {
            reads(&*alice, &space, &page, "a page by bob")
        })
        .await?;
        w.converged(start.elapsed());
        Ok(())
    })
}
