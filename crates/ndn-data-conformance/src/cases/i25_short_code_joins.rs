//! Introductions, i25 — a short code joins.
//!
//! Alice's laptop offers her notebook as a writer. The code's short form is one line of at most
//! 3 × 98 columns: the laptop's device name, the address its host gives as a first contact, and
//! twenty BIP39 words (the secret and the anchor's fingerprint, checksummed with the name and the
//! address). Bob's phone is given that line and nothing else. Its host dials the address once
//! with no key to expect (`Introducer::dial_first`: the code carries none), the hint record
//! `<laptop>/32=hint/<token>` is fetched and verified against the code, the laptop's key it names
//! is the one the dial proved (so no second dial), and Bob joins as a writer: each side then reads
//! what the other writes. A compact full link of a second offer joins Carol, a reader, with no
//! first contact and no hint record fetched (it dials by its own hint); the old twenty-four words
//! of a third offer join Dave with no dial at all and nothing fetched. The host's link layer is
//! the reference host's stand-in (192.0.2.x addresses; the world already routes by name), so what
//! is tested is the device's own logic: which dials it asks for, how often, and what it fetches.

use std::net::SocketAddr;
use std::time::Duration;

use ndn_data::intro::{Contact, ShortCode, hint_name, hint_token};
use ndn_data::{Code, Role};
use ndn_trust_envelope::TrustEnvelope;

use super::i1_join_by_code::{
    ALICE, BOB, CAROL, FOLDER, alice_keeps_a_notebook, joins, offer, reads, shut_out,
};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::provider::LinkCall;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i25",
    title: "A short code joins: one line, a first contact dialled once, a hint record fetched",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "An offer's short code is one line of at most 3 × 98 columns, made of the device's \
             name, one address and BIP39 words; a device given only that line dials the \
             address once with no key to expect, fetches and verifies the hint record, and \
             joins as the offer says; the compact full link joins with no first-contact dial \
             and no hint record, the old words with no dial at all.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

pub(super) const DAVE: Dev = Dev(3);

/// Alice's laptop and three strangers' phones. Names are counted to three components, so the
/// hint records (`/alice/laptop/32=hint/<token>`) each device receives can be told.
pub(super) fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "phone");
    p.device("dave", "phone");
    p.strangers();
    p.count_names(3);
    p
}

/// How many columns three lines of a code's width make.
pub(super) const SHORT_WIDTH: usize = 3 * 98;

/// What a joiner's host was asked of its link layer.
#[derive(Debug, Default)]
pub(super) struct Dials {
    /// Calls of `dial_first`, with the addresses.
    pub first: Vec<SocketAddr>,
    /// Calls of `dial`, with the addresses tried and the key to prove.
    pub dial: Vec<(Vec<SocketAddr>, [u8; 32])>,
    /// Calls of `undial`.
    pub undial: usize,
    /// The dials that were answered: each made a link.
    pub answered: usize,
}

impl Dials {
    /// The links the host still keeps for the introduction: every dial that was answered
    /// less every `undial`. A first contact replaced by a dial of the record's key is one
    /// link taken down and one made.
    pub fn kept(&self) -> i64 {
        self.answered as i64 - self.undial as i64
    }
}

/// What `d`'s host was asked of its link layer so far.
pub(super) async fn dials(w: &World, d: Dev) -> Result<Dials, Failure> {
    let mut out = Dials::default();
    for call in w.link_calls(d).await? {
        match call {
            LinkCall::DialFirst { addr, answered, .. } => {
                out.first.push(addr);
                out.answered += usize::from(answered);
            }
            LinkCall::Dial {
                candidates,
                key,
                answered,
                ..
            } => {
                out.dial.push((candidates, key));
                out.answered += usize::from(answered);
            }
            LinkCall::Undial { .. } => out.undial += 1,
        }
    }
    Ok(out)
}

/// The short line of `code`, read back: made, one line of at most [`SHORT_WIDTH`] columns,
/// the device name, one dialable address and twenty words; `Code::share` shows it.
pub(super) fn short_line(
    w: &World,
    code: &Code,
) -> Result<(String, ShortCode, SocketAddr), Failure> {
    let Some(short) = code.short.clone() else {
        return Err(Failure::new(format!(
            "the offer made no short code (why: {:?})",
            code.short_why
        )));
    };
    ensure!(
        code.short_why.is_none(),
        "the offer made a short code and also says why it made none: {:?}",
        code.short_why
    );
    ensure!(
        !short.contains(['\n', '\r']) && short.chars().count() <= SHORT_WIDTH,
        "the short code is {} columns, or more than one line, not at most {SHORT_WIDTH}: {short}",
        short.chars().count()
    );
    ensure!(
        code.share() == short,
        "Code::share shows {:?}, not the short code",
        code.share()
    );
    let laptop = w.net().spec(ALICE).name();
    let tokens: Vec<&str> = short.split_whitespace().collect();
    ensure!(
        tokens.len() == 22 && tokens[0] == laptop.to_string(),
        "the short code is not the device name, an address and twenty words: {short}"
    );
    let Ok(addr) = tokens[1].parse::<SocketAddr>() else {
        return Err(Failure::new(format!(
            "the second token of the short code is no address: {short}"
        )));
    };
    ensure!(
        tokens[2..]
            .iter()
            .all(|t| (3..=8).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_lowercase())),
        "the short code's words are not BIP39 words: {short}"
    );
    // Read as a device reads it: every word on the list, the checksum over the name and the
    // address matching.
    let read = ShortCode::parse(&short, false)
        .map_err(|e| Failure::new(format!("the short code does not read: {e}")))?;
    ensure!(
        read.device == laptop && read.contact == Some(Contact::Address(addr)),
        "the short code reads as {read:?}, not the laptop at {addr}"
    );
    Ok((short, read, addr))
}

/// How many hint records (`<device>/32=hint/…`) reached `d`'s links: the Data packets of the
/// hint name of `read`'s secret.
pub(super) fn hint_records_at(w: &World, d: Dev, device: &Name, secret: &[u8; 16]) -> u64 {
    w.net().received(d, &hint_name(device, &hint_token(secret)))
}

/// The secret of a compact full link.
fn secret_of(link: &str) -> Result<[u8; 16], Failure> {
    match TrustEnvelope::from_uri(link) {
        Ok(TrustEnvelope::Intro(intro)) => Ok(intro.secret),
        other => Err(Failure::new(format!(
            "an offer's link is not an introduction link: {other:?}"
        ))),
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        let laptop = w.net().spec(ALICE).name();
        let clean = w.net().faults().is_none();
        alice_keeps_a_notebook(w).await?;
        let alice_key = w.link_key(ALICE).await?;

        ensure!(
            shut_out(&*w.at(BOB), &cover).await?,
            "bob reads alice's folder before any introduction"
        );

        // The short code: one line, and all Bob is given.
        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        let (short, read, addr) = short_line(w, &code)?;
        ensure!(
            short.chars().count() < code.link.chars().count(),
            "the short code ({} columns) is not shorter than the full link ({})",
            short.chars().count(),
            code.link.chars().count()
        );
        ensure!(
            code.link.len() <= ndn_trust_envelope::qr::MAX_TEXT_LEN,
            "the code's link ({} characters) does not fit one QR",
            code.link.len()
        );
        w.measure(
            "compact full link",
            code.link.chars().count() as u64,
            "chars",
        );

        let start = tokio::time::Instant::now();
        let joined = joins(w, BOB, &short).await?;
        let took = start.elapsed();
        ensure!(
            joined.folder == folder && joined.role == Role::Writer && joined.inviter == n("/alice"),
            "bob's join says {joined:?}, not alice's notebook as a writer"
        );
        w.measure(
            "join by the short line, code to member",
            took.as_millis() as u64,
            "ms",
        );

        // The first contact was dialled once, the address the code names; the record's key is
        // the one that dial proved, so nothing was dialled again. A join asked again after a
        // lost exchange (a faulty network) dials again but takes the earlier link down first:
        // one link is kept.
        let bob_dials = dials(w, BOB).await?;
        ensure!(
            !bob_dials.first.is_empty() && bob_dials.first.iter().all(|a| *a == addr),
            "bob's host was asked to dial first at {:?}, not at the code's {addr}",
            bob_dials.first
        );
        ensure!(
            bob_dials.dial.is_empty(),
            "bob's host was asked to dial by a key as well: {:?}",
            bob_dials.dial
        );
        ensure!(
            bob_dials.kept() == 1,
            "bob's host keeps {} first-contact links ({} dials, {} taken down), not one",
            bob_dials.kept(),
            bob_dials.first.len(),
            bob_dials.undial
        );
        ensure!(
            !clean || (bob_dials.first.len() == 1 && bob_dials.undial == 0),
            "on a clean network bob's host was asked to dial first {} times and take {} down, \
             not once and none",
            bob_dials.first.len(),
            bob_dials.undial
        );
        // The hint record was fetched: it reached Bob (once, on a clean network).
        let records = hint_records_at(w, BOB, &laptop, &read.secret);
        ensure!(
            records >= 1 && (!clean || records == 1),
            "{records} hint records reached bob, not the one he fetched"
        );

        // Each reads what the other writes, with no further gesture.
        let bob = w.at(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &cover, "cover by alice")
        })
        .await?;
        let page = n(&format!("{FOLDER}/page-bob"));
        w.until("bob writes a page into the folder", LIMIT, || async {
            match bob.put(&page, text("a page by bob"), note(1)).await {
                Ok(_) => Ok(true),
                Err(DataError::NotReady { .. } | DataError::Unavailable { .. }) => Ok(false),
                Err(e) => Err(e.into()),
            }
        })
        .await?;
        let alice = w.at(ALICE);
        w.until("alice reads bob's page", LIMIT, || {
            reads(&*alice, &page, "a page by bob")
        })
        .await?;
        alice
            .put(&cover, text("cover, second by alice"), note(1))
            .await?;
        w.until("bob reads alice's second cover", LIMIT, || {
            reads(&*bob, &cover, "cover, second by alice")
        })
        .await?;

        // The compact full link of a second offer joins Carol, a reader: no first contact is
        // dialled and no hint record is fetched; the link's own hint is dialled, by the laptop's
        // key, at the address the short code named.
        let full = w.offer(ALICE, &folder, offer(w, Role::Reader, 3)).await?;
        let joined = joins(w, CAROL, &full.link).await?;
        ensure!(
            joined.folder == folder && joined.role == Role::Reader,
            "carol's join by the full link says {joined:?}, not the notebook as a reader"
        );
        let carol_dials = dials(w, CAROL).await?;
        ensure!(
            carol_dials.first.is_empty(),
            "carol's host dialled a first contact by a full link: {:?}",
            carol_dials.first
        );
        ensure!(
            !carol_dials.dial.is_empty()
                && carol_dials
                    .dial
                    .iter()
                    .all(|(c, key)| *c == [addr] && *key == alice_key)
                && carol_dials.kept() == 1,
            "carol's host was asked to dial {:?} ({} undialled), not alice's key at {addr} once \
             kept",
            carol_dials.dial,
            carol_dials.undial
        );
        let records = hint_records_at(w, CAROL, &laptop, &secret_of(&full.link)?);
        ensure!(
            records == 0,
            "{records} hint records reached carol, who joined by a full link and fetches none"
        );
        let carol = w.at(CAROL);
        w.until("carol reads alice's cover", LIMIT, || {
            reads(&*carol, &cover, "cover, second by alice")
        })
        .await?;

        // The old words of a third offer join Dave: no dial, nothing fetched.
        let words = w.offer(ALICE, &folder, offer(w, Role::Reader, 3)).await?;
        let joined = joins(w, DAVE, &words.words).await?;
        ensure!(
            joined.folder == folder && joined.role == Role::Reader,
            "dave's join by the words says {joined:?}, not the notebook as a reader"
        );
        let dave_calls = w.link_calls(DAVE).await?;
        ensure!(
            dave_calls.is_empty(),
            "dave's host was asked of its link layer by the words: {dave_calls:?}"
        );
        let records = hint_records_at(w, DAVE, &laptop, &secret_of(&words.link)?);
        ensure!(
            records == 0,
            "{records} hint records reached dave, who joined by the words and fetches none"
        );
        let dave = w.at(DAVE);
        w.until("dave reads alice's cover", LIMIT, || {
            reads(&*dave, &cover, "cover, second by alice")
        })
        .await?;
        w.converged(took);
        Ok(())
    })
}
