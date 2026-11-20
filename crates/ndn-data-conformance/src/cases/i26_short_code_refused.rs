//! Introductions, i26 — a short code is refused, saying why, and nothing is joined.
//!
//! Alice's laptop offers her notebook; Bob's phone holds only short lines. A line mistyped in
//! one word, in the device's name or in the address's port is refused before anything is dialled
//! or sent, with the checksum's text and the next step a bad request has (fix it); so are a
//! line of nineteen or twenty-one words and one whose word is not on the list, each with its own
//! text. A line that reads but names an offer the laptop never made, or an address nobody
//! answers at, is refused as not ready (retry later) with the text of the step that failed, and
//! the first-contact link it made is taken down. A hint record altered at the first contact
//! (whoever answers at the address serves Bob's node the record with its last signature octet
//! flipped) is refused as a record that does not prove the inviter's (ask for a new code). A closed offer
//! is answered by a signed gone mark, and Bob is told it is closed; an expired offer, that it
//! expired; the laptop offline, that he should retry later. After all of them Bob is a member of
//! nothing, the laptop was told of no grant, and no first-contact link of his host stays up;
//! the offer that waited while the laptop was offline then admits him.
//!
//! The case could not be made for a hint record that names another offer: only the inviter's key
//! can sign one, and a node on the way can only alter or replay a packet it has seen. The
//! device's own tests make the inviter lie.

use std::time::Duration;

use ndn_data::intro::{Contact, ShortCode, ShortError};
use ndn_data::{IntroRefusal, NextStep, Offer, Role};

use super::i1_join_by_code::{
    ALICE, BOB, FOLDER, alice_keeps_a_notebook, joins, offer, reads, refused, shut_out,
};
use super::i25_short_code_joins::{dials, short_line};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Plan, World};

pub(super) const CASE: Case = Case {
    id: "i26",
    title: "A short code is refused, saying why: a typo, a wrong count, a closed, expired or \
            unanswered offer, an altered record",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A short code that does not read (a mistyped word, name or port; a wrong count; a \
             word off the list) is refused with the checksum's or the count's text and next \
             step fix-the-request before anything is dialled or sent; a code the laptop does \
             not know, an address nobody answers at and a laptop offline are not ready, retry \
             later; a hint record altered on its way is refused as not the inviter's; a closed \
             or expired offer is told closed or expired; every refusal leaves the joiner a \
             member of nothing and no first-contact link up, and the offer that waited admits \
             him.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

/// Alice's laptop and Bob's phone: strangers to each other.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.strangers();
    p
}

/// What Bob's host and wire did: nothing at all.
async fn nothing_sent(
    w: &World,
    before: crate::world::DeviceWire,
    what: &str,
) -> Result<(), Failure> {
    let after = w.net().device_wire(BOB);
    ensure!(
        after.interests == before.interests && after.data == before.data,
        "bob's phone sent packets onto its links ({} Interests, {} Data more) for {what}",
        after.interests - before.interests,
        after.data - before.data
    );
    let d = dials(w, BOB).await?;
    ensure!(
        d.first.is_empty() && d.dial.is_empty() && d.undial == 0,
        "bob's host was asked to dial for {what}: {d:?}"
    );
    Ok(())
}

/// `line` is refused as a bad request with `expected`'s text, before anything is dialled or sent.
async fn does_not_read(
    w: &World,
    line: &str,
    expected: ShortError,
    what: &str,
) -> Result<(), Failure> {
    let before = w.net().device_wire(BOB);
    let e = refused(w, BOB, line).await?;
    ensure!(
        matches!(&e, DataError::BadRequest { why, .. } if *why == expected.to_string())
            && e.next() == NextStep::FixRequest
            && !e.retry(),
        "bob's join by {what} answered {e:?} (next: {:?}), not the bad request {:?} (next: fix \
         the request)",
        e.next(),
        expected.to_string()
    );
    nothing_sent(w, before, what).await
}

/// `line` is refused as not ready, retry later, with a text that starts with `text`, and the
/// links the host made for it are taken down.
async fn not_ready(w: &World, line: &str, text: &str, what: &str) -> Result<(), Failure> {
    let e = refused(w, BOB, line).await?;
    ensure!(
        matches!(&e, DataError::NotReady { why, .. } if why.starts_with(text))
            && e.retry()
            && e.next() == NextStep::RetryLater,
        "bob's join by {what} answered {e:?}, not 'not ready: retry' saying {text:?}"
    );
    no_link_kept(w, what).await
}

/// Bob's host keeps no link a join of his made.
async fn no_link_kept(w: &World, what: &str) -> Result<(), Failure> {
    let d = dials(w, BOB).await?;
    ensure!(
        d.kept() == 0,
        "after {what} bob's host keeps {} links ({d:?})",
        d.kept()
    );
    Ok(())
}

/// `line` is refused by the inviter's own answer, as `why`, next step ask the inviter, and the
/// links the host made for it are taken down.
async fn told(w: &World, line: &str, why: IntroRefusal, what: &str) -> Result<(), Failure> {
    let e = refused(w, BOB, line).await?;
    ensure!(
        matches!(&e, DataError::Introduction { why: got, .. } if *got == why)
            && e.next() == NextStep::AskOwner
            && !e.retry(),
        "bob's join by {what} answered {e:?}, not '{why}' (next: ask the inviter)"
    );
    no_link_kept(w, what).await
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        let laptop = w.net().spec(ALICE).name();
        alice_keeps_a_notebook(w).await?;

        // Typos: a line that does not read is refused before anything is dialled or sent.
        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        let (short, read, addr) = short_line(w, &code)?;
        let tokens: Vec<&str> = short.split_whitespace().collect();
        let words = &tokens[2..];
        let other = words
            .iter()
            .find(|word| **word != words[3])
            .copied()
            .ok_or_else(|| Failure::new("a short code of one word repeated"))?;
        let with_word = |i: usize, word: &str| {
            let mut changed: Vec<&str> = tokens.clone();
            changed[2 + i] = word;
            changed.join(" ")
        };
        let checksum = ShortError::Checksum;
        does_not_read(
            w,
            &with_word(3, other),
            checksum.clone(),
            "one word changed",
        )
        .await?;
        does_not_read(
            w,
            &short.replacen(&laptop.to_string(), "/alice/laptoq", 1),
            checksum.clone(),
            "the device's name changed by a letter",
        )
        .await?;
        does_not_read(
            w,
            &short.replacen(
                &addr.to_string(),
                &format!("{}:{}", addr.ip(), addr.port() + 1),
                1,
            ),
            checksum,
            "the address's port changed",
        )
        .await?;
        does_not_read(
            w,
            &with_word(3, "zzzz"),
            ShortError::UnknownWord(4),
            "a word that is on no list",
        )
        .await?;
        does_not_read(
            w,
            &tokens[..tokens.len() - 1].join(" "),
            ShortError::Words(19),
            "nineteen words",
        )
        .await?;
        does_not_read(
            w,
            &format!("{short} {}", words[0]),
            ShortError::Words(21),
            "twenty-one words",
        )
        .await?;

        // A line that reads, of an offer the laptop never made: its token is no token it
        // holds, so nothing answers, and the first contact's link is taken down.
        let stranger = ShortCode {
            secret: [0x5a; 16],
            ..read.clone()
        }
        .encode()
        .map_err(|e| Failure::new(format!("a short code could not be written: {e}")))?;
        not_ready(
            w,
            &stranger,
            "the inviter's hint for this offer was not fetched from the first contact",
            "a code of an offer the laptop never made",
        )
        .await?;
        // An address nobody answers at: the dial fails and no offer is touched.
        let nowhere = ShortCode {
            contact: Some(Contact::Address(
                "192.0.2.200:4433".parse().expect("an address"),
            )),
            ..read.clone()
        }
        .encode()
        .map_err(|e| Failure::new(format!("a short code could not be written: {e}")))?;
        not_ready(
            w,
            &nowhere,
            "the first contact 192.0.2.200:4433 did not answer",
            "a first contact nobody answers at",
        )
        .await?;

        // A hint record altered at the first contact: whoever answers at the address serves
        // what it likes. Bob's own node answers the record's name with the record it fetched
        // from the laptop, its signature's last octet flipped.
        let altered = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        let (altered_line, altered_read, _) = short_line(w, &altered)?;
        let record =
            ndn_data::intro::hint_name(&laptop, &ndn_data::intro::hint_token(&altered_read.secret));
        w.replay_altered(BOB, &record).await?;
        // Let the altered copy and any duplicated or held-back copies of the genuine record
        // reach Bob's node before he joins, as the other cases settle after an act of the wire.
        w.sleep(SETTLE).await;
        let e = refused(w, BOB, &altered_line).await?;
        ensure!(
            matches!(
                &e,
                DataError::Introduction {
                    why: IntroRefusal::Hint { why },
                    ..
                } if why.starts_with("signer:")
            ) && e.next() == NextStep::RetryLater
                && e.to_string()
                    .contains("retry at most 3 times; if it is refused every time, do not use"),
            "bob's join by a code whose hint record was altered answered {e:?} (next: {:?}), not \
             'what answered does not prove the inviter's (signer): retry at most 3 times, and if \
             refused every time do not use this code'",
            e.next()
        );
        no_link_kept(w, "an altered hint record").await?;

        // A closed offer is told closed: the laptop answers its token with a signed gone mark.
        let closed = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        let (closed_line, _, _) = short_line(w, &closed)?;
        w.close_offer(ALICE, &closed.offer).await?;
        told(w, &closed_line, IntroRefusal::Closed, "a closed offer").await?;

        // An expired offer is told expired.
        let short_lived = Offer {
            role: Role::Writer,
            until: Timestamp(w.net().date(ALICE).0 + 10 * 60 * 1000),
            tries: 3,
        };
        let expiring = w.offer(ALICE, &folder, short_lived).await?;
        let (expiring_line, _, _) = short_line(w, &expiring)?;
        w.sleep(Duration::from_secs(30 * 60)).await;
        told(w, &expiring_line, IntroRefusal::Expired, "an expired offer").await?;

        // None of it joined anything, told the laptop of a grant, or left a link up.
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*w.at(BOB), &cover).await?,
            "bob reads alice's folder after refused joins"
        );
        let joined = w.joined_folders(BOB).await?;
        ensure!(
            joined.folders.is_empty(),
            "bob's layer lists {:?} as joined after refused joins",
            joined.folders
        );
        ensure!(
            w.link_grants(ALICE).await?.told.is_empty(),
            "alice's host was told of a grant after refused joins"
        );
        no_link_kept(w, "all of them").await?;

        // The laptop offline: retry later. The offer waits, and the same line admits him
        // once the laptop is back.
        let waiting = w.offer(ALICE, &folder, offer(w, Role::Writer, 1)).await?;
        let (waiting_line, _, _) = short_line(w, &waiting)?;
        w.net().offline(ALICE);
        let e = refused(w, BOB, &waiting_line).await?;
        w.net().online(ALICE);
        ensure!(
            matches!(&e, DataError::NotReady { why, .. }
                if why.starts_with("the inviter's hint for this offer was not fetched from the first contact"))
                && e.retry()
                && e.next() == NextStep::RetryLater,
            "bob's join while alice's laptop is offline answered {e:?}, not 'not ready: retry'"
        );
        no_link_kept(w, "the laptop offline").await?;
        let joined = joins(w, BOB, &waiting_line).await?;
        ensure!(joined.folder == folder, "bob joined {joined:?}");
        let bob = w.at(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &cover, "cover by alice")
        })
        .await?;
        Ok(())
    })
}
