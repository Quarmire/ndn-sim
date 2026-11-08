//! Introductions, i1 — a stranger joins a folder by a code, and each reads what the other writes.
//!
//! Alice keeps a notebook folder and wants Bob in it. They are strangers: neither node holds the
//! other's trust context. Alice's laptop makes a one-use offer of the folder as a writer and
//! shows the code; Bob's phone gets the code and nothing else. Bob joins; from then on each reads
//! what the other writes in the folder. Carol joins a second offer by its words, as a reader:
//! she reads, and her own write into the folder is refused. Mirrors ndf's "alice invites bob to
//! a note" (G1–G4). The kit the other introduction cases share lives here.

use std::time::Duration;

use ndn_data::{Code, Joined, Offer, Role};
use ndn_trust_envelope::TrustEnvelope;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i1",
    title: "A stranger joins a folder by a code; each reads what the other writes",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "Given only a code, a stranger becomes a member of the folder with the role the \
             offer names — no second gesture by the owner — and each side then reads what the \
             other writes; a reader joined by the code's words reads and may not write.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

pub(super) const ALICE: Dev = Dev(0);
pub(super) const BOB: Dev = Dev(1);
pub(super) const CAROL: Dev = Dev(2);

/// Alice's notebook folder.
pub(super) const FOLDER: &str = "/alice/32=data/notebook";

/// Alice's laptop, Bob's and Carol's phones: strangers to each other.
pub(super) fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("carol", "phone");
    p.strangers();
    p
}

/// Alice shares her folder with herself alone (a log of notes, sealed to her), and writes the
/// cover.
pub(super) async fn alice_keeps_a_notebook(w: &World) -> Result<(), Failure> {
    let alice = w.at(ALICE);
    alice
        .share_folder(
            &n(FOLDER),
            members(Rule::Log, &["/alice"], &[person("/alice")]).into(),
        )
        .await?;
    alice
        .put(
            &n(&format!("{FOLDER}/cover")),
            text("cover by alice"),
            note(1),
        )
        .await?;
    Ok(())
}

/// An offer of `role`, allowing `tries` wrong tries, expiring a day from now by Alice's clock.
pub(super) fn offer(w: &World, role: Role, tries: u32) -> Offer {
    Offer {
        role,
        until: Timestamp(w.net().date(ALICE).0 + DAY.as_millis() as u64),
        tries,
    }
}

/// `d` joins by `code`, which must succeed.
pub(super) async fn joins(w: &World, d: Dev, code: &str) -> Result<Joined, Failure> {
    w.join(d, code).await?.map_err(|e| {
        Failure::new(format!(
            "{} could not join by the code: {e} (next: {:?})",
            w.net().spec(d).name(),
            e.next()
        ))
    })
}

/// `d` joins by `code`, which must be refused: the refusal.
pub(super) async fn refused(w: &World, d: Dev, code: &str) -> Result<DataError, Failure> {
    match w.join(d, code).await? {
        Ok(j) => Err(Failure::new(format!(
            "{} joined {} by a code that must be refused",
            w.net().spec(d).name(),
            j.folder
        ))),
        Err(e) => Ok(e),
    }
}

/// `code`'s link with its secret replaced by `secret`: a code forged without the secret.
pub(super) fn forged(code: &Code, secret: u8) -> String {
    let Ok(TrustEnvelope::Intro(mut intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an offer's link is an introduction link");
    };
    intro.secret = [secret; ndn_trust_envelope::INTRO_SECRET_LEN];
    TrustEnvelope::Intro(intro).to_uri()
}

/// Whether `layer` reads `text` as the newest note of the log collection `c`.
pub(super) async fn reads(layer: &dyn DataLayer, c: &Name, text: &str) -> Result<bool, Failure> {
    match layer.get(c).await {
        Ok(Answer {
            got: Got::Version(v),
            ..
        }) => Ok(field_of(&v, "text") == Some(text)),
        Ok(_) => Ok(false),
        Err(
            DataError::Unavailable { .. }
            | DataError::NotFound { .. }
            | DataError::Sealed { .. }
            | DataError::NotReady { .. },
        ) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Whether `layer` cannot read `c` at all now: sealed to it, or nothing held.
pub(super) async fn shut_out(layer: &dyn DataLayer, c: &Name) -> Result<bool, Failure> {
    Ok(match layer.get(c).await {
        Ok(Answer {
            got: Got::Version(v),
            ..
        }) => field_of(&v, "text").is_none(),
        Ok(_) => true,
        Err(_) => true,
    })
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;

        // Bob is a stranger: he cannot read Alice's folder.
        ensure!(
            shut_out(&*w.at(BOB), &cover).await?,
            "bob reads alice's folder before any introduction"
        );

        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        ensure!(
            code.link.len() <= ndn_trust_envelope::qr::MAX_TEXT_LEN,
            "the code's link ({} characters) does not fit one QR",
            code.link.len()
        );
        let start = tokio::time::Instant::now();
        let joined = joins(w, BOB, &code.link).await?;
        let took = start.elapsed();
        ensure!(
            joined.folder == folder && joined.role == Role::Writer && joined.inviter == n("/alice"),
            "bob's join says {joined:?}, not alice's notebook as a writer"
        );
        w.measure("join, code to member", took.as_millis() as u64, "ms");

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

        // Carol joins a second offer by its words, as a reader.
        let words = w.offer(ALICE, &folder, offer(w, Role::Reader, 3)).await?;
        let joined = joins(w, CAROL, &words.words).await?;
        ensure!(
            joined.role == Role::Reader,
            "carol joined as {:?}, not as a reader",
            joined.role
        );
        let carol = w.at(CAROL);
        w.until("carol reads alice's cover", LIMIT, || {
            reads(&*carol, &cover, "cover, second by alice")
        })
        .await?;
        let mine = n(&format!("{FOLDER}/page-carol"));
        let refusal = carol.put(&mine, text("a page by carol"), note(1)).await;
        ensure!(
            matches!(refusal, Err(DataError::NotAllowed { .. })),
            "carol, a reader, wrote into the folder: {refusal:?}"
        );
        w.converged(took);
        Ok(())
    })
}
