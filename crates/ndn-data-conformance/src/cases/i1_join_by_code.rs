//! Introductions, i1 — a stranger joins a folder by a code, and each reads what the other writes.
//!
//! Alice keeps a notebook folder and wants Bob in it. They are strangers: neither node holds the
//! other's trust context. Alice's laptop makes a one-use offer of the folder as a writer and
//! shows the code; Bob's phone gets the code and nothing else. Bob joins; from then on each reads
//! what the other writes in the folder. Carol joins a second offer by its words, as a reader:
//! she reads, and her own write into the folder is refused. Mirrors ndf's "alice invites bob to
//! a note" (G1–G4). The kit the other introduction cases share lives here.
//!
//! Written over the neutral [`Spaces`](crate::spaces::Spaces) surface and the neutral
//! introduction verbs of [`crate::invite`]: the folder is a space and each note a path in it, a
//! reading is the newest bytes at a path.

use std::time::Duration;

use ndn_data::Name;
use ndn_trust_envelope::TrustEnvelope;

use super::kit::{DAY, LIMIT, n, octets, private};
pub(super) use super::n1_named_by_key::{reads, shut_out};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{InviteCode, InviteFailure, InviteJoined, InviteOffer, InviteRole};
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

/// Alice shares her folder with herself alone (notes, sealed to her), and writes the cover.
pub(super) async fn alice_keeps_a_notebook(w: &World) -> Result<(), Failure> {
    let alice = w.spaces(ALICE);
    alice.create(&n(FOLDER), private(&[], &[])).await?;
    alice
        .put(&n(FOLDER), &n("/cover"), octets("cover by alice"))
        .await?;
    Ok(())
}

/// An offer of `role`, allowing `tries` wrong tries, expiring a day from now by Alice's clock.
pub(super) fn offer(w: &World, role: InviteRole, tries: u32) -> InviteOffer {
    InviteOffer {
        role,
        until: w.net().date(ALICE).0 + DAY.as_millis() as u64,
        tries,
    }
}

/// `d` joins by `code`, which must succeed: joining again while the refusal says retry later
/// ([`World::join_again`]).
pub(super) async fn joins(w: &World, d: Dev, code: &str) -> Result<InviteJoined, Failure> {
    w.join_again(d, code).await?.map_err(|e| {
        Failure::new(format!(
            "{} could not join by the code: {e} (next: {})",
            w.net().spec(d).name(),
            e.next
        ))
    })
}

/// `d` joins by `code`, which must be refused: the refusal. A refusal whose
/// next step is `RetryLater` (the inviter's device not reached: on a faulty
/// network an ask, or every answer to it, lost) is asked again as a host
/// does ([`World::join_again`]), so the refusal judged is the inviter's
/// own, never a lost exchange's — a join refused while the inviter is
/// offline still ends `NotReady` once the host stops asking.
pub(super) async fn refused(w: &World, d: Dev, code: &str) -> Result<InviteFailure, Failure> {
    match w.join_again(d, code).await? {
        Ok(j) => Err(Failure::new(format!(
            "{} joined {} by a code that must be refused",
            w.net().spec(d).name(),
            j.space
        ))),
        Err(e) => Ok(e),
    }
}

/// `d` writes `words` at `path` of `space`, once its device can: it may first wait for the
/// folder's record and the epoch's key (`"RetryLater"`).
pub(super) async fn writes(
    w: &World,
    d: Dev,
    space: &Name,
    path: &Name,
    words: &str,
) -> Result<(), Failure> {
    let spaces = w.spaces(d);
    w.until(
        &format!("{} writes {path} into the folder", w.net().spec(d).name()),
        LIMIT,
        || async {
            match spaces.put(space, path, octets(words)).await {
                Ok(_) => Ok(true),
                Err(e) if e.retry_later() => Ok(false),
                Err(e) => Err(e),
            }
        },
    )
    .await
    .map(|_| ())
}

/// `code`'s link with its secret replaced by `secret`: a code forged without the secret.
pub(super) fn forged(code: &InviteCode, secret: u8) -> String {
    let Ok(TrustEnvelope::Intro(mut intro)) = TrustEnvelope::from_uri(&code.link) else {
        panic!("an offer's link is an introduction link");
    };
    intro.secret = [secret; ndn_trust_envelope::INTRO_SECRET_LEN];
    TrustEnvelope::Intro(intro).to_uri()
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = n(FOLDER);
        let cover = n("/cover");
        alice_keeps_a_notebook(w).await?;

        // Bob is a stranger: he cannot read Alice's folder.
        ensure!(
            shut_out(&*w.spaces(BOB), &space, &cover).await?,
            "bob reads alice's folder before any introduction"
        );

        let code = w
            .offer(ALICE, &space, offer(w, InviteRole::Writer, 3))
            .await?;
        ensure!(
            code.link.len() <= ndn_trust_envelope::qr::MAX_TEXT_LEN,
            "the code's link ({} characters) does not fit one QR",
            code.link.len()
        );
        let start = tokio::time::Instant::now();
        let joined = joins(w, BOB, &code.link).await?;
        let took = start.elapsed();
        ensure!(
            joined.space == space
                && joined.role == InviteRole::Writer
                && joined.inviter == n("/alice"),
            "bob's join says {joined:?}, not alice's notebook as a writer"
        );
        w.measure("join, code to member", took.as_millis() as u64, "ms");

        // Each reads what the other writes, with no further gesture.
        let bob = w.spaces(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &space, &cover, "cover by alice")
        })
        .await?;
        let page = n("/page-bob");
        writes(w, BOB, &space, &page, "a page by bob").await?;
        let alice = w.spaces(ALICE);
        w.until("alice reads bob's page", LIMIT, || {
            reads(&*alice, &space, &page, "a page by bob")
        })
        .await?;
        alice
            .put(&space, &cover, octets("cover, second by alice"))
            .await?;
        w.until("bob reads alice's second cover", LIMIT, || {
            reads(&*bob, &space, &cover, "cover, second by alice")
        })
        .await?;

        // Carol joins a second offer by its words, as a reader.
        let words = w
            .offer(ALICE, &space, offer(w, InviteRole::Reader, 3))
            .await?;
        let joined = joins(w, CAROL, &words.words).await?;
        ensure!(
            joined.role == InviteRole::Reader,
            "carol joined as {:?}, not as a reader",
            joined.role
        );
        let carol = w.spaces(CAROL);
        w.until("carol reads alice's cover", LIMIT, || {
            reads(&*carol, &space, &cover, "cover, second by alice")
        })
        .await?;
        let refusal = carol
            .put(&space, &n("/page-carol"), octets("a page by carol"))
            .await;
        ensure!(
            matches!(&refusal, Err(e) if e.kind_is("NotAllowed")),
            "carol, a reader, wrote into the folder: {refusal:?}"
        );
        w.converged(took);
        Ok(())
    })
}
