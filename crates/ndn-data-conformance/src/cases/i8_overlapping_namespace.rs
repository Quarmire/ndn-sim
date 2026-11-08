//! Introductions, i8 — a joiner cannot claim a namespace overlapping one the inviter trusts.
//!
//! Alice keeps a notebook. Carol joins it by a first code, so Alice's device trusts `/carol`.
//! Mallory, a stranger whose namespace is `/carol/m` — a name under Carol's, where Carol's
//! devices' names live — gets Alice's second code and asks with it: refused as a conflict (fix
//! it locally: join from a namespace of your own), and she reads nothing. A stranger whose
//! namespace is the bare typed prefix `/user`, over every person's `/user/<hash>`, is refused
//! alike. The offer stays unspent: Bob, holding it, still joins. Guards the round-2 review's H1.

use std::time::Duration;

use ndn_data::{IntroRefusal, NextStep, Role};

use super::i1_join_by_code::{alice_keeps_a_notebook, joins, offer, reads, refused, shut_out};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, World};

pub(super) const CASE: Case = Case {
    id: "i8",
    title: "A joiner cannot claim a namespace overlapping one the inviter trusts",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "An ask whose namespace is under or over a namespace the inviter's device already \
             trusts, or a shared typed prefix, is refused as a conflict (next: fix locally), \
             grants no membership and no reading, and leaves the offer to its holder.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const ALICE: Dev = Dev(0);
const CAROL: Dev = Dev(1);
const MALLORY: Dev = Dev(2);
const SQUATTER: Dev = Dev(3);
const BOB: Dev = Dev(4);

const FOLDER: &str = super::i1_join_by_code::FOLDER;

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("carol", "phone");
    p.device("carol/m", "phone");
    p.device("user", "phone");
    p.device("bob", "phone");
    p.strangers();
    p
}

fn conflict(e: &DataError) -> bool {
    matches!(
        e,
        DataError::Introduction {
            why: IntroRefusal::Conflict,
            ..
        }
    ) && e.next() == NextStep::FixLocal
        && !e.retry()
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;
        let first = w.offer(ALICE, &folder, offer(w, Role::Reader, 3)).await?;
        joins(w, CAROL, &first.link).await?;

        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 3)).await?;
        let e = refused(w, MALLORY, &code.link).await?;
        ensure!(
            conflict(&e),
            "mallory (/carol/m, under /carol which alice trusts) asking answered {e:?}, not \
             'conflict: fix locally'"
        );
        let e = refused(w, SQUATTER, &code.link).await?;
        ensure!(
            conflict(&e),
            "a stranger claiming the bare /user prefix answered {e:?}, not 'conflict'"
        );
        w.sleep(SETTLE).await;
        for d in [MALLORY, SQUATTER] {
            ensure!(
                shut_out(&*w.at(d), &cover).await?,
                "{} reads alice's folder after a refused ask",
                w.net().spec(d).name()
            );
        }

        joins(w, BOB, &code.link).await?;
        let bob = w.at(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &cover, "cover by alice")
        })
        .await?;
        Ok(())
    })
}
