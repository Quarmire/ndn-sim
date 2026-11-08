//! Introductions, i11 — a stranger cannot close someone else's offer, and a used offer counts no
//! tries.
//!
//! An offer's name is public: it is a record in Alice's log, served to anyone. Carol, who does
//! not hold the secret, asks with guessed ones until her tries are spent: she is refused for
//! good — but only she. Bob, holding the real code, still joins. Then on a second offer allowing
//! a single wrong try, Bob joins first and Carol asks with a guess: she is told the offer is
//! used, and nothing is counted — Bob, whose answer was lost, asking again is answered again.
//! Guards the round-2 review's M2.

use std::time::Duration;

use ndn_data::{IntroRefusal, Role};

use super::i1_join_by_code::{
    ALICE, BOB, CAROL, FOLDER, alice_keeps_a_notebook, forged, joins, offer, plan, reads, refused,
    shut_out,
};
use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::World;

pub(super) const CASE: Case = Case {
    id: "i11",
    title: "A stranger cannot close someone else's offer; a used offer counts no tries",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "Wrong tries are counted per asker: a stranger spending its own tries is refused for \
             good while the code's holder still joins; on a used offer a stranger's ask is \
             answered as used and counted nowhere, and the offer's user asking again is \
             answered again.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

fn refusal(e: &DataError) -> Option<&IntroRefusal> {
    match e {
        DataError::Introduction { why, .. } => Some(why),
        _ => None,
    }
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n(FOLDER);
        let cover = n(&format!("{FOLDER}/cover"));
        alice_keeps_a_notebook(w).await?;

        let code = w.offer(ALICE, &folder, offer(w, Role::Writer, 2)).await?;
        let mut last = None;
        for guess in [0xC1, 0xC2, 0xC3] {
            last = Some(refused(w, CAROL, &forged(&code, guess)).await?);
        }
        let e = last.expect("three guesses");
        ensure!(
            refusal(&e) == Some(&IntroRefusal::Closed),
            "carol's third guess, her tries spent, answered {e:?}, not 'closed'"
        );
        joins(w, BOB, &code.link).await?;
        let bob = w.at(BOB);
        w.until("bob reads alice's cover", LIMIT, || {
            reads(&*bob, &cover, "cover by alice")
        })
        .await?;

        let second = w.offer(ALICE, &folder, offer(w, Role::Writer, 1)).await?;
        joins(w, BOB, &second.link).await?;
        for guess in [0xD1, 0xD2] {
            let e = refused(w, CAROL, &forged(&second, guess)).await?;
            ensure!(
                refusal(&e) == Some(&IntroRefusal::Used),
                "carol's guess at a used offer answered {e:?}, not 'used'"
            );
        }
        let again = joins(w, BOB, &second.link).await?;
        ensure!(
            again.folder == folder,
            "bob asking again on his used offer was answered {again:?}"
        );
        w.sleep(SETTLE).await;
        ensure!(
            shut_out(&*w.at(CAROL), &cover).await?,
            "carol reads alice's folder after her refused asks"
        );
        Ok(())
    })
}
