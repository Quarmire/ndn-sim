//! Introductions, i23 — the joiner holds a grant for the inviter, re-derived from the record.
//!
//! Alice's laptop offers her notebook and, by a second code, her diary to Bob, both as writers; Bob
//! joins both. A grant is built at both ends: Bob's host is told of one grant for Alice's key per
//! folder (`Introducer::grant`: her namespace, the folder, and her role as the members record
//! gives it — a writer, as it lists her namespace), `Device::grants` lists them, and no
//! departure is ever made for them (the person let go is told by the inviter; a mirror admits the
//! inviter's own link). A record that leaves Bob out of the notebook, which his device takes as
//! `i19` and `i21` do, tells it `Introducer::revoke_grant` with Alice's key and the notebook,
//! once; `Device::grants` lists the diary's grant alone, and still no departure. After a restart
//! of Bob's device the entries are the same set less the ended, and the host is told nothing but
//! the entries in force (it may be told them again). A
//! second join of the notebook — Alice invites him again — makes the entry again (round 9: the
//! mirror grant, spec data-layer §19.8).

use std::time::Duration;

use super::i1_join_by_code::{
    FOLDER, alice_keeps_a_notebook, joins, offer, reads, restarted_told, writes,
};
use super::kit::{LIMIT, SETTLE, n, private};
use crate::case::{Case, CaseFuture, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::invite::{GrantEvent, GrantLog, InviteGrant, InviteRole};
use crate::spaces::SpaceChange;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "i23",
    title: "The joiner holds a grant for the inviter, told once and re-derived from the record",
    slice: 6,
    needs: &[
        Feature::Log,
        Feature::Seal,
        Feature::FolderMembers,
        Feature::Introduction,
    ],
    model: &[],
    guards: "A join tells the joiner's host exactly one grant for the inviter's key, her \
             namespace, the folder and her role as the record gives it, and never a departure; \
             Device::grants lists it; a record that leaves the joiner out tells revoke_grant \
             once and Device::grants drops it; a restart keeps the rest and tells nothing but \
             what is in force; a second join of the folder makes the entry again; clean or \
             faulty.",
    budget: Duration::from_secs(4 * 3600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const BOB: Dev = Dev(1);
const PHONE: Dev = Dev(2);

/// Alice's second folder.
const DIARY: &str = "/alice/32=data/diary";

/// Not among strangers, as i16: the nodes hold each other's trust contexts, so Alice's phone
/// reads what Bob writes.
fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("bob", "phone");
    p.device("alice", "phone");
    p
}

/// Whether `a` and `b` hold the same grants, in any order.
pub(super) fn same_set(a: &[InviteGrant], b: &[InviteGrant]) -> bool {
    a.len() == b.len() && a.iter().all(|g| b.contains(g))
}

/// A mirror makes no departure: nothing told, nothing listed.
pub(super) fn no_departure(log: &GrantLog, when: &str) -> Result<(), Failure> {
    ensure!(
        !log.told
            .iter()
            .any(|e| matches!(e, GrantEvent::Departed(_)))
            && log.departures.is_empty(),
        "{when}: bob's host was told {:?} and his layer lists the departures {:?}; a mirror \
         grant never makes a departure (the person let go is told by the inviter)",
        log.told,
        log.departures
    );
    Ok(())
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let (notebook, diary) = (n(FOLDER), n(DIARY));
        alice_keeps_a_notebook(w).await?;
        w.spaces(LAPTOP).create(&diary, private(&[], &[])).await?;
        let alices_key = w.link_key(LAPTOP).await?;
        let bobs_key = w.link_key(BOB).await?;
        let none = w.link_grants(BOB).await?;
        ensure!(
            none.told.is_empty() && none.now.is_empty(),
            "bob's host was told {:?} and his layer lists {:?} before he joined anything",
            none.told,
            none.now
        );

        // Bob joins the notebook: his host is told of exactly one grant, for Alice's key.
        let for_notebook = w
            .offer(LAPTOP, &notebook, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, BOB, &for_notebook.link).await?;
        let joined = w.link_grants(BOB).await?;
        let [GrantEvent::Granted(of_notebook)] = joined.told.as_slice() else {
            return Err(Failure::new(format!(
                "bob's host was told {:?} after he joined the notebook; it must be told of \
                 exactly one grant, for the inviter's key",
                joined.told
            )));
        };
        ensure!(
            of_notebook.key == alices_key
                && of_notebook.namespaces == [n("/alice")]
                && of_notebook.space == notebook
                && of_notebook.role == InviteRole::Writer
                && of_notebook.until.is_none(),
            "the grant bob's host was told of is {of_notebook:?}; it must name alice's key \
             {alices_key:02x?}, /alice, the notebook, alice's role in the record (a writer) and \
             no date (the entry follows the record)"
        );
        ensure!(
            joined.now == [of_notebook.clone()],
            "after the join Device::grants lists {:?}, not the grant bob's host was told of",
            joined.now
        );
        no_departure(&joined, "after bob joined the notebook")?;

        // The diary, by a second code: a second entry, a folder of its own.
        let for_diary = w
            .offer(LAPTOP, &diary, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, BOB, &for_diary.link).await?;
        let both = w.link_grants(BOB).await?;
        let [first, GrantEvent::Granted(of_diary)] = both.told.as_slice() else {
            return Err(Failure::new(format!(
                "bob's host was told {:?} after he joined the diary; it must be told of the \
                 notebook's grant and then the diary's",
                both.told
            )));
        };
        ensure!(
            *first == GrantEvent::Granted(of_notebook.clone())
                && of_diary.key == alices_key
                && of_diary.space == diary
                && of_diary.role == InviteRole::Writer
                && same_set(&both.now, &[of_notebook.clone(), of_diary.clone()]),
            "bob's host was told {:?} and Device::grants lists {:?}; the two folders are two \
             entries of alice's key, the second the diary's",
            both.told,
            both.now
        );

        // Bob writes a page into each; Alice's phone reads both, so it holds the records that
        // admit him.
        let phone = w.spaces(PHONE);
        let at = n("/page");
        for (space, who) in [(&notebook, "notebook"), (&diary, "diary")] {
            let words = format!("a page by bob in the {who}");
            writes(w, BOB, space, &at, &words).await?;
            w.until(
                &format!("alice's phone reads bob's page of the {who}"),
                LIMIT,
                || reads(&*phone, space, &at, &words),
            )
            .await?;
        }

        // A record from the phone leaves Bob out of the notebook. Alice's laptop is told he was
        // let go; his device takes the record that lets him go, as a host does (i19, i21).
        phone
            .change(
                &notebook,
                SpaceChange {
                    remove: vec![n("/bob")],
                    ..SpaceChange::default()
                },
            )
            .await?;
        w.until("alice's laptop ends bob's grant", LIMIT, || async {
            Ok(w.link_grants(LAPTOP).await?.told.iter().any(|e| {
                matches!(e, GrantEvent::Revoked { key, space }
                    if *key == bobs_key && *space == notebook)
            }))
        })
        .await?;
        let laptop = w.link_grants(LAPTOP).await?;
        let Some(GrantEvent::Departed(left)) = laptop
            .told
            .iter()
            .find(|e| matches!(e, GrantEvent::Departed(_)))
        else {
            return Err(Failure::new(format!(
                "alice's host was told {:?}; a record that lets bob go must tell it of his \
                 departure, naming the record",
                laptop.told
            )));
        };
        w.until(
            "bob's device takes the record that lets him go",
            LIMIT,
            || async {
                match w
                    .take_departure(BOB, LAPTOP, &notebook, &left.record)
                    .await?
                {
                    Ok(()) => Ok(true),
                    Err(e) if e.retry_later() => Ok(false),
                    Err(e) => Err(e.into()),
                }
            },
        )
        .await?;
        w.until(
            "bob's host is told alice's grant of the notebook ended",
            LIMIT,
            || async {
                Ok(w.link_grants(BOB).await?.told.iter().any(|e| {
                    matches!(e, GrantEvent::Revoked { key, space }
                        if *key == alices_key && *space == notebook)
                }))
            },
        )
        .await?;
        w.sleep(SETTLE).await;
        let ended = w.link_grants(BOB).await?;
        ensure!(
            ended.told
                == [
                    GrantEvent::Granted(of_notebook.clone()),
                    GrantEvent::Granted(of_diary.clone()),
                    GrantEvent::Revoked {
                        key: alices_key,
                        space: notebook.clone(),
                    },
                ],
            "after the record that leaves bob out bob's host was told {:?}; expected the two \
             grants, then once that alice's grant of the notebook ended, naming her key and the \
             notebook",
            ended.told
        );
        ensure!(
            ended.now == [of_diary.clone()],
            "after the record that leaves bob out Device::grants lists {:?}, not the diary's \
             grant alone",
            ended.now
        );
        no_departure(&ended, "after the record that leaves bob out")?;
        let listed = w.joined_folders(BOB).await?;
        ensure!(
            listed.spaces.len() == 1 && listed.spaces[0].space == diary,
            "after the record that leaves bob out of the notebook his device lists {:?} as \
             joined; expected the diary alone",
            listed.spaces
        );

        // A restart of Bob's device: the same entries less the ended, and the host told nothing
        // but the entries in force (it may be told them again).
        w.stop(BOB).await?;
        w.restart(BOB).await?;
        let restarted = w.link_grants(BOB).await?;
        restarted_told(&ended, &restarted)?;

        // Invited again: a new offer, joined again, makes the notebook's entry again.
        let again = w
            .offer(LAPTOP, &notebook, offer(w, InviteRole::Writer, 3))
            .await?;
        joins(w, BOB, &again.link).await?;
        let rejoined = w.link_grants(BOB).await?;
        let told = restarted.told.len();
        ensure!(
            rejoined.told.len() == told + 1 && rejoined.told[..told] == restarted.told[..],
            "bob joined the notebook again and his host was told {:?}; expected what it was told \
             before, then one grant",
            rejoined.told
        );
        let GrantEvent::Granted(remade) = &rejoined.told[told] else {
            return Err(Failure::new(format!(
                "bob joined the notebook again and his host was told {:?} last; it must be told \
                 the grant",
                rejoined.told[told]
            )));
        };
        ensure!(
            remade.key == alices_key
                && remade.space == notebook
                && remade.namespaces == [n("/alice")]
                && remade.role == InviteRole::Writer
                && remade.until.is_none()
                && same_set(&rejoined.now, &[remade.clone(), of_diary.clone()]),
            "after bob joined the notebook again the grant is {remade:?} and Device::grants lists \
             {:?}; the entry must be made again for alice's key and the notebook, beside the \
             diary's",
            rejoined.now
        );
        no_departure(&rejoined, "after bob joined the notebook again")?;
        Ok(())
    })
}
