//! Keys over time 7 — the cut is bounded by the loss.
//!
//! Alice last had her phone in hand at a time she can name. Her phone wrote one more honest
//! entry after that, then the thief took it, key and storage, and wrote on with the key. Until
//! Alice reports the loss, the thief's entries verify, so her laptop — the namespace's root
//! device — and her tablet sync and keep them. A cut made of everything the root holds would
//! make the thief's entries valid forever (security review S5-01). The fix (M3, slice 5): Alice
//! says when she lost the phone; her laptop suspects the key from then on (takes nothing new of
//! it), and the cut keeps only what the laptop first verified before that time. What it left out
//! is listed, so she re-admits her honest entry exactly, one by one.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "k7",
    title: "Cut bounded by the loss",
    slice: 5,
    needs: &[
        Feature::Merge,
        Feature::Revocation,
        Feature::Readmit,
        Feature::RevocationRecheck,
        Feature::BoundedCut,
    ],
    model: &["M3"],
    guards: "A thief's writes between the theft and the owner's report stay out of the cut even \
             though the root held them: the cut keeps only what the root first verified before \
             the loss the owner states, so afterwards they are refused at every honest device \
             and withdrawn where held; the root takes nothing new of a suspected key; the honest \
             entries it first saw after the stated loss are listed and come back one by one.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const PHONE: Dev = Dev(0);
const LAPTOP: Dev = Dev(1);
const TABLET: Dev = Dev(2);
const DESKTOP: Dev = Dev(3);
const THIEF: Dev = Dev(4);

fn plan() -> Plan {
    let mut p = Plan::new();
    let phone = p.device("alice", "phone");
    p.device("alice", "laptop");
    p.device("alice", "tablet");
    p.device("alice", "desktop");
    p.thief(phone);
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let journal = n("/alice/32=data/journal");
        let (phone, laptop, tablet, desktop) =
            (w.at(PHONE), w.at(LAPTOP), w.at(TABLET), w.at(DESKTOP));
        w.net().offline(DESKTOP);
        laptop
            .share(&journal, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        w.until("the phone knows the shared journal", LIMIT, || {
            known(&*phone, &journal)
        })
        .await?;
        let early = phone
            .put(&journal, content(&[("monday", "market")]), note(1))
            .await?;
        w.until(
            "the laptop and the tablet hold the phone's entry",
            LIMIT,
            || async { agree(&[&*phone, &*laptop, &*tablet], &journal, &[&early]).await },
        )
        .await?;

        // The last time Alice had the phone in hand. It writes one more honest entry, which the
        // laptop first sees after that time; then the thief takes it.
        let lost = loss_time(w, LAPTOP).await;
        let late = phone
            .put(&journal, content(&[("tuesday", "dentist")]), note(1))
            .await?;
        w.until(
            "the laptop and the tablet hold the phone's later entry",
            LIMIT,
            || async { agree(&[&*phone, &*laptop, &*tablet], &journal, &[&early, &late]).await },
        )
        .await?;
        let thief = stolen(w, THIEF, &journal, &late).await?;
        w.net().offline(PHONE);
        let taken = thief
            .put(
                &journal,
                content(&[("thief", "written before the report")]),
                note(1),
            )
            .await?;
        ensure!(
            taken.writer == late.writer && taken.seq > late.seq,
            "precondition: the thief signs as the phone past its entries ({late:?}), got \
             {taken:?}"
        );
        w.until(
            "the laptop and the tablet hold the thief's version, the key not yet suspected",
            LIMIT,
            || async {
                Ok(has(&*laptop, &journal, &taken).await?
                    && has(&*tablet, &journal, &taken).await?)
            },
        )
        .await?;

        // Alice reports the loss, naming when she last had the phone: her laptop suspects the
        // key. The thief writes on.
        w.suspect(LAPTOP, PHONE, lost).await?;
        w.gesture();
        let after_report = thief
            .put(
                &journal,
                content(&[("thief2", "written after the report")]),
                note(1),
            )
            .await?;
        w.until("the tablet takes the thief's next version", LIMIT, || {
            has(&*tablet, &journal, &after_report)
        })
        .await?;
        let root_took_suspected = has(&*laptop, &journal, &after_report).await?;

        // She revokes the key with the cut bounded by the loss; the revocation reaches every
        // honest device.
        let mut tablets_feed = tablet.watch(&journal, &Frontier::new()).await?;
        let left_out = w.revoke(LAPTOP, PHONE, lost).await?;
        w.gesture();
        let mut seen = Vec::new();
        let took = drain_until(
            &mut tablets_feed,
            &mut seen,
            "the tablet withdraws the thief's version the root held before the report, once the \
             cut bounded by the loss arrives",
            LIMIT,
            |changes| withdrawn(changes, &taken),
        )
        .await?;
        w.converged(took);

        // The cut left out what the laptop first saw after the stated loss: the thief's version
        // and the phone's honest later entry. Alice re-admits the honest one, exactly.
        let honest = log_entry(w, PHONE, &journal, &late);
        let theirs = log_entry(w, PHONE, &journal, &taken);
        ensure!(
            full_name_of(&left_out, &theirs).is_some(),
            "the revocation did not list the thief's version {theirs} the laptop held but left \
             out of the cut (listed: {left_out:?})"
        );
        let honest_full = full_name_of(&left_out, &honest).cloned().ok_or_else(|| {
            Failure::new(format!(
                "the revocation did not list the phone's entry {honest}, which the laptop first \
                 verified after the stated loss, for re-admission (listed: {left_out:?})"
            ))
        })?;
        w.gesture();
        w.readmit_name(LAPTOP, &honest_full).await?;
        w.net().online(DESKTOP);
        w.converge(
            "every honest device holds both honest entries once one is re-admitted",
            LIMIT,
            || async { agree(&[&*laptop, &*tablet, &*desktop], &journal, &[&early, &late]).await },
        )
        .await?;
        w.sleep(SETTLE).await;

        for (who, layer) in [
            ("laptop", &laptop),
            ("tablet", &tablet),
            ("desktop", &desktop),
        ] {
            let looked = look(&**layer, &journal, &Frontier::new(), LOOK).await?;
            ensure!(
                !versions(&looked)
                    .any(|v| field_of(v, "thief").is_some() || field_of(v, "thief2").is_some()),
                "the {who} accepts a version the thief wrote with the key before or after the \
                 owner's report"
            );
            let s = state(&**layer, &journal).await?;
            ensure!(
                !s.at.contains(&taken) && !s.at.contains(&after_report),
                "the {who}'s journal includes a thief's version ({taken:?} or {after_report:?}) \
                 after the cut bounded by the loss"
            );
            ensure!(
                s.at.contains(&early)
                    && s.at.contains(&late)
                    && field(&s.value, "monday") == Some("market")
                    && field(&s.value, "tuesday") == Some("dentist"),
                "the {who} lacks an honest entry of the phone's: the one in the cut or the one \
                 re-admitted ({:?})",
                s.value
            );
        }
        ensure!(
            !root_took_suspected,
            "the laptop, suspecting the key since the stated loss, took the thief's version \
             written after the report"
        );
        Ok(())
    })
}
