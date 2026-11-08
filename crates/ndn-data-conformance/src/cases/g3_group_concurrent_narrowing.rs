//! Slice 6, g3 — a group is judged alike on every reader while a member's collection narrows.
//!
//! Alice's trip folder is shared with Bob by one folder record; Bob writes a group across two of
//! its collections. At the same time Alice's phone, offline and unaware of the group, narrows one
//! of the two collections to Alice alone. Her laptop saw the group first; Carol, away, receives
//! the group and the narrowing together; the phone receives the group after its own narrowing.
//! Whatever each saw first, every reader must end with the same verdict on the group — here
//! refused, since its member in the narrowed collection lies outside the cut at what the phone
//! had seen of Bob — and the same state of both collections.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::element::Edit;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "g3",
    title: "A group is judged alike on every reader while a member's collection narrows",
    slice: 6,
    needs: &[
        Feature::Merge,
        Feature::RemovalCut,
        Feature::AppOps,
        Feature::Groups,
        Feature::FolderMembers,
    ],
    model: &["M14"],
    guards: "Readers that received a group and a concurrent narrowing of one member's collection \
             in different orders reach the same verdict on the group (no member counted \
             anywhere) and the same state of every member collection.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const BOB: Dev = Dev(2);
const CAROL: Dev = Dev(3);
const READERS: [(&str, Dev); 3] = [("laptop", LAPTOP), ("phone", PHONE), ("Carol", CAROL)];

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("bob", "laptop");
    p.device("carol", "laptop");
    p
}

/// Whether every reader holds the same state of `c` — frontier, value and what it holds without
/// counting — with none of Bob's group in it.
async fn judged_alike(w: &World, c: &Name, group: &[VersionId]) -> Result<bool, Failure> {
    let mut first: Option<State> = None;
    for (_, d) in READERS {
        let Some((s, v)) = element_now(&*w.at(d), c).await? else {
            return Ok(false);
        };
        if setting(&v, "bob").is_some() || group.iter().any(|id| s.at.contains(id)) {
            return Ok(false);
        }
        match &first {
            None => first = Some(s),
            Some(f) if f.at != s.at || f.value != s.value || f.not_counted != s.not_counted => {
                return Ok(false);
            }
            Some(_) => {}
        }
    }
    Ok(true)
}

/// What each reader holds of `c`, for a failure's detail.
async fn views(w: &World, c: &Name) -> Result<String, Failure> {
    let mut out = Vec::new();
    for (who, d) in READERS {
        let view = element_now(&*w.at(d), c).await?.map(|(s, v)| {
            format!(
                "at {:?}, not counted {:?}, bob {:?}",
                s.at,
                s.not_counted,
                setting(&v, "bob")
            )
        });
        out.push(format!("{who}: {view:?}"));
    }
    Ok(format!("{c}: {}", out.join("; ")))
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let folder = n("/alice/32=data/trip");
        let (a, b) = (
            n("/alice/32=data/trip/days"),
            n("/alice/32=data/trip/costs"),
        );
        let (laptop, phone, bob) = (w.at(LAPTOP), w.at(PHONE), w.at(BOB));
        laptop
            .share_folder(
                &folder,
                members(
                    element_rule(),
                    &["/alice", "/bob"],
                    &[person("/alice"), person("/bob"), person("/carol")],
                )
                .into(),
            )
            .await?;
        let mut seeds = Vec::new();
        for c in [&a, &b] {
            seeds.push(
                put_element(w, LAPTOP, c, |op| {
                    op.then(0, Edit::Create("list".into())).set("alice", "made")
                })
                .await?,
            );
        }
        w.until("every device holds both lists", LIMIT, || async {
            for d in [PHONE, BOB, CAROL] {
                for (c, id) in [&a, &b].into_iter().zip(&seeds) {
                    if !has(&*w.at(d), c, id).await? {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })
        .await?;

        // The phone and Carol are away; Bob writes his group; the phone narrows the costs.
        w.net().offline(PHONE);
        w.net().offline(CAROL);
        let mut items = Vec::new();
        for c in [&a, &b] {
            let op = element_op(w, BOB, c, |op| op.set("bob", "booked")).await?;
            items.push((c.clone(), ndn_data::Edit::Op(op.encode())));
        }
        let group = bob.put_group(items, element_type()).await?;
        w.until("the laptop takes Bob's group", LIMIT, || async {
            Ok(has(&*laptop, &a, &group[0]).await? && has(&*laptop, &b, &group[1]).await?)
        })
        .await?;
        w.gesture();
        phone
            .share(
                &b,
                Share {
                    rule: element_rule(),
                    writers: vec![n("/alice")],
                    readers: Vec::new(),
                },
            )
            .await?;
        w.net().online(PHONE);
        w.net().online(CAROL);

        let start = tokio::time::Instant::now();
        let took = w
            .until("every reader judges the group alike", LIMIT, || async {
                Ok(judged_alike(w, &a, &group).await? && judged_alike(w, &b, &group).await?)
            })
            .await;
        if let Err(f) = took {
            return Err(Failure::new(format!(
                "{f} (group {group:?}; {}; {})",
                views(w, &a).await?,
                views(w, &b).await?
            )));
        }
        w.converged(start.elapsed());
        w.sleep(SETTLE).await;
        for c in [&a, &b] {
            ensure!(
                judged_alike(w, c, &group).await?,
                "the readers' states of {c} differ, or one counts Bob's group, once everything \
                 settled ({})",
                views(w, c).await?
            );
        }
        Ok(())
    })
}
