//! Durability, d15 — a durable put survives a crash.
//!
//! Alice's laptop is the only device of a space: it has heard no peer, so a put is durable by
//! default and returns only after the flush that covers it. The laptop writes three entries, one
//! after the other, and the power is cut the moment the last returns. It restarts on the disk as
//! the last flush left it and reads all three at their paths, applying the very entries it had
//! signed.
//!
//! The guard: a put that returned on a device with no peer to hold a copy is on the disk; a power
//! cut right after it takes nothing back. (The neutral `put` has no options: the default is the
//! durable one, and this is the device it applies to.)
//!
//! Devices: alice's laptop alone.

use std::time::Duration;

use super::durability::{create, holds, space};
use super::kit::{LIMIT, n, octets};
use crate::case::{Case, CaseFuture};
use crate::feature::Feature;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "d15",
    title: "A durable put survives a crash",
    slice: 9,
    needs: &[Feature::Crash],
    model: &[],
    guards: "A device with no peer writes three entries, each put returning only after its \
             flush; a power cut right after the last put restarts it on the disk as the flush \
             left it, and it reads all three, holding the very entries it signed.",
    budget: Duration::from_secs(600),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = space();
        create(w, LAPTOP, &space).await?;
        let mut put = Vec::new();
        for i in 0..3 {
            let (path, text) = (format!("/a{i}"), format!("durable {i}"));
            put.push((
                w.space_put(LAPTOP, &space, &n(&path), octets(&text))
                    .await?,
                n(&path),
                text,
            ));
        }

        // The power is cut right after the last put returned.
        let laptop = w.crash(LAPTOP).await?;
        w.until(
            "the laptop reads its three entries again",
            LIMIT,
            || async {
                for (e, path, text) in &put {
                    if !holds(&*laptop, &space, path, e, text).await? {
                        return Ok(false);
                    }
                }
                Ok(true)
            },
        )
        .await?;
        Ok(())
    })
}
