//! Durability, d11 — with no peer reachable at the restart the hole is signed, and a reader that
//! joins later does not wait on it.
//!
//! Alice's laptop creates a space and writes `/kept` before any peer is there, so that put waits
//! for its flush and is on the disk. Her phone then follows and writes, the laptop hears it, and
//! the phone goes out of reach. With the flush held the laptop puts two more entries; the phone
//! never sees them. The power is cut. The laptop restarts without them and nobody can return
//! them: it reads `/kept` and nothing at the lost paths. Its next entry carries the signed gap
//! statement ([`AlertKind::GapSigned`] on its watch). Bob's tablet, which joins only now and can
//! reach only the laptop, applies that entry and reads the paths written after the crash: it
//! does not wait on the seqs the gap statement declares lost.
//!
//! The guard: what no flush covered and no peer holds is declared lost in a signed statement the
//! first entry after the crash carries; readers apply the entries that follow it and wait for
//! nothing inside the hole.
//!
//! Devices: alice's laptop and phone, bob's tablet.

use std::time::Duration;

use super::durability::{peers, space, write_ahead};
use super::kit::{LIMIT, SETTLE, alerted, drain, drain_until, has, item, known, n, octets, public};
use crate::case::{Case, CaseFuture};
use crate::ensure;
use crate::feature::Feature;
use crate::spaces::AlertKind;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "d11",
    title: "With no peer reachable after a crash the hole is signed and readers do not wait",
    slice: 9,
    needs: &[Feature::Crash],
    model: &[],
    guards: "A device whose last unflushed puts were lost and whose peers are out of reach \
             restarts, reads what its flush covered, signs a gap statement in its first entry \
             (a GapSigned alert), and a reader that joins afterwards applies its entries and \
             reads the paths written after the crash without waiting on the hole.",
    budget: Duration::from_secs(900),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);
const TABLET: Dev = Dev(2);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p.device("bob", "tablet");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let space = space();
        let laptop = w.spaces(LAPTOP);
        laptop.create(&space, public(&[])).await?;
        // No peer is known: this put returns once its flush has, and is on the disk.
        let kept = w
            .space_put(LAPTOP, &space, &n("/kept"), octets("kept"))
            .await?;
        peers(w, LAPTOP, PHONE, &space).await?;

        // The phone is gone before the laptop writes ahead of its flush.
        w.net().offline(PHONE);
        w.block_flush(LAPTOP, true).await?;
        let first = write_ahead(w, LAPTOP, &space, "/lost0", "lost 0").await?;
        let second = write_ahead(w, LAPTOP, &space, "/lost1", "lost 1").await?;
        ensure!(
            first.seq > kept.seq && second.seq > first.seq,
            "seqs follow put order"
        );

        // The power is cut, and no peer is reachable.
        let laptop = w.crash(LAPTOP).await?;
        w.block_flush(LAPTOP, false).await?;
        let mut feed = w.retry_later(|| laptop.watch(&space)).await?;
        w.until("the laptop reads what its flush covered", LIMIT, || async {
            Ok(item(&*laptop, &space, &n("/kept")).await?.map(|i| i.bytes) == Some(octets("kept")))
        })
        .await?;
        for lost in [&first, &second] {
            ensure!(
                !has(&*laptop, &space, lost).await?,
                "the laptop holds {} that no flush covered and no peer was there to return",
                lost.name
            );
        }

        // Its first entry after the crash states the gap.
        let after = w
            .space_put(LAPTOP, &space, &n("/after"), octets("after"))
            .await?;
        ensure!(
            after.seq > second.seq,
            "the laptop signed seq {} after the crash, where an earlier run showed up to {}",
            after.seq,
            second.seq
        );
        let mut saw = Vec::new();
        drain_until(
            &mut *feed,
            &mut saw,
            "the laptop's gap statement is reported",
            LIMIT,
            |seen| alerted(seen, |k| matches!(k, AlertKind::GapSigned)),
        )
        .await?;

        // A reader that joins now, with the phone still out of reach, does not wait on the hole.
        let tablet = w.spaces(TABLET);
        w.retry_later(|| tablet.open(&space)).await?;
        w.until("the tablet holds the space's members", LIMIT, || {
            known(&*tablet, &space)
        })
        .await?;
        w.until(
            "the tablet applies the laptop's first entry after the crash",
            LIMIT,
            || has(&*tablet, &space, &after),
        )
        .await?;
        let read = item(&*tablet, &space, &n("/after")).await?;
        ensure!(
            read.as_ref()
                .is_some_and(|i| i.bytes == octets("after") && i.entry() == after),
            "the tablet applies the entry but reads {read:?} at /after"
        );
        w.until(
            "the tablet reads what the laptop's flush covered",
            LIMIT,
            || async {
                Ok(item(&*tablet, &space, &n("/kept")).await?.map(|i| i.bytes)
                    == Some(octets("kept")))
            },
        )
        .await?;
        let mut quiet = Vec::new();
        drain(&mut *feed, SETTLE, &mut quiet).await?;
        ensure!(
            item(&*tablet, &space, &n("/lost0")).await?.is_none()
                && item(&*tablet, &space, &n("/lost1")).await?.is_none(),
            "the tablet reads a path whose entry nobody holds"
        );
        Ok(())
    })
}
