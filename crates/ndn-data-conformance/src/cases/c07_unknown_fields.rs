//! Case 7 — an older lens edits a newer note.
//!
//! The phone's lens knows note type 1 (text). The laptop added tags (type 2). Under the draft
//! model the old writer rewrote the note and silently dropped the field it did not know. The fix
//! (M7): writers keep fields they do not understand; the tags survive the phone's edit.

use std::time::Duration;

use super::*;
use crate::case::CaseFuture;
use crate::ensure;
use crate::world::{Dev, Plan, World};

pub(super) const CASE: Case = Case {
    id: "c7",
    title: "An older lens edits a newer note",
    slice: 1,
    needs: &[Feature::Merge],
    model: &["M7"],
    guards: "A writer keeps every field it does not know: after a type-1 edit of a type-2 note, \
             the type-2 field is still there, on every device, beside the new text.",
    budget: Duration::from_secs(1800),
    plan,
    run,
};

const LAPTOP: Dev = Dev(0);
const PHONE: Dev = Dev(1);

fn plan() -> Plan {
    let mut p = Plan::new();
    p.device("alice", "laptop");
    p.device("alice", "phone");
    p
}

fn run(w: &World) -> CaseFuture<'_> {
    Box::pin(async move {
        let item = n("/alice/32=data/notes/shopping");
        let (laptop, phone) = (w.at(LAPTOP), w.at(PHONE));
        laptop
            .share(&item, members(merge(), &["/alice"], &[person("/alice")]))
            .await?;
        let tagged = laptop
            .put(
                &item,
                content(&[("text", "buy milk"), ("tags", "errand")]),
                note(2),
            )
            .await?;
        w.until("the phone holds the tagged note", LIMIT, || {
            has(&*phone, &item, &tagged)
        })
        .await?;

        let edit = phone.put(&item, text("buy oat milk"), note(1)).await?;
        w.converge("both devices hold the phone's edit", LIMIT, || async {
            agree(&[&*laptop, &*phone], &item, &[&edit]).await
        })
        .await?;
        for (device, layer) in [("laptop", &laptop), ("phone", &phone)] {
            let s = state(&**layer, &item).await?;
            ensure!(
                field(&s.value, "text") == Some("buy oat milk"),
                "the {device} shows text {:?}, not the phone's edit",
                field(&s.value, "text")
            );
            ensure!(
                field(&s.value, "tags") == Some("errand"),
                "the {device} lost the tags the type-1 writer did not know (now {:?})",
                field(&s.value, "tags")
            );
        }
        Ok(())
    })
}
