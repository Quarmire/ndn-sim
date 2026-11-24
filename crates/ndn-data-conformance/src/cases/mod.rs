//! The cases, in study order: the use cases (`c1`…`c4`, `c8`, `c9`), with slice 3's large
//! data (`h1`, `h10`) beside them and slice 5's keys over time (`k1`…`k10`: an expired
//! certificate, a backdated version, exact re-admission, a late revocation, a renewal, a
//! recovery, and from its
//! security review a cut bounded by the loss, a lapsed guest, other bytes at a name in the cut,
//! a revoked issuer) beside theirs (c3), the items left open after the model's fixes
//! (`o1`…`o5`), the slice-2 security review (`r1`…`r6`): the attacks it found, the concurrent
//! share its merge must keep, other bytes at a seq a removal cut kept, and an old-form removal
//! cut across an upgrade — with round 3's removal that outlasts a later revision signed without
//! it (`r7`) —, and slice 6's
//! substrate for apps that write registers (the built-in newest-wins rule) in folders
//! (`f1`, `f3`: a folder's members record, and a collection's first own record under it;
//! `i1`…`i13`: joining a folder by a code;
//! `n1`, `n2`: people named by their keys, adopting each other by name alone, and members of
//! one folder reading each other), and slice 7's signals (`e1`…`e19`, over spaces and
//! `ndn-surface`: live data pushed to a
//! space's members — reach, a stranger, a forger, a replay, a removal and a revocation, what a
//! relay sees, no store, the newest per address under loss, a commit, four senders at 60 Hz, a
//! member claiming another's run, a flood of unfetchable headers, forgeries starving a run, one
//! member's devices hogging run slots, the last sequence, a revoked issuer, and a scope named
//! in very many words, and a member whose clock stepped back across a restart), and round 5's
//! batching (`d8`: a burst of puts, each stored as one batch, arriving in
//! order and surviving a restart), round 11's durability under a crash (`d9`…`d16`: a crash
//! between a put and its flush never re-signs a seq a peer saw, or returns the entries whole
//! from a reachable peer, or signs the hole when none is reachable; a restored old image is
//! detected; a killed process loses nothing; a failing disk refuses puts past the reservation;
//! a durable put survives; a members operation is not shown before its flush), and round 9's
//! two ends of a grant
//! (`i22`…`i24`: the joiner's list of joined folders follows the members record, the joiner holds
//! a grant for the inviter that the record re-derives, and mutual invitations make an inviter's
//! entry and a mirror entry that end one by one), and round 10's short introduction code (`i25`,
//! `i26`: a short line of a device name, an address and twenty words joins with one first-contact
//! dial and a fetched hint record while the compact full link and the old words fetch none, and
//! a mistyped, miscounted, unanswered, altered, closed or expired line is refused saying why),
//! and round 11's chain, fold and grants of the log (`q1`…`q6`: two packets at one name from a
//! copied key, a removal that keeps exactly the chain ancestors of its tip, the membership fold
//! applied in three arrival orders, a cold device that asks for nothing inside a declared gap,
//! the epoch repair after two concurrent removals, and a new device's grant of the epoch key).
//! Each file states the story, the devices, and the invariant it asserts.
//!
//! A register collection (`register()`) holds the bytes of the newest version, one value per
//! path: every device converges to one value (`agree`), the value is the head with the highest
//! digest (`winning`), and nothing a refused or removed writer signed after its cut appears
//! (rule R).

//! The cases written over the neutral `Spaces` trait import their kit from [`kit`]; the cases not
//! yet ported use the older kit below, over `ndn_data::DataLayer`, which leaves with them.

use std::time::Duration;

use futures::StreamExt;
use ndn_data::merge::{NEWEST, winner};
use ndn_data::{
    Answer, Audience, Change, Changes, Content, DataError, DataLayer, Frontier, Got, Keep, Name,
    NextStep, Payload, PutOptions, Rule, Share, State, TypeId, Version, VersionId,
};

use crate::case::{Case, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::world::{Dev, World};

mod c01_offline_notes;
mod c02_removed_offline;
mod c03_stolen_key;
mod c04_lens_seal;
mod c08_nested_summaries;
mod c09_family_chat;
mod chain_kit;
mod d10_crash_peer_returns_entries;
mod d11_no_peer_hole_is_signed;
mod d12_restored_image_rolled_back;
mod d13_kill_nine_loses_nothing;
mod d14_failed_flush_refuses_puts;
mod d15_durable_put_survives;
mod d16_members_op_waits_for_flush;
mod d8_batched_burst;
mod d9_crash_between_put_and_flush;
mod durability;
mod e10_signal_sixty_hertz;
mod e11_signal_claimed_run;
mod e12_signal_admission_flood;
mod e13_signal_forged_starve;
mod e14_signal_slot_hog;
mod e15_signal_last_sequence;
mod e16_signal_revoked_issuer;
mod e17_signal_long_scope;
mod e18_signal_clock_stepped_back;
mod e19_signal_clock_not_ratcheted;
mod e1_signal_reach;
mod e2_signal_stranger;
mod e3_signal_forgery;
mod e4_signal_replay;
mod e5_signal_removal;
mod e6_signal_relay_ciphertext;
mod e7_signal_no_store;
mod e8_signal_latest_under_loss;
mod e9_signal_commit;
mod f1_folder_members;
mod f3_first_own_record;
mod f4_let_go_keeps_joined;
mod h10_holder_serves_others;
mod h1_large_photo;
mod i10_removal_lasts;
mod i11_stranger_cannot_close;
mod i12_removed_elsewhere;
mod i13_close_keeps_answering;
mod i14_join_ready;
mod i15_grant_given_once;
mod i16_grant_follows_the_record;
mod i17_grant_follows_the_role;
mod i18_two_folders_one_person;
mod i19_person_let_go_takes_the_record;
mod i1_join_by_code;
mod i20_writers_who_never_met;
mod i21_let_go_member_invited_again;
mod i22_joiners_list_follows_the_record;
mod i23_joiner_holds_a_grant_for_the_inviter;
mod i24_mutual_invitations_two_folders;
mod i25_short_code_joins;
mod i26_short_code_refused;
mod i2_used_code;
mod i3_expired_code;
mod i4_wrong_tries;
mod i5_replayed_code;
mod i6_forged_ask;
mod i7_inviter_offline;
mod i8_overlapping_namespace;
mod i9_inviter_overlap;
mod k10_revoked_issuer;
mod k1_expired_key;
mod k2_backdated;
mod k3_exact_readmit;
mod k4_late_revocation;
mod k5_renewed_key;
mod k6_recovery_cut;
mod k7_bounded_cut;
mod k8_lapsed_guest;
mod k9_other_bytes;
pub mod kit;
mod n1_named_by_key;
mod n2_members_read_each_other;
mod o1_cut_recheck;
mod o2_readmit;
mod o3_many_writers;
mod o4_sustained_writes;
mod o5_lossy_sealed_folder;
mod p1_put_never_waits;
mod p2_narrowed_audience;
mod q1_equivocation_evidence;
mod q2_chain_tip;
mod q3_fold_order;
mod q4_declared_voids;
mod q5_epoch_repair;
mod q6_grant;
mod r1_concurrent_shares;
mod r2_group_removal;
mod r3_own_device_removed;
mod r4_concurrent_add_remove;
mod r5_removal_cut_bytes;
mod r6_unbound_cut_upgrade;
mod r7_removal_across_revisions;
mod signal_kit;
mod w1_folder_watch;

/// Every case, in study order.
pub const CASES: &[Case] = &[
    c01_offline_notes::CASE,
    c02_removed_offline::CASE,
    c03_stolen_key::CASE,
    k1_expired_key::CASE,
    k2_backdated::CASE,
    k3_exact_readmit::CASE,
    k4_late_revocation::CASE,
    k5_renewed_key::CASE,
    k6_recovery_cut::CASE,
    k7_bounded_cut::CASE,
    k8_lapsed_guest::CASE,
    k9_other_bytes::CASE,
    k10_revoked_issuer::CASE,
    c04_lens_seal::CASE,
    h1_large_photo::CASE,
    h10_holder_serves_others::CASE,
    c08_nested_summaries::CASE,
    c09_family_chat::CASE,
    o1_cut_recheck::CASE,
    o2_readmit::CASE,
    o3_many_writers::CASE,
    o4_sustained_writes::CASE,
    o5_lossy_sealed_folder::CASE,
    p1_put_never_waits::CASE,
    p2_narrowed_audience::CASE,
    r1_concurrent_shares::CASE,
    r2_group_removal::CASE,
    r3_own_device_removed::CASE,
    r4_concurrent_add_remove::CASE,
    r5_removal_cut_bytes::CASE,
    r6_unbound_cut_upgrade::CASE,
    r7_removal_across_revisions::CASE,
    f1_folder_members::CASE,
    f3_first_own_record::CASE,
    w1_folder_watch::CASE,
    i1_join_by_code::CASE,
    i2_used_code::CASE,
    i3_expired_code::CASE,
    i4_wrong_tries::CASE,
    i5_replayed_code::CASE,
    i6_forged_ask::CASE,
    i7_inviter_offline::CASE,
    i8_overlapping_namespace::CASE,
    i9_inviter_overlap::CASE,
    i10_removal_lasts::CASE,
    i11_stranger_cannot_close::CASE,
    i12_removed_elsewhere::CASE,
    i13_close_keeps_answering::CASE,
    i14_join_ready::CASE,
    i15_grant_given_once::CASE,
    i16_grant_follows_the_record::CASE,
    i17_grant_follows_the_role::CASE,
    i18_two_folders_one_person::CASE,
    i19_person_let_go_takes_the_record::CASE,
    i20_writers_who_never_met::CASE,
    i21_let_go_member_invited_again::CASE,
    i22_joiners_list_follows_the_record::CASE,
    i23_joiner_holds_a_grant_for_the_inviter::CASE,
    i24_mutual_invitations_two_folders::CASE,
    i25_short_code_joins::CASE,
    i26_short_code_refused::CASE,
    f4_let_go_keeps_joined::CASE,
    n1_named_by_key::CASE,
    n2_members_read_each_other::CASE,
    e1_signal_reach::CASE,
    e2_signal_stranger::CASE,
    e3_signal_forgery::CASE,
    e4_signal_replay::CASE,
    e5_signal_removal::CASE,
    e6_signal_relay_ciphertext::CASE,
    e7_signal_no_store::CASE,
    e8_signal_latest_under_loss::CASE,
    e9_signal_commit::CASE,
    e10_signal_sixty_hertz::CASE,
    e11_signal_claimed_run::CASE,
    e12_signal_admission_flood::CASE,
    e13_signal_forged_starve::CASE,
    e14_signal_slot_hog::CASE,
    e15_signal_last_sequence::CASE,
    e16_signal_revoked_issuer::CASE,
    e17_signal_long_scope::CASE,
    e18_signal_clock_stepped_back::CASE,
    e19_signal_clock_not_ratcheted::CASE,
    d8_batched_burst::CASE,
    d9_crash_between_put_and_flush::CASE,
    d10_crash_peer_returns_entries::CASE,
    d11_no_peer_hole_is_signed::CASE,
    d12_restored_image_rolled_back::CASE,
    d13_kill_nine_loses_nothing::CASE,
    d14_failed_flush_refuses_puts::CASE,
    d15_durable_put_survives::CASE,
    d16_members_op_waits_for_flush::CASE,
    q1_equivocation_evidence::CASE,
    q2_chain_tip::CASE,
    q3_fold_order::CASE,
    q4_declared_voids::CASE,
    q5_epoch_repair::CASE,
    q6_grant::CASE,
];

// ---- the kit the cases share ------------------------------------------------------------------

/// How long devices that can reach each other get to agree.
const LIMIT: Duration = Duration::from_secs(120);
/// How long a case lets the network run before asserting that something did *not* happen.
const SETTLE: Duration = Duration::from_secs(60);
/// How long a watch is drained for one look at a collection.
const LOOK: Duration = Duration::from_secs(5);

fn n(s: &str) -> Name {
    s.parse().expect("case names are valid NDN names")
}

fn person(s: &str) -> Audience {
    Audience::Person(n(s))
}

/// The rule of the registers the cases write: the built-in newest-wins one.
fn register() -> Rule {
    Rule::Merge {
        function: n(NEWEST),
    }
}

/// The note type: revision 1 has `text`; revision 2 adds `tags`.
fn note(revision: u64) -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/note"),
            revision,
        },
        keep: Keep::Forever,
    }
}

/// The version `id` of `collection` as `layer` lists it: a device lists its own writes at once.
async fn listed(
    layer: &dyn DataLayer,
    collection: &Name,
    id: &VersionId,
) -> Result<Version, Failure> {
    let seen = look(layer, collection, &Frontier::new(), LOOK).await?;
    version(&seen, id).cloned().ok_or_else(|| {
        Failure::new(format!(
            "the writer's own watch of {collection} does not list version {} it wrote",
            id.seq.0
        ))
    })
}

fn content(fields: &[(&str, &str)]) -> Content {
    fields.iter().fold(Content::new(), |c, (k, v)| {
        c.with(*k, bytes::Bytes::copy_from_slice(v.as_bytes()))
    })
}

fn text(s: &str) -> Content {
    content(&[("text", s)])
}

/// A members record: `writers` are key-name prefixes.
fn members(rule: Rule, writers: &[&str], readers: &[Audience]) -> Share {
    Share {
        rule,
        writers: writers.iter().map(|w| n(w)).collect(),
        readers: readers.to_vec(),
    }
}

/// The field `f` of `c` as text.
fn field<'c>(c: &'c Content, f: &str) -> Option<&'c str> {
    c.get(f).and_then(|v| std::str::from_utf8(v).ok())
}

/// The merged state of a merge collection as `layer` sees it now; `None` while it has nothing, or
/// while the device answers [`NextStep::RetryLater`] (a record admitting it not received or
/// walked to yet: read again).
async fn state_now(layer: &dyn DataLayer, collection: &Name) -> Result<Option<State>, Failure> {
    match layer.get(collection).await {
        Ok(answer) => match answer.got {
            Got::State(s) => Ok(Some(s)),
            other => Err(Failure::new(format!(
                "get on merge collection {collection} answered {other:?}; it must answer the \
                 merged state at a frontier (M10)"
            ))),
        },
        Err(DataError::Unavailable { .. } | DataError::NotFound { .. }) => Ok(None),
        Err(e) if e.next() == NextStep::RetryLater => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The field `f` of the entry a version carries inline (a large payload carries none: `get` of
/// the version's name reads it).
fn field_of<'v>(v: &'v Version, f: &str) -> Option<&'v str> {
    match &v.payload {
        Payload::Entry(c) => field(c, f),
        Payload::Large { .. } => None,
    }
}

/// The merged state, which must exist.
async fn state(layer: &dyn DataLayer, collection: &Name) -> Result<State, Failure> {
    state_now(layer, collection)
        .await?
        .ok_or_else(|| Failure::new(format!("no state of {collection} is held")))
}

/// Whether `layer`'s merged state of `collection` includes `id`.
async fn has(layer: &dyn DataLayer, collection: &Name, id: &VersionId) -> Result<bool, Failure> {
    Ok(state_now(layer, collection)
        .await?
        .is_some_and(|s| s.at.contains(id)))
}

/// The octets `s`'s register value holds after `by` (its first 32 octets): what the head that
/// wins wrote. Empty while nothing is written, and for a removal.
fn written(s: &State) -> &[u8] {
    s.value
        .bytes()
        .and_then(|b| b.get(32..))
        .unwrap_or_default()
}

/// The octets for a register write of `s`.
fn octets(s: &str) -> bytes::Bytes {
    bytes::Bytes::copy_from_slice(s.as_bytes())
}

/// Rule R (b): `layer`'s state of the register `collection` reads what the head with the highest
/// signed digest (`Version::signed`) wrote. `heads` are the versions nothing supersedes, the ones
/// the case made over no
/// other, as `layer` lists them with the octets each wrote. Returns the state.
async fn winning(
    layer: &dyn DataLayer,
    collection: &Name,
    heads: &[&VersionId],
) -> Result<State, Failure> {
    let changes = look(layer, collection, &Frontier::new(), LOOK).await?;
    let mut picks = Vec::with_capacity(heads.len());
    for id in heads {
        let v = version(&changes, id)
            .ok_or_else(|| Failure::new(format!("the watch does not list head {id:?}")))?;
        let op =
            v.op.clone()
                .ok_or_else(|| Failure::new(format!("head {id:?} lists no octets of its write")))?;
        picks.push((&v.signed, op));
    }
    let want =
        winner(picks).ok_or_else(|| Failure::new(format!("no head of {collection} was given")))?;
    let s = state(layer, collection).await?;
    ensure!(
        written(&s) == &want[..],
        "the register {collection} reads {:?}; the head with the highest signed digest wrote {:?}",
        String::from_utf8_lossy(written(&s)),
        String::from_utf8_lossy(&want)
    );
    Ok(s)
}

/// Whether `layer` holds a state of `collection` at all: it knows the collection's members
/// record, so its writes go into the collection as shared.
async fn known(layer: &dyn DataLayer, collection: &Name) -> Result<bool, Failure> {
    Ok(state_now(layer, collection).await?.is_some())
}

/// Drain `stream` for `window` of virtual time.
async fn drain(
    stream: &mut Changes,
    window: Duration,
    into: &mut Vec<Change>,
) -> Result<(), Failure> {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) | Ok(None) => return Ok(()),
            Ok(Some(item)) => into.push(item?),
        }
    }
}

/// Drain `stream` into `into` until `done` holds of everything received, for at most `limit` of
/// virtual time; returns how long it took.
async fn drain_until(
    stream: &mut Changes,
    into: &mut Vec<Change>,
    what: &str,
    limit: Duration,
    mut done: impl FnMut(&[Change]) -> bool,
) -> Result<Duration, Failure> {
    let start = tokio::time::Instant::now();
    loop {
        if done(into) {
            return Ok(start.elapsed());
        }
        let left = limit.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Err(Failure::new(format!(
                "{what}: not reached within {limit:?} of virtual time"
            )));
        }
        drain(stream, LOOK.min(left), into).await?;
    }
}

/// Everything `layer` reports for `collection` beyond `since`, within `window`.
async fn look(
    layer: &dyn DataLayer,
    collection: &Name,
    since: &Frontier,
    window: Duration,
) -> Result<Vec<Change>, Failure> {
    let mut stream = layer.watch(collection, since).await?;
    let mut out = Vec::new();
    drain(&mut stream, window, &mut out).await?;
    Ok(out)
}

/// The versions among `changes`.
fn versions(changes: &[Change]) -> impl Iterator<Item = &Version> {
    changes.iter().filter_map(|c| match c {
        Change::Version(v) => Some(v),
        _ => None,
    })
}

/// The version `id` among `changes`.
fn version<'c>(changes: &'c [Change], id: &VersionId) -> Option<&'c Version> {
    versions(changes).find(|v| v.id == *id)
}

// ---- the keys-over-time kit (c3, k1–k10, o2) -----------------------------------------------

/// The log entry name of version `id` of `collection`, which device `writer` wrote
/// (`<writer>/32=log/<collection>/seq=<n>`): the name a cut and a re-admission speak of.
fn log_entry(w: &World, writer: Dev, collection: &Name, id: &VersionId) -> Name {
    ndn_data::wire::log_name(&w.net().spec(writer).name(), Some(collection), id.seq.0)
}

/// Whether `changes` report version `id` withdrawn.
fn withdrawn(changes: &[Change], id: &VersionId) -> bool {
    changes
        .iter()
        .any(|c| matches!(c, Change::Withdrawn { id: w, .. } if w == id))
}
