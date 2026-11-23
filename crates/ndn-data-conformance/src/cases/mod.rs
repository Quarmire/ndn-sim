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
//! one folder reading each other), and slice 7's signals (`e1`…`e18`: live data pushed to a
//! folder's members — reach, a stranger, a forger, a replay, a removal and a revocation, what a
//! relay sees, no store, the newest per address under loss, a commit, four senders at 60 Hz, a
//! member claiming another's run, a flood of unfetchable headers, forgeries starving a run, one
//! member's devices hogging run slots, the last sequence, a revoked issuer, and a scope named
//! in very many words, and a member whose clock stepped back across a restart), and round 5's
//! batching (`d8`: a burst of puts, each stored as one batch, arriving in
//! order and surviving a restart), and round 9's two ends of a grant
//! (`i22`…`i24`: the joiner's list of joined folders follows the members record, the joiner holds
//! a grant for the inviter that the record re-derives, and mutual invitations make an inviter's
//! entry and a mirror entry that end one by one), and round 10's short introduction code (`i25`,
//! `i26`: a short line of a device name, an address and twenty words joins with one first-contact
//! dial and a fetched hint record while the compact full link and the old words fetch none, and
//! a mistyped, miscounted, unanswered, altered, closed or expired line is refused saying why).
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
use ndn_data::wire::device_of;
use ndn_data::{
    Answer, Audience, Change, Changes, Content, DataError, DataLayer, Frontier, Got, Keep, Name,
    NextStep, Payload, PutOptions, Rule, Share, State, Timestamp, TypeId, Version, VersionId,
};
use ndn_surface::signal::{Signal, SignalError, SignalRun, SignalStats};

use crate::case::{Case, Failure};
use crate::ensure;
use crate::feature::Feature;
use crate::signal;
use crate::world::{Dev, Plan, World};

mod c01_offline_notes;
mod c02_removed_offline;
mod c03_stolen_key;
mod c04_lens_seal;
mod c08_nested_summaries;
mod c09_family_chat;
mod d8_batched_burst;
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
mod r1_concurrent_shares;
mod r2_group_removal;
mod r3_own_device_removed;
mod r4_concurrent_add_remove;
mod r5_removal_cut_bytes;
mod r6_unbound_cut_upgrade;
mod r7_removal_across_revisions;
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
];

// ---- the kit the cases share ------------------------------------------------------------------

/// How long devices that can reach each other get to agree.
const LIMIT: Duration = Duration::from_secs(120);
/// How long a device that reaches a writer's data only through a copy another device holds gets
/// to read it. A walk asks the unreachable writer first, in each of its three tries, before it
/// asks a device that holds the packet for it, so each packet of the walk (root, folder, collection,
/// page, entry) costs about 7 s of virtual time before it is had: 39 s with no loss at all, and
/// 43 to 100 s at 20 % loss over fault seeds 0 to 159 (i20, i22 once 133 s), against a [`LIMIT`] of 120 s.
const RELAYED: Duration = Duration::from_secs(300);
/// How long a case lets the network run before asserting that something did *not* happen.
const SETTLE: Duration = Duration::from_secs(60);
/// How long a watch is drained for one look at a collection.
const LOOK: Duration = Duration::from_secs(5);
const DAY: Duration = Duration::from_secs(24 * 3600);

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

/// The photo type: revision 1 has `file` (the photo's name) and `image` (its octets).
fn photo(keep: Keep) -> PutOptions {
    PutOptions {
        type_id: TypeId {
            name: n("/types/photo"),
            revision: 1,
        },
        keep,
    }
}

/// A photo's octets: about 1.6 MB, some 390 chunks of 4096 octets.
const IMAGE: usize = 1_600_000;

/// A photo named `file` of `len` octets, the same every run: the octets come from a generator
/// (xorshift) seeded by the name.
fn picture(file: &str, len: usize) -> Content {
    let mut x = file.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    });
    let mut image = Vec::with_capacity(len + 8);
    while image.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        image.extend_from_slice(&x.to_le_bytes());
    }
    image.truncate(len);
    Content::new()
        .with("file", bytes::Bytes::copy_from_slice(file.as_bytes()))
        .with("image", bytes::Bytes::from(image))
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

/// The octets a version carries in pieces; `None` when it is carried inline.
fn large(v: &Version) -> Option<u64> {
    match v.payload {
        Payload::Large { size } => Some(size),
        _ => None,
    }
}

/// `d` reads the version `name` whole: `get` until it answers the entry `expected` (while no
/// path or holder answers, it asks again). Records the read's cost to `d` on its links as
/// `<what>: Interests` and `<what>: bytes received`.
async fn read_whole(
    w: &World,
    d: Dev,
    name: &Name,
    expected: &Content,
    what: &str,
) -> Result<(), Failure> {
    let layer = w.at(d);
    let before = w.net().device_wire(d);
    w.until(what, LIMIT, || async {
        match layer.get(name).await {
            Ok(Answer {
                got: Got::Version(v),
                ..
            }) => match &v.payload {
                Payload::Entry(c) if c == expected => Ok(true),
                Payload::Entry(c) => Err(Failure::new(format!(
                    "{what}: {name} read as other content than was written ({} octets of \
                     `image`, {} written)",
                    c.get("image").map_or(0, |b| b.len()),
                    expected.get("image").map_or(0, |b| b.len())
                ))),
                Payload::Large { size } => Err(Failure::new(format!(
                    "{what}: get of {name} answered its size ({size} octets), not the entry \
                     read whole"
                ))),
            },
            Ok(answer) => Err(Failure::new(format!(
                "{what}: get of version {name} answered {:?}, not the version",
                answer.got
            ))),
            // Not yet (nothing held, a record admitting the reader not walked to): read again.
            Err(DataError::NotFound { .. }) => Ok(false),
            Err(e) if e.next() == NextStep::RetryLater => Ok(false),
            Err(e) => Err(e.into()),
        }
    })
    .await?;
    let spent = w.net().device_wire(d) - before;
    w.measure(format!("{what}: Interests"), spent.interests, "round trips");
    w.measure(format!("{what}: bytes received"), spent.in_bytes, "bytes");
    Ok(())
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

/// Whether the register write `v` carries exactly the octets of `s`.
fn op_is(v: &Version, s: &str) -> bool {
    v.op.as_deref() == Some(s.as_bytes())
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

/// The thief `thief` takes the stolen device and switches it on: its data layer, once it holds
/// version `id` of `collection` as the device did.
async fn stolen(
    w: &World,
    thief: Dev,
    collection: &Name,
    id: &VersionId,
) -> Result<std::sync::Arc<dyn DataLayer>, Failure> {
    w.steal(thief).await?;
    let layer = w.at(thief);
    w.until(
        "the stolen device, switched on by the thief, holds what it held",
        LIMIT,
        || has(&*layer, collection, id),
    )
    .await?;
    Ok(layer)
}

/// Whether every layer holds the same merged state, including every id in `ids`. Every layer is
/// read at each poll: a device's first read of a collection is its first look, from which it
/// follows the collection, so reading a device only once those before it hold would begin its
/// look late and time the devices one after another rather than side by side.
async fn agree(
    layers: &[&dyn DataLayer],
    collection: &Name,
    ids: &[&VersionId],
) -> Result<bool, Failure> {
    let mut states = Vec::with_capacity(layers.len());
    for layer in layers {
        states.push(state_now(*layer, collection).await?);
    }
    let mut first: Option<&State> = None;
    for s in &states {
        let Some(s) = s else {
            return Ok(false);
        };
        if !ids.iter().all(|id| s.at.contains(id)) {
            return Ok(false);
        }
        match first {
            None => first = Some(s),
            Some(f) if f.at != s.at || f.value != s.value => return Ok(false),
            Some(_) => {}
        }
    }
    Ok(true)
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

/// Whether `changes` report an equivocation.
fn equivocation(changes: &[Change]) -> bool {
    changes
        .iter()
        .any(|c| matches!(c, Change::Equivocation { .. }))
}

// ---- the keys-over-time kit (c3, k1–k10, o2) -----------------------------------------------

/// The time the owner says a device was lost, by the clock of `root` (the namespace's root
/// device, which bounds the revocation's cut by what it first verified before then): a second
/// after everything the case saw so far, so what `root` held by now came strictly before it.
async fn loss_time(w: &World, root: Dev) -> Timestamp {
    w.sleep(Duration::from_secs(1)).await;
    w.net().date(root)
}

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

// ---- the signals kit (e1–e10) -----------------------------------------------------------------

/// How long a sender waits before sending its final value again while a receiver has not yet
/// acknowledged it, as a host re-sends its latest presence or cursor until it is seen.
const RESEND: Duration = Duration::from_millis(250);
/// One frame at 60 Hz.
const FRAME: Duration = Duration::from_micros(16_667);
/// What a final value's payload starts with: a receiver acknowledges each one it delivers.
const FINAL: &str = "final:";

/// A folder every one of `people` writes and reads, sealed to them.
fn sealed_to(people: &[&str]) -> Share {
    let readers: Vec<Audience> = people.iter().map(|p| person(p)).collect();
    members(Rule::Log, people, &readers)
}

/// The sync group of namespace `ns` (`<ns>/32=sync`), where members push signals for its
/// devices.
fn group(ns: &Name) -> Name {
    n(&format!("{ns}/32=sync"))
}

/// Why a signal verb failed, as a case failure.
fn refused(what: &str, e: SignalError) -> Failure {
    Failure::new(format!("{what}: {e} (next step: {:?})", e.next()))
}

/// `verb` asked again while it answers [`NextStep::RetryLater`] (no record or epoch key held
/// yet), as a host does what the refusal says, every [`crate::world::AGAIN_PAUSE`] for at most
/// [`crate::world::AGAIN_FOR`]; then, or at any other refusal, the answer as it came.
async fn signal_again<T, F, Fut>(mut verb: F) -> Result<T, SignalError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, SignalError>>,
{
    let start = tokio::time::Instant::now();
    loop {
        match verb().await {
            Err(e)
                if e.next() == NextStep::RetryLater
                    && start.elapsed() < crate::world::AGAIN_FOR =>
            {
                tokio::time::sleep(crate::world::AGAIN_PAUSE).await;
            }
            answer => return answer,
        }
    }
}

/// The device whose key signed a signal's run header.
fn sender_of(s: &Signal) -> Name {
    device_of(&s.sender).unwrap_or_else(|| s.sender.clone())
}

/// The payload acknowledging the final `payload`: `seen:` and the final, which is no final
/// itself, so acknowledgements are never acknowledged.
fn acknowledging(payload: &[u8]) -> Vec<u8> {
    [b"seen:".as_slice(), payload].concat()
}

/// The address a receiver acknowledges `sender`'s final at `address` on:
/// `seen/<12 hex digits of SHA-256(sender ‖ address)>`, so acknowledgements of finals of other
/// senders or addresses keep their own latest.
fn ack_address(sender: &Name, address: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(sender.encode_to_tlv());
    h.update(address);
    let digest = h.finalize();
    let mut out = b"seen/".to_vec();
    for b in &digest[..6] {
        out.extend_from_slice(format!("{b:02x}").as_bytes());
    }
    out
}

/// A run, shared by its device's sends and its inbox's acknowledgements.
type Run = std::sync::Arc<futures::lock::Mutex<SignalRun>>;
/// What one device sent: (address, payload).
type Ledger = std::sync::Arc<std::sync::Mutex<std::collections::BTreeSet<(Vec<u8>, Vec<u8>)>>>;

/// Send one signal on `run` and note it in `ledger`, as a host does what a refusal says: past
/// the run's rate (`RateLimited`) after `retry_after`, and again while the next step is retry
/// later (a new epoch's key not held yet) every [`crate::world::AGAIN_PAUSE`], for at most
/// [`crate::world::AGAIN_FOR`]. Returns its sequence.
async fn send_on(
    run: &Run,
    ledger: &Ledger,
    address: &[u8],
    payload: &[u8],
) -> Result<u64, SignalError> {
    let start = tokio::time::Instant::now();
    loop {
        let sent = run.lock().await.send(address, payload).await;
        match sent {
            Err(SignalError::RateLimited { retry_after }) => tokio::time::sleep(retry_after).await,
            Err(e)
                if e.next() == NextStep::RetryLater
                    && start.elapsed() < crate::world::AGAIN_FOR =>
            {
                tokio::time::sleep(crate::world::AGAIN_PAUSE).await;
            }
            Err(e) => return Err(e),
            Ok(seq) => {
                ledger
                    .lock()
                    .expect("the ledger's lock")
                    .insert((address.to_vec(), payload.to_vec()));
                return Ok(seq);
            }
        }
    }
}

/// One device's part in a signal case: its app following the scope, its run, the signals its
/// subscriber delivered (in order) and what it sent. Its inbox acknowledges on its run every
/// final of another sender it delivers ([`ack_address`]).
struct Peer {
    who: String,
    me: Name,
    scope: Name,
    run: Run,
    sent: Ledger,
    got: std::sync::Arc<std::sync::Mutex<Vec<Signal>>>,
    inbox: tokio::task::JoinHandle<()>,
    /// The app's watch of the scope, which keeps its device following it (its records and
    /// epoch keys arrive), as an app showing the scope does.
    _follow: Changes,
}

impl Peer {
    /// `d` takes part in `scope`'s signals: its app watches the scope, so its device follows it,
    /// and its host's signals subscribe to it and open a run, each asked again while refused
    /// with retry later (the record or the epoch key not held yet).
    async fn join(w: &World, d: Dev, scope: &Name) -> Result<Peer, Failure> {
        let me = w.net().spec(d).name();
        let who = me.to_string();
        let (layer, since) = (w.at(d), Frontier::new());
        let follow = w.again(|| layer.watch(scope, &since)).await?;
        let signals = w.signals(d).await?;
        let mut sub = signal_again(|| signals.subscribe(scope))
            .await
            .map_err(|e| refused(&format!("{who} subscribes to {scope}"), e))?;
        let run: Run = std::sync::Arc::new(futures::lock::Mutex::new(
            signal_again(|| signals.open(scope))
                .await
                .map_err(|e| refused(&format!("{who} opens a run in {scope}"), e))?,
        ));
        let sent = Ledger::default();
        let got = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let inbox = {
            let (me, run, sent, got) = (me.clone(), run.clone(), sent.clone(), got.clone());
            tokio::spawn(async move {
                while let Some(s) = sub.next().await {
                    let from = sender_of(&s);
                    let ack = (from != me && s.payload.starts_with(FINAL.as_bytes()))
                        .then(|| (ack_address(&from, &s.address), acknowledging(&s.payload)));
                    got.lock().expect("the inbox's lock").push(s);
                    // A lost acknowledgement is made good by the next one: the sender sends its
                    // final again until it sees one.
                    if let Some((address, payload)) = ack {
                        let _ = send_on(&run, &sent, &address, &payload).await;
                    }
                }
            })
        };
        Ok(Peer {
            who,
            me,
            scope: scope.clone(),
            run,
            sent,
            got,
            inbox,
            _follow: follow,
        })
    }

    /// Send one signal now.
    async fn send(&self, address: &str, payload: &str) -> Result<u64, Failure> {
        send_on(
            &self.run,
            &self.sent,
            address.as_bytes(),
            payload.as_bytes(),
        )
        .await
        .map_err(|e| refused(&format!("{} sends at {address}", self.who), e))
    }

    /// Send `payload` (a [`FINAL`]) at `address` until every one of `to` acknowledged it,
    /// again every [`RESEND`], for at most [`LIMIT`]. Returns how many times it was sent.
    async fn send_final(&self, address: &str, payload: &str, to: &[&Peer]) -> Result<u32, Failure> {
        debug_assert!(payload.starts_with(FINAL));
        let ack = ack_address(&self.me, address.as_bytes());
        let start = tokio::time::Instant::now();
        let mut sends = 0;
        loop {
            let seen = to.iter().all(|p| {
                self.latest(p, &ack)
                    .is_some_and(|s| s.payload == acknowledging(payload.as_bytes()))
            });
            if seen {
                return Ok(sends);
            }
            if start.elapsed() >= LIMIT {
                return Err(Failure::new(format!(
                    "{}'s final {payload:?} at {address} was not seen by every receiver within \
                     {LIMIT:?} of virtual time, sent {sends} times",
                    self.who
                )));
            }
            self.send(address, payload).await?;
            sends += 1;
            tokio::time::sleep(RESEND).await;
        }
    }

    /// Every signal its subscriber delivered so far, in order.
    fn all(&self) -> Vec<Signal> {
        self.got.lock().expect("the inbox's lock").clone()
    }

    /// The last signal it delivered from `from` at `address`.
    fn latest(&self, from: &Peer, address: &[u8]) -> Option<Signal> {
        self.got
            .lock()
            .expect("the inbox's lock")
            .iter()
            .rev()
            .find(|s| sender_of(s) == from.me && s.address == address)
            .cloned()
    }

    /// How many signals it delivered whose payload contains `part`.
    fn delivered(&self, part: &str) -> usize {
        self.got
            .lock()
            .expect("the inbox's lock")
            .iter()
            .filter(|s| contains(&s.payload, part.as_bytes()))
            .count()
    }

    /// What every delivery must be, whatever the network did: of its scope, from one of
    /// `peers` and something that peer sent, from the network (no ring), each (sender, run, seq)
    /// once, and per (sender, address) never older than one delivered before it.
    fn check(&self, peers: &[&Peer]) -> Result<(), Failure> {
        let got = self.all();
        let mut once = std::collections::BTreeSet::new();
        let mut newest: std::collections::BTreeMap<(Name, bytes::Bytes), u64> =
            std::collections::BTreeMap::new();
        for s in &got {
            let from = sender_of(s);
            let Some(peer) = peers.iter().find(|p| p.me == from) else {
                return Err(Failure::new(format!(
                    "{} delivered a signal from {}, no sender of the case: {s:?}",
                    self.who, s.sender
                )));
            };
            ensure!(
                s.scope == self.scope,
                "{} delivered a signal of {} on its subscription to {}",
                self.who,
                s.scope,
                self.scope
            );
            ensure!(
                peer.sent
                    .lock()
                    .expect("the ledger's lock")
                    .contains(&(s.address.to_vec(), s.payload.to_vec())),
                "{} delivered {:?} at {:?} as {from}'s, which {from} never sent",
                self.who,
                String::from_utf8_lossy(&s.payload),
                String::from_utf8_lossy(&s.address)
            );
            ensure!(
                from == self.me || !s.local,
                "{} delivered {from}'s signal off a local ring: every device is its own host",
                self.who
            );
            ensure!(
                once.insert((from.clone(), s.run.0, s.seq)),
                "{} delivered {from}'s signal seq {} of its run twice",
                self.who,
                s.seq
            );
            let last = newest.entry((from.clone(), s.address.clone())).or_insert(0);
            ensure!(
                s.seq > *last,
                "{} delivered {from}'s seq {} at {:?} after seq {}: an older signal after a \
                 newer one for the same sender and address",
                self.who,
                s.seq,
                String::from_utf8_lossy(&s.address),
                *last
            );
            *last = s.seq;
        }
        Ok(())
    }

    /// What its run sends: the run's id.
    async fn run_id(&self) -> [u8; 16] {
        self.run.lock().await.id().0
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.inbox.abort();
    }
}

/// Whether `part` appears in `bytes`.
fn contains(bytes: &[u8], part: &[u8]) -> bool {
    !part.is_empty() && bytes.windows(part.len()).any(|w| w == part)
}

/// `d`'s signal counters now.
async fn stats(w: &World, d: Dev) -> Result<SignalStats, Failure> {
    Ok(w.signals(d).await?.stats())
}

/// How many packets (or signals) `s` counts as dropped, whatever the reason.
fn dropped(s: &SignalStats) -> u64 {
    s.stale
        + s.replayed
        + s.expired
        + s.not_member
        + s.bad_signature
        + s.unknown_run
        + s.unknown_key
        + s.flood
        + s.malformed
        + s.unsubscribed
}

/// Wait until `rose` holds of `d`'s signal counters, for at most [`LIMIT`]; while it does not,
/// `again` is done every [`RESEND`] (a packet sent again, as the packet that should raise the
/// counter may be lost on its way).
async fn until_counted<F, Fut>(
    w: &World,
    d: Dev,
    what: &str,
    rose: impl Fn(&SignalStats) -> bool,
    mut again: F,
) -> Result<SignalStats, Failure>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), Failure>>,
{
    let start = tokio::time::Instant::now();
    loop {
        let now = stats(w, d).await?;
        if rose(&now) {
            return Ok(now);
        }
        if start.elapsed() >= LIMIT {
            return Err(Failure::new(format!(
                "{what}: not counted within {LIMIT:?} of virtual time ({now:?})"
            )));
        }
        again().await?;
        tokio::time::sleep(RESEND).await;
    }
}

/// The signal key `d` holds for `scope` to seal with now (newest epoch), as (id, key).
fn signal_key(w: &World, d: Dev, scope: &Name) -> Result<([u8; 8], [u8; 32]), Failure> {
    let gate = w.gate(d)?;
    let held = gate.signal_scope(scope)?;
    let key = held.keys.first().ok_or_else(|| {
        Failure::new(format!(
            "{} holds no signal key of {scope}: it is no sealed scope there",
            w.net().spec(d).name()
        ))
    })?;
    Ok((key.id, *key.expose()))
}

/// The SignalBody of the sealed packet a push Interest `wire` carries, opened with `key`.
fn opened(wire: &bytes::Bytes, key: &[u8; 32]) -> Option<signal::Body> {
    let (_, packet) = signal::pushed(wire)?;
    let body = signal::open(&signal::sealed(&packet)?, key)?;
    signal::parse_body(&body)
}
