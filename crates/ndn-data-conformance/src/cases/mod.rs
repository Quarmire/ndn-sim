//! The cases, in study order: the use cases (`c1`…`c4`, `c8`, `c9`), with slice 3's large
//! data (`h1`, `h10`) beside them and slice 5's keys over time (`k1`…`k10`: an expired
//! certificate, a backdated version, exact re-admission, a late revocation, a renewal, a
//! recovery, and from its
//! security review a cut bounded by the loss, a lapsed guest, other bytes at a name in the cut,
//! a revoked issuer) beside theirs (c3), the items left open after the model's fixes
//! (`o1`…`o5`), the slice-2 security review (`r1`, `r4`, `r5`, `r7`: the concurrent
//! share its merge must keep, other bytes at a seq a removal cut kept — with round 3's removal
//! that outlasts a later revision signed without it (`r7`) —, and slice 6's
//! substrate for apps that write registers (the built-in newest-wins rule) in folders
//! (`f1`: a folder's members record;
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
//! Six cases of the earlier two-implementation suite (`p2`, `r2`, `r3`, `r6`, `f3`, `f4`) drove
//! the removed `ndn-data` crate's own collections and audiences, and left with it. The cases are
//! written over the neutral `Spaces` trait and import their kit from [`kit`].

use crate::case::Case;

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
mod q1_equivocation_evidence;
mod q2_chain_tip;
mod q3_fold_order;
mod q4_declared_voids;
mod q5_epoch_repair;
mod q6_grant;
mod r1_concurrent_shares;
mod r4_concurrent_add_remove;
mod r5_removal_cut_bytes;
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
    r1_concurrent_shares::CASE,
    r4_concurrent_add_remove::CASE,
    r5_removal_cut_bytes::CASE,
    r7_removal_across_revisions::CASE,
    f1_folder_members::CASE,
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
