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
//! one folder reading each other), and round 5's
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
//! the epoch repair after two concurrent removals, and a new device's grant of the epoch key),
//! and the channels (`c19`…`c22`, over `ndn-heap`'s live channels through the forwarders' side
//! tables: a signed checkpoint exposes a forgery by a member holding the channel key, with
//! evidence against its link, and a lost frame is no forgery (`c19`); what such a member cannot
//! forge: a session, another session's frame under this channel's id, a checkpoint (`c20`,
//! which stands where the design's e3 row says "c3"; `c3` itself is the stolen-key case);
//! `Verified` is never given a frame no checkpoint lists (`c21`); two receivers behind a relay
//! cost the sender's link one copy of each frame (`c22`); the cases ported from the retired
//! signals: members' live messages reach each other, newest per path, once, attributed to the
//! sender's device (`c23`, from `e1`); a stranger's ask is refused saying why, a frame made
//! without the key does not open, a reader receives and cannot emit (`c24`, from `e2`); a frame
//! sent again is refused as replayed (`c26`, from `e4`); a removed member and a revoked key are
//! stopped (`c27`, from `e5`); a relay sees only ciphertext (`c28`, replacing `e6`); no store
//! keeps a channel packet (`c29`, from `e7`); the newest per path under loss, duplicates and
//! reordering (`c30`, from `e8`); live edits end in one commit (`c31`, from `e9`); four senders
//! at 60 Hz (`c32`, from `e10`); a member's Data claiming another sender's channel is refused at
//! the relay (`c33`, replacing `e11`); a member's flood of asks does not keep a genuine receiver
//! out (`c34`, replacing `e12`); a flood of frames that do not authenticate starves none
//! (`c35`, from `e13`); a frame at the largest sequences stops nothing (`c37`, from `e15`); a
//! revoked issuer ends the session held of its key (`c38`, from `e16`); a space and a path
//! named as long as they go (`c39`, replacing `e17`); and a sender restarted with its clock
//! stepped back, and a crash loop with a corrected clock, need nothing durable (`c40`, `c41`,
//! from `e18`, `e19`). `e3` has no case of its own: `c19` and `c20` assert it; `e14` has none
//! (the caps it asserted are unit tests), and `c36` is unused).
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
mod c19_checkpoint_exposes_forgery;
mod c20_forged_forms_refused;
mod c21_verified_never_unlisted;
mod c22_channel_fan_out;
mod c23_live_reach;
mod c24_stranger_takes_no_part;
mod c26_replayed_frame_refused;
mod c27_removal_rekeys;
mod c28_relay_sees_ciphertext;
mod c29_no_store_keeps_a_frame;
mod c30_latest_under_loss;
mod c31_live_edits_one_commit;
mod c32_sixty_hertz;
mod c33_claimed_route;
mod c34_ask_flood;
mod c35_forged_flood_starves_nothing;
mod c37_last_sequence;
mod c38_revoked_issuer;
mod c39_long_names;
mod c40_clock_stepped_back;
mod c41_clock_not_ratcheted;
mod chain_kit;
mod channel_kit;
mod channel_ledger;
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
mod f1_folder_members;
mod frame_tap;
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
    c22_channel_fan_out::CASE,
    c19_checkpoint_exposes_forgery::CASE,
    c21_verified_never_unlisted::CASE,
    c20_forged_forms_refused::CASE,
    c23_live_reach::CASE,
    c24_stranger_takes_no_part::CASE,
    c26_replayed_frame_refused::CASE,
    c27_removal_rekeys::CASE,
    c28_relay_sees_ciphertext::CASE,
    c29_no_store_keeps_a_frame::CASE,
    c30_latest_under_loss::CASE,
    c31_live_edits_one_commit::CASE,
    c32_sixty_hertz::CASE,
    c33_claimed_route::CASE,
    c34_ask_flood::CASE,
    c35_forged_flood_starves_nothing::CASE,
    c37_last_sequence::CASE,
    c38_revoked_issuer::CASE,
    c39_long_names::CASE,
    c40_clock_stepped_back::CASE,
    c41_clock_not_ratcheted::CASE,
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
