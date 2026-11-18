//! A **fault profile** for one direction of a link: every packet crossing it is dropped,
//! duplicated, forged, delayed, reordered or (a Data) held back, each by a seeded draw. The
//! semantics are exactly those of ndf's element-link fault layer (`NDF_LINK_FAULTS`), so a
//! scenario run here under a profile meets the same network a faulty ndf run meets.
//!
//! The definition (`Faults`, `FaultStream`, `Fate`, `FAULTY`, the `key=value` text form and the
//! frame reading) lives in the `ndn-faults` crate of ndn-rs, a leaf with no dependency but
//! `bytes`, so that ndn-link's test-only fault layer (cargo feature `fault-injection`) draws
//! the very same fates for the same seed on a real link. This module re-exports it: every
//! `ndn_sim::Faults` and `ndn_sim::faults::…` use is unchanged and the draws are bit-identical
//! (the unit tests of the profile moved with it; the test below pins the sequence through this
//! re-export).
//!
//! Install a profile on a running fabric with
//! [`RunningSimulation::set_link_faults`](crate::RunningSimulation::set_link_faults).

pub use ndn_faults::{FAULTY, Fate, FaultStream, Faults, carries_data};

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use ndn_packet::Name;
    use ndn_packet::encode::DataBuilder;

    /// The first fates of `FAULTY` at seed 3 on the direction 1 → 2 over one Data, as the
    /// simulator drew them before the definition moved to `ndn-faults`: (copies, delay in ms,
    /// forged). A change here means every recorded `--faulty` run changes.
    #[test]
    fn the_faulty_stream_through_the_reexport_is_what_it_was() {
        let d: Bytes = DataBuilder::new("/a/b".parse::<Name>().unwrap(), b"content").build();
        let mut s = Faults::parse(FAULTY).unwrap().with_seed(3).stream(1, 2);
        let got: Vec<(u8, u128, bool)> = (0..12)
            .map(|_| {
                let f = s.fate(d.clone());
                (f.copies, f.delay.as_millis(), f.frame != d)
            })
            .collect();
        assert_eq!(
            got,
            vec![
                (1, 1418, false),
                (0, 0, false),
                (1, 406, false),
                (1, 1401, false),
                (0, 0, false),
                (1, 540, true),
                (2, 593, false),
                (0, 0, false),
                (1, 1509, true),
                (0, 0, false),
                (1, 1406, false),
                (1, 1563, false),
            ],
            "{got:?}"
        );
    }
}
