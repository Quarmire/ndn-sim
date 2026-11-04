//! What a case needs of an implementation, in the plan's terms.
//!
//! A case runs only when its provider supports every feature it needs; otherwise it is reported
//! not implemented, naming what is missing. Features follow the plan's slice items, so a provider
//! can implement a slice's features one at a time and say so honestly.

/// One feature of the data layer a case relies on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// Versions (writer = key, seq, parents, type, keep), owner-signed members records, the merge
    /// rule, signed nested summaries, and `get`, `put`, `watch` over them.
    Merge,
    /// Members records whose writers lie under other people's prefixes.
    WritersAcrossPrefixes,
    /// `snapshot`: one signed record pinning exact versions or states.
    Snapshot,
    /// `share` removing a writer: a cut at what the owner had seen.
    RemovalCut,
    /// Re-checking accepted versions when a cut arrives (`Change::Withdrawn`).
    CutRecheck,
    /// Seals: reading only within a version's audience, `DataError::Sealed`.
    Seal,
    /// The log rule: a collection is the union of its members' logs.
    Log,
    /// `prune` refusing versions another key signed (`DataError::NotOwnWrites`, model change
    /// M9): removing someone else's data in a shared collection is an edit instead.
    PruneScope,
    /// Custody leases (`hold`), capped by keep.
    Custody,
    /// `prune` of one's own writes, and `DataError::Pruned` for readers.
    Prune,
    /// Payloads larger than one packet (log rule): a version carrying `Payload::Large`, its
    /// chunks and manifest verified piece by piece, read whole by `get`.
    LargePayloads,
    /// Signed blocks of small entries under a producer's accepted delay (model change M6): one
    /// signature per block, each entry verifiable through it.
    Blocks,
    /// The one-key rule: one key writes, and its signed head bounds how fresh `get` is and
    /// refuses a rollback.
    OneKey,
    /// Retention by expiry: a version whose keep passed by a device's own clock is dropped there,
    /// served by none, and answered `DataError::Expired`.
    Expiry,
    /// Range reads of a one-key stream by seq and by time (`<C>/32=range/<R>`), fetching the
    /// blocks in range and a logarithmic search, not the stream.
    RangeReads,
    /// Revocation as a cut in the trust context: the key's versions the cut lists stay valid,
    /// every other packet it signed is refused, whatever date it claims.
    Revocation,
    /// The owner re-admitting exact versions outside a cut (name and digest, in the trust
    /// context).
    Readmit,
    /// A revocation arriving re-checks what a device accepted from the key: a version outside
    /// the cut is withdrawn (`Change::Withdrawn`).
    RevocationRecheck,
    /// Keys over time: a version's validity does not depend on a clock — an expired
    /// certificate ends nothing, a renewed one continues the key's log.
    KeyLifetime,
    /// Recovering a namespace whose root was compromised carries its revocations and cuts.
    Recovery,
    /// Named functions whose answers are sealed to their inputs' audience.
    Functions,
}

impl Feature {
    /// The plan slice that adds it.
    pub fn slice(self) -> u8 {
        match self {
            Feature::Merge | Feature::WritersAcrossPrefixes | Feature::Snapshot => 1,
            Feature::RemovalCut
            | Feature::CutRecheck
            | Feature::Seal
            | Feature::Log
            | Feature::PruneScope => 2,
            Feature::Custody | Feature::Prune | Feature::LargePayloads => 3,
            Feature::Blocks | Feature::OneKey | Feature::Expiry | Feature::RangeReads => 4,
            Feature::Revocation
            | Feature::Readmit
            | Feature::RevocationRecheck
            | Feature::KeyLifetime
            | Feature::Recovery => 5,
            Feature::Functions => 6,
        }
    }

    /// A short label, as the report shows it.
    pub fn label(self) -> &'static str {
        match self {
            Feature::Merge => "merge rule",
            Feature::WritersAcrossPrefixes => "writers across prefixes",
            Feature::Snapshot => "snapshot",
            Feature::RemovalCut => "removal cut",
            Feature::CutRecheck => "re-check on cut arrival",
            Feature::Seal => "seal",
            Feature::Log => "log rule",
            Feature::PruneScope => "prune scope",
            Feature::Custody => "custody",
            Feature::Prune => "prune",
            Feature::LargePayloads => "large payloads",
            Feature::Blocks => "signed blocks",
            Feature::OneKey => "one-key rule",
            Feature::Expiry => "retention by expiry",
            Feature::RangeReads => "range reads",
            Feature::Revocation => "revocation",
            Feature::Readmit => "re-admission",
            Feature::RevocationRecheck => "re-check on revocation arrival",
            Feature::KeyLifetime => "keys over time",
            Feature::Recovery => "recovery carries cuts",
            Feature::Functions => "named functions",
        }
    }
}
