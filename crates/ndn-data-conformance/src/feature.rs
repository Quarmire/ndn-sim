//! What a case needs of an implementation, in the plan's terms.
//!
//! A case runs only when its provider supports every feature it needs; otherwise it is reported
//! not implemented, naming what is missing. Features follow the plan's slice items, so a provider
//! can implement a slice's features one at a time and say so honestly.

/// One feature of the data layer a case relies on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// Versions (writer = key, seq, parents, type, keep), owner-signed members records, the
    /// built-in newest-wins register, signed nested summaries, and `get`, `put`, `put_op`,
    /// `watch` over them.
    Merge,
    /// Members records whose writers lie under other people's prefixes.
    WritersAcrossPrefixes,
    /// `share` removing a writer: a cut at what the owner had seen.
    RemovalCut,
    /// Re-checking accepted versions when a cut arrives (`Change::Withdrawn`).
    CutRecheck,
    /// Seals: reading only within a version's audience, `DataError::Sealed`.
    Seal,
    /// The log rule: a collection is the union of its members' logs.
    Log,
    /// Payloads larger than one packet (log rule): a version carrying `Payload::Large`, its
    /// chunks and manifest verified piece by piece, read whole by `get`.
    LargePayloads,
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
    /// A revocation's cut bounded by the root's own observation: the owner states when the
    /// device was lost, the root suspects the key (takes nothing new of it), and the cut keeps
    /// only what the root first verified before then; what it left out is listed for exact
    /// re-admission.
    BoundedCut,
    /// A cut binds its ranges to bytes (a root-signed manifest of each entry's digest): other
    /// bytes at a name in the cut are refused, by data layers and forwarders.
    CutManifest,
    /// A removal cut signed before cuts bound bytes (seqs only, no `CutBytes`) stays in force
    /// across an upgrade: the versions it keeps are refused but kept, and the owner's next record
    /// binds them from the bytes it holds.
    UnboundCut,
    /// A key's authority over data ends with its certificate, for every role (a guest's, a
    /// member's, a node's, an admin's): once lapsed without a renewal, its data is refused until
    /// the root's revoke-with-cut, which then decides alone.
    GuestExpiry,
    /// A later trust-context version that revokes an issuer re-checks what a device holds
    /// through it, on adoption and on restart.
    IssuerRecheck,
    /// A folder's members record (`share_folder`): one record, one seal epoch and one grant per
    /// reader for every collection under it, each collection free to narrow it.
    FolderMembers,
    /// One `watch` of a folder: every collection under it, those created after the watch began
    /// included, every kind of change, each tagged with its collection.
    FolderWatch,
    /// Joining a folder by a code (`Device::offer`, `Device::join`): a one-use offer, an ask
    /// sealed to the offering device and proving the code's secret, an answer bound to the
    /// asker's key; both sides adopt each other's anchor and the owner adds the joiner.
    Introduction,
    /// People named by their root key (`/user/<0xA1: SHA-256 of an Ed25519 key>`, ndn-cert's
    /// `GenesisKey`): a host adopts such a namespace by its name alone (`Provider::adopt`), its
    /// version 1 checked as the genesis the name hashes, and a device of such a person serves
    /// what an adopter fetches — its namespace's trust-context versions and its certificate.
    SelfCertifying,
    /// Signals (`ndn_surface::signal`, spec signals.md): ephemeral live data pushed unsigned into
    /// a space's sync group, each packet signed by a run key a member's device key vouched
    /// for, sealed under the space's signal key in a sealed space, gated by the members in
    /// force on every packet, never an entry and never cached. `ndn-heap` only.
    Signals,
    /// Durability under a crash: a device's own log survives its process dying between a
    /// write and its flush (`Provider::crash`, `image`, `restore`, `block_flush`), a signed gap
    /// statement stands for what was lost, and a restored backup is detected.
    Crash,
    /// A log is a chain: an entry names the entry before it, and a removal keeps exactly the
    /// chain's ancestors of its tip.
    Chain,
    /// The old crate's own shapes, which the neutral `Spaces` trait does not carry:
    /// collections with their own members records under a folder, device and group audiences
    /// (`Audience::Device`, `Audience::Group`). A case that still drives `World::at` needs it;
    /// only `ndn-data` supports it, and a case leaves it when it is ported (or at stage 9).
    OldLayer,
}

impl Feature {
    /// The plan slice that adds it.
    pub fn slice(self) -> u8 {
        match self {
            Feature::Merge | Feature::WritersAcrossPrefixes => 1,
            Feature::RemovalCut | Feature::CutRecheck | Feature::Seal | Feature::Log => 2,
            Feature::LargePayloads => 3,
            Feature::Revocation
            | Feature::Readmit
            | Feature::RevocationRecheck
            | Feature::KeyLifetime
            | Feature::Recovery
            | Feature::BoundedCut
            | Feature::CutManifest
            | Feature::UnboundCut
            | Feature::GuestExpiry
            | Feature::IssuerRecheck => 5,
            Feature::FolderMembers
            | Feature::FolderWatch
            | Feature::Introduction
            | Feature::SelfCertifying => 6,
            Feature::Signals => 7,
            Feature::Crash | Feature::Chain => 9,
            Feature::OldLayer => 1,
        }
    }

    /// A short label, as the report shows it.
    pub fn label(self) -> &'static str {
        match self {
            Feature::Merge => "merge rule",
            Feature::WritersAcrossPrefixes => "writers across prefixes",
            Feature::RemovalCut => "removal cut",
            Feature::CutRecheck => "re-check on cut arrival",
            Feature::Seal => "seal",
            Feature::Log => "log rule",
            Feature::LargePayloads => "large payloads",
            Feature::Revocation => "revocation",
            Feature::Readmit => "re-admission",
            Feature::RevocationRecheck => "re-check on revocation arrival",
            Feature::KeyLifetime => "keys over time",
            Feature::Recovery => "recovery carries cuts",
            Feature::BoundedCut => "cut bounded by the loss",
            Feature::CutManifest => "cut binds bytes",
            Feature::UnboundCut => "old-form removal cut kept",
            Feature::GuestExpiry => "lapsed key needs a cut",
            Feature::IssuerRecheck => "re-check on issuer revocation",
            Feature::FolderMembers => "folder members",
            Feature::FolderWatch => "folder watch",
            Feature::Introduction => "introduction",
            Feature::SelfCertifying => "names by key",
            Feature::Signals => "signals",
            Feature::Crash => "crash durability",
            Feature::Chain => "chain tip",
            Feature::OldLayer => "old crate's collections and audiences",
        }
    }
}
