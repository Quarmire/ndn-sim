//! One conformance case: what it guards, its devices, and the scenario.

use std::pin::Pin;
use std::time::Duration;

use ndn_data::{DataError, NextStep};

use crate::feature::Feature;
use crate::world::{Plan, World};

/// The scenario's future, borrowing the world it runs in.
pub type CaseFuture<'w> = Pin<Box<dyn Future<Output = Result<(), Failure>> + 'w>>;

/// A use case (or an open item) of the data-layer study as an executable scenario.
pub struct Case {
    /// Stable id: `c1`…`c11` for the use cases, `h1` for slice 3's large data,
    /// `k1`…`k10` for slice 5's keys over time,
    /// `b1`…`b4` and `f1`, `f2` for slice 6's merge rules by name, app-built
    /// operations and merge pieces, and folder members, `i1`…`i13` for joining a folder
    /// by a code, `n1` for people named by their keys, `e1`…`e10` for slice 7's signals,
    /// `o1`…`o4` for the open items, `r1`…`r4` for the slice-2 security review (the attacks it
    /// found, and the concurrent share its merge keeps).
    pub id: &'static str,
    /// The use case's title.
    pub title: &'static str,
    /// The plan slice whose implementation makes it pass.
    pub slice: u8,
    /// What it needs of an implementation; it runs only when all are supported.
    pub needs: &'static [Feature],
    /// The model changes it motivated (`M1`…`M15`).
    pub model: &'static [&'static str],
    /// The invariant it asserts, from the use case's fix.
    pub guards: &'static str,
    /// Virtual time the scenario may take before it counts as hung.
    pub budget: Duration,
    /// The devices it needs.
    pub plan: fn() -> Plan,
    /// The scenario.
    pub run: fn(&World) -> CaseFuture<'_>,
}

/// Why a case failed: an invariant did not hold, or a verb failed where it must not.
///
/// A failure a provider's verb answered carries what the layer says to do about it
/// ([`next`](Self::next): the kind of its `NextStep`, `"RetryLater"`, `"AskOwner"`, …) and the kind
/// of refusal ([`kind`](Self::kind): `"Sealed"`, `"NotAllowed"`, `"NotReady"`, …), as strings, so
/// the same checks hold on every provider; one the case itself raised carries neither.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// What happened.
    pub detail: String,
    /// The next step the failing verb named, by its kind.
    pub next: Option<&'static str>,
    /// The kind of refusal the failing verb answered.
    pub kind: Option<&'static str>,
}

impl Failure {
    /// A failure with this explanation, from the case itself.
    pub fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
            next: None,
            kind: None,
        }
    }

    /// A failure a verb answered: `detail` says what, `next` what to do (the kind of
    /// `NextStep`), `kind` the kind of refusal.
    pub fn answered(detail: impl Into<String>, next: &'static str, kind: &'static str) -> Self {
        Self {
            detail: detail.into(),
            next: Some(next),
            kind: Some(kind),
        }
    }

    /// Whether the verb that failed named `next` as the next step (`"RetryLater"`).
    pub fn next_is(&self, next: &str) -> bool {
        self.next == Some(next)
    }

    /// Whether the verb that failed says to ask again later.
    pub fn retry_later(&self) -> bool {
        self.next_is("RetryLater")
    }

    /// Whether the verb that failed answered a refusal of this kind (`"Sealed"`).
    pub fn kind_is(&self, kind: &str) -> bool {
        self.kind == Some(kind)
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl From<DataError> for Failure {
    fn from(e: DataError) -> Self {
        let next = match e.next() {
            NextStep::None => "None",
            NextStep::RetryLater => "RetryLater",
            NextStep::AskOwner => "AskOwner",
            NextStep::UseOwnerDevice => "UseOwnerDevice",
            NextStep::EditInstead => "EditInstead",
            NextStep::FixLocal => "FixLocal",
            NextStep::FixName => "FixName",
            NextStep::FixRequest => "FixRequest",
            NextStep::UpdateProgram => "UpdateProgram",
        };
        let kind = match &e {
            DataError::Unavailable { .. } => "Unavailable",
            DataError::NotReady { .. } => "NotReady",
            DataError::NotFound { .. } => "NotFound",
            DataError::BadName { .. } => "BadName",
            DataError::Refused { .. } => "Refused",
            DataError::NotAllowed { .. } => "NotAllowed",
            DataError::NotOwner { .. } => "NotOwner",
            DataError::Sealed { .. } => "Sealed",
            DataError::TooLarge { .. } => "TooLarge",
            DataError::BadRequest { .. } => "BadRequest",
            DataError::Local { .. } => "Local",
            DataError::RuleUnknown { .. } => "RuleUnknown",
            DataError::Introduction { .. } => "Introduction",
        };
        Failure::answered(
            format!("verb failed: {e} (next step: {:?})", e.next()),
            next,
            kind,
        )
    }
}

/// Fail the case with a formatted explanation unless `cond` holds.
#[macro_export]
macro_rules! ensure {
    ($cond:expr, $($fmt:tt)+) => {
        if !$cond {
            return Err($crate::Failure::new(format!($($fmt)+)));
        }
    };
}
