//! One conformance case: what it guards, its devices, and the scenario.

use std::pin::Pin;
use std::time::Duration;

use ndn_data::DataError;

use crate::feature::Feature;
use crate::world::{Plan, World};

/// The scenario's future, borrowing the world it runs in.
pub type CaseFuture<'w> = Pin<Box<dyn Future<Output = Result<(), Failure>> + 'w>>;

/// A use case (or an open item) of the data-layer study as an executable scenario.
pub struct Case {
    /// Stable id: `c1`…`c12` for the use cases, `h1`…`h9` for slice 3's custody of large data,
    /// `s1`…`s6` for slice 4's small constant streams, `k1`…`k10` for slice 5's keys over time,
    /// `b1`…`b5`, `g1`…`g3` and `f1`, `f2` for slice 6's merge rules by name, app-built
    /// operations and merge pieces, groups, and folder members, `o1`…`o4` for the open items,
    /// `r1`…`r4` for the slice-2 security review (the attacks it found, and the concurrent share
    /// its merge keeps).
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure(pub String);

impl Failure {
    /// A failure with this explanation.
    pub fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<DataError> for Failure {
    fn from(e: DataError) -> Self {
        Failure(format!("verb failed: {e} (next step: {:?})", e.next()))
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
