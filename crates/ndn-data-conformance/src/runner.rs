//! Running cases against a provider, each on its own virtual-time kernel.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use ndn_sim::VirtualKernel;

use crate::case::{Case, Failure};
use crate::cases::CASES;
use crate::provider::Provider;
use crate::report::{CaseResult, Cost, Report, Status};
use crate::world::World;

/// The implementations the runner knows, by constructor.
pub const PROVIDERS: &[fn() -> Arc<dyn Provider>] = &[crate::reference::Reference::provider];

/// Run one case against `provider`. Without a provider, or with one that does not implement a
/// feature the case needs, the scenario does not run and the case is [`Status::NotImplemented`].
pub fn run_case(case: &Case, provider: Option<&Arc<dyn Provider>>) -> CaseResult {
    let result = |status, detail: String, cost, measured| CaseResult {
        id: case.id,
        title: case.title,
        slice: case.slice,
        model: case.model,
        guards: case.guards,
        status,
        detail,
        cost,
        measured,
    };
    let Some(provider) = provider else {
        return result(
            Status::NotImplemented,
            format!(
                "no ndn-data implementation is registered; slice {} provides what this case needs",
                case.slice
            ),
            Cost::default(),
            Vec::new(),
        );
    };
    let missing: Vec<String> = case
        .needs
        .iter()
        .filter(|f| !provider.supports(**f))
        .map(|f| format!("{} (slice {})", f.label(), f.slice()))
        .collect();
    if !missing.is_empty() {
        return result(
            Status::NotImplemented,
            format!(
                "{} does not implement {}",
                provider.name(),
                missing.join(", ")
            ),
            Cost::default(),
            Vec::new(),
        );
    }

    let plan = (case.plan)();
    let provider = Arc::clone(provider);
    let kernel = VirtualKernel::new();
    let ran = std::panic::catch_unwind(AssertUnwindSafe(|| {
        kernel.run_capped(case.budget, |k| async move {
            let world = match World::build(k, &plan, provider).await {
                Ok(w) => w,
                Err(e) => {
                    return (
                        Err(Failure::new(format!("setup failed: {e:#}"))),
                        Cost::default(),
                        Vec::new(),
                    );
                }
            };
            let start = world.mark();
            let outcome = (case.run)(&world).await;
            let cost = world.reported_cost(start);
            let measured = world.measured();
            world.shutdown().await;
            (outcome, cost, measured)
        })
    }));
    match ran {
        Ok(Ok((Ok(()), cost, measured))) => result(Status::Pass, String::new(), cost, measured),
        Ok(Ok((Err(f), cost, measured))) => result(Status::Fail, f.0, cost, measured),
        Ok(Err(exceeded)) => result(
            Status::Fail,
            exceeded.to_string(),
            Cost::default(),
            Vec::new(),
        ),
        Err(panic) => {
            let msg = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("non-string panic");
            result(
                Status::Fail,
                format!("panicked: {msg}"),
                Cost::default(),
                Vec::new(),
            )
        }
    }
}

/// Run every case, in study order, against `provider`.
pub fn run_all(provider: Option<Arc<dyn Provider>>) -> Report {
    run_only(provider, &[])
}

/// Run the cases whose ids are in `only` (every case when it is empty), in study order.
pub fn run_only(provider: Option<Arc<dyn Provider>>, only: &[String]) -> Report {
    let cases = CASES
        .iter()
        .filter(|c| only.is_empty() || only.iter().any(|id| id == c.id))
        .map(|c| run_case(c, provider.as_ref()))
        .collect();
    Report::new(provider.map(|p| p.name().to_owned()), cases)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn without_a_provider_every_case_is_reported_not_implemented() {
        let report = run_all(None);
        assert_eq!(
            report.cases.len(),
            16,
            "twelve use cases and four open items"
        );
        assert_eq!(report.totals.not_implemented, 16);
        assert_eq!((report.totals.pass, report.totals.fail), (0, 0));
        let ids: BTreeSet<&str> = report.cases.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), 19, "case ids are unique");
        for c in &report.cases {
            assert_eq!(c.status, Status::NotImplemented);
            assert!(
                (1..=7).contains(&c.slice),
                "{} names slice {}",
                c.id,
                c.slice
            );
            assert!(!c.guards.is_empty() && !c.detail.is_empty());
            assert_eq!(
                c.cost,
                Cost::default(),
                "nothing ran, so nothing is measured"
            );
        }
    }

    #[test]
    fn the_report_serializes_for_the_results_page() {
        let json = serde_json::to_value(run_all(None)).unwrap();
        assert_eq!(json["suite"], "ndn-data-conformance");
        assert!(json["provider"].is_null());
        assert_eq!(json["cases"][0]["status"], "not-implemented");
        assert!(json["cases"][0]["cost"]["round_trips"].is_null());
    }

    #[test]
    fn every_case_plans_its_devices() {
        for case in CASES {
            assert!(!(case.plan)().is_empty(), "{} plans no device", case.id);
        }
    }
}
