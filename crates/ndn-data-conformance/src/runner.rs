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

/// The seed of the thread-local RNG `ndn-sync` draws its jitter from (the periodic sync interval
/// and the suppression delay), set before each case. Unseeded, it is seeded per process from the
/// OS, and in a suite it carries over from the case before: a case's devices would send their sync
/// notices at different moments each run, and the Interests and bytes a case measures would
/// depend on the run and on the cases before it. The case runs on the calling thread (the
/// kernel's runtime is single-threaded), so seeding this thread pins the draws.
const JITTER_SEED: u64 = 0x6e64_6e2d_6461_7461;

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
    fastrand::seed(JITTER_SEED);
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

/// What differs between a case run alone and the same case run in a suite (`in_suite`): its
/// status, each cost field and each measure, one line per difference; empty when they agree.
/// `alone` is the case's entry in the JSON report of a run of that case by itself (another
/// process, so nothing a suite leaves behind can reach it), compared with `in_suite` serialized
/// the same way.
pub fn differences(alone: &serde_json::Value, in_suite: &CaseResult) -> Vec<String> {
    let suite = serde_json::to_value(in_suite).expect("a case result serializes");
    let mut out = Vec::new();
    if alone["status"] != suite["status"] {
        out.push(format!(
            "status: alone {}, in the suite {}",
            alone["status"], suite["status"]
        ));
    }
    let fields = suite["cost"].as_object().into_iter().flat_map(|c| c.keys());
    for field in fields {
        let (a, s) = (&alone["cost"][field], &suite["cost"][field]);
        if a != s {
            out.push(format!("cost {field}: alone {a}, in the suite {s}"));
        }
    }
    let measures = |report: &serde_json::Value| -> Vec<(String, serde_json::Value)> {
        report["measured"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|m| {
                let what = m["what"].as_str().unwrap_or_default().to_owned();
                (what, m["value"].clone())
            })
            .collect()
    };
    let (alone_m, suite_m) = (measures(alone), measures(&suite));
    let value = |list: &[(String, serde_json::Value)], what: &str| {
        list.iter()
            .find(|(w, _)| w == what)
            .map_or_else(|| "nothing".to_owned(), |(_, v)| v.to_string())
    };
    let mut whats: Vec<&str> = suite_m.iter().map(|(w, _)| w.as_str()).collect();
    for (w, _) in &alone_m {
        if !whats.contains(&w.as_str()) {
            whats.push(w);
        }
    }
    for what in whats {
        let (a, s) = (value(&alone_m, what), value(&suite_m, what));
        if a != s {
            out.push(format!("measure {what:?}: alone {a}, in the suite {s}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn without_a_provider_every_case_is_reported_not_implemented() {
        let report = run_all(None);
        assert!(!report.cases.is_empty());
        assert_eq!(report.totals.not_implemented, report.cases.len());
        assert_eq!((report.totals.pass, report.totals.fail), (0, 0));
        let ids: BTreeSet<&str> = report.cases.iter().map(|c| c.id).collect();
        assert_eq!(ids.len(), report.cases.len(), "case ids are unique");
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

    #[test]
    fn a_case_passes_from_the_slice_of_the_latest_feature_it_needs() {
        for case in CASES {
            let latest = case.needs.iter().map(|f| f.slice()).max();
            assert!(
                latest.is_some_and(|s| s <= case.slice),
                "{} names slice {} but needs {:?}",
                case.id,
                case.slice,
                case.needs
            );
        }
    }

    fn ran(round_trips: u64, interests: u64) -> CaseResult {
        CaseResult {
            id: "o3",
            title: "t",
            slice: 2,
            model: &[],
            guards: "g",
            status: Status::Pass,
            detail: String::new(),
            cost: Cost {
                round_trips: Some(round_trips),
                bytes: Some(100),
                ..Cost::default()
            },
            measured: vec![crate::report::Measure {
                what: "one new version, 8 writers: Interests".into(),
                value: interests,
                unit: "round trips",
            }],
        }
    }

    #[test]
    fn a_case_alone_and_in_the_suite_agree_or_each_difference_is_named() {
        let alone = serde_json::to_value(ran(10, 6)).unwrap();
        assert!(differences(&alone, &ran(10, 6)).is_empty());
        assert_eq!(
            differences(&alone, &ran(11, 5)),
            [
                "cost round_trips: alone 10, in the suite 11",
                "measure \"one new version, 8 writers: Interests\": alone 6, in the suite 5",
            ]
        );
        let mut failed = ran(10, 6);
        failed.status = Status::Fail;
        failed.measured.clear();
        assert_eq!(
            differences(&alone, &failed),
            [
                "status: alone \"pass\", in the suite \"fail\"",
                "measure \"one new version, 8 writers: Interests\": alone 6, in the suite nothing",
            ]
        );
    }
}
