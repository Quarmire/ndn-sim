//! The validation platform (axis 2), end-to-end over the shipped example specs.
//!
//! - Every `examples/checks/*.toml` must PARSE and PASS (they are the CI-ready green gate).
//! - Every `examples/probes/*.toml` must PARSE and currently FAIL (they are open findings; a probe
//!   that starts passing is a signal to promote it to `checks/` — this test fails loudly when that
//!   happens so the finding doesn't silently rot).

use std::path::{Path, PathBuf};

use ndn_sim::{ValidationSpec, run_validation};

fn examples_dir(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples").join(sub)
}

fn toml_specs(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {dir:?}: {e}"))
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    out.sort();
    out
}

#[test]
fn all_check_examples_pass() {
    let dir = examples_dir("checks");
    let specs = toml_specs(&dir);
    assert!(!specs.is_empty(), "no check examples found in {dir:?}");
    for path in specs {
        let spec = ValidationSpec::from_toml(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("parse {path:?}: {e}"));
        let report = run_validation(&spec).unwrap_or_else(|e| panic!("run {path:?}: {e}"));
        assert!(
            report.passed,
            "check example {path:?} must PASS but did not:\n{}",
            report.summary()
        );
    }
}

#[test]
fn all_probe_examples_currently_fail() {
    let dir = examples_dir("probes");
    // An empty probes/ dir is a *good* state — no open findings. Only the specs that exist must
    // still fail (a probe that starts passing should be promoted to checks/).
    for path in toml_specs(&dir) {
        let spec = ValidationSpec::from_toml(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("parse {path:?}: {e}"));
        let report = run_validation(&spec).unwrap_or_else(|e| panic!("run {path:?}: {e}"));
        assert!(
            !report.passed,
            "probe {path:?} now PASSES — promote it to examples/checks/ and update probes/README.md:\n{}",
            report.summary()
        );
    }
}
