//! `ndn-data-conformance [--provider NAME] [--case ID]… [--json PATH] [--check-determinism]` — run
//! every case (or the named ones), print a table, and write the JSON report the Results page
//! reads. Exits non-zero only if a case fails; cases with no implementation are reported as not
//! implemented, not as failures.
//!
//! `--check-determinism` then runs each of those cases again alone, each in a fresh process of
//! this runner, and fails naming every case whose status, cost or measures differ from its run in
//! the suite.

use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;

use ndn_data_conformance::runner::PROVIDERS;
use ndn_data_conformance::{Provider, Report, differences, run_only};

fn main() -> ExitCode {
    if std::env::var_os("RUST_LOG").is_some() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .init();
    }
    let mut json: Option<String> = None;
    let mut wanted: Option<String> = None;
    let mut only: Vec<String> = Vec::new();
    let mut check_determinism = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = args.next(),
            "--provider" => wanted = args.next(),
            "--case" => only.extend(args.next()),
            "--check-determinism" => check_determinism = true,
            "-h" | "--help" => {
                println!(
                    "usage: ndn-data-conformance [--provider NAME] [--case ID]... [--json PATH] \
                     [--check-determinism]"
                );
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument {other:?}; see --help");
                return ExitCode::from(2);
            }
        }
    }

    let providers: Vec<Arc<dyn Provider>> = PROVIDERS.iter().map(|make| make()).collect();
    let provider = match wanted {
        Some(name) => match providers.into_iter().find(|p| p.name() == name) {
            Some(p) => Some(p),
            None => {
                eprintln!("no provider named {name:?} is registered");
                return ExitCode::from(2);
            }
        },
        None if providers.len() > 1 => {
            eprintln!("several providers are registered; choose one with --provider");
            return ExitCode::from(2);
        }
        None => providers.into_iter().next(),
    };

    let report = run_only(provider, &only);
    print!("{}", report.table());
    if let Some(path) = json {
        let body = serde_json::to_string_pretty(&report).expect("the report serializes");
        if let Err(e) = std::fs::write(&path, body + "\n") {
            eprintln!("cannot write {path}: {e}");
            return ExitCode::from(2);
        }
        println!("wrote {path}");
    }
    let deterministic = if check_determinism {
        match check(&report) {
            Ok(same) => same,
            Err(e) => {
                eprintln!("determinism check: {e}");
                return ExitCode::from(2);
            }
        }
    } else {
        true
    };
    if report.totals.fail > 0 || !deterministic {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Run each case of `report` alone, in its own process, and compare it with its run in the
/// suite. Prints a line per case; returns whether every case agreed.
fn check(report: &Report) -> Result<bool, String> {
    println!("determinism: each case alone, in a fresh process, against its run above");
    let mut differing = 0;
    for case in &report.cases {
        let alone = run_alone(case.id, report.provider.as_deref())?;
        let diffs = differences(&alone, case);
        if diffs.is_empty() {
            println!("  {:<4} same", case.id);
        } else {
            differing += 1;
            println!("  {:<4} DIFFERS", case.id);
            for d in diffs {
                println!("         {d}");
            }
        }
    }
    let n = report.cases.len();
    if differing == 0 {
        println!("determinism: {n} of {n} cases identical alone and in the suite");
    } else {
        println!("determinism: {differing} of {n} cases differ alone and in the suite");
    }
    Ok(differing == 0)
}

/// Case `id`'s entry in the JSON report of this runner run as a child on that case alone.
fn run_alone(id: &str, provider: Option<&str>) -> Result<serde_json::Value, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this runner: {e}"))?;
    let path: PathBuf = std::env::temp_dir().join(format!(
        "ndn-data-conformance-{}-{id}.json",
        std::process::id()
    ));
    let mut child = Command::new(exe);
    child
        .args(["--case", id, "--json"])
        .arg(&path)
        .stdout(Stdio::null());
    if let Some(p) = provider {
        child.args(["--provider", p]);
    }
    // A failing case exits non-zero having written its report; compare it all the same.
    let status = child
        .status()
        .map_err(|e| format!("cannot run {id} alone: {e}"))?;
    let body = std::fs::read_to_string(&path)
        .map_err(|e| format!("{id} alone ({status}) wrote no report: {e}"))?;
    let _ = std::fs::remove_file(&path);
    let report: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("{id} alone: unreadable report: {e}"))?;
    report["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|c| c["id"] == id))
        .cloned()
        .ok_or_else(|| format!("{id} alone: the report has no such case"))
}
