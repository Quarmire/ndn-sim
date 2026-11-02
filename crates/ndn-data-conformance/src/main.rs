//! `ndn-data-conformance [--provider NAME] [--case ID]… [--json PATH]` — run every case (or the
//! named ones), print a table, and write the JSON report the Results page reads. Exits non-zero only if a case fails; cases with
//! no implementation are reported as not implemented, not as failures.

use std::process::ExitCode;
use std::sync::Arc;

use ndn_data_conformance::runner::PROVIDERS;
use ndn_data_conformance::{Provider, run_only};

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
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = args.next(),
            "--provider" => wanted = args.next(),
            "--case" => only.extend(args.next()),
            "-h" | "--help" => {
                println!(
                    "usage: ndn-data-conformance [--provider NAME] [--case ID]... [--json PATH]"
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
    if report.totals.fail > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
