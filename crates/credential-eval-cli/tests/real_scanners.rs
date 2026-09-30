//! Integration test against the real pinned scanners. Skipped unless
//! `CREDENTIAL_EVAL_REAL_SCANNERS=1` (CI does not install the scanners).
//!
//! Local run (pinned peers first on `PATH`, `npm ci` done in `adapters/node`):
//!
//! ```sh
//! PATH="<dir with gitleaks 8.30.1 and trufflehog 3.97.4>:$PATH" \
//!   CREDENTIAL_EVAL_REAL_SCANNERS=1 \
//!   cargo test -p credential-eval-cli --test real_scanners -- --nocapture
//! ```
//!
//! Every built-in adapter runs with its default (legacy-pinned)
//! configuration over `tests/fixtures/contracts-smoke`. Each must complete,
//! and `--jobs 1` and `--jobs 4` must give the same semantic artifact.

mod common;

use common::*;
use credential_eval_adapters::AdapterEnv;
use credential_eval_contracts::observation::ScannerStatus;

#[test]
fn all_builtin_adapters_complete_on_the_smoke_corpus() {
    if std::env::var("CREDENTIAL_EVAL_REAL_SCANNERS").as_deref() != Ok("1") {
        eprintln!("skipped: set CREDENTIAL_EVAL_REAL_SCANNERS=1 to run against real scanners");
        return;
    }
    let corpus = smoke_corpus();
    let env = AdapterEnv::from_process();
    let serial = credential_eval_cli::default_config(&[], 1).unwrap();
    let parallel = credential_eval_cli::default_config(&[], 4).unwrap();
    let one = run_with(&corpus, &serial, &env);
    let four = run_with(&corpus, &parallel, &env);
    assert_schema_valid(&four.artifact);
    assert_eq!(semantic_text(&one.artifact), semantic_text(&four.artifact));

    eprintln!("scanner         version          status     findings");
    for (identity, run) in four
        .artifact
        .manifest
        .scanners
        .iter()
        .zip(&four.artifact.scanners)
    {
        eprintln!(
            "{:<15} {:<16} {:<10} {}",
            identity.id.as_str(),
            identity.version.as_deref().unwrap_or("-"),
            format!("{:?}", run.status),
            run.findings.len()
        );
    }
    let execution = four.artifact.non_semantic.execution.as_ref().unwrap();
    eprintln!(
        "jobs 4: wall {} ms, {} scanner processes ({} ms), evaluator {} ms; semantic digest {}",
        execution.wall_ms,
        execution.processes,
        execution.scanner_process_ms,
        execution.evaluator_ms,
        four.artifact.semantic_digest()
    );
    for run in &four.artifact.scanners {
        assert_eq!(
            run.status,
            ScannerStatus::Complete,
            "{}: {:?}",
            run.scanner,
            run.detail
        );
    }
}
