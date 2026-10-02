//! `redact-secret-alloc --out <performance-artifact.json>`
//!
//! Counts allocation requests of the pinned Redact Secret core builds on the
//! generated synthetic workloads and writes a `PerformanceArtifact`. A one-line
//! summary per comparison goes to stderr; no value is ever printed.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use redact_secret_alloc::report;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let out = match args.as_slice() {
        [flag, path] if flag == "--out" => path,
        _ => {
            eprintln!("usage: redact-secret-alloc --out <performance-artifact.json>");
            return ExitCode::from(2);
        }
    };
    let artifact = report::run(&report::comparisons());
    for result in &artifact.allocation {
        eprintln!(
            "{} {:?}: {} -> {} requests ({:+}), findings {}",
            result.card,
            result.workload,
            result.baseline_counts.requests,
            result.candidate_counts.requests,
            result.request_delta,
            if result.findings_identical {
                "identical"
            } else {
                "DIFFER"
            },
        );
    }
    let mut text = serde_json::to_string_pretty(&artifact).expect("artifact serializes");
    text.push('\n');
    if let Err(e) = std::fs::write(out, text) {
        eprintln!("error: cannot write --out: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
