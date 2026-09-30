//! `credential-eval` command-line interface.
//!
//! ```text
//! credential-eval run --corpus <snapshot.json> --out <artifact.json>
//!                     [--config <run-config.json>] [--scanner <id>]... [--jobs N]
//!                     [--observations-out <file>] [--node-dir <dir>]
//!                     [--candidate-root <scanner>=<dir>]... [--work-dir <dir>]
//!                     [--require-complete]
//! credential-eval default-config [--scanner <id>]... [--jobs N]
//! credential-eval --version
//! ```
//!
//! Exit codes: 0 artifact written; 1 run failed (no artifact); 2 usage or
//! configuration error; 3 artifact written but a scanner did not complete and
//! `--require-complete` was given; 130 cancelled.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use credential_eval_adapters::AdapterEnv;
use credential_eval_adapters::process::CancelToken;
use credential_eval_cli::orchestrate::{self, RunError, RunRequest};
use credential_eval_contracts::config::RunConfig;
use credential_eval_contracts::corpus::CorpusSnapshot;
use credential_eval_contracts::observation::ScannerStatus;

const USAGE: &str = "\
usage:
  credential-eval run --corpus <snapshot.json> --out <artifact.json>
                      [--config <run-config.json>] [--scanner <id>]... [--jobs N]
                      [--observations-out <file>] [--node-dir <dir>]
                      [--candidate-root <scanner>=<dir>]... [--work-dir <dir>]
                      [--require-complete]
  credential-eval default-config [--scanner <id>]... [--jobs N]
  credential-eval --version";

struct Usage(String);

fn usage(message: impl Into<String>) -> Usage {
    Usage(message.into())
}

#[derive(Default)]
struct RunArgs {
    corpus: Option<PathBuf>,
    out: Option<PathBuf>,
    config: Option<PathBuf>,
    scanners: Vec<String>,
    jobs: Option<u32>,
    observations_out: Option<PathBuf>,
    node_dir: Option<PathBuf>,
    candidate_roots: BTreeMap<String, PathBuf>,
    work_dir: Option<PathBuf>,
    require_complete: bool,
}

fn parse(args: &[OsString]) -> Result<RunArgs, Usage> {
    let mut parsed = RunArgs::default();
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let flag = flag
            .to_str()
            .ok_or_else(|| usage("arguments must be UTF-8"))?;
        let mut value = || {
            iter.next()
                .cloned()
                .ok_or_else(|| usage(format!("{flag} needs a value")))
        };
        match flag {
            "--corpus" => parsed.corpus = Some(value()?.into()),
            "--out" => parsed.out = Some(value()?.into()),
            "--config" => parsed.config = Some(value()?.into()),
            "--observations-out" => parsed.observations_out = Some(value()?.into()),
            "--node-dir" => parsed.node_dir = Some(value()?.into()),
            "--work-dir" => parsed.work_dir = Some(value()?.into()),
            "--scanner" => parsed.scanners.push(
                value()?
                    .into_string()
                    .map_err(|_| usage("--scanner must be UTF-8"))?,
            ),
            "--jobs" => {
                let jobs: u32 = value()?
                    .to_str()
                    .and_then(|s| s.parse().ok())
                    .filter(|n| *n >= 1)
                    .ok_or_else(|| usage("--jobs must be a positive integer"))?;
                parsed.jobs = Some(jobs);
            }
            "--candidate-root" => {
                let spec = value()?
                    .into_string()
                    .map_err(|_| usage("--candidate-root must be UTF-8"))?;
                let (id, dir) = spec
                    .split_once('=')
                    .ok_or_else(|| usage("--candidate-root takes <scanner>=<dir>"))?;
                parsed
                    .candidate_roots
                    .insert(id.to_owned(), PathBuf::from(dir));
            }
            "--require-complete" => parsed.require_complete = true,
            other => return Err(usage(format!("unknown argument {other:?}"))),
        }
    }
    Ok(parsed)
}

fn load_config(args: &RunArgs) -> Result<RunConfig, Usage> {
    let mut config = match &args.config {
        None => credential_eval_cli::default_config(&args.scanners, args.jobs.unwrap_or(1))
            .map_err(usage)?,
        Some(path) => {
            let bytes = fs::read(path).map_err(|e| usage(format!("cannot read --config: {e}")))?;
            let mut config: RunConfig = serde_json::from_slice(&bytes)
                .map_err(|e| usage(format!("invalid --config: {e}")))?;
            if !args.scanners.is_empty() {
                for id in &args.scanners {
                    if !config.scanners.iter().any(|s| s.id.as_str() == id) {
                        return Err(usage(format!("--scanner {id} is not in --config")));
                    }
                }
                config
                    .scanners
                    .retain(|s| args.scanners.iter().any(|id| id == s.id.as_str()));
            }
            config
        }
    };
    if let Some(jobs) = args.jobs {
        // A scheduling bound: normalized out of the config hash.
        config.execution.jobs = jobs;
    }
    Ok(config)
}

/// Write `bytes` to `path` atomically (temporary sibling, then rename).
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.flush()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

fn pretty<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("contract types serialize");
    bytes.push(b'\n');
    bytes
}

fn run(args: &[OsString]) -> ExitCode {
    let args = match parse(args) {
        Ok(args) => args,
        Err(Usage(message)) => {
            eprintln!("error: {message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let (Some(corpus_path), Some(out)) = (&args.corpus, &args.out) else {
        eprintln!("error: run needs --corpus and --out\n{USAGE}");
        return ExitCode::from(2);
    };
    if args.config.is_none() && args.scanners.is_empty() {
        eprintln!(
            "error: select scanners with --scanner (built-in: {}) or pass --config\n{USAGE}",
            credential_eval_cli::builtin_ids()
        );
        return ExitCode::from(2);
    }
    let config = match load_config(&args) {
        Ok(config) => config,
        Err(Usage(message)) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let corpus = match fs::read(corpus_path)
        .map_err(|e| e.to_string())
        .and_then(|bytes| CorpusSnapshot::from_json(&bytes).map_err(|e| e.to_string()))
    {
        Ok(corpus) => corpus,
        Err(message) => {
            eprintln!("error: invalid corpus snapshot: {message}");
            return ExitCode::from(1);
        }
    };
    let mut env = AdapterEnv::from_process();
    if let Some(dir) = &args.node_dir {
        env.node_dir.clone_from(dir);
    }
    env.candidate_roots = args.candidate_roots.clone();

    let cancel = CancelToken::new();
    let handler = cancel.clone();
    if ctrlc::set_handler(move || handler.cancel()).is_err() {
        eprintln!("warning: could not install the interrupt handler");
    }
    let request = RunRequest {
        corpus: &corpus,
        config: &config,
        env: &env,
        work_dir: args.work_dir.as_deref(),
        cancel: &cancel,
    };
    let output = match orchestrate::run(&request) {
        Ok(output) => output,
        Err(RunError::Cancelled) => {
            eprintln!("run cancelled; no artifact written");
            return ExitCode::from(130);
        }
        Err(error @ RunError::Config(_)) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };
    if let Some(path) = &args.observations_out {
        if let Err(e) = write_atomic(path, &pretty(&output.observations)) {
            eprintln!("error: cannot write --observations-out: {e}");
            return ExitCode::from(1);
        }
    }
    if let Err(e) = write_atomic(out, &pretty(&output.artifact)) {
        eprintln!("error: cannot write --out: {e}");
        return ExitCode::from(1);
    }
    // Sanitized summary: identities, statuses and counts only.
    let mut incomplete = false;
    for (identity, run) in output
        .artifact
        .manifest
        .scanners
        .iter()
        .zip(&output.artifact.scanners)
    {
        incomplete |= run.status != ScannerStatus::Complete;
        eprintln!(
            "{} {}: {:?}{} ({} findings)",
            identity.id,
            identity.version.as_deref().unwrap_or("unknown-version"),
            run.status,
            run.detail
                .as_deref()
                .map(|d| format!(" - {d}"))
                .unwrap_or_default(),
            run.findings.len()
        );
    }
    if let Some(execution) = &output.artifact.non_semantic.execution {
        eprintln!(
            "jobs {} · wall {} ms · scanner processes {} ({} ms) · evaluator {} ms",
            execution.jobs,
            execution.wall_ms,
            execution.processes,
            execution.scanner_process_ms,
            execution.evaluator_ms
        );
    }
    eprintln!("semantic digest {}", output.artifact.semantic_digest());
    if args.require_complete && incomplete {
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

fn default_config_command(args: &[OsString]) -> ExitCode {
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(Usage(message)) => {
            eprintln!("error: {message}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match credential_eval_cli::default_config(&parsed.scanners, parsed.jobs.unwrap_or(1)) {
        Ok(config) => {
            let _ = std::io::stdout().write_all(&pretty(&config));
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match args.first().and_then(|a| a.to_str()) {
        Some("--version" | "-V") => {
            println!(
                "{} {} (protocol {})",
                credential_eval_contracts::ENGINE_NAME,
                credential_eval_kernel::score::ENGINE_VERSION,
                credential_eval_contracts::PROTOCOL_VERSION
            );
            ExitCode::SUCCESS
        }
        Some("run") => run(&args[1..]),
        Some("default-config") => default_config_command(&args[1..]),
        Some("--help" | "-h" | "help") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}
