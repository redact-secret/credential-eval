//! `credential-eval` command-line interface.
//!
//! ```text
//! credential-eval run --corpus <snapshot.json> --out <artifact.json>
//!                     [--config <run-config.json>] [--scanner <id>]... [--jobs N]
//!                     [--observations-out <file>] [--node-dir <dir>]
//!                     [--candidate-root <scanner>=<dir>]... [--work-dir <dir>]
//!                     [--methods <m,...|all> [--reference <scanner>] [--evidence <file>]
//!                      [--seed case-id|legacy-category] [--fail-on-assertions]
//!                      [--legacy-eval-out <file>]]
//!                     [--run-class official|exploratory]
//!                     [--evidence-release <tag> --evidence-manifest <file>
//!                      --evidence-manifest-digest <sha256>]
//!                     [--require-complete] [--strict]
//! credential-eval compat legacy-bench --artifact <artifact.json> --index <legacy-index.json>
//!                     --out-dir <dir>
//! credential-eval perf run --config <performance-config.json> --out <performance-artifact.json>
//!                     [--work-dir <dir>]
//! credential-eval default-config [--scanner <id>]... [--jobs N]
//! credential-eval --version
//! ```
//!
//! Without `--methods`, `run` measures the corpus cases (the legacy `bench`
//! pipeline). With `--methods`, it builds evaluation cases from the corpus,
//! generates every variant, scans the variant corpus and evaluates it (the
//! legacy `eval` pipeline).
//!
//! `--run-class` defaults to `exploratory`. An `official` run needs a pinned
//! evidence release and a `pin` on every configured scanner, and refuses to
//! run when either does not verify (`docs/official-runs.md`). The evidence
//! release flags may also be given to an exploratory run; a mismatch is then
//! refused as well.
//!
//! Exit codes: 0 artifact written; 1 run failed (no artifact); 2 usage or
//! configuration error; 3 artifact written but `--require-complete`/`--strict`
//! was given and a scanner did not complete (or, for methods, a generation
//! error occurred, or an assertion failed under `--fail-on-assertions`);
//! 4 refused: the evidence snapshot did not verify against the pinned release,
//! or (official run) a scanner did not match its pin (no artifact);
//! 130 cancelled.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use credential_eval_adapters::AdapterEnv;
use credential_eval_adapters::process::CancelToken;
use credential_eval_cli::evidence;
use credential_eval_cli::official;
use credential_eval_cli::orchestrate::{self, MethodRequest, RunError, RunRequest};
use credential_eval_cli::perf;
use credential_eval_contracts::artifact::{RunArtifact, RunClass};
use credential_eval_contracts::config::{EvaluationSettings, RunConfig, SeedConvention};
use credential_eval_contracts::corpus::CorpusSnapshot;
use credential_eval_contracts::ids::ScannerId;
use credential_eval_contracts::observation::ScannerStatus;
use credential_eval_contracts::performance::PerformanceConfig;
use credential_eval_kernel::evaluation::{GenerationLimits, MethodId};

const USAGE: &str = "\
usage:
  credential-eval run --corpus <snapshot.json> --out <artifact.json>
                      [--config <run-config.json>] [--scanner <id>]... [--jobs N]
                      [--observations-out <file>] [--node-dir <dir>]
                      [--candidate-root <scanner>=<dir>]... [--work-dir <dir>]
                      [--methods <m,...|all> [--reference <scanner>] [--evidence <file>]
                       [--seed case-id|legacy-category] [--fail-on-assertions]
                       [--legacy-eval-out <file>]]
                      [--run-class official|exploratory]
                      [--evidence-release <tag> --evidence-manifest <file>
                       --evidence-manifest-digest <sha256>]
                      [--require-complete] [--strict]
  credential-eval compat legacy-bench --artifact <artifact.json>
                      --index <legacy-index.json> --out-dir <dir>
  credential-eval perf run --config <performance-config.json>
                      --out <performance-artifact.json> [--work-dir <dir>]
  credential-eval default-config [--scanner <id>]... [--jobs N]
  credential-eval --version
methods: twin, benign, metamorphic, mutation, differential";

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
    methods: Option<Vec<MethodId>>,
    reference: Option<ScannerId>,
    evidence: Option<PathBuf>,
    seed: Option<SeedConvention>,
    fail_on_assertions: bool,
    legacy_eval_out: Option<PathBuf>,
    run_class: Option<RunClass>,
    evidence_release: Option<String>,
    evidence_manifest: Option<PathBuf>,
    evidence_manifest_digest: Option<String>,
}

fn parse_methods(list: &str) -> Result<Vec<MethodId>, Usage> {
    if list == "all" {
        return Ok(MethodId::ALL.to_vec());
    }
    let mut methods = Vec::new();
    for id in list.split(',') {
        let method = MethodId::parse(id).ok_or_else(|| usage(format!("unknown method {id:?}")))?;
        if methods.contains(&method) {
            return Err(usage(format!("duplicate method {id:?}")));
        }
        methods.push(method);
    }
    methods.sort();
    Ok(methods)
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
            "--require-complete" | "--strict" => parsed.require_complete = true,
            "--fail-on-assertions" => parsed.fail_on_assertions = true,
            "--methods" => {
                let list = value()?
                    .into_string()
                    .map_err(|_| usage("--methods must be UTF-8"))?;
                parsed.methods = Some(parse_methods(&list)?);
            }
            "--reference" => {
                let id = value()?
                    .into_string()
                    .map_err(|_| usage("--reference must be UTF-8"))?;
                parsed.reference =
                    Some(ScannerId::new(id).map_err(|e| usage(format!("--reference: {e}")))?);
            }
            "--evidence" => parsed.evidence = Some(value()?.into()),
            "--legacy-eval-out" => parsed.legacy_eval_out = Some(value()?.into()),
            "--run-class" => {
                parsed.run_class = Some(
                    value()?
                        .to_str()
                        .and_then(official::parse_run_class)
                        .ok_or_else(|| usage("--run-class takes official or exploratory"))?,
                );
            }
            "--evidence-release" => {
                parsed.evidence_release = Some(
                    value()?
                        .into_string()
                        .map_err(|_| usage("--evidence-release must be UTF-8"))?,
                );
            }
            "--evidence-manifest" => parsed.evidence_manifest = Some(value()?.into()),
            "--evidence-manifest-digest" => {
                parsed.evidence_manifest_digest = Some(
                    value()?
                        .into_string()
                        .map_err(|_| usage("--evidence-manifest-digest must be UTF-8"))?,
                );
            }
            "--seed" => {
                parsed.seed = Some(match value()?.to_str() {
                    Some("case-id") => SeedConvention::CaseId,
                    Some("legacy-category") => SeedConvention::LegacyCategory,
                    _ => return Err(usage("--seed takes case-id or legacy-category")),
                });
            }
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

fn read_bounded(path: &Path, limit: u64, what: &str) -> Result<Vec<u8>, String> {
    let meta = fs::metadata(path).map_err(|e| format!("cannot read {what}: {e}"))?;
    if meta.len() > limit {
        return Err(format!("{what} exceeds {limit} bytes"));
    }
    fs::read(path).map_err(|e| format!("cannot read {what}: {e}"))
}

/// Method-run inputs resolved from the arguments.
struct MethodInputs {
    methods: Vec<MethodId>,
    loaded: evidence::LoadedEvidence,
}

/// Resolve `--methods`/`--evidence`/`--reference`/`--seed` into the config.
fn method_inputs(args: &RunArgs, config: &mut RunConfig) -> Result<Option<MethodInputs>, Usage> {
    let Some(methods) = &args.methods else {
        if !config.methods.is_empty() || config.evaluation.is_some() {
            return Err(usage(
                "the configuration names evaluation methods; select them with --methods",
            ));
        }
        if args.reference.is_some()
            || args.evidence.is_some()
            || args.seed.is_some()
            || args.fail_on_assertions
            || args.legacy_eval_out.is_some()
        {
            return Err(usage(
                "--reference, --evidence, --seed, --fail-on-assertions and --legacy-eval-out need --methods",
            ));
        }
        return Ok(None);
    };
    let bytes = match &args.evidence {
        Some(path) => {
            read_bounded(path, evidence::MAX_EVIDENCE_BYTES, "--evidence").map_err(usage)?
        }
        None => format!(
            r#"{{"schema":"{}","families":{{}}}}"#,
            evidence::EVIDENCE_SCHEMA
        )
        .into_bytes(),
    };
    let loaded = evidence::load(&bytes).map_err(usage)?;
    config.methods = methods.iter().map(|m| m.component()).collect();
    config.evaluation = Some(EvaluationSettings {
        reference: args.reference.clone(),
        seed: args.seed.unwrap_or(SeedConvention::CaseId),
        evidence_digest: loaded.digest.clone(),
        family_allowlist: loaded.allowlist.is_some(),
    });
    Ok(Some(MethodInputs {
        methods: methods.clone(),
        loaded,
    }))
}

/// Print a sanitized summary (identities, statuses and counts only). Returns
/// whether a scanner did not complete.
fn summarize(artifact: &RunArtifact) -> bool {
    let mut incomplete = false;
    for (identity, run) in artifact.manifest.scanners.iter().zip(&artifact.scanners) {
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
    if !artifact.variants.is_empty() {
        let assertions: usize = artifact.scanners.iter().map(|s| s.assertions.len()).sum();
        eprintln!(
            "{} variants · {} assertions · {} comparisons · {} review occurrences",
            artifact.variants.len(),
            assertions,
            artifact.comparisons.len(),
            artifact.review_queue.len()
        );
    }
    if let Some(execution) = &artifact.non_semantic.execution {
        eprintln!(
            "jobs {} · wall {} ms · scanner processes {} ({} ms) · evaluator {} ms",
            execution.jobs,
            execution.wall_ms,
            execution.processes,
            execution.scanner_process_ms,
            execution.evaluator_ms
        );
    }
    eprintln!(
        "run class {} · publication {}",
        serde_name(&artifact.manifest.run_class),
        serde_name(&artifact.manifest.publication)
    );
    eprintln!("semantic digest {}", artifact.semantic_digest());
    incomplete
}

/// The serialized name of an optional enum value (`unrecorded` when absent).
fn serde_name<T: serde::Serialize>(value: &Option<T>) -> String {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => name,
        _ => "unrecorded".into(),
    }
}

fn fail(error: RunError) -> ExitCode {
    match error {
        RunError::Cancelled => {
            eprintln!("run cancelled; no artifact written");
            ExitCode::from(130)
        }
        error @ RunError::Config(_) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
        error @ RunError::Refused(_) => {
            eprintln!("error: {error}; no artifact written");
            ExitCode::from(4)
        }
        error => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
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
    let mut config = match load_config(&args) {
        Ok(config) => config,
        Err(Usage(message)) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let methods = match method_inputs(&args, &mut config) {
        Ok(methods) => methods,
        Err(Usage(message)) => {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    };
    let run_class = args.run_class.unwrap_or(RunClass::Exploratory);
    let release = match (
        &args.evidence_release,
        &args.evidence_manifest,
        &args.evidence_manifest_digest,
    ) {
        (None, None, None) => None,
        (Some(tag), Some(manifest), Some(digest)) => Some((tag, manifest, digest)),
        _ => {
            eprintln!(
                "error: --evidence-release, --evidence-manifest and --evidence-manifest-digest go together"
            );
            return ExitCode::from(2);
        }
    };
    if run_class == RunClass::Official {
        if release.is_none() {
            eprintln!(
                "error: an official run needs a pinned evidence release \
                 (--evidence-release, --evidence-manifest, --evidence-manifest-digest)"
            );
            return ExitCode::from(2);
        }
        if let Err(message) = official::check_official_config(&config) {
            eprintln!("error: {message}");
            return ExitCode::from(2);
        }
    }
    let corpus_bytes = match fs::read(corpus_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("error: invalid corpus snapshot: {e}");
            return ExitCode::from(1);
        }
    };
    let mut corpus = match CorpusSnapshot::from_json(&corpus_bytes) {
        Ok(corpus) => corpus,
        Err(message) => {
            eprintln!("error: invalid corpus snapshot: {message}");
            return ExitCode::from(1);
        }
    };
    if corpus.identity.release.is_some() {
        eprintln!(
            "error: invalid corpus snapshot: identity.release is recorded by the evaluator \
             after verification; pass --evidence-release instead"
        );
        return ExitCode::from(1);
    }
    if let Some((tag, manifest, digest)) = release {
        let manifest = match read_bounded(
            manifest,
            official::MAX_RELEASE_MANIFEST_BYTES,
            "--evidence-manifest",
        ) {
            Ok(bytes) => bytes,
            Err(message) => {
                eprintln!("error: {message}");
                return ExitCode::from(2);
            }
        };
        match official::verify_release(tag, digest, &manifest, &corpus_bytes) {
            Ok(verified) => corpus.identity.release = Some(verified),
            Err(message) => {
                eprintln!("error: evidence release refused: {message}; no artifact written");
                return ExitCode::from(4);
            }
        }
    }
    drop(corpus_bytes);
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
        enforce_pins: run_class == RunClass::Official,
    };
    let (observations, artifact, method_failure) = match &methods {
        None => match orchestrate::run(&request) {
            Ok(output) => (output.observations, output.artifact, false),
            Err(error) => return fail(error),
        },
        Some(inputs) => {
            let method_request = MethodRequest {
                methods: &inputs.methods,
                evidence: &inputs.loaded.evidence,
                allowlist: inputs.loaded.allowlist.as_ref(),
                limits: GenerationLimits::default(),
            };
            let output = match orchestrate::run_methods(&request, &method_request) {
                Ok(output) => output,
                Err(error) => return fail(error),
            };
            if let Some(path) = &args.legacy_eval_out {
                let view = credential_eval_compat::eval::render(
                    &output.plan,
                    &output.report,
                    &output.observations,
                );
                if let Err(e) = write_atomic(path, &pretty(&view)) {
                    eprintln!("error: cannot write --legacy-eval-out: {e}");
                    return ExitCode::from(1);
                }
            }
            let failed = output
                .report
                .exit_code(args.require_complete, args.fail_on_assertions)
                != 0;
            (output.observations, output.artifact, failed)
        }
    };
    let mut artifact = artifact;
    official::stamp(&mut artifact, run_class);
    if let Some(path) = &args.observations_out {
        if let Err(e) = write_atomic(path, &pretty(&observations)) {
            eprintln!("error: cannot write --observations-out: {e}");
            return ExitCode::from(1);
        }
    }
    if let Err(e) = write_atomic(out, &pretty(&artifact)) {
        eprintln!("error: cannot write --out: {e}");
        return ExitCode::from(1);
    }
    let incomplete = summarize(&artifact);
    if (args.require_complete && incomplete)
        || ((args.require_complete || args.fail_on_assertions) && method_failure)
    {
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

/// `perf` subcommands: measurements that are not detection outcomes (ADR 0002).
fn perf_command(args: &[OsString]) -> ExitCode {
    let Some("run") = args.first().and_then(|a| a.to_str()) else {
        eprintln!("error: perf takes a subcommand: run\n{USAGE}");
        return ExitCode::from(2);
    };
    let (mut config_path, mut out, mut work_dir) = (None, None, None);
    let mut iter = args[1..].iter();
    while let Some(flag) = iter.next() {
        let slot = match flag.to_str() {
            Some("--config") => &mut config_path,
            Some("--out") => &mut out,
            Some("--work-dir") => &mut work_dir,
            _ => {
                eprintln!("error: unknown argument {flag:?}\n{USAGE}");
                return ExitCode::from(2);
            }
        };
        let Some(value) = iter.next() else {
            eprintln!("error: {flag:?} needs a value");
            return ExitCode::from(2);
        };
        *slot = Some(PathBuf::from(value));
    }
    let (Some(config_path), Some(out)) = (config_path, out) else {
        eprintln!("error: perf run needs --config and --out\n{USAGE}");
        return ExitCode::from(2);
    };
    let config: PerformanceConfig =
        match read_bounded(&config_path, 1 << 20, "--config").and_then(|bytes| {
            serde_json::from_slice(&bytes).map_err(|e| format!("invalid --config: {e}"))
        }) {
            Ok(config) => config,
            Err(message) => {
                eprintln!("error: {message}");
                return ExitCode::from(2);
            }
        };
    let cancel = CancelToken::new();
    let handler = cancel.clone();
    if ctrlc::set_handler(move || handler.cancel()).is_err() {
        eprintln!("warning: could not install the interrupt handler");
    }
    let scratch;
    let work_dir = match work_dir {
        Some(dir) => dir,
        None => {
            scratch = match tempfile::tempdir() {
                Ok(dir) => dir,
                Err(e) => {
                    eprintln!("error: cannot create a work directory: {e}");
                    return ExitCode::from(1);
                }
            };
            scratch.path().to_path_buf()
        }
    };
    let artifact = match perf::run_latency(&config, &work_dir, &cancel) {
        Ok(artifact) => artifact,
        Err(perf::PerfError::Cancelled) => {
            eprintln!("run cancelled; no artifact written");
            return ExitCode::from(130);
        }
        Err(error @ perf::PerfError::Config(_)) => {
            eprintln!("error: {error}");
            return ExitCode::from(2);
        }
        Err(error @ perf::PerfError::Subject(_)) => {
            eprintln!("error: {error}; no artifact written");
            return ExitCode::from(4);
        }
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = write_atomic(&out, &pretty(&artifact)) {
        eprintln!("error: cannot write --out: {e}");
        return ExitCode::from(1);
    }
    for result in &artifact.latency {
        eprintln!(
            "{:?}/{:?}: {:?} (median x{:.3}, min x{:.3}, noise ±{:.1}%{})",
            result.workload,
            result.shape,
            result.direction,
            result.median_ratio,
            result.min_ratio,
            result.noise_band * 100.0,
            if result.failed_invocations > 0 {
                format!(", {} failed invocations", result.failed_invocations)
            } else {
                String::new()
            }
        );
    }
    eprintln!("semantic digest {}", artifact.semantic_digest());
    ExitCode::SUCCESS
}

/// `compat` subcommands (migration-only; removed with `credential-eval-compat`).
fn compat_command(args: &[OsString]) -> ExitCode {
    let Some("legacy-bench") = args.first().and_then(|a| a.to_str()) else {
        eprintln!("error: compat takes a subcommand: legacy-bench\n{USAGE}");
        return ExitCode::from(2);
    };
    let (mut artifact, mut index, mut out_dir) = (None, None, None);
    let mut iter = args[1..].iter();
    while let Some(flag) = iter.next() {
        let slot = match flag.to_str() {
            Some("--artifact") => &mut artifact,
            Some("--index") => &mut index,
            Some("--out-dir") => &mut out_dir,
            _ => {
                eprintln!("error: unknown argument {flag:?}\n{USAGE}");
                return ExitCode::from(2);
            }
        };
        let Some(value) = iter.next() else {
            eprintln!("error: {flag:?} needs a value");
            return ExitCode::from(2);
        };
        *slot = Some(PathBuf::from(value));
    }
    let (Some(artifact), Some(index), Some(out_dir)) = (artifact, index, out_dir) else {
        eprintln!("error: legacy-bench needs --artifact, --index and --out-dir\n{USAGE}");
        return ExitCode::from(2);
    };
    let load = || -> Result<_, String> {
        let artifact: RunArtifact = serde_json::from_slice(
            &fs::read(&artifact).map_err(|e| format!("cannot read --artifact: {e}"))?,
        )
        .map_err(|e| format!("invalid artifact: {e}"))?;
        let index: credential_eval_compat::bench::LegacyIndex = serde_json::from_slice(
            &fs::read(&index).map_err(|e| format!("cannot read --index: {e}"))?,
        )
        .map_err(|e| format!("invalid legacy index: {e}"))?;
        credential_eval_compat::bench::render(&artifact, &index).map_err(|e| e.to_string())
    };
    let outputs = match load() {
        Ok(outputs) => outputs,
        Err(message) => {
            eprintln!("error: {message}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = fs::create_dir_all(&out_dir) {
        eprintln!("error: cannot create --out-dir: {e}");
        return ExitCode::from(1);
    }
    for (name, body) in outputs
        .categories
        .iter()
        .map(|(k, v)| (k.as_str(), v))
        .chain([("summary", &outputs.summary)])
    {
        if let Err(e) = write_atomic(&out_dir.join(format!("{name}.json")), &pretty(body)) {
            eprintln!("error: cannot write {name}.json: {e}");
            return ExitCode::from(1);
        }
    }
    eprintln!(
        "wrote {} category files and summary.json",
        outputs.categories.len()
    );
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
        Some("compat") => compat_command(&args[1..]),
        Some("perf") => perf_command(&args[1..]),
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
