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
//!                     [--reuse-observations <observations.json> [--fresh <scanner>]...]
//!                     [--require-complete] [--strict] [--require-fully-measured]
//!                     [--progress-interval <seconds>] [--no-progress]
//! credential-eval compat legacy-bench --artifact <artifact.json> --index <legacy-index.json>
//!                     --out-dir <dir>
//! credential-eval perf run --config <performance-config.json> --out <performance-artifact.json>
//!                     [--work-dir <dir>]
//! credential-eval perf instructions --config <performance-config.json>
//!                     --out <performance-artifact.json> [--valgrind <path>] [--work-dir <dir>]
//! credential-eval perf confirm --artifact <performance-artifact.json> --artifact <...>
//!                     --out <direction-confirmation.json>
//! credential-eval default-config [--scanner <id>]... [--jobs N]
//! credential-eval capabilities
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
//! `--reuse-observations` offers the `--observations-out` of an earlier run
//! over the same fixture bytes: a scanner whose identity is unchanged keeps
//! its recorded observation (launching no scan), every other scanner runs
//! fresh, and `--fresh` forces a scanner to run. A population, protocol or
//! receipt that does not verify is refused (exit 4) instead of being scanned
//! around. Exploratory runs only (`docs/decisions/0008-*`).
//!
//! Progress: unless `--no-progress`, `run` writes bounded `progress ...` lines
//! to stderr (scanner, phase, elapsed time, processed count) and, every
//! `--progress-interval` seconds (default 10, 0 disables), one heartbeat line
//! per running scanner task. Lines hold fixed vocabulary and numbers only.
//! stdout is untouched. See `docs/performance-measurement.md`.
//!
//! Exit codes: 0 artifact written; 1 run failed (no artifact); 2 usage or
//! configuration error; 3 artifact written but `--require-complete`/`--strict`
//! was given and a scanner did not complete (or, for methods, a generation
//! error occurred, or an assertion failed under `--fail-on-assertions`), or
//! `--require-fully-measured` was given and a scanner left a case unmeasured
//! (a configuration that chose per-case handling, ADR 0003);
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
use std::time::{Duration, Instant};

use credential_eval_adapters::AdapterEnv;
use credential_eval_adapters::process::CancelToken;
use credential_eval_cli::evidence;
use credential_eval_cli::official;
use credential_eval_cli::orchestrate::{self, MethodRequest, RunError, RunRequest};
use credential_eval_cli::perf;
use credential_eval_cli::progress::{Event, Kind, Phase, Progress, Silent, StderrProgress};
use credential_eval_contracts::artifact::{RunArtifact, RunClass};
use credential_eval_contracts::config::{EvaluationSettings, RunConfig, SeedConvention};
use credential_eval_contracts::corpus::CorpusSnapshot;
use credential_eval_contracts::ids::ScannerId;
use credential_eval_contracts::observation::{ObservationSet, ScannerStatus};
use credential_eval_contracts::performance::{PerformanceArtifact, PerformanceConfig};
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
                      [--reuse-observations <observations.json> [--fresh <scanner>]...]
                      [--require-complete] [--strict] [--require-fully-measured]
                      [--progress-interval <seconds>] [--no-progress]
  credential-eval compat legacy-bench --artifact <artifact.json>
                      --index <legacy-index.json> --out-dir <dir>
  credential-eval perf run --config <performance-config.json>
                      --out <performance-artifact.json> [--work-dir <dir>]
  credential-eval perf instructions --config <performance-config.json>
                      --out <performance-artifact.json> [--valgrind <path>] [--work-dir <dir>]
  credential-eval perf confirm --artifact <performance-artifact.json>
                      --artifact <performance-artifact.json>... --out <direction-confirmation.json>
  credential-eval default-config [--scanner <id>]... [--jobs N]
  credential-eval capabilities
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
    require_fully_measured: bool,
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
    no_progress: bool,
    progress_interval: Option<u64>,
    reuse_observations: Option<PathBuf>,
    fresh: Vec<String>,
}

/// Largest observation set accepted by `--reuse-observations`, in bytes.
const MAX_REUSE_BYTES: u64 = 512 * 1024 * 1024;

/// Default seconds between heartbeat lines.
const DEFAULT_PROGRESS_INTERVAL: u64 = 10;
/// Longest accepted heartbeat interval, in seconds (bounds the silence).
const MAX_PROGRESS_INTERVAL: u64 = 3600;

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
            "--reuse-observations" => parsed.reuse_observations = Some(value()?.into()),
            "--fresh" => parsed.fresh.push(
                value()?
                    .into_string()
                    .map_err(|_| usage("--fresh must be UTF-8"))?,
            ),
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
            "--require-fully-measured" => parsed.require_fully_measured = true,
            "--fail-on-assertions" => parsed.fail_on_assertions = true,
            "--no-progress" => parsed.no_progress = true,
            "--progress-interval" => {
                parsed.progress_interval = Some(
                    value()?
                        .to_str()
                        .and_then(|s| s.parse().ok())
                        .filter(|n| *n <= MAX_PROGRESS_INTERVAL)
                        .ok_or_else(|| {
                            usage(format!(
                                "--progress-interval takes 0..={MAX_PROGRESS_INTERVAL} seconds"
                            ))
                        })?,
                );
            }
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

/// ` (method: n, ...)` for an evaluation-method run: the unmeasured variants
/// of one scanner by the method that generated them (ADR 0004). Empty for a
/// plain run, whose cases are not variants.
fn unmeasured_by_method(
    artifact: &RunArtifact,
    run: &credential_eval_contracts::artifact::ScannerRun,
) -> String {
    if artifact.variants.is_empty() {
        return String::new();
    }
    let path_of: std::collections::BTreeMap<_, _> =
        run.cases.iter().map(|c| (&c.case_id, &c.path)).collect();
    let method_of: std::collections::BTreeMap<_, _> = artifact
        .variants
        .iter()
        .map(|v| (&v.path, v.method.id.as_str()))
        .collect();
    let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for u in &run.unmeasured_cases {
        let method = path_of
            .get(&u.case_id)
            .and_then(|p| method_of.get(p))
            .copied()
            .unwrap_or("unknown");
        *counts.entry(method).or_default() += 1;
    }
    let parts: Vec<String> = counts.iter().map(|(m, n)| format!("{m}: {n}")).collect();
    format!(" (variants by method: {})", parts.join(", "))
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
        if !run.unmeasured_cases.is_empty() {
            eprintln!(
                "{} unmeasured: {} of {} cases could not be mapped to ranges and are in no denominator{}",
                identity.id,
                run.unmeasured_cases.len(),
                run.cases.len(),
                unmeasured_by_method(artifact, run)
            );
        }
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
    if let Some(execution) = &artifact.non_semantic.execution {
        if let Some(p) = &execution.phases {
            eprintln!(
                "phases: materialize {} ms · generate {} ms · prepare {} ms · scan {} ms · evaluate {} ms ({} cases, {} fixtures)",
                p.materialize_ms,
                p.generate_ms,
                p.prepare_ms,
                p.scan_ms,
                p.evaluate_ms,
                p.cases,
                p.fixtures
            );
        }
        for (id, t) in &execution.scanners {
            if let (Some(origin), Some(reason)) = (t.origin, &t.origin_reason) {
                eprintln!("origin {id}: {} ({reason})", serde_name(&Some(origin)));
            }
            eprintln!(
                "timing {id}: queue {} ms · process {} ms · normalize {} ms · {} tasks · {} B received · {} findings · {}{}",
                t.queue_ms,
                t.process_ms,
                t.normalize_ms,
                t.tasks,
                t.received_bytes,
                t.findings,
                serde_name(&Some(t.completion)),
                t.failed_phase
                    .map(|p| format!(" (failed in {})", p.name()))
                    .unwrap_or_default()
            );
        }
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
        error @ (RunError::Refused(_) | RunError::ReuseRefused(_)) => {
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
    if args.reuse_observations.is_none() && !args.fresh.is_empty() {
        eprintln!("error: --fresh needs --reuse-observations");
        return ExitCode::from(2);
    }
    if args.reuse_observations.is_some() && run_class == RunClass::Official {
        eprintln!(
            "error: an official run measures every scanner fresh; --reuse-observations \
             is for exploratory runs (docs/decisions/0008)"
        );
        return ExitCode::from(2);
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

    let source = match &args.reuse_observations {
        None => None,
        Some(path) => {
            match read_bounded(path, MAX_REUSE_BYTES, "--reuse-observations").and_then(|bytes| {
                serde_json::from_slice::<ObservationSet>(&bytes).map_err(|e| {
                    format!("--reuse-observations is not a valid observation set: {e}")
                })
            }) {
                Ok(set) => Some(set),
                Err(message) => {
                    eprintln!("error: observation reuse refused: {message}; no artifact written");
                    return ExitCode::from(4);
                }
            }
        }
    };
    let mut fresh = std::collections::BTreeSet::new();
    for id in &args.fresh {
        match ScannerId::new(id.clone()) {
            Ok(id) => {
                fresh.insert(id);
            }
            Err(e) => {
                eprintln!("error: --fresh: {e}");
                return ExitCode::from(2);
            }
        }
    }
    let reuse = source.as_ref().map(|source| orchestrate::ReuseRequest {
        source,
        fresh: &fresh,
    });

    let cancel = CancelToken::new();
    let handler = cancel.clone();
    if ctrlc::set_handler(move || handler.cancel()).is_err() {
        eprintln!("warning: could not install the interrupt handler");
    }
    let run_started = Instant::now();
    let interval = args.progress_interval.unwrap_or(DEFAULT_PROGRESS_INTERVAL);
    let progress = StderrProgress::new((interval > 0).then(|| Duration::from_secs(interval)));
    let silent = Silent;
    let progress: &dyn Progress = if args.no_progress { &silent } else { &progress };
    let request = RunRequest {
        corpus: &corpus,
        config: &config,
        env: &env,
        work_dir: args.work_dir.as_deref(),
        cancel: &cancel,
        enforce_pins: run_class == RunClass::Official,
        progress,
        reuse: reuse.as_ref(),
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
    let serialize = Instant::now();
    if !args.no_progress {
        progress.event(&Event {
            scanner: None,
            phase: Phase::Serialize,
            kind: Kind::Start,
            run_elapsed: run_started.elapsed(),
            elapsed: None,
            processed: None,
            status: None,
        });
    }
    let artifact_bytes = pretty(&artifact);
    if let Err(e) = write_atomic(out, &artifact_bytes) {
        eprintln!("error: cannot write --out: {e}");
        return ExitCode::from(1);
    }
    if !args.no_progress {
        progress.event(&Event {
            scanner: None,
            phase: Phase::Serialize,
            kind: Kind::End,
            run_elapsed: run_started.elapsed(),
            elapsed: Some(serialize.elapsed()),
            processed: Some((artifact_bytes.len() as u64, artifact_bytes.len() as u64)),
            status: None,
        });
    }
    let incomplete = summarize(&artifact);
    let gaps = artifact
        .scanners
        .iter()
        .any(|s| !s.unmeasured_cases.is_empty());
    if (args.require_fully_measured && gaps)
        || (args.require_complete && incomplete)
        || ((args.require_complete || args.fail_on_assertions) && method_failure)
    {
        return ExitCode::from(3);
    }
    ExitCode::SUCCESS
}

/// `perf` subcommands: measurements that are not detection outcomes (ADR 0002).
fn perf_command(args: &[OsString]) -> ExitCode {
    let instructions = match args.first().and_then(|a| a.to_str()) {
        Some("run") => false,
        Some("instructions") => true,
        Some("confirm") => return perf_confirm(&args[1..]),
        _ => {
            eprintln!("error: perf takes a subcommand: run, instructions, confirm\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    let (mut config_path, mut out, mut work_dir, mut valgrind) = (None, None, None, None);
    let mut iter = args[1..].iter();
    while let Some(flag) = iter.next() {
        let slot = match flag.to_str() {
            Some("--config") => &mut config_path,
            Some("--out") => &mut out,
            Some("--work-dir") => &mut work_dir,
            Some("--valgrind") if instructions => &mut valgrind,
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
        eprintln!("error: perf run and perf instructions need --config and --out\n{USAGE}");
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
    let result = if instructions {
        let valgrind = valgrind.unwrap_or_else(|| PathBuf::from("valgrind"));
        let valgrind = if valgrind.components().count() > 1 {
            Some(valgrind)
        } else {
            credential_eval_adapters::provenance::which(
                &valgrind.to_string_lossy(),
                std::env::var_os("PATH").as_deref(),
            )
        };
        match valgrind {
            Some(valgrind) => perf::run_instructions(&config, &valgrind, &work_dir, &cancel),
            None => Err(perf::PerfError::Subject(
                "valgrind not found on PATH".into(),
            )),
        }
    } else {
        perf::run_latency(&config, &work_dir, &cancel)
    };
    let artifact = match result {
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
    for result in &artifact.instructions {
        eprintln!(
            "{:?}: {:?} (instructions x{:.4}, band ±{:.2}%{})",
            result.workload,
            result.direction,
            result.ratio,
            result.noise_band * 100.0,
            if result.failed_invocations > 0 {
                format!(", {} failed invocations", result.failed_invocations)
            } else {
                String::new()
            }
        );
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

/// `perf confirm`: combine independent latency runs into confirmed directions.
fn perf_confirm(args: &[OsString]) -> ExitCode {
    let (mut artifacts, mut out) = (Vec::new(), None);
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let Some(value) = iter.next() else {
            eprintln!("error: {flag:?} needs a value");
            return ExitCode::from(2);
        };
        match flag.to_str() {
            Some("--artifact") => artifacts.push(PathBuf::from(value)),
            Some("--out") => out = Some(PathBuf::from(value)),
            _ => {
                eprintln!("error: unknown argument {flag:?}\n{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(out) = out else {
        eprintln!("error: perf confirm needs --artifact (twice or more) and --out\n{USAGE}");
        return ExitCode::from(2);
    };
    let mut loaded = Vec::new();
    for path in &artifacts {
        match read_bounded(path, 64 << 20, "--artifact").and_then(|bytes| {
            serde_json::from_slice::<PerformanceArtifact>(&bytes)
                .map_err(|e| format!("invalid --artifact {}: {e}", path.display()))
        }) {
            Ok(artifact) => loaded.push(artifact),
            Err(message) => {
                eprintln!("error: {message}");
                return ExitCode::from(2);
            }
        }
    }
    let refs: Vec<&PerformanceArtifact> = loaded.iter().collect();
    let confirmation = match credential_eval_perf::confirm::confirm(&refs) {
        Ok(confirmation) => confirmation,
        Err(error) => {
            eprintln!("error: {error}; no confirmation written");
            return ExitCode::from(2);
        }
    };
    if let Err(e) = write_atomic(&out, &pretty(&confirmation)) {
        eprintln!("error: cannot write --out: {e}");
        return ExitCode::from(1);
    }
    for result in &confirmation.results {
        eprintln!(
            "{:?}/{:?}: {:?} {:?}",
            result.workload, result.shape, result.status, result.directions
        );
    }
    let confirmed = confirmation
        .results
        .iter()
        .filter(|r| {
            matches!(
                r.status,
                credential_eval_contracts::performance::Confirmation::ConfirmedFaster
                    | credential_eval_contracts::performance::Confirmation::ConfirmedSlower
            )
        })
        .count();
    eprintln!(
        "{} runs · {confirmed} of {} cells confirmed · same CPU model: {}",
        confirmation.runs.len(),
        confirmation.results.len(),
        match confirmation.same_cpu_model {
            Some(true) => "yes",
            Some(false) => "NO",
            None => "unrecorded",
        }
    );
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

/// What this build supports, for a consumer that pins an engine version: the
/// contract revision, the representation contract it reads and reports, and
/// the opt-in decoded-finding mapping of each adapter. Stable, sorted JSON.
fn capabilities() -> serde_json::Value {
    use credential_eval_adapters::decode::{DECODED_MAPPING_KEY, MAX_DEPTH, SOURCE_SEGMENT};
    use credential_eval_contracts::representation::{CONTRACT_REVISION, REPRESENTATION_CONTRACT};
    serde_json::json!({
        "engine": {
            "name": credential_eval_contracts::ENGINE_NAME,
            "version": credential_eval_kernel::score::ENGINE_VERSION,
        },
        "protocol_version": credential_eval_contracts::PROTOCOL_VERSION,
        "contract_revision": CONTRACT_REVISION,
        "schemas": [
            "credential-eval/corpus-snapshot/v1",
            "credential-eval/observation-set/v1",
            "credential-eval/run-artifact/v1",
            "credential-eval/run-config/v1",
        ],
        "representation": {
            "contract": REPRESENTATION_CONTRACT,
            "snapshot_fields": [
                "cases[].expected[].base",
                "cases[].expected[].decoded",
                "cases[].expected[].fragments",
                "cases[].representation",
                "identity.representation",
            ],
            "input_validity": ["unpaired-surrogate-split", "valid"],
            "input_validity_refused": ["invalid-utf8"],
            "decode_steps_verified": ["base64", "hex", "strip-codepoints"],
            "decode_steps_carried_unverified": ["normalize"],
            "artifact_fields": [
                "manifest.representation",
                "scanners[].cases[].actual[].mapping",
                "scanners[].findings[].mapping",
            ],
            "decoded_mapping": {
                "configuration_key": DECODED_MAPPING_KEY,
                "values": ["off", SOURCE_SEGMENT],
                "max_depth": MAX_DEPTH,
                "adapters": {
                    "gitleaks": ["base64", "hex"],
                    "trufflehog": ["base64"],
                },
            },
        },
    })
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
        Some("capabilities") => {
            let mut text =
                serde_json::to_string_pretty(&capabilities()).expect("capabilities serialize");
            text.push('\n');
            print!("{text}");
            ExitCode::SUCCESS
        }
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
