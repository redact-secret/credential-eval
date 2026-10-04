//! Run orchestration: corpus → materialized fixtures → bounded parallel scanner
//! execution → normalized observations → kernel artifact.
//!
//! Scheduling never changes semantics. Every (scanner, replay) task writes its
//! result into a slot indexed by its position in a fixed task list, and
//! collation reads the slots in that order, so completion order cannot leak
//! into the artifact. Concurrency is bounded globally (`jobs`) and per scanner
//! (`limits.concurrency`); each process is bounded by its scanner limits.
//! Raw scanner output lives only inside a task: it is normalized and dropped
//! before the task returns.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use credential_eval_adapters::process::{self, CancelToken};
use credential_eval_adapters::{
    Adapter, AdapterEnv, Fixtures, NormalizedFinding, ObservationResult, Prepared, ScannerIdentity,
    ScannerObservation, ScannerProvenance, classify, request,
};
use credential_eval_contracts::artifact::{ExecutionDiagnostics, RunArtifact};
use credential_eval_contracts::config::{RunConfig, ScannerSpec, SeedConvention};
use credential_eval_contracts::corpus::CorpusSnapshot;
use credential_eval_contracts::ids::FixturePath;
use credential_eval_contracts::observation::{ObservationSet, Replays, UnmeasuredPath};
use credential_eval_contracts::schema::ObservationSetSchema;
use credential_eval_kernel::evaluation::cases::build_cases;
use credential_eval_kernel::evaluation::{
    EvaluateOptions, EvaluationEvidence, EvaluationPlan, EvaluationReport, GenerationLimits,
    MethodId, evaluate, plan_evaluation,
};
use credential_eval_kernel::observe::restrict_observations;

/// A run-level failure (the run produces no artifact).
#[derive(Debug)]
pub enum RunError {
    /// Invalid run configuration.
    Config(String),
    /// Corpus could not be read or is invalid.
    Corpus(String),
    /// Materialization or output I/O failed.
    Io(String),
    /// The run was cancelled.
    Cancelled,
    /// An official run refused its inputs (a scanner did not match its pin).
    Refused(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(m) => write!(f, "invalid run configuration: {m}"),
            Self::Corpus(m) => write!(f, "invalid corpus snapshot: {m}"),
            Self::Io(m) => write!(f, "I/O error: {m}"),
            Self::Cancelled => write!(f, "run cancelled"),
            Self::Refused(m) => write!(f, "official run refused: {m}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Inputs of one run.
pub struct RunRequest<'a> {
    /// Validated corpus.
    pub corpus: &'a CorpusSnapshot,
    /// Run configuration (its `execution.jobs` is the global job bound).
    pub config: &'a RunConfig,
    /// Adapter host environment.
    pub env: &'a AdapterEnv,
    /// Parent directory for the temporary materialization (system temp when `None`).
    pub work_dir: Option<&'a Path>,
    /// Cancellation.
    pub cancel: &'a CancelToken,
    /// Official run: refuse to scan unless every scanner resolved to its
    /// `pin` ([`crate::official::check_pin`]). Exploratory runs ignore pins.
    pub enforce_pins: bool,
}

/// Result of a run.
pub struct RunOutput {
    /// The observations handed to the kernel.
    pub observations: ObservationSet,
    /// The artifact, including non-semantic execution diagnostics.
    pub artifact: RunArtifact,
}

struct Scanner {
    spec: ScannerSpec,
    adapter: Box<dyn Adapter>,
}

/// Check the configuration and bind every scanner to its adapter.
fn bind(config: &RunConfig) -> Result<Vec<Scanner>, RunError> {
    if config.execution.jobs == 0 {
        return Err(RunError::Config("execution.jobs must be at least 1".into()));
    }
    if config.accounting.replays == 0 {
        return Err(RunError::Config(
            "accounting.replays must be at least 1".into(),
        ));
    }
    if config.scanners.is_empty() {
        return Err(RunError::Config("no scanners selected".into()));
    }
    let mut seen = BTreeSet::new();
    let mut scanners = Vec::new();
    for spec in &config.scanners {
        if !seen.insert(spec.id.clone()) {
            return Err(RunError::Config(format!(
                "duplicate scanner id {}",
                spec.id
            )));
        }
        let adapter =
            credential_eval_adapters::find(spec.adapter.id.as_str()).ok_or_else(|| {
                RunError::Config(format!(
                    "scanner {} names unknown adapter {}",
                    spec.id, spec.adapter.id
                ))
            })?;
        let implemented = adapter.identity();
        if implemented.version != spec.adapter.version {
            return Err(RunError::Config(format!(
                "scanner {} expects adapter {} version {}, but version {} is built in",
                spec.id, spec.adapter.id, spec.adapter.version, implemented.version
            )));
        }
        let limits = &spec.limits;
        if limits.concurrency == 0 || limits.timeout_ms == 0 || limits.max_stdout_bytes == 0 {
            return Err(RunError::Config(format!(
                "scanner {} limits must be positive (timeout, stdout cap, concurrency)",
                spec.id
            )));
        }
        scanners.push(Scanner {
            spec: spec.clone(),
            adapter,
        });
    }
    scanners.sort_by(|a, b| a.spec.id.cmp(&b.spec.id));
    Ok(scanners)
}

/// Materialize every case under a fresh private temporary directory. The
/// directory is removed when the returned guard drops (including on error).
fn materialize(
    corpus: &CorpusSnapshot,
    parent: Option<&Path>,
) -> Result<(tempfile::TempDir, PathBuf), RunError> {
    let io = |e: std::io::Error| RunError::Io(e.to_string());
    let mut builder = tempfile::Builder::new();
    builder.prefix("credential-eval-");
    let dir = match parent {
        Some(parent) => builder.tempdir_in(parent),
        None => builder.tempdir(),
    }
    .map_err(io)?;
    // Scanners report paths under the canonical root (e.g. /private/var on macOS).
    let root = dir.path().canonicalize().map_err(io)?;
    for case in &corpus.cases {
        let target = root.join(case.path.as_str());
        if let Some(parent) = target.parent() {
            create_private_dirs(parent).map_err(io)?;
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&target).map_err(io)?;
        file.write_all(case.content.as_bytes()).map_err(io)?;
    }
    Ok((dir, root))
}

fn create_private_dirs(path: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// Outcome of one scan task.
enum TaskResult {
    /// Normalized, range-checked findings in adapter emission order, and the
    /// fixtures the adapter could not map (sorted by path).
    Findings(Vec<NormalizedFinding>, Vec<UnmeasuredPath>),
    /// Explicit failure.
    Failed(ObservationResult),
    /// Not run: an earlier replay of the same scanner already failed.
    Skipped,
}

struct Task {
    scanner: usize,
    replay: u32,
}

struct Slot {
    result: TaskResult,
    process: Duration,
    normalize: Duration,
}

struct Queue {
    pending: VecDeque<usize>,
    running: Vec<u32>,
    /// Lowest failed replay per scanner; later replays are skipped.
    failed: Vec<Option<u32>>,
}

/// Timing of a run, accumulated across its phases (non-semantic).
struct Timing {
    wall: Instant,
    started_at: String,
    evaluator: Duration,
    processes: u64,
    scanner_process: Duration,
}

impl Timing {
    fn start() -> Self {
        Self {
            wall: Instant::now(),
            started_at: crate::time::now_rfc3339(),
            evaluator: Duration::ZERO,
            processes: 0,
            scanner_process: Duration::ZERO,
        }
    }

    /// Record the run's non-semantic metadata on `artifact`.
    fn stamp(self, artifact: &mut RunArtifact, jobs: u32) {
        artifact.non_semantic.started_at = Some(self.started_at);
        artifact.non_semantic.finished_at = Some(crate::time::now_rfc3339());
        artifact.non_semantic.host = Some(format!(
            "{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
        artifact.non_semantic.execution = Some(ExecutionDiagnostics {
            jobs,
            processes: self.processes,
            wall_ms: millis(self.wall.elapsed()),
            scanner_process_ms: millis(self.scanner_process),
            evaluator_ms: millis(self.evaluator),
        });
    }
}

/// Execute `request` and build the artifact (a corpus measurement: the
/// legacy `bench` pipeline).
pub fn run(request: &RunRequest<'_>) -> Result<RunOutput, RunError> {
    let mut timing = Timing::start();
    request
        .corpus
        .validate()
        .map_err(|e| RunError::Corpus(e.to_string()))?;
    let observations = scan(request, request.corpus, &mut timing)?;
    let phase = Instant::now();
    let artifact = credential_eval_kernel::score::build_artifact(
        request.corpus,
        request.config,
        &observations,
    )
    .map_err(|e| RunError::Config(e.to_string()))?;
    timing.evaluator += phase.elapsed();
    let mut artifact = artifact;
    timing.stamp(&mut artifact, request.config.execution.jobs);
    Ok(RunOutput {
        observations,
        artifact,
    })
}

/// Scan `corpus` with every configured scanner: materialize, execute bounded
/// parallel (scanner, replay) tasks, and collate observations
/// deterministically. The materialized fixtures are removed before return.
fn scan(
    request: &RunRequest<'_>,
    corpus: &CorpusSnapshot,
    timing: &mut Timing,
) -> Result<ObservationSet, RunError> {
    let mut evaluator = Duration::ZERO;
    let mut processes = 0u64;
    let mut scanner_process = Duration::ZERO;

    let phase = Instant::now();
    let scanners = bind(request.config)?;
    let (guard, root) = materialize(corpus, request.work_dir)?;
    let mut paths: Vec<&str> = corpus.cases.iter().map(|c| c.path.as_str()).collect();
    paths.sort_unstable();
    let fixtures = Fixtures::new(
        root.clone(),
        corpus
            .cases
            .iter()
            .map(|c| (c.path.as_str(), c.content.as_str())),
    );
    evaluator += phase.elapsed();

    // Prepare every scanner (bounded version probes).
    let mut prepared: Vec<Result<Prepared, Box<credential_eval_adapters::PrepareFailure>>> =
        Vec::new();
    for scanner in &scanners {
        if request.cancel.is_cancelled() {
            return Err(RunError::Cancelled);
        }
        let result = scanner
            .adapter
            .prepare(&scanner.spec, request.env, request.cancel);
        let (count, time) = match &result {
            Ok(p) => (p.processes, p.process_time),
            Err(f) => (f.processes, f.process_time),
        };
        processes += count;
        scanner_process += time;
        prepared.push(result);
    }
    if request.enforce_pins {
        // Before any scan runs: an official run never measures an unpinned
        // or mismatched scanner.
        for (scanner, result) in scanners.iter().zip(&prepared) {
            let (version, provenance) = match result {
                Ok(p) => (p.version.as_deref(), &p.provenance),
                Err(f) => (f.version.as_deref(), &f.provenance),
            };
            crate::official::check_pin(&scanner.spec, version, provenance)
                .map_err(RunError::Refused)?;
        }
    }

    // Fixed task list: scanners in id order, replays ascending.
    let replays = request.config.accounting.replays;
    let tasks: Vec<Task> = prepared
        .iter()
        .enumerate()
        .filter(|(_, p)| p.is_ok())
        .flat_map(|(scanner, _)| (0..replays).map(move |replay| Task { scanner, replay }))
        .collect();
    let slots: Vec<Mutex<Option<Slot>>> = tasks.iter().map(|_| Mutex::new(None)).collect();
    let queue = Mutex::new(Queue {
        pending: (0..tasks.len()).collect(),
        running: vec![0; scanners.len()],
        failed: vec![None; scanners.len()],
    });
    let wake = Condvar::new();
    let jobs = usize::try_from(request.config.execution.jobs)
        .unwrap_or(usize::MAX)
        .min(tasks.len().max(1));

    thread::scope(|scope| {
        for _ in 0..jobs {
            scope.spawn(|| {
                loop {
                    let mut state = queue.lock().expect("queue lock");
                    let next = loop {
                        if request.cancel.is_cancelled() {
                            break None;
                        }
                        // Drop tasks made moot by an earlier failed replay.
                        let failed = state.failed.clone();
                        let before = state.pending.len();
                        state.pending.retain(|&i| {
                            let t = &tasks[i];
                            let moot = failed[t.scanner].is_some_and(|f| t.replay > f);
                            if moot {
                                *slots[i].lock().expect("slot lock") = Some(Slot {
                                    result: TaskResult::Skipped,
                                    process: Duration::ZERO,
                                    normalize: Duration::ZERO,
                                });
                            }
                            !moot
                        });
                        if state.pending.len() != before {
                            wake.notify_all();
                        }
                        let eligible = state.pending.iter().position(|&i| {
                            let s = tasks[i].scanner;
                            state.running[s] < scanners[s].spec.limits.concurrency
                        });
                        if let Some(position) = eligible {
                            let index = state.pending.remove(position).expect("position");
                            state.running[tasks[index].scanner] += 1;
                            break Some(index);
                        }
                        if state.pending.is_empty() {
                            break None;
                        }
                        state = wake
                            .wait_timeout(state, Duration::from_millis(50))
                            .expect("queue lock")
                            .0;
                    };
                    drop(state);
                    let Some(index) = next else {
                        wake.notify_all();
                        return;
                    };
                    let task = &tasks[index];
                    let scanner = &scanners[task.scanner];
                    let ready = prepared[task.scanner].as_ref().expect("prepared scanner");
                    let slot = execute(scanner, ready, &root, &paths, &fixtures, request.cancel);
                    let failed = matches!(slot.result, TaskResult::Failed(_));
                    *slots[index].lock().expect("slot lock") = Some(slot);
                    let mut state = queue.lock().expect("queue lock");
                    state.running[task.scanner] -= 1;
                    if failed {
                        let entry = &mut state.failed[task.scanner];
                        *entry = Some(entry.map_or(task.replay, |f| f.min(task.replay)));
                    }
                    drop(state);
                    wake.notify_all();
                }
            });
        }
    });
    if request.cancel.is_cancelled() {
        return Err(RunError::Cancelled);
    }

    // Deterministic collation in task-list order.
    let phase = Instant::now();
    let mut per_scanner: Vec<Vec<(u32, TaskResult)>> =
        scanners.iter().map(|_| Vec::new()).collect();
    let mut durations: Vec<Duration> = prepared
        .iter()
        .map(|p| match p {
            Ok(p) => p.process_time,
            Err(f) => f.process_time,
        })
        .collect();
    for (task, slot) in tasks.iter().zip(slots) {
        let slot = slot.into_inner().expect("slot lock").unwrap_or(Slot {
            result: TaskResult::Skipped,
            process: Duration::ZERO,
            normalize: Duration::ZERO,
        });
        if !matches!(slot.result, TaskResult::Skipped) {
            processes += 1;
        }
        scanner_process += slot.process;
        durations[task.scanner] += slot.process;
        evaluator += slot.normalize;
        per_scanner[task.scanner].push((task.replay, slot.result));
    }
    let observations: Vec<ScannerObservation> = scanners
        .iter()
        .zip(prepared)
        .zip(per_scanner)
        .zip(durations)
        .map(|(((scanner, prepared), results), duration)| {
            observe(scanner, prepared, results, replays, duration)
        })
        .collect();
    let observations = ObservationSet {
        schema: ObservationSetSchema,
        corpus_digest: corpus.identity.corpus_digest.clone(),
        observations,
    };
    drop(guard); // remove the materialized fixtures
    evaluator += phase.elapsed();
    timing.evaluator += evaluator;
    timing.processes += processes;
    timing.scanner_process += scanner_process;
    Ok(observations)
}

/// Inputs of an evaluation-method run beyond [`RunRequest`].
pub struct MethodRequest<'a> {
    /// Methods to apply.
    pub methods: &'a [MethodId],
    /// Evaluation evidence (family contracts, validators, taxonomies).
    pub evidence: &'a EvaluationEvidence,
    /// Classification allowlist applied to findings before evaluation
    /// (`None`: families pass through).
    pub allowlist: Option<&'a BTreeSet<String>>,
    /// Generation bounds.
    pub limits: GenerationLimits,
}

/// Result of an evaluation-method run.
pub struct MethodOutput {
    /// The generated plan (its variant corpus is what the scanners saw).
    pub plan: EvaluationPlan,
    /// Observations over the variant corpus, after the family allowlist.
    pub observations: ObservationSet,
    /// The evaluation report.
    pub report: EvaluationReport,
    /// The canonical artifact.
    pub artifact: RunArtifact,
}

/// Execute an evaluation-method run (the legacy `eval` pipeline): build the
/// cases of `request.corpus`, generate every variant before any scanner runs,
/// scan the variant corpus, then evaluate. `request.config.evaluation` must
/// be set; its reference and seed convention drive the kernel.
pub fn run_methods(
    request: &RunRequest<'_>,
    methods: &MethodRequest<'_>,
) -> Result<MethodOutput, RunError> {
    let mut timing = Timing::start();
    let settings = request.config.evaluation.as_ref().ok_or_else(|| {
        RunError::Config("an evaluation-method run needs evaluation settings".into())
    })?;
    if methods.methods.is_empty() {
        return Err(RunError::Config("no evaluation methods selected".into()));
    }
    if let Some(reference) = &settings.reference {
        if !request.config.scanners.iter().any(|s| &s.id == reference) {
            return Err(RunError::Config(format!(
                "reference scanner {reference} is not a configured scanner"
            )));
        }
    }
    let phase = Instant::now();
    request
        .corpus
        .validate()
        .map_err(|e| RunError::Corpus(e.to_string()))?;
    let seed: &dyn Fn(&credential_eval_contracts::corpus::Case) -> String = match settings.seed {
        SeedConvention::CaseId => &credential_eval_kernel::evaluation::cases::case_id_seed,
        SeedConvention::LegacyCategory => &credential_eval_kernel::compat::legacy_seed,
    };
    let cases = build_cases(request.corpus, methods.methods, seed)
        .map_err(|e| RunError::Corpus(e.to_string()))?;
    let plan = plan_evaluation(cases, methods.evidence, &methods.limits)
        .map_err(|e| RunError::Corpus(e.to_string()))?;
    let variants = plan.variant_corpus(&request.corpus.identity);
    timing.evaluator += phase.elapsed();

    let observed = scan(request, &variants, &mut timing)?;

    let phase = Instant::now();
    let observations = match methods.allowlist {
        Some(allowlist) => restrict_observations(&observed, allowlist),
        None => observed,
    };
    let report = evaluate(
        &plan,
        &request.corpus.identity,
        &observations,
        EvaluateOptions {
            reference: settings.reference.as_ref(),
            accounting: &request.config.accounting,
        },
    )
    .map_err(|e| RunError::Config(e.to_string()))?;
    let mut artifact = report
        .artifact(&plan, request.corpus, request.config, &observations)
        .map_err(|e| RunError::Config(e.to_string()))?;
    timing.evaluator += phase.elapsed();
    timing.stamp(&mut artifact, request.config.execution.jobs);
    Ok(MethodOutput {
        plan,
        observations,
        report,
        artifact,
    })
}

fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Run one scan and normalize its output. Raw stdout never leaves here.
fn execute(
    scanner: &Scanner,
    prepared: &Prepared,
    root: &Path,
    paths: &[&str],
    fixtures: &Fixtures<'_>,
    cancel: &CancelToken,
) -> Slot {
    let invocation = scanner.adapter.scan_invocation(prepared, root, paths);
    let run = process::run(&request(invocation, root, &scanner.spec.limits), cancel);
    let process = run.elapsed;
    let started = Instant::now();
    let result = match classify(scanner.adapter.as_ref(), run, &scanner.spec.limits) {
        Err(failure) => TaskResult::Failed(failure),
        Ok(stdout) => {
            let normalized = scanner
                .adapter
                .normalize_measured(prepared, &stdout, fixtures);
            drop(stdout);
            match normalized {
                Err(error) => TaskResult::Failed(ObservationResult::Malformed {
                    reason: format!("scanner output could not be mapped to ranges: {error}"),
                }),
                Ok(credential_eval_adapters::Measured {
                    findings,
                    unmeasured,
                }) => {
                    let unmeasured: Vec<UnmeasuredPath> = unmeasured
                        .into_iter()
                        .map(|(path, reason)| UnmeasuredPath {
                            path,
                            reason: format!(
                                "scanner output could not be mapped to ranges: {reason}"
                            ),
                        })
                        .collect();
                    let valid = findings.iter().all(|f| {
                        fixtures
                            .content(f.path.as_str())
                            .is_some_and(|text| f.range().is_valid_in(text))
                    });
                    if valid {
                        TaskResult::Findings(findings, unmeasured)
                    } else {
                        TaskResult::Failed(ObservationResult::Malformed {
                            reason:
                                "scanner finding is not a valid UTF-8 byte range of its fixture"
                                    .into(),
                        })
                    }
                }
            }
        }
    };
    Slot {
        result,
        process,
        normalize: started.elapsed(),
    }
}

/// Collate one scanner's replays into its observation.
fn observe(
    scanner: &Scanner,
    prepared: Result<Prepared, Box<credential_eval_adapters::PrepareFailure>>,
    results: Vec<(u32, TaskResult)>,
    replays: u32,
    duration: Duration,
) -> ScannerObservation {
    let identity = |version: Option<String>, provenance: ScannerProvenance| ScannerIdentity {
        id: scanner.spec.id.clone(),
        version,
        mode: scanner.spec.mode.clone(),
        adapter: scanner.spec.adapter.clone(),
        configuration_hash: scanner.spec.configuration_hash(),
        provenance: Some(provenance),
        build: Some(scanner.adapter.build(&scanner.spec)),
    };
    let duration_ms = Some(millis(duration));
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(failure) => {
            return ScannerObservation {
                scanner: identity(failure.version, failure.provenance),
                result: failure.result,
                duration_ms,
            };
        }
    };
    let scanner_identity = identity(prepared.version, prepared.provenance);
    let mut runs: Vec<Vec<NormalizedFinding>> = Vec::new();
    let mut gaps: Vec<Vec<UnmeasuredPath>> = Vec::new();
    for (_, result) in results {
        match result {
            TaskResult::Findings(findings, unmeasured) => {
                runs.push(findings);
                gaps.push(unmeasured);
            }
            // The lowest failed replay decides; later replays were skipped.
            TaskResult::Failed(failure) => {
                return ScannerObservation {
                    scanner: scanner_identity,
                    result: failure,
                    duration_ms,
                };
            }
            TaskResult::Skipped => {}
        }
    }
    let result = if runs.len() != replays as usize {
        ObservationResult::Error {
            reason: "scanner replays did not all run".into(),
        }
    } else {
        let mut divergent = divergent_paths(&runs);
        // Replays must also agree on which fixtures could not be mapped.
        for other in &gaps[1..] {
            for entry in gaps[0].iter().chain(other.iter()) {
                if gaps[0].contains(entry) != other.contains(entry) {
                    divergent.push(entry.path.clone());
                }
            }
        }
        divergent.sort();
        divergent.dedup();
        let record = Replays {
            count: replays,
            agreed: divergent.is_empty(),
        };
        if divergent.is_empty() {
            ObservationResult::Complete {
                findings: runs.swap_remove(0),
                replays: record,
                unmeasured: gaps.swap_remove(0),
            }
        } else {
            ObservationResult::Unstable {
                replays: record,
                divergent_paths: divergent,
            }
        }
    };
    ScannerObservation {
        scanner: scanner_identity,
        result,
        duration_ms,
    }
}

/// Paths whose multiset of whole normalized findings differs between replays
/// (the stricter `eval` replay rule), sorted.
fn divergent_paths(runs: &[Vec<NormalizedFinding>]) -> Vec<FixturePath> {
    let by_path = |findings: &[NormalizedFinding]| {
        let mut map: BTreeMap<FixturePath, Vec<NormalizedFinding>> = BTreeMap::new();
        for f in findings {
            map.entry(f.path.clone()).or_default().push(f.clone());
        }
        for list in map.values_mut() {
            list.sort();
        }
        map
    };
    let first = by_path(&runs[0]);
    let mut divergent = BTreeSet::new();
    for other in &runs[1..] {
        let other = by_path(other);
        for path in first.keys().chain(other.keys()) {
            if first.get(path) != other.get(path) {
                divergent.insert(path.clone());
            }
        }
    }
    divergent.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(path: &str, start: u64) -> NormalizedFinding {
        NormalizedFinding {
            path: FixturePath::new(path).unwrap(),
            start,
            end: start + 1,
            family: None,
            action: None,
            mapping: None,
        }
    }

    #[test]
    fn replay_comparison_is_order_insensitive_and_names_paths() {
        let a = vec![f("a", 1), f("b", 2), f("a", 3)];
        let b = vec![f("a", 3), f("a", 1), f("b", 2)];
        assert!(divergent_paths(&[a.clone(), b]).is_empty());
        let c = vec![f("a", 1), f("a", 3), f("c", 0)];
        let names: Vec<String> = divergent_paths(&[a, c])
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(names, ["b", "c"]);
    }
}
