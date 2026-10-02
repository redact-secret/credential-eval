//! Latency/throughput measurement mode (ADR 0002, kind 1).
//!
//! Runs two pinned scanner builds, as external processes, over generated
//! synthetic workloads. Per workload and shape the schedule is:
//!
//! 1. an untimed warm-up of both builds;
//! 2. `rounds` rounds; in each round three arms run one batch each: the
//!    baseline (A), the candidate (B) and the baseline again as the A/A
//!    control (C). The arm order rotates every round, so every arm visits every
//!    position and a drift in host load cannot favour one build.
//!
//! A batch is `batch_invocations` passes over the workload; one pass is one
//! invocation (`whole`) or one invocation per chunk (`chunked`). The sample
//! is the batch's summed process wall time per pass, in nanoseconds. Only the
//! processes' own spawn-to-reap times are summed; generation, file writes and
//! bookkeeping are outside the clock.
//!
//! The result is a direction relative to the A/A noise band, never a budget
//! (`credential-eval-perf::stats`). Scheduling is serial: concurrency would
//! change the numbers, so none exists.
//!
//! Scanner output is read up to an explicit cap and dropped unread; it never
//! reaches the artifact.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use credential_eval_adapters::process::{self, CancelToken, ProcessOutcome, ProcessRequest};
use credential_eval_adapters::provenance;
use credential_eval_contracts::artifact::EngineIdentity;
use credential_eval_contracts::ids::{ComponentId, Sha256Digest};
use credential_eval_contracts::performance::{
    GenerationContract, InputDelivery, LatencyResult, MeasurementKind, PerfSubject,
    PerformanceArtifact, PerformanceConfig, PerformanceManifest, PerformanceNonSemantic, ScanShape,
    Schedule, SubjectIdentity, WORKLOAD_CONTRACT_VERSION, WorkloadIdentity, bounds,
};
use credential_eval_contracts::schema::PerformanceArtifactSchema;
use credential_eval_contracts::{ENGINE_NAME, performance::PERFORMANCE_PROTOCOL_VERSION};
use credential_eval_perf::{host, stats, workloads};

use crate::time;

/// Id of the workload generator contract.
pub const GENERATOR_ID: &str = "credential-eval-perf-workloads";

/// Why a latency run did not produce an artifact.
#[derive(Debug)]
pub enum PerfError {
    /// The configuration is outside the engine's bounds or inconsistent.
    Config(String),
    /// A subject executable is missing, unreadable or does not match its pin.
    Subject(String),
    /// A workload could not be generated within its limit.
    Workload(String),
    /// The run would exceed the invocation bound.
    TooManyInvocations {
        /// Planned invocations.
        planned: u64,
    },
    /// Working files could not be written.
    Io(String),
    /// The run was cancelled.
    Cancelled,
}

impl std::fmt::Display for PerfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(m) => write!(f, "invalid performance configuration: {m}"),
            Self::Subject(m) => write!(f, "subject refused: {m}"),
            Self::Workload(m) => write!(f, "workload refused: {m}"),
            Self::TooManyInvocations { planned } => write!(
                f,
                "run plans {planned} invocations; the bound is {}",
                bounds::MAX_TOTAL_INVOCATIONS
            ),
            Self::Io(m) => write!(f, "working files: {m}"),
            Self::Cancelled => f.write_str("cancelled"),
        }
    }
}

impl std::error::Error for PerfError {}

/// A resolved subject: the executable, its digest and its pin check.
struct Resolved {
    program: PathBuf,
    sha256: Sha256Digest,
}

fn resolve(subject: &PerfSubject) -> Result<Resolved, PerfError> {
    let given = Path::new(&subject.program);
    let program = if given.components().count() > 1 {
        given.to_path_buf()
    } else {
        provenance::which(&subject.program, std::env::var_os("PATH").as_deref())
            .ok_or_else(|| PerfError::Subject(format!("{}: not found on PATH", subject.id)))?
    };
    let sha256 = provenance::sha256_file(&program)
        .map_err(|e| PerfError::Subject(format!("{}: cannot read executable: {e}", subject.id)))?;
    if let Some(pin) = &subject.sha256 {
        if *pin != sha256 {
            return Err(PerfError::Subject(format!(
                "{}: executable digest does not match its pin",
                subject.id
            )));
        }
    }
    Ok(Resolved { program, sha256 })
}

/// One prepared input of a workload in one shape: the bytes (stdin delivery)
/// or the file holding them.
enum Piece {
    Stdin(Vec<u8>),
    File(PathBuf),
}

fn request(
    subject: &PerfSubject,
    resolved: &Resolved,
    piece: &Piece,
    cwd: &Path,
    config: &PerformanceConfig,
) -> ProcessRequest {
    let args: Vec<OsString> = subject
        .args
        .iter()
        .map(|arg| match (arg.as_str(), piece) {
            ("{input}", Piece::File(path)) => path.as_os_str().to_owned(),
            _ => OsString::from(arg),
        })
        .collect();
    ProcessRequest {
        program: resolved.program.clone(),
        args,
        cwd: cwd.to_path_buf(),
        stdin: match piece {
            Piece::Stdin(bytes) => Some(bytes.clone()),
            Piece::File(_) => None,
        },
        timeout: Duration::from_millis(config.limits.timeout_ms),
        max_stdout: config.limits.max_response_bytes,
        max_stderr: config.limits.max_diagnostic_bytes,
    }
}

/// Time of one pass over `pieces`, in nanoseconds, and whether every
/// invocation completed. Scanner output is dropped here.
fn pass(
    subject: &PerfSubject,
    resolved: &Resolved,
    pieces: &[Piece],
    cwd: &Path,
    config: &PerformanceConfig,
    cancel: &CancelToken,
) -> Result<(u64, u32), PerfError> {
    let mut nanos: u64 = 0;
    let mut failed = 0;
    for piece in pieces {
        if cancel.is_cancelled() {
            return Err(PerfError::Cancelled);
        }
        let run = process::run(&request(subject, resolved, piece, cwd, config), cancel);
        nanos = nanos.saturating_add(u64::try_from(run.elapsed.as_nanos()).unwrap_or(u64::MAX));
        match run.outcome {
            ProcessOutcome::Exited {
                code: Some(code), ..
            } if subject.ok_exit_codes.contains(&code) => {}
            ProcessOutcome::Cancelled => return Err(PerfError::Cancelled),
            _ => failed += 1,
        }
    }
    Ok((nanos, failed))
}

/// One batch: `batch_invocations` passes. The sample is time per pass.
fn batch(
    subject: &PerfSubject,
    resolved: &Resolved,
    pieces: &[Piece],
    cwd: &Path,
    config: &PerformanceConfig,
    cancel: &CancelToken,
) -> Result<(u64, u32), PerfError> {
    let mut total: u64 = 0;
    let mut failed = 0;
    for _ in 0..config.batch_invocations {
        let (nanos, bad) = pass(subject, resolved, pieces, cwd, config, cancel)?;
        total = total.saturating_add(nanos);
        failed += bad;
    }
    Ok((total / u64::from(config.batch_invocations), failed))
}

fn prepare(
    shape: ScanShape,
    input: &str,
    delivery: InputDelivery,
    dir: &Path,
    tag: &str,
    chunk_bytes: usize,
) -> Result<Vec<Piece>, PerfError> {
    let parts: Vec<&str> = match shape {
        ScanShape::Whole => vec![input],
        ScanShape::Chunked => workloads::chunks(input, chunk_bytes),
    };
    parts
        .into_iter()
        .enumerate()
        .map(|(index, part)| match delivery {
            InputDelivery::Stdin => Ok(Piece::Stdin(part.as_bytes().to_vec())),
            InputDelivery::File => {
                let path = dir.join(format!("{tag}-{index}.in"));
                fs::write(&path, part).map_err(|e| PerfError::Io(e.to_string()))?;
                Ok(Piece::File(path))
            }
        })
        .collect()
}

/// Run a latency measurement. Never returns an artifact for a refused
/// configuration, a subject that fails its pin, or a cancelled run.
pub fn run_latency(
    config: &PerformanceConfig,
    work_dir: &Path,
    cancel: &CancelToken,
) -> Result<PerformanceArtifact, PerfError> {
    config.validate().map_err(PerfError::Config)?;
    let started_at = time::now_rfc3339();
    let mut host = host::diagnostics();

    let baseline = resolve(&config.baseline)?;
    let candidate = resolve(&config.candidate)?;

    // Generate everything first: a workload that is too large refuses the run
    // before any scanner starts.
    let max_input = usize::try_from(config.limits.max_input_bytes).unwrap_or(usize::MAX);
    let mut generated = Vec::new();
    for spec in &config.workloads {
        let text = workloads::generate(spec.id, spec.units, max_input)
            .map_err(|e| PerfError::Workload(format!("{:?}: {e}", spec.id)))?;
        generated.push((spec, text));
    }

    // Plan the invocation count before running anything.
    let chunk_bytes = config.chunk_bytes as usize;
    let mut planned: u64 = 0;
    for (_, text) in &generated {
        for shape in &config.shapes {
            let pieces = match shape {
                ScanShape::Whole => 1,
                ScanShape::Chunked => workloads::chunks(text, chunk_bytes).len() as u64,
            };
            let passes = u64::from(config.rounds) * 3 * u64::from(config.batch_invocations)
                + 2 * u64::from(config.warmup_invocations);
            planned = planned.saturating_add(pieces.saturating_mul(passes));
        }
    }
    if planned > bounds::MAX_TOTAL_INVOCATIONS {
        return Err(PerfError::TooManyInvocations { planned });
    }

    fs::create_dir_all(work_dir).map_err(|e| PerfError::Io(e.to_string()))?;
    let mut identities = Vec::new();
    let mut latency = Vec::new();
    for (spec, text) in &generated {
        identities.push(WorkloadIdentity {
            id: spec.id,
            units: spec.units,
            bytes: text.len() as u64,
            digest: workloads::digest(text.as_bytes()),
        });
        for shape in &config.shapes {
            // The baseline and the control share one prepared set of inputs.
            let a = prepare(
                *shape,
                text,
                config.baseline.delivery,
                work_dir,
                "a",
                chunk_bytes,
            )?;
            let b = prepare(
                *shape,
                text,
                config.candidate.delivery,
                work_dir,
                "b",
                chunk_bytes,
            )?;
            for _ in 0..config.warmup_invocations {
                pass(&config.baseline, &baseline, &a, work_dir, config, cancel)?;
                pass(&config.candidate, &candidate, &b, work_dir, config, cancel)?;
            }
            let mut samples: [Vec<u64>; 3] = [vec![], vec![], vec![]];
            let mut failed: u32 = 0;
            for round in 0..config.rounds as usize {
                // Rotate (A, B, C) so each arm takes each position in turn.
                for step in 0..3 {
                    let arm = (round + step) % 3;
                    let (subject, resolved, pieces) = match arm {
                        1 => (&config.candidate, &candidate, &b),
                        // Arm 0 is the baseline, arm 2 its A/A control.
                        _ => (&config.baseline, &baseline, &a),
                    };
                    let (nanos, bad) = batch(subject, resolved, pieces, work_dir, config, cancel)?;
                    samples[arm].push(nanos);
                    failed += bad;
                }
            }
            let [s_a, s_b, s_c] = samples;
            let (a_sum, b_sum, c_sum) = (
                stats::summarize(s_a),
                stats::summarize(s_b),
                stats::summarize(s_c),
            );
            let verdict = stats::verdict(&a_sum, &b_sum, &c_sum, failed);
            latency.push(LatencyResult {
                workload: spec.id,
                shape: *shape,
                baseline: a_sum,
                candidate: b_sum,
                control: c_sum,
                median_ratio: verdict.median_ratio,
                min_ratio: verdict.min_ratio,
                noise_band: verdict.noise_band,
                direction: verdict.direction,
                failed_invocations: failed,
            });
        }
    }

    host.load_after = host::load_average();
    let identity = |subject: &PerfSubject, resolved: &Resolved| SubjectIdentity {
        id: subject.id.clone(),
        version: subject.version.clone(),
        revision: subject.revision.clone(),
        executable_sha256: Some(resolved.sha256.clone()),
    };
    let mut artifact = PerformanceArtifact {
        schema: PerformanceArtifactSchema,
        manifest: PerformanceManifest {
            engine: EngineIdentity {
                name: ENGINE_NAME.to_string(),
                version: credential_eval_kernel::score::ENGINE_VERSION.to_string(),
            },
            performance_protocol: PERFORMANCE_PROTOCOL_VERSION.to_string(),
            kind: MeasurementKind::Latency,
            config_hash: Some(config.config_hash()),
            generation: GenerationContract {
                id: ComponentId::new(GENERATOR_ID).expect("constant is a valid id"),
                version: WORKLOAD_CONTRACT_VERSION,
            },
            subjects: vec![
                identity(&config.baseline, &baseline),
                identity(&config.candidate, &candidate),
            ],
            toolchain: config.toolchain.clone(),
            schedule: Some(Schedule {
                rounds: config.rounds,
                batch_invocations: config.batch_invocations,
                warmup_invocations: config.warmup_invocations,
                chunk_bytes: config.chunk_bytes,
            }),
        },
        workloads: identities,
        latency,
        allocation: vec![],
        lost_paths: vec![],
        non_semantic: PerformanceNonSemantic {
            started_at: Some(started_at),
            finished_at: Some(time::now_rfc3339()),
            host,
        },
    };
    artifact.canonicalize();
    Ok(artifact)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use credential_eval_contracts::ids::{ReleaseTag, ScannerId};
    use credential_eval_contracts::performance::{Direction, PerfLimits, WorkloadId, WorkloadSpec};
    use credential_eval_contracts::schema::PerformanceConfigSchema;

    fn subject(id: &str, script: &str) -> PerfSubject {
        PerfSubject {
            id: ScannerId::new(id).unwrap(),
            version: ReleaseTag::new("test").unwrap(),
            revision: None,
            program: "/bin/sh".into(),
            args: vec!["-c".into(), script.into()],
            delivery: InputDelivery::Stdin,
            ok_exit_codes: vec![0],
            sha256: None,
        }
    }

    fn config(candidate: &str) -> PerformanceConfig {
        PerformanceConfig {
            schema: PerformanceConfigSchema,
            baseline: subject("scanner-a", "cat >/dev/null"),
            candidate: subject("scanner-b", candidate),
            workloads: vec![WorkloadSpec {
                id: WorkloadId::RepeatedShortLogLines,
                units: 50,
            }],
            shapes: vec![ScanShape::Whole, ScanShape::Chunked],
            chunk_bytes: 1024,
            rounds: 3,
            batch_invocations: 1,
            warmup_invocations: 1,
            limits: PerfLimits {
                timeout_ms: 10_000,
                max_input_bytes: 1 << 20,
                max_response_bytes: 1 << 16,
                max_diagnostic_bytes: 1 << 12,
            },
            toolchain: vec![],
        }
    }

    /// Timing tests must not overlap: concurrent process spawns are the noise
    /// the A/A control exists to measure, and they would swamp a 3-round run.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn run(config: &PerformanceConfig) -> Result<PerformanceArtifact, PerfError> {
        let _serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        run_latency(config, dir.path(), &CancelToken::new())
    }

    #[test]
    fn a_slower_candidate_is_reported_slower_and_the_control_is_quiet() {
        let artifact = run(&config("sleep 0.4; cat >/dev/null")).unwrap();
        assert_eq!(artifact.manifest.kind, MeasurementKind::Latency);
        let whole = artifact
            .latency
            .iter()
            .find(|r| r.shape == ScanShape::Whole)
            .unwrap();
        assert_eq!(whole.failed_invocations, 0);
        assert_eq!(whole.direction, Direction::Slower, "{whole:?}");
        assert!(whole.median_ratio > 3.0, "{whole:?}");
        assert_eq!(whole.baseline.samples_ns.len(), 3);
        assert_eq!(whole.control.samples_ns.len(), 3);
        // The chunked shape visits every chunk: more invocations, same verdict.
        let chunked = artifact
            .latency
            .iter()
            .find(|r| r.shape == ScanShape::Chunked)
            .unwrap();
        assert!(chunked.baseline.median_ns > 0);
    }

    #[test]
    fn the_control_is_a_second_measurement_of_the_baseline() {
        // Identical builds: the direction itself is statistical and is covered
        // by `stats` unit tests; here the structure is checked.
        let artifact = run(&config("cat >/dev/null")).unwrap();
        assert_eq!(artifact.latency.len(), 2);
        for result in &artifact.latency {
            assert_eq!(result.failed_invocations, 0);
            for arm in [&result.baseline, &result.candidate, &result.control] {
                assert_eq!(arm.samples_ns.len(), 3);
                assert!(arm.min_ns > 0 && arm.min_ns <= arm.median_ns);
            }
            assert!(result.noise_band >= stats::NOISE_FLOOR);
        }
    }

    #[test]
    fn failures_are_counted_and_void_the_direction() {
        let artifact = run(&config("cat >/dev/null; exit 3")).unwrap();
        for result in &artifact.latency {
            assert!(result.failed_invocations > 0);
            assert_eq!(result.direction, Direction::Indistinguishable);
        }
        let mut allow = config("cat >/dev/null; exit 3");
        allow.candidate.ok_exit_codes = vec![0, 3];
        let artifact = run(&allow).unwrap();
        assert!(artifact.latency.iter().all(|r| r.failed_invocations == 0));
    }

    #[test]
    fn semantic_output_is_deterministic_across_runs() {
        let a = run(&config("cat >/dev/null")).unwrap();
        let b = run(&config("cat >/dev/null")).unwrap();
        assert_eq!(a.semantic_digest(), b.semantic_digest());
        assert_eq!(a.workloads, b.workloads);
        assert_eq!(a.manifest, b.manifest);
    }

    #[test]
    fn file_delivery_substitutes_the_input_path() {
        let mut config = config("test -s \"$1\"");
        config.candidate.args = vec![
            "-c".into(),
            "test -s \"$1\"".into(),
            "sh".into(),
            "{input}".into(),
        ];
        config.candidate.delivery = InputDelivery::File;
        let artifact = run(&config).unwrap();
        assert!(
            artifact.latency.iter().all(|r| r.failed_invocations == 0),
            "{artifact:?}"
        );
    }

    #[test]
    fn a_pin_mismatch_refuses_the_run() {
        let mut config = config("cat >/dev/null");
        config.baseline.sha256 =
            Some(Sha256Digest::new(format!("sha256:{}", "0".repeat(64))).unwrap());
        assert!(matches!(run(&config), Err(PerfError::Subject(_))));
    }

    #[test]
    fn bounds_refuse_before_any_scanner_starts() {
        let mut oversize = config("cat >/dev/null");
        oversize.limits.max_input_bytes = 100;
        assert!(matches!(run(&oversize), Err(PerfError::Workload(_))));
        let mut many = config("cat >/dev/null");
        many.workloads[0].units = 100_000;
        many.limits.max_input_bytes = 8 << 20;
        many.chunk_bytes = 1024;
        many.rounds = 200;
        many.batch_invocations = 100;
        assert!(matches!(
            run(&many),
            Err(PerfError::TooManyInvocations { .. })
        ));
        let mut invalid = config("cat >/dev/null");
        invalid.rounds = 1;
        assert!(matches!(run(&invalid), Err(PerfError::Config(_))));
    }

    #[test]
    fn a_missing_executable_is_refused() {
        let mut config = config("cat >/dev/null");
        config.candidate.program = "/nonexistent/scanner".into();
        assert!(matches!(run(&config), Err(PerfError::Subject(_))));
    }

    #[test]
    fn a_cancelled_run_returns_no_artifact() {
        let dir = tempfile::tempdir().unwrap();
        let cancel = CancelToken::new();
        cancel.cancel();
        assert!(matches!(
            run_latency(&config("cat >/dev/null"), dir.path(), &cancel),
            Err(PerfError::Cancelled)
        ));
    }
}
