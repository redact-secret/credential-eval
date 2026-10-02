//! Confirmed directions: combining independent latency runs.
//!
//! A direction from one run on a shared host is not a result: the A/A control
//! sees noise inside the run but not the changes between runs (neighbouring
//! VMs, a different CPU generation). A direction is `confirmed` only when every
//! independent run of the same configuration reports it.

use credential_eval_contracts::canonical::sha256_canonical;
use credential_eval_contracts::ids::Sha256Digest;
use credential_eval_contracts::performance::{
    Confirmation, ConfirmedResult, Direction, DirectionConfirmation, MeasurementKind,
    PerformanceArtifact, RunReference, ScanShape, WorkloadId,
};
use credential_eval_contracts::schema::DirectionConfirmationSchema;

/// Why runs cannot be combined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmError {
    /// Fewer than two runs.
    NeedTwoRuns,
    /// A run is not a latency artifact.
    NotLatency,
    /// A run has no configuration digest.
    NoConfigHash,
    /// The runs do not share the configuration, subjects (versions, revisions
    /// and executable digests), workloads or measured cells.
    Mismatch(&'static str),
    /// Two runs are the same artifact: they are not independent.
    Duplicate,
}

impl std::fmt::Display for ConfirmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NeedTwoRuns => f.write_str("at least two runs are needed"),
            Self::NotLatency => f.write_str("every run must be a latency artifact"),
            Self::NoConfigHash => f.write_str("a run has no configuration digest"),
            Self::Mismatch(what) => write!(f, "the runs do not share their {what}"),
            Self::Duplicate => f.write_str("two runs are the same artifact, not independent runs"),
        }
    }
}

impl std::error::Error for ConfirmError {}

fn status(directions: &[Direction]) -> Confirmation {
    let first = directions[0];
    if directions.iter().all(|d| *d == first) {
        match first {
            Direction::Faster => Confirmation::ConfirmedFaster,
            Direction::Slower => Confirmation::ConfirmedSlower,
            Direction::Indistinguishable => Confirmation::NoEvidence,
        }
    } else {
        Confirmation::Unconfirmed
    }
}

fn cpu_digest(artifact: &PerformanceArtifact) -> Option<Sha256Digest> {
    artifact
        .non_semantic
        .host
        .cpu_model
        .as_ref()
        .map(sha256_canonical)
}

/// Combine independent latency runs of one configuration. The result does not
/// depend on the order of `runs`.
pub fn confirm(runs: &[&PerformanceArtifact]) -> Result<DirectionConfirmation, ConfirmError> {
    if runs.len() < 2 {
        return Err(ConfirmError::NeedTwoRuns);
    }
    let mut ordered: Vec<(Sha256Digest, &PerformanceArtifact)> =
        runs.iter().map(|a| (sha256_canonical(*a), *a)).collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    if ordered.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(ConfirmError::Duplicate);
    }
    let first = ordered[0].1;
    for (_, run) in &ordered {
        if run.manifest.kind != MeasurementKind::Latency {
            return Err(ConfirmError::NotLatency);
        }
        if run.manifest.config_hash.is_none() {
            return Err(ConfirmError::NoConfigHash);
        }
        if run.manifest.config_hash != first.manifest.config_hash {
            return Err(ConfirmError::Mismatch("configuration"));
        }
        if run.manifest.subjects != first.manifest.subjects {
            return Err(ConfirmError::Mismatch("subjects"));
        }
        if run.workloads != first.workloads {
            return Err(ConfirmError::Mismatch("workloads"));
        }
        let cells = |a: &PerformanceArtifact| -> Vec<(WorkloadId, ScanShape)> {
            a.latency.iter().map(|r| (r.workload, r.shape)).collect()
        };
        if cells(run) != cells(first) {
            return Err(ConfirmError::Mismatch("measured cells"));
        }
    }
    let results = (0..first.latency.len())
        .map(|cell| {
            let directions: Vec<Direction> = ordered
                .iter()
                .map(|(_, run)| run.latency[cell].direction)
                .collect();
            ConfirmedResult {
                workload: first.latency[cell].workload,
                shape: first.latency[cell].shape,
                status: status(&directions),
                directions,
            }
        })
        .collect();
    let digests: Vec<Option<Sha256Digest>> =
        ordered.iter().map(|(_, run)| cpu_digest(run)).collect();
    let same_cpu_model = digests
        .iter()
        .all(Option::is_some)
        .then(|| digests.iter().all(|d| *d == digests[0]));
    let mut confirmation = DirectionConfirmation {
        schema: DirectionConfirmationSchema,
        config_hash: first.manifest.config_hash.clone().expect("checked above"),
        subjects: first.manifest.subjects.clone(),
        runs: ordered
            .iter()
            .map(|(digest, run)| RunReference {
                artifact_digest: digest.clone(),
                cpu_model_digest: cpu_digest(run),
            })
            .collect(),
        same_cpu_model,
        results,
    };
    confirmation.results.sort();
    Ok(confirmation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_eval_contracts::artifact::EngineIdentity;
    use credential_eval_contracts::ids::{ComponentId, ReleaseTag, ScannerId};
    use credential_eval_contracts::performance::{
        GenerationContract, HostDiagnostics, LatencyResult, PerformanceManifest,
        PerformanceNonSemantic, SubjectIdentity, TimingSummary, WorkloadIdentity,
    };
    use credential_eval_contracts::schema::PerformanceArtifactSchema;

    fn digest(n: u8) -> Sha256Digest {
        Sha256Digest::new(format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }

    fn timing() -> TimingSummary {
        TimingSummary {
            min_ns: 1,
            median_ns: 1,
            samples_ns: vec![1],
        }
    }

    fn result(workload: WorkloadId, direction: Direction) -> LatencyResult {
        LatencyResult {
            workload,
            shape: ScanShape::Whole,
            baseline: timing(),
            candidate: timing(),
            control: timing(),
            median_ratio: 1.0,
            min_ratio: 1.0,
            noise_band: 0.05,
            direction,
            failed_invocations: 0,
        }
    }

    /// A run with the given directions for `sparse-unicode` and `dense-unicode`;
    /// `seed` makes otherwise equal runs distinct artifacts.
    fn run(seed: u8, directions: [Direction; 2], cpu: Option<&str>) -> PerformanceArtifact {
        PerformanceArtifact {
            schema: PerformanceArtifactSchema,
            manifest: PerformanceManifest {
                engine: EngineIdentity {
                    name: "credential-eval".into(),
                    version: "0".into(),
                },
                performance_protocol: "credential-eval-performance/1".into(),
                kind: MeasurementKind::Latency,
                config_hash: Some(digest(1)),
                generation: GenerationContract {
                    id: ComponentId::new("g").unwrap(),
                    version: 1,
                },
                subjects: vec![SubjectIdentity {
                    id: ScannerId::new("a").unwrap(),
                    version: ReleaseTag::new("1").unwrap(),
                    revision: None,
                    executable_sha256: Some(digest(2)),
                }],
                toolchain: vec![],
                schedule: None,
            },
            workloads: vec![WorkloadIdentity {
                id: WorkloadId::SparseUnicode,
                units: 1,
                bytes: 1,
                digest: digest(3),
            }],
            latency: vec![
                result(WorkloadId::SparseUnicode, directions[0]),
                result(WorkloadId::DenseUnicode, directions[1]),
            ],
            allocation: vec![],
            lost_paths: vec![],
            non_semantic: PerformanceNonSemantic {
                started_at: Some(format!("run-{seed}")),
                finished_at: None,
                host: HostDiagnostics {
                    os: ComponentId::new("linux").unwrap(),
                    arch: ComponentId::new("x86-64").unwrap(),
                    cpu_model: cpu.map(str::to_owned),
                    cpus: 2,
                    load_before: None,
                    load_after: None,
                },
            },
        }
    }

    use Direction::{Faster, Indistinguishable, Slower};

    #[test]
    fn agreement_confirms_and_everything_else_does_not() {
        let a = run(1, [Faster, Slower], Some("Xeon"));
        let b = run(2, [Faster, Indistinguishable], Some("Xeon"));
        let c = confirm(&[&a, &b]).unwrap();
        let by = |w| c.results.iter().find(|r| r.workload == w).unwrap().status;
        assert_eq!(by(WorkloadId::SparseUnicode), Confirmation::ConfirmedFaster);
        // One run saw a direction, the other did not: not a result.
        assert_eq!(by(WorkloadId::DenseUnicode), Confirmation::Unconfirmed);

        let d = run(3, [Slower, Indistinguishable], Some("Xeon"));
        let e = run(4, [Slower, Indistinguishable], Some("Xeon"));
        let c = confirm(&[&d, &e]).unwrap();
        let by = |w| c.results.iter().find(|r| r.workload == w).unwrap().status;
        assert_eq!(by(WorkloadId::SparseUnicode), Confirmation::ConfirmedSlower);
        assert_eq!(by(WorkloadId::DenseUnicode), Confirmation::NoEvidence);

        // Opposite directions are unconfirmed, not "confirmed slower".
        let f = run(5, [Faster, Faster], None);
        let g = run(6, [Slower, Faster], None);
        let c = confirm(&[&f, &g]).unwrap();
        assert_eq!(c.results[0].status, Confirmation::Unconfirmed);
        assert_eq!(c.results[1].status, Confirmation::ConfirmedFaster);
    }

    #[test]
    fn three_runs_must_all_agree() {
        let a = run(1, [Faster, Faster], None);
        let b = run(2, [Faster, Faster], None);
        let c = run(3, [Faster, Indistinguishable], None);
        let confirmed = confirm(&[&a, &b, &c]).unwrap();
        assert_eq!(confirmed.runs.len(), 3);
        assert_eq!(confirmed.results[0].status, Confirmation::ConfirmedFaster);
        assert_eq!(confirmed.results[1].status, Confirmation::Unconfirmed);
    }

    #[test]
    fn the_order_of_the_runs_does_not_matter() {
        let a = run(1, [Faster, Slower], Some("A"));
        let b = run(2, [Slower, Slower], Some("B"));
        assert_eq!(confirm(&[&a, &b]).unwrap(), confirm(&[&b, &a]).unwrap());
    }

    #[test]
    fn cpu_models_are_compared_by_digest_and_only_when_recorded() {
        let a = run(1, [Faster, Faster], Some("Xeon 8370C"));
        let b = run(2, [Faster, Faster], Some("Xeon 8370C"));
        let c = run(3, [Faster, Faster], Some("EPYC 7763"));
        let none = run(4, [Faster, Faster], None);
        assert_eq!(confirm(&[&a, &b]).unwrap().same_cpu_model, Some(true));
        assert_eq!(confirm(&[&a, &c]).unwrap().same_cpu_model, Some(false));
        assert_eq!(confirm(&[&a, &none]).unwrap().same_cpu_model, None);
        // The model text itself is not in the confirmation.
        let text = serde_json::to_string(&confirm(&[&a, &c]).unwrap()).unwrap();
        assert!(!text.contains("Xeon") && !text.contains("EPYC"));
    }

    #[test]
    fn runs_that_cannot_be_combined_are_refused() {
        let a = run(1, [Faster, Faster], None);
        assert_eq!(confirm(&[&a]), Err(ConfirmError::NeedTwoRuns));
        assert_eq!(confirm(&[&a, &a]), Err(ConfirmError::Duplicate));

        let mut other = run(2, [Faster, Faster], None);
        other.manifest.config_hash = Some(digest(9));
        assert_eq!(
            confirm(&[&a, &other]),
            Err(ConfirmError::Mismatch("configuration"))
        );

        let mut other = run(2, [Faster, Faster], None);
        other.manifest.subjects[0].executable_sha256 = Some(digest(9));
        assert_eq!(
            confirm(&[&a, &other]),
            Err(ConfirmError::Mismatch("subjects"))
        );

        let mut other = run(2, [Faster, Faster], None);
        other.workloads[0].digest = digest(9);
        assert_eq!(
            confirm(&[&a, &other]),
            Err(ConfirmError::Mismatch("workloads"))
        );

        let mut other = run(2, [Faster, Faster], None);
        other.latency.pop();
        assert_eq!(
            confirm(&[&a, &other]),
            Err(ConfirmError::Mismatch("measured cells"))
        );

        let mut other = run(2, [Faster, Faster], None);
        other.manifest.kind = MeasurementKind::Allocation;
        assert_eq!(confirm(&[&a, &other]), Err(ConfirmError::NotLatency));

        let mut one = run(1, [Faster, Faster], None);
        let mut two = run(2, [Faster, Faster], None);
        one.manifest.config_hash = None;
        two.manifest.config_hash = None;
        assert_eq!(confirm(&[&one, &two]), Err(ConfirmError::NoConfigHash));
    }
}
