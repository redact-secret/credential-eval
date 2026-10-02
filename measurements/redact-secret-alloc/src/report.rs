//! Allocation comparisons and the performance artifact they are recorded in.

use credential_eval_contracts::artifact::EngineIdentity;
use credential_eval_contracts::ids::ComponentId;
use credential_eval_contracts::performance::{
    AllocationResult, GenerationContract, LostPath, LostReason, MeasurementKind,
    PERFORMANCE_PROTOCOL_VERSION, PerformanceArtifact, PerformanceManifest, PerformanceNonSemantic,
    ToolchainEntry, WORKLOAD_CONTRACT_VERSION, WorkloadId, WorkloadIdentity,
};
use credential_eval_contracts::schema::PerformanceArtifactSchema;
use credential_eval_contracts::{ENGINE_NAME, ids::ReleaseTag};
use credential_eval_perf::{host, workloads};

use crate::cores::{self, Core};

/// Id of the workload generator contract (shared with the latency mode).
pub const GENERATOR_ID: &str = "credential-eval-perf-workloads";

/// One card's comparison: which pair of builds, on which workloads.
pub struct Comparison {
    /// Card id (`card-1121`).
    pub card: &'static str,
    /// Baseline build.
    pub baseline: fn() -> Core,
    /// Candidate build.
    pub candidate: fn() -> Core,
    /// `(workload, units)` in measurement order.
    pub workloads: &'static [(WorkloadId, u32)],
}

/// The cards the issue names.
///
/// * #1121: the generic-assignment baseline, 1,000 assignments per fixture
///   (ordinary 18,451 -> 5,451; diverse 18,459 -> 4,274; references
///   12,155 -> 1,054 requests).
/// * #1131 (Azure) and #1135 (overlap DP): not measured in the original PRs.
///   The overlap workloads are public-API end-to-end proxies; see
///   [`lost_paths`].
pub fn comparisons() -> Vec<Comparison> {
    vec![
        Comparison {
            card: "card-1121",
            baseline: cores::before,
            candidate: cores::mid,
            workloads: &[
                (WorkloadId::AssignmentsOrdinary, 1000),
                (WorkloadId::AssignmentsDiverse, 1000),
                (WorkloadId::AssignmentsReferences, 1000),
            ],
        },
        Comparison {
            card: "card-1131",
            baseline: cores::mid,
            candidate: cores::after,
            workloads: &[
                (WorkloadId::AzureSingle, 1),
                (WorkloadId::AzureRepeatedRecords, 100),
                (WorkloadId::AzureDuplicateKeys, 100),
                (WorkloadId::AzureBenign, 1000),
            ],
        },
        Comparison {
            card: "card-1135",
            baseline: cores::mid,
            candidate: cores::after,
            workloads: &[
                (WorkloadId::OverlapDisjoint, 5000),
                (WorkloadId::OverlapSparse, 5000),
                (WorkloadId::OverlapPairs, 5000),
                (WorkloadId::OverlapDense, 5000),
            ],
        },
    ]
}

/// Reproduction paths that the public API cannot carry over.
pub fn lost_paths() -> Vec<LostPath> {
    let path = |card: &str, helper: &str| LostPath {
        card: ComponentId::new(card).expect("constant id"),
        helper: ComponentId::new(helper).expect("constant id"),
        reason: LostReason::CratePrivateHelper,
    };
    vec![
        // #1131 measured `azure_storage_candidate` through an exported probe hook.
        path("card-1131", "azure-probe"),
        // #1135 measured the private weighted-interval selection (`OverlapProbe`).
        path("card-1135", "overlap-probe"),
    ]
}

/// Run every comparison and build the artifact.
pub fn run(comparisons: &[Comparison]) -> PerformanceArtifact {
    let started_at = now();
    let host = host::diagnostics();
    let mut subjects = std::collections::BTreeMap::new();
    let mut workload_identities = std::collections::BTreeMap::new();
    let mut allocation = Vec::new();

    for comparison in comparisons {
        let (baseline, candidate) = ((comparison.baseline)(), (comparison.candidate)());
        for core in [&baseline, &candidate] {
            subjects.entry(core.id).or_insert_with(|| core.identity());
        }
        for &(id, units) in comparison.workloads {
            let text = cores::input(id, units);
            workload_identities
                .entry((id, units))
                .or_insert_with(|| WorkloadIdentity {
                    id,
                    units,
                    bytes: text.len() as u64,
                    digest: workloads::digest(text.as_bytes()),
                });
            let baseline_counts = baseline.counts(&text);
            let candidate_counts = candidate.counts(&text);
            allocation.push(AllocationResult {
                card: ComponentId::new(comparison.card).expect("constant id"),
                workload: id,
                baseline: baseline.identity().id,
                candidate: candidate.identity().id,
                request_delta: i64::try_from(candidate_counts.requests).unwrap_or(i64::MAX)
                    - i64::try_from(baseline_counts.requests).unwrap_or(i64::MAX),
                findings_identical: baseline_counts.findings_digest
                    == candidate_counts.findings_digest,
                baseline_counts,
                candidate_counts,
            });
        }
    }

    let mut artifact = PerformanceArtifact {
        schema: PerformanceArtifactSchema,
        manifest: PerformanceManifest {
            engine: EngineIdentity {
                name: ENGINE_NAME.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            performance_protocol: PERFORMANCE_PROTOCOL_VERSION.to_string(),
            kind: MeasurementKind::Allocation,
            config_hash: None,
            generation: GenerationContract {
                id: ComponentId::new(GENERATOR_ID).expect("constant id"),
                version: WORKLOAD_CONTRACT_VERSION,
            },
            subjects: subjects.into_values().collect(),
            toolchain: toolchain(),
            schedule: None,
        },
        workloads: workload_identities.into_values().collect(),
        latency: vec![],
        allocation,
        lost_paths: lost_paths(),
        non_semantic: PerformanceNonSemantic {
            started_at: Some(started_at),
            finished_at: Some(now()),
            host,
        },
    };
    artifact.canonicalize();
    artifact
}

fn toolchain() -> Vec<ToolchainEntry> {
    [
        ("llvm", env!("HARNESS_LLVM_VERSION")),
        ("rustc", env!("HARNESS_RUSTC_RELEASE")),
    ]
    .into_iter()
    .filter_map(|(name, version)| {
        Some(ToolchainEntry {
            name: ComponentId::new(name).ok()?,
            version: ReleaseTag::new(version).ok()?,
        })
    })
    .collect()
}

fn now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    rfc3339(secs)
}

/// Seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days).
pub fn rfc3339(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}
