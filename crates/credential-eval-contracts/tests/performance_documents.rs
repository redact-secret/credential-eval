//! The committed performance artifacts (`docs/measurements/`) are valid
//! `PerformanceArtifact` documents, and the committed allocation counts keep
//! the beta.13 baseline of issue #1121 (ADR 0002).

use std::path::PathBuf;

use credential_eval_contracts::performance::{
    Direction, MeasurementKind, PerformanceArtifact, WorkloadId,
};
use credential_eval_contracts::schema::all_schemas;
use serde_json::Value;

fn measurements() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/measurements");
    let mut out: Vec<_> = std::fs::read_dir(dir)
        .expect("docs/measurements")
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
        .map(|e| {
            (
                e.file_name().to_string_lossy().into_owned(),
                std::fs::read_to_string(e.path()).expect("artifact"),
            )
        })
        .collect();
    out.sort();
    out
}

#[test]
fn committed_artifacts_validate_against_their_schema_and_round_trip() {
    let schema = all_schemas()
        .into_iter()
        .find(|(file, _)| *file == "performance-artifact-v1.schema.json")
        .map(|(_, schema)| serde_json::to_value(&schema).expect("schema json"))
        .expect("performance artifact schema");
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let artifacts = measurements();
    assert!(!artifacts.is_empty(), "no committed performance artifact");
    for (name, text) in artifacts {
        let value: Value = serde_json::from_str(&text).expect("json");
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| e.to_string())
            .collect();
        assert!(errors.is_empty(), "{name}: {errors:?}");
        let artifact: PerformanceArtifact = serde_json::from_str(&text).expect("typed");
        assert_eq!(
            serde_json::to_value(&artifact).expect("serializes"),
            value,
            "{name}: the artifact is not in canonical form"
        );
    }
}

#[test]
fn the_committed_allocation_counts_reproduce_the_1121_baseline() {
    let (_, text) = measurements()
        .into_iter()
        .find(|(name, _)| name == "redact-secret-allocation-counts.json")
        .expect("committed allocation counts");
    let artifact: PerformanceArtifact = serde_json::from_str(&text).expect("typed");
    assert_eq!(artifact.manifest.kind, MeasurementKind::Allocation);
    let requests = |workload: WorkloadId| {
        let result = artifact
            .allocation
            .iter()
            .find(|r| r.card.as_str() == "card-1121" && r.workload == workload)
            .expect("measured");
        assert!(result.findings_identical);
        (
            result.baseline_counts.requests,
            result.candidate_counts.requests,
        )
    };
    assert_eq!(requests(WorkloadId::AssignmentsOrdinary), (18_451, 5_451));
    assert_eq!(requests(WorkloadId::AssignmentsDiverse), (18_459, 4_274));
    assert_eq!(requests(WorkloadId::AssignmentsReferences), (12_155, 1_054));
    // The cards whose isolated probes are not reachable are recorded as lost.
    let lost: Vec<&str> = artifact
        .lost_paths
        .iter()
        .map(|p| p.helper.as_str())
        .collect();
    assert_eq!(lost, ["azure-probe", "overlap-probe"]);
    // Sanitized: no generated line, only identities and counts.
    assert!(!text.contains("api_key"));
    assert!(!text.contains("AccountKey"));
}

#[test]
fn the_committed_instruction_counts_are_exact_and_show_the_cards() {
    let load = |name: &str| -> PerformanceArtifact {
        let (_, text) = measurements()
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("{name} is committed"));
        serde_json::from_str(&text).expect("typed")
    };
    for name in [
        "redact-secret-instruction-counts-1121.json",
        "redact-secret-instruction-counts-1131-1135.json",
    ] {
        let artifact = load(name);
        assert_eq!(artifact.manifest.kind, MeasurementKind::Instructions);
        assert!(!artifact.instructions.is_empty());
        for result in &artifact.instructions {
            // Exact counts: no spread, and the control reproduces the baseline.
            assert_eq!(result.baseline.spread, 0, "{name} {:?}", result.workload);
            assert_eq!(result.candidate.spread, 0, "{name} {:?}", result.workload);
            assert_eq!(result.control.counts, result.baseline.counts);
            assert_eq!(result.failed_invocations, 0);
        }
    }
    let direction = |artifact: &PerformanceArtifact, workload: WorkloadId| {
        artifact
            .instructions
            .iter()
            .find(|r| r.workload == workload)
            .expect("measured")
            .direction
    };
    let first = load("redact-secret-instruction-counts-1121.json");
    for workload in [
        WorkloadId::AssignmentsOrdinary,
        WorkloadId::AssignmentsDiverse,
        WorkloadId::AssignmentsReferences,
    ] {
        assert_eq!(
            direction(&first, workload),
            Direction::Faster,
            "{workload:?}"
        );
    }
    let second = load("redact-secret-instruction-counts-1131-1135.json");
    assert_eq!(
        direction(&second, WorkloadId::AzureDuplicateKeys),
        Direction::Faster
    );
    let duplicate = second
        .instructions
        .iter()
        .find(|r| r.workload == WorkloadId::AzureDuplicateKeys)
        .expect("measured");
    assert!(duplicate.ratio < 0.25, "{}", duplicate.ratio);
}
