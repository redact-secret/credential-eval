//! Orchestration tests with fake scanner executables (no real scanner is
//! needed): explicit failure states, output bounds, determinism across job
//! counts, replay stability, and the Node adapter's offset conversion and
//! package provenance.

#![cfg(unix)]

mod common;

use std::fs;
use std::time::{Duration, Instant};

use common::*;
use credential_eval_contracts::artifact::CaseMeasurement;
use credential_eval_contracts::observation::{ObservationResult, ProvenanceKind, ScannerStatus};
use serde_json::json;

/// Two Gitleaks rows on smoke fixtures, printed in an order that depends on
/// the process id (the adapter must not care).
const TWO_ROWS: &str = r#"a="{\"RuleID\":\"generic-api-key\",\"File\":\"$root/contracts-smoke/positive-exact.txt\",\"Secret\":\"EXAMPLE_FAKE_KEY_0123456789abcdef\",\"StartLine\":2,\"StartColumn\":1,\"Tags\":[]}"
b="{\"RuleID\":\"unmapped-rule\",\"File\":\"contracts-smoke/positive-partial.txt\",\"Secret\":\"EXAMPLE_FAKE_KEY_0000\",\"StartLine\":1,\"Tags\":[]}"
if [ $(( $$ % 2 )) -eq 0 ]; then echo "[$a,$b]"; else echo "[$b,$a]"; fi"#;

fn status_of(output: &credential_eval_cli::orchestrate::RunOutput, id: &str) -> ObservationResult {
    output
        .observations
        .observations
        .iter()
        .find(|o| o.scanner.id.as_str() == id)
        .expect("scanner observed")
        .result
        .clone()
}

#[test]
fn complete_scan_maps_ranges_families_and_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(dir.path(), "gitleaks", "8.30.1", TWO_ROWS);
    let corpus = smoke_corpus();
    let out = run(&corpus, &config(vec![gitleaks_spec("gitleaks", &bin)], 2));
    let ObservationResult::Complete {
        findings, replays, ..
    } = status_of(&out, "gitleaks")
    else {
        panic!("expected complete");
    };
    assert_eq!((replays.count, replays.agreed), (2, true));
    let exact = findings
        .iter()
        .find(|f| f.path.as_str() == "contracts-smoke/positive-exact.txt")
        .unwrap();
    // "# café config (synthetic)\n" is 27 bytes (é is two); the value starts
    // 11 bytes into line 2.
    assert_eq!((exact.start, exact.end), (38, 71));
    assert_eq!(exact.family.as_deref(), Some("generic-token"));
    let partial = findings
        .iter()
        .find(|f| f.path.as_str() == "contracts-smoke/positive-partial.txt")
        .unwrap();
    assert_eq!(partial.family, None);

    let identity = &out.artifact.manifest.scanners[0];
    assert_eq!(identity.version.as_deref(), Some("8.30.1"));
    let provenance = identity.provenance.as_ref().unwrap();
    assert_eq!(provenance.components.len(), 1);
    assert_eq!(provenance.components[0].kind, ProvenanceKind::Executable);
    assert!(provenance.components[0].sha256.is_some());
    // Host paths never reach the artifact.
    let text = serde_json::to_string(&out.artifact).unwrap();
    assert!(!text.contains(dir.path().to_str().unwrap()));
    // Nor do matched values beyond what the corpus itself contains: the
    // artifact holds ranges, not scanner output.
    assert!(!text.contains("\"Secret\""));
    let diagnostics = out.artifact.non_semantic.execution.as_ref().unwrap();
    assert_eq!(diagnostics.processes, 3); // version probe + 2 replays
    // The kernel accounts the complete scanner's cases into the artifact.
    let aggregates = &out.artifact.scanners[0].aggregates;
    assert!(aggregates.groups.contains_key("must-redact/T1"));
    assert!(aggregates.groups.contains_key("pending/T0"));
    assert_schema_valid(&out.artifact);
}

#[test]
fn failures_are_explicit_and_never_miss() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let specs = vec![
        gitleaks_spec("missing", &d.join("does-not-exist")),
        gitleaks_spec(
            "wrong-version",
            &fake_gitleaks(d, "v", "8.30.2", "echo '[]'"),
        ),
        gitleaks_spec(
            "malformed",
            &fake_gitleaks(d, "m", "8.30.1", "echo 'not json'"),
        ),
        gitleaks_spec(
            "nonzero",
            &fake_gitleaks(d, "n", "8.30.1", "echo '[]'; exit 4"),
        ),
        gitleaks_spec(
            "unmappable",
            &fake_gitleaks(
                d,
                "u",
                "8.30.1",
                r#"echo "[{\"RuleID\":\"jwt\",\"File\":\"$root/contracts-smoke/positive-exact.txt\",\"Secret\":\"NOT-IN-FILE\",\"StartLine\":2}]""#,
            ),
        ),
        gitleaks_spec("empty", &fake_gitleaks(d, "e", "8.30.1", "echo '[]'")),
    ];
    let out = run(&smoke_corpus(), &config(specs, 4));
    let reason = |id| match status_of(&out, id) {
        ObservationResult::Unavailable { reason }
        | ObservationResult::Malformed { reason }
        | ObservationResult::Error { reason } => reason,
        other => panic!("{id}: unexpected {other:?}"),
    };
    assert!(matches!(
        status_of(&out, "missing"),
        ObservationResult::Unavailable { .. }
    ));
    assert_eq!(reason("missing"), "scanner executable not found");
    assert!(matches!(
        status_of(&out, "wrong-version"),
        ObservationResult::Unavailable { .. }
    ));
    assert!(reason("wrong-version").contains("required_version"));
    assert!(matches!(
        status_of(&out, "malformed"),
        ObservationResult::Malformed { .. }
    ));
    assert!(matches!(
        status_of(&out, "nonzero"),
        ObservationResult::Error { .. }
    ));
    assert!(matches!(
        status_of(&out, "unmappable"),
        ObservationResult::Malformed { .. }
    ));
    assert!(reason("unmappable").contains("Ambiguous or unmappable"));
    // An empty report is a complete observation with no findings.
    assert!(
        matches!(status_of(&out, "empty"), ObservationResult::Complete { ref findings, .. } if findings.is_empty())
    );

    for run in &out.artifact.scanners {
        if run.scanner.as_str() == "empty" {
            continue;
        }
        assert_ne!(run.status, ScannerStatus::Complete);
        assert!(run.findings.is_empty());
        for case in &run.cases {
            assert!(
                matches!(case.measurement, CaseMeasurement::NotMeasured { .. }),
                "{} {} must be not-measured",
                run.scanner,
                case.case_id
            );
        }
    }
    // The wrong-version scanner still records what was found.
    let wrong = out
        .artifact
        .manifest
        .scanners
        .iter()
        .find(|s| s.id.as_str() == "wrong-version")
        .unwrap();
    assert_eq!(wrong.version.as_deref(), Some("8.30.2"));
    assert_schema_valid(&out.artifact);
}

#[test]
fn timeout_kills_the_process() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(dir.path(), "slow", "8.30.1", "exec sleep 30");
    let mut spec = gitleaks_spec("slow", &bin);
    spec.limits.timeout_ms = 1_500;
    let started = Instant::now();
    let out = run(&smoke_corpus(), &config(vec![spec], 1));
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "timeout must be enforced"
    );
    assert_eq!(
        status_of(&out, "slow"),
        ObservationResult::Timeout { timeout_ms: 1_500 }
    );
    // The first replay timed out, so the second was cancelled, not run.
    assert_eq!(
        out.artifact
            .non_semantic
            .execution
            .as_ref()
            .unwrap()
            .processes,
        2
    );
}

#[test]
fn oversized_stdout_is_bounded_and_malformed() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(
        dir.path(),
        "loud",
        "8.30.1",
        "exec head -c 50000000 /dev/zero",
    );
    let mut spec = gitleaks_spec("loud", &bin);
    spec.limits.max_stdout_bytes = 4096;
    let started = Instant::now();
    let out = run(&smoke_corpus(), &config(vec![spec], 1));
    assert!(started.elapsed() < Duration::from_secs(10));
    let ObservationResult::Malformed { reason } = status_of(&out, "loud") else {
        panic!("expected malformed");
    };
    assert!(reason.contains("max_stdout_bytes"));
}

#[test]
fn unstable_replays_discard_findings() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("count");
    let body = format!(
        r#"n=$(cat '{state}' 2>/dev/null || echo 0); echo $((n + 1)) > '{state}'
if [ "$n" -eq 0 ]; then {TWO_ROWS}
else echo '[]'; fi"#,
        state = state.display()
    );
    let bin = fake_gitleaks(dir.path(), "flaky", "8.30.1", &body);
    let mut spec = gitleaks_spec("flaky", &bin);
    spec.limits.concurrency = 1;
    let out = run(&smoke_corpus(), &config(vec![spec], 4));
    let ObservationResult::Unstable {
        replays,
        divergent_paths,
    } = status_of(&out, "flaky")
    else {
        panic!("expected unstable");
    };
    assert!(!replays.agreed);
    let paths: Vec<&str> = divergent_paths.iter().map(|p| p.as_str()).collect();
    assert_eq!(
        paths,
        [
            "contracts-smoke/positive-exact.txt",
            "contracts-smoke/positive-partial.txt"
        ]
    );
}

#[test]
fn jobs_do_not_change_the_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let specs = || {
        vec![
            gitleaks_spec("a", &fake_gitleaks(d, "a", "8.30.1", TWO_ROWS)),
            gitleaks_spec(
                "b",
                &fake_gitleaks(d, "b", "8.30.1", &format!("sleep 0.2; {TWO_ROWS}")),
            ),
            gitleaks_spec("c", &fake_gitleaks(d, "c", "8.30.1", "echo '[]'")),
            gitleaks_spec("d", &fake_gitleaks(d, "d", "8.30.1", "echo 'broken'")),
            gitleaks_spec("e", &d.join("missing")),
        ]
    };
    let corpus = smoke_corpus();
    let one = run(&corpus, &config(specs(), 1));
    let eight = run(&corpus, &config(specs(), 8));
    // Reversed scanner order and case order must not matter either.
    let mut reversed_specs = specs();
    reversed_specs.reverse();
    let mut reversed_corpus = corpus.clone();
    reversed_corpus.cases.reverse();
    let reversed = run(&reversed_corpus, &config(reversed_specs, 3));

    assert_eq!(
        one.artifact.manifest.config_hash,
        eight.artifact.manifest.config_hash
    );
    assert_eq!(
        one.artifact.semantic_digest(),
        eight.artifact.semantic_digest()
    );
    assert_eq!(semantic_text(&one.artifact), semantic_text(&eight.artifact));
    assert_eq!(
        semantic_text(&one.artifact),
        semantic_text(&reversed.artifact)
    );
    let without_durations = |mut set: credential_eval_contracts::observation::ObservationSet| {
        for o in &mut set.observations {
            o.duration_ms = None;
        }
        set
    };
    assert_eq!(
        without_durations(one.observations),
        without_durations(eight.observations)
    );
    assert_eq!(
        eight.artifact.non_semantic.execution.as_ref().unwrap().jobs,
        8
    );
    assert_schema_valid(&eight.artifact);
}

#[test]
fn materialized_fixtures_are_removed() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("root.txt");
    let body = format!("echo \"$root\" > '{}'; echo '[]'", marker.display());
    let bin = fake_gitleaks(dir.path(), "g", "8.30.1", &body);
    run(&smoke_corpus(), &config(vec![gitleaks_spec("g", &bin)], 1));
    let root = fs::read_to_string(&marker).unwrap();
    assert!(
        !std::path::Path::new(root.trim()).exists(),
        "temporary fixtures must be cleaned up"
    );
}

/// A fake `node` that answers `--version`, the shim's `version` and `scan`
/// commands (the shim path is ignored), and a fake package root.
fn fake_node(dir: &std::path::Path, scan_output: &str) -> std::path::PathBuf {
    let body = format!(
        r#"if [ "$1" = "--version" ]; then echo v22.0.0-fake; exit 0; fi
case "$2" in
  version) [ -f "$4/node_modules/@redact-secret/core/package.json" ] || exit 3; echo '{{"version":"9.9.9-fake"}}';;
  scan) cat > /dev/null; printf '%s\n' {scan_output};;
esac"#
    );
    script(dir, "node", &body)
}

fn package_root(dir: &std::path::Path, lock_version: &str) {
    let pkg = dir.join("node_modules/@redact-secret/core");
    fs::create_dir_all(&pkg).unwrap();
    fs::write(
        pkg.join("package.json"),
        r#"{"name":"@redact-secret/core","version":"9.9.9-fake"}"#,
    )
    .unwrap();
    fs::write(
        dir.join("package-lock.json"),
        json!({"lockfileVersion": 3, "packages": {"node_modules/@redact-secret/core": {
            "version": lock_version, "integrity": "sha512-FAKE"}}})
        .to_string(),
    )
    .unwrap();
    fs::write(dir.join("shim.mjs"), "// fake shim\n").unwrap();
}

#[test]
fn node_adapter_converts_utf16_offsets_and_records_packages() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    // "密钥 id=EXAMPLEKEYID0001 secret=" is 30 UTF-16 units and 34 bytes.
    let node = fake_node(
        d,
        r#"'{"path":"contracts-smoke/positive-miss-companion.txt","start":30,"end":66,"label":"generic-token","type":"generic_secret","action":"redact"}' '{"done":true,"findings":1}'"#,
    );
    package_root(d, "9.9.9-fake");
    let adapter = credential_eval_adapters::find("redact-secret").unwrap();
    let mut spec = adapter.default_spec();
    spec.configuration
        .insert("node".into(), json!(node.to_str().unwrap()));
    let mut env = env();
    env.node_dir = d.to_path_buf();
    let out = run_with(&smoke_corpus(), &config(vec![spec.clone()], 2), &env);
    let ObservationResult::Complete { findings, .. } = status_of(&out, "redact-secret") else {
        panic!("expected complete: {:?}", status_of(&out, "redact-secret"));
    };
    assert_eq!((findings[0].start, findings[0].end), (34, 70));
    assert_eq!(findings[0].family.as_deref(), Some("generic-token"));
    assert_eq!(findings[0].action.as_deref(), Some("redact"));
    let identity = &out.artifact.manifest.scanners[0];
    assert_eq!(identity.version.as_deref(), Some("9.9.9-fake"));
    let kinds: Vec<ProvenanceKind> = identity
        .provenance
        .as_ref()
        .unwrap()
        .components
        .iter()
        .map(|c| c.kind)
        .collect();
    assert_eq!(
        kinds,
        [
            ProvenanceKind::Runtime,
            ProvenanceKind::Shim,
            ProvenanceKind::Lockfile,
            ProvenanceKind::NpmPackage
        ]
    );
    let package = identity
        .provenance
        .as_ref()
        .unwrap()
        .components
        .last()
        .unwrap();
    assert_eq!(package.integrity.as_deref(), Some("sha512-FAKE"));
    assert!(package.sha256.is_some(), "installed tree digest");

    // Candidate mode needs an explicit root; without one it is unavailable.
    let mut candidate = spec.clone();
    candidate
        .configuration
        .insert("package_source".into(), json!("candidate"));
    let out = run_with(&smoke_corpus(), &config(vec![candidate.clone()], 1), &env);
    assert!(matches!(
        status_of(&out, "redact-secret"),
        ObservationResult::Unavailable { .. }
    ));
    let mut with_root = env.clone();
    with_root
        .candidate_roots
        .insert("redact-secret".into(), d.to_path_buf());
    let out = run_with(&smoke_corpus(), &config(vec![candidate], 1), &with_root);
    assert!(matches!(
        status_of(&out, "redact-secret"),
        ObservationResult::Complete { .. }
    ));
}

#[test]
fn node_adapter_rejects_lockfile_drift_and_truncated_output() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let node = fake_node(
        d,
        r#"'{"path":"contracts-smoke/positive-exact.txt","start":0,"end":1,"label":"x"}'"#,
    );
    let adapter = credential_eval_adapters::find("redact-secret").unwrap();
    let mut spec = adapter.default_spec();
    spec.configuration
        .insert("node".into(), json!(node.to_str().unwrap()));
    let mut env = env();
    env.node_dir = d.to_path_buf();

    package_root(d, "1.0.0");
    let out = run_with(&smoke_corpus(), &config(vec![spec.clone()], 1), &env);
    let ObservationResult::Error { reason } = status_of(&out, "redact-secret") else {
        panic!("expected error");
    };
    assert!(reason.contains("lockfile"));

    package_root(d, "9.9.9-fake");
    let out = run_with(&smoke_corpus(), &config(vec![spec], 1), &env);
    let ObservationResult::Malformed { reason } = status_of(&out, "redact-secret") else {
        panic!("expected malformed");
    };
    assert!(reason.contains("Incomplete scanner output"));
}

#[test]
fn invalid_configurations_fail_before_running() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(dir.path(), "g", "8.30.1", "echo '[]'");
    let corpus = smoke_corpus();
    let env = env();
    let run_err = |config| {
        credential_eval_cli::orchestrate::run(&credential_eval_cli::orchestrate::RunRequest {
            corpus: &corpus,
            config: &config,
            env: &env,
            work_dir: None,
            cancel: &credential_eval_adapters::process::CancelToken::new(),
            enforce_pins: false,
            progress: &credential_eval_cli::progress::Silent,
        })
        .err()
        .expect("run must fail")
        .to_string()
    };
    let mut stale = gitleaks_spec("g", &bin);
    stale.adapter.version = "1".into();
    assert!(run_err(config(vec![stale], 1)).contains("version"));
    let dup = vec![gitleaks_spec("g", &bin), gitleaks_spec("g", &bin)];
    assert!(run_err(config(dup, 1)).contains("duplicate"));

    // Changed adapter-owned configuration is a scanner error, not a silent run.
    let mut changed = gitleaks_spec("g", &bin);
    changed
        .configuration
        .insert("rules".into(), json!("custom"));
    let out = run(&corpus, &config(vec![changed], 1));
    assert!(matches!(
        status_of(&out, "g"),
        ObservationResult::Error { .. }
    ));
    let mut networked = gitleaks_spec("g", &bin);
    networked.network = credential_eval_contracts::config::NetworkPolicy::Allowed;
    let out = run(&corpus, &config(vec![networked], 1));
    assert!(matches!(
        status_of(&out, "g"),
        ObservationResult::Unsupported { .. }
    ));
}

/// One mappable row and one decoded row the adapter cannot map (depth 2), on
/// two different fixtures (ADR 0003).
const ONE_GOOD_ONE_DECODED: &str = r#"echo "[{\"RuleID\":\"generic-api-key\",\"File\":\"$root/contracts-smoke/positive-exact.txt\",\"Secret\":\"EXAMPLE_FAKE_KEY_0123456789abcdef\",\"StartLine\":2,\"StartColumn\":1,\"Tags\":[]},{\"RuleID\":\"generic-api-key\",\"File\":\"$root/contracts-smoke/positive-partial.txt\",\"Secret\":\"x\",\"StartLine\":1,\"Tags\":[\"decoded:base64\",\"decode-depth:2\"]}]""#;

fn per_case(spec: &mut credential_eval_contracts::config::ScannerSpec) {
    spec.configuration
        .insert("unmappable_findings".into(), json!("unmeasured-case"));
}

#[test]
fn unmappable_finding_fails_the_scanner_unless_the_config_chose_per_case_handling() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(dir.path(), "gitleaks", "8.30.1", ONE_GOOD_ONE_DECODED);
    let corpus = smoke_corpus();
    let out = run(&corpus, &config(vec![gitleaks_spec("gitleaks", &bin)], 2));
    assert!(matches!(
        status_of(&out, "gitleaks"),
        ObservationResult::Malformed { .. }
    ));
}

#[test]
fn per_case_handling_leaves_the_fixture_unmeasured_and_the_rest_measured() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(dir.path(), "gitleaks", "8.30.1", ONE_GOOD_ONE_DECODED);
    let corpus = smoke_corpus();
    let mut spec = gitleaks_spec("gitleaks", &bin);
    per_case(&mut spec);
    let out = run(&corpus, &config(vec![spec], 2));
    let ObservationResult::Complete {
        findings,
        unmeasured,
        ..
    } = status_of(&out, "gitleaks")
    else {
        panic!("expected complete");
    };
    assert_eq!(findings.len(), 1);
    assert_eq!(unmeasured.len(), 1);
    assert_eq!(
        unmeasured[0].path.as_str(),
        "contracts-smoke/positive-partial.txt"
    );
    assert!(
        unmeasured[0]
            .reason
            .ends_with("Unsupported decoded Gitleaks finding")
    );

    let run = &out.artifact.scanners[0];
    assert_eq!(run.status, ScannerStatus::Complete);
    // The unmeasured case is reported, never a miss, and in no group.
    assert_eq!(run.unmeasured_cases.len(), 1);
    let case = run
        .cases
        .iter()
        .find(|c| c.path.as_str() == "contracts-smoke/positive-partial.txt")
        .unwrap();
    assert_eq!(run.unmeasured_cases[0].case_id, case.case_id);
    assert!(matches!(
        case.measurement,
        CaseMeasurement::NotMeasured {
            status: ScannerStatus::Malformed
        }
    ));
    assert!(case.actual.is_empty());
    let measured = run
        .cases
        .iter()
        .filter(|c| !matches!(c.measurement, CaseMeasurement::NotMeasured { .. }))
        .count();
    assert_eq!(measured, run.cases.len() - 1);
    assert_schema_valid(&out.artifact);
    // Raw output never reaches the artifact.
    let text = serde_json::to_string(&out.artifact).unwrap();
    assert!(!text.contains("decoded:base64"));
}

#[test]
fn per_case_handling_still_fails_closed_on_an_unattributable_row() {
    let dir = tempfile::tempdir().unwrap();
    let scan = r#"echo "[{\"RuleID\":\"generic-api-key\",\"File\":\"$root/not-a-fixture.txt\",\"Secret\":\"x\",\"StartLine\":1,\"Tags\":[]}]""#;
    let bin = fake_gitleaks(dir.path(), "gitleaks", "8.30.1", scan);
    let corpus = smoke_corpus();
    let mut spec = gitleaks_spec("gitleaks", &bin);
    per_case(&mut spec);
    let out = run(&corpus, &config(vec![spec], 2));
    assert!(matches!(
        status_of(&out, "gitleaks"),
        ObservationResult::Malformed { .. }
    ));
}

#[test]
fn an_invalid_per_case_value_is_a_configuration_error() {
    let dir = tempfile::tempdir().unwrap();
    let bin = fake_gitleaks(dir.path(), "gitleaks", "8.30.1", "echo '[]'");
    let corpus = smoke_corpus();
    let mut spec = gitleaks_spec("gitleaks", &bin);
    spec.configuration
        .insert("unmappable_findings".into(), json!("ignore"));
    let out = run(&corpus, &config(vec![spec], 1));
    assert!(matches!(
        status_of(&out, "gitleaks"),
        ObservationResult::Error { .. }
    ));
}
