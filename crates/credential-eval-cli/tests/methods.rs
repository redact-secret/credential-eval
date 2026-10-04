//! End-to-end tests of evaluation-method runs (`run --methods`) with fake
//! scanners over a synthetic corpus: bounded, deterministic, schema-valid,
//! and wired through build_cases → plan → variant corpus → scan → evaluate.

#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;
use credential_eval_contracts::artifact::RunArtifact;
use credential_eval_contracts::corpus::CorpusSnapshot;
use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_credential-eval"))
}

/// A fake Gitleaks that reports every match of `pattern` (an ERE) under the
/// materialized root as a `generic-api-key` finding.
fn grep_scanner(dir: &Path, name: &str, pattern: &str) -> PathBuf {
    let scan = format!(
        r#"printf '['
grep -rnoE '{pattern}' "$root" | awk -F: 'BEGIN {{ sep = "" }} {{ printf "%s{{\"RuleID\":\"generic-api-key\",\"File\":\"%s\",\"Secret\":\"%s\",\"StartLine\":%s}}", sep, $1, $3, $2; sep = "," }}'
printf ']'"#
    );
    fake_gitleaks(dir, name, "8.30.1", &scan)
}

/// The smoke corpus with a reviewed taxonomy on its benign control (required
/// by the `benign` method).
fn corpus(dir: &Path) -> PathBuf {
    let smoke = smoke_corpus();
    let mut cases = smoke.cases.clone();
    for case in &mut cases {
        if case.id.as_str() == "benign-placeholder" {
            case.grouping.taxonomy = Some("placeholder".into());
        }
    }
    let corpus = CorpusSnapshot::seal(
        smoke.identity.source.clone(),
        smoke.identity.revision.clone(),
        smoke.identity.evidence_schema.clone(),
        cases,
    );
    let path = dir.join("corpus.json");
    fs::write(&path, serde_json::to_vec(&corpus).unwrap()).unwrap();
    path
}

fn evidence(dir: &Path) -> PathBuf {
    let path = dir.join("evidence.json");
    fs::write(
        &path,
        r#"{
  "schema": "credential-eval/evaluation-evidence/v1",
  "families": {
    "example-api-key": { "pattern": "^EXAMPLE_FAKE_KEY_[0-9a-f]{16,}$" },
    "generic-token": {}
  },
  "benign_taxonomies": ["placeholder"],
  "classification_allowlist": true
}"#,
    )
    .unwrap();
    path
}

struct Setup {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    corpus: PathBuf,
    evidence: PathBuf,
    config: PathBuf,
}

fn setup(broken: bool) -> Setup {
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path().to_path_buf();
    let mut scanners = vec![
        gitleaks_spec(
            "reference",
            &grep_scanner(&d, "g1", "EXAMPLE_FAKE_KEY_[0-9a-f]+"),
        ),
        gitleaks_spec("peer", &grep_scanner(&d, "g2", "EXAMPLE_FAKE_KEY_[0-9]+")),
    ];
    if broken {
        scanners.push(gitleaks_spec(
            "broken",
            &fake_gitleaks(&d, "g3", "8.30.1", "echo nope"),
        ));
    }
    let config = d.join("run-config.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&common::config(scanners, 1)).unwrap(),
    )
    .unwrap();
    Setup {
        corpus: corpus(&d),
        evidence: evidence(&d),
        config,
        dir: d,
        _dir: tmp,
    }
}

fn method_run(s: &Setup, name: &str, extra: &[&str]) -> (Output, PathBuf) {
    let out = s.dir.join(format!("{name}.json"));
    let output = bin()
        .args(["run", "--corpus"])
        .arg(&s.corpus)
        .arg("--config")
        .arg(&s.config)
        .arg("--evidence")
        .arg(&s.evidence)
        .args(["--methods", "all", "--reference", "reference", "--out"])
        .arg(&out)
        .args(extra)
        .output()
        .unwrap();
    (output, out)
}

#[test]
fn method_runs_are_deterministic_schema_valid_and_complete() {
    let s = setup(false);
    let view = s.dir.join("legacy-eval.json");
    let mut texts = Vec::new();
    for jobs in ["1", "8"] {
        let mut extra = vec!["--jobs", jobs];
        let view_arg = view.to_str().unwrap().to_owned();
        if jobs == "1" {
            extra.extend(["--legacy-eval-out", view_arg.as_str()]);
        }
        let (output, out) = method_run(&s, &format!("artifact-{jobs}"), &extra);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(
            !stderr.contains("EXAMPLE_FAKE"),
            "stderr must not echo values"
        );
        let artifact: RunArtifact = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        assert_schema_valid(&artifact);
        texts.push(semantic_text(&artifact));

        // Wiring: five methods, variants, per-variant cases, assertions,
        // reference comparisons, a review queue and resolution.
        assert_eq!(artifact.manifest.methods.len(), 5);
        assert!(!artifact.variants.is_empty());
        for run in &artifact.scanners {
            assert_eq!(run.cases.len(), artifact.variants.len());
            assert!(!run.assertions.is_empty());
            assert!(!run.aggregates.resolution.is_empty());
            assert!(run.aggregates.groups.is_empty());
        }
        assert!(
            artifact
                .comparisons
                .iter()
                .all(|c| c.reference.as_str() == "reference")
        );
        assert!(!artifact.comparisons.is_empty());
        assert!(!artifact.review_queue.is_empty());
        // Evidence is the base snapshot, not the derived variant corpus.
        let base = CorpusSnapshot::from_json(&fs::read(&s.corpus).unwrap()).unwrap();
        assert_eq!(artifact.manifest.evidence, base.identity);
    }
    assert_eq!(texts[0], texts[1], "jobs must not change a method run");

    // The legacy evaluation view is written and sanitized.
    let view: Value = serde_json::from_slice(&fs::read(&view).unwrap()).unwrap();
    assert_eq!(view["view"], "credential-eval/legacy-evaluation-view/v1");
    assert!(view["results"].as_array().unwrap().len() > 8);
    assert!(view["byMethod"].as_object().unwrap().len() > 1);
    assert!(
        !view
            .to_string()
            .contains("EXAMPLE_FAKE_KEY_0123456789abcdef")
    );
}

#[test]
fn seed_convention_and_evidence_are_part_of_the_run_identity() {
    let s = setup(false);
    let hash = |extra: &[&str], name: &str| {
        let (output, out) = method_run(&s, name, extra);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let a: RunArtifact = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
        a.manifest.config_hash
    };
    let canonical = hash(&[], "canonical");
    let legacy = hash(&["--seed", "legacy-category"], "legacy");
    assert_ne!(canonical, legacy);
}

#[test]
fn strict_method_runs_fail_on_incomplete_scanners() {
    let s = setup(true);
    let (output, out) = method_run(&s, "lenient", &[]);
    assert!(output.status.success());
    let artifact: RunArtifact = serde_json::from_slice(&fs::read(out).unwrap()).unwrap();
    let broken = artifact
        .scanners
        .iter()
        .find(|r| r.scanner.as_str() == "broken")
        .unwrap();
    // A failed scanner is never a MISS: every assertion is not-measured.
    assert!(
        broken
            .assertions
            .iter()
            .all(|a| a.status == credential_eval_contracts::artifact::AssertionStatus::NotMeasured)
    );
    let (output, _) = method_run(&s, "strict", &["--strict"]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn method_flags_are_validated() {
    let s = setup(false);
    let run = |args: &[&str]| {
        bin()
            .args(["run", "--corpus"])
            .arg(&s.corpus)
            .arg("--config")
            .arg(&s.config)
            .args(["--out"])
            .arg(s.dir.join("x.json"))
            .args(args)
            .output()
            .unwrap()
            .status
            .code()
    };
    assert_eq!(run(&["--reference", "reference"]), Some(2));
    assert_eq!(run(&["--methods", "twin,nope"]), Some(2));
    assert_eq!(run(&["--methods", "twin,twin"]), Some(2));
    assert_eq!(run(&["--methods", "all", "--reference", "absent"]), Some(2));
    assert_eq!(run(&["--methods", "all", "--seed", "other"]), Some(2));
    let bad = s.dir.join("bad-evidence.json");
    fs::write(&bad, r#"{"schema":"credential-eval/evaluation-evidence/v1","families":{},"validators":{"x":"legacy:nope"}}"#).unwrap();
    assert_eq!(
        run(&["--methods", "all", "--evidence", bad.to_str().unwrap()]),
        Some(2)
    );
}

/// A fake Gitleaks like [`grep_scanner`] that cannot map the first fixture
/// containing the canonical value: it reports a decoded depth-2 row for it
/// instead (ADR 0003, ADR 0004).
fn partial_scanner(dir: &Path, name: &str, pattern: &str) -> PathBuf {
    let scan = format!(
        r#"unm=$(grep -rlE 'EXAMPLE_FAKE_KEY_0123456789abcdef' "$root" | grep -E 'metamorphic|mutation' | sort | head -1)
printf '['
grep -rnoE '{pattern}' "$root" | grep -v "^$unm:" | awk -F: '{{ printf "%s{{\"RuleID\":\"generic-api-key\",\"File\":\"%s\",\"Secret\":\"%s\",\"StartLine\":%s}}", sep, $1, $3, $2; sep = "," }}'
printf ',{{"RuleID":"generic-api-key","File":"%s","Secret":"x","StartLine":1,"Tags":["decoded:base64","decode-depth:2"]}}' "$unm"
printf ']'"#
    );
    fake_gitleaks(dir, name, "8.30.1", &scan)
}

#[test]
fn an_unmeasured_variant_is_in_no_denominator_and_never_a_miss_in_methods() {
    use credential_eval_contracts::artifact::{AssertionStatus, CaseMeasurement};
    let tmp = tempfile::tempdir().unwrap();
    let d = tmp.path().to_path_buf();
    let clean = |name: &str, id: &str| {
        gitleaks_spec(id, &grep_scanner(&d, name, "EXAMPLE_FAKE_KEY_[0-9a-f]+"))
    };
    let mut gappy = gitleaks_spec(
        "gappy",
        &partial_scanner(&d, "g2", "EXAMPLE_FAKE_KEY_[0-9a-f]+"),
    );
    gappy
        .configuration
        .insert("unmappable_findings".into(), "unmeasured-case".into());
    // The same fake without the opt-in: the scanner is malformed, as before.
    let mut strict = gitleaks_spec(
        "strict",
        &partial_scanner(&d, "g3", "EXAMPLE_FAKE_KEY_[0-9a-f]+"),
    );
    strict
        .configuration
        .insert("unmappable_findings".into(), "fail".into());
    let config = d.join("run-config.json");
    fs::write(
        &config,
        serde_json::to_vec_pretty(&common::config(
            vec![clean("g1", "reference"), clean("g4", "peer"), gappy, strict],
            1,
        ))
        .unwrap(),
    )
    .unwrap();
    let s = Setup {
        corpus: corpus(&d),
        evidence: evidence(&d),
        config,
        dir: d,
        _dir: tmp,
    };
    let mut texts = Vec::new();
    for jobs in ["1", "8"] {
        let (output, out) = method_run(&s, &format!("gap-{jobs}"), &["--jobs", jobs]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{stderr}");
        assert!(
            stderr.contains("gappy unmeasured:") && stderr.contains("variants by method:"),
            "{stderr}"
        );
        let artifact: RunArtifact = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        assert_schema_valid(&artifact);
        texts.push(semantic_text(&artifact));
        let run = |id: &str| {
            artifact
                .scanners
                .iter()
                .find(|r| r.scanner.as_str() == id)
                .unwrap()
        };
        let (reference, gappy, strict) = (run("reference"), run("gappy"), run("strict"));
        assert_eq!(
            strict.status,
            credential_eval_contracts::observation::ScannerStatus::Malformed,
            "without the opt-in a single unmappable row still fails the scanner"
        );
        assert_eq!(reference.unmeasured_cases.len(), 0);
        assert_eq!(gappy.unmeasured_cases.len(), 1);
        let gone = &gappy.unmeasured_cases[0].case_id;
        let row = gappy.cases.iter().find(|c| &c.case_id == gone).unwrap();
        assert!(matches!(
            row.measurement,
            CaseMeasurement::NotMeasured { .. }
        ));
        assert!(row.actual.is_empty());
        // No assertion mentions the unmeasured variant, and none is a
        // not-measured stand-in: it is in no denominator.
        let record = artifact
            .variants
            .iter()
            .find(|v| v.path == row.path)
            .unwrap();
        let (case_id, variant) = (record.case_id.clone(), record.variant.clone());
        let mentions = |a: &credential_eval_contracts::artifact::Assertion| {
            a.case_id == case_id
                && (a.variant.as_ref() == Some(&variant)
                    || a.baseline.as_ref() == Some(&variant)
                    || a.candidate.as_ref() == Some(&variant))
        };
        assert!(!gappy.assertions.iter().any(mentions));
        assert!(
            gappy
                .assertions
                .iter()
                .all(|a| a.status != AssertionStatus::NotMeasured)
        );
        assert!(gappy.assertions.len() < reference.assertions.len());
        // Every other variant of the scanner is measured as the clean peer is.
        let peer = run("peer");
        let kept = peer.assertions.iter().filter(|a| !mentions(a)).count();
        assert_eq!(gappy.assertions.len(), kept);
        // Differential comparisons skip the variant for that peer only.
        let compared = |peer: &str| {
            artifact
                .comparisons
                .iter()
                .filter(|c| c.peer.as_str() == peer && c.case_id == case_id && c.variant == variant)
                .count()
        };
        // A clean peer is compared with the reference on the variant (or the
        // variant carries assertions), the gappy one is not.
        assert!(compared("peer") > 0 || peer.assertions.iter().any(mentions));
        assert_eq!(compared("gappy"), 0);
    }
    assert_eq!(texts[0], texts[1], "jobs must not change a method run");
    // `--require-fully-measured` surfaces the gap as an exit code.
    let (output, _) = method_run(&s, "gate", &["--require-fully-measured"]);
    assert_eq!(output.status.code(), Some(3));
}
