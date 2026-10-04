//! Integration test against the real pinned scanners. Skipped unless
//! `CREDENTIAL_EVAL_REAL_SCANNERS=1` (CI does not install the scanners).
//!
//! Local run (pinned peers first on `PATH`, `npm ci` done in `adapters/node`):
//!
//! ```sh
//! PATH="<dir with gitleaks 8.30.1 and trufflehog 3.97.4>:$PATH" \
//!   CREDENTIAL_EVAL_REAL_SCANNERS=1 \
//!   cargo test -p credential-eval-cli --test real_scanners -- --nocapture
//! ```
//!
//! Every built-in adapter runs with its default (legacy-pinned)
//! configuration over `tests/fixtures/contracts-smoke`. Each must complete,
//! and `--jobs 1` and `--jobs 4` must give the same semantic artifact.

mod common;

use common::*;
use credential_eval_adapters::AdapterEnv;
use credential_eval_contracts::observation::ScannerStatus;

#[test]
fn all_builtin_adapters_complete_on_the_smoke_corpus() {
    if std::env::var("CREDENTIAL_EVAL_REAL_SCANNERS").as_deref() != Ok("1") {
        eprintln!("skipped: set CREDENTIAL_EVAL_REAL_SCANNERS=1 to run against real scanners");
        return;
    }
    let corpus = smoke_corpus();
    let env = AdapterEnv::from_process();
    let serial = credential_eval_cli::default_config(&[], 1).unwrap();
    let parallel = credential_eval_cli::default_config(&[], 4).unwrap();
    let one = run_with(&corpus, &serial, &env);
    let four = run_with(&corpus, &parallel, &env);
    assert_schema_valid(&four.artifact);
    assert_eq!(semantic_text(&one.artifact), semantic_text(&four.artifact));

    eprintln!("scanner         version          status     findings");
    for (identity, run) in four
        .artifact
        .manifest
        .scanners
        .iter()
        .zip(&four.artifact.scanners)
    {
        eprintln!(
            "{:<15} {:<16} {:<10} {}",
            identity.id.as_str(),
            identity.version.as_deref().unwrap_or("-"),
            format!("{:?}", run.status),
            run.findings.len()
        );
    }
    let execution = four.artifact.non_semantic.execution.as_ref().unwrap();
    eprintln!(
        "jobs 4: wall {} ms, {} scanner processes ({} ms), evaluator {} ms; semantic digest {}",
        execution.wall_ms,
        execution.processes,
        execution.scanner_process_ms,
        execution.evaluator_ms,
        four.artifact.semantic_digest()
    );
    for run in &four.artifact.scanners {
        assert_eq!(
            run.status,
            ScannerStatus::Complete,
            "{}: {:?}",
            run.scanner,
            run.detail
        );
    }
}

// ---------------------------------------------------------------------------
// Representation contract against the real pinned peers (ADR 0005).

mod representation {
    use super::*;
    use credential_eval_contracts::artifact::{CaseMeasurement, Outcome, ScannerRun};
    use credential_eval_contracts::canonical::sha256_bytes;
    use credential_eval_contracts::corpus::{Case, CorpusSnapshot};
    use credential_eval_contracts::schema::RepresentationContract;
    use serde_json::{Value, json};

    /// A GitHub-PAT-shaped value built at run time from parts, so no
    /// credential-shaped literal sits in the repository. Never issued.
    fn token() -> String {
        ["gh", "p_", "Zk3Qm8Xv1Rt6Yb2Nc5Wd9Ha4Js7Lp0Ue1Fg2"].concat()
    }

    fn b64(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
            for i in 0..=chunk.len() {
                out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
            }
            for _ in chunk.len() + 1..4 {
                out.push('=');
            }
        }
        out
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const B64: &str = r#"{"codec": "base64", "alphabet": "standard", "padding": "padded"}"#;
    const HEX: &str = r#"{"codec": "hex", "case": "lower"}"#;

    /// `ENCODED=<encoded>` with the secret value encoded through `layers`
    /// (outermost last); the expected span is the encoded run.
    fn encoded_case(id: &str, layers: &[&str]) -> Case {
        let secret = token();
        let mut text = secret.clone().into_bytes();
        let mut via: Vec<Value> = Vec::new();
        for layer in layers {
            text = if *layer == "base64" {
                b64(&text).into_bytes()
            } else {
                hex(&text).into_bytes()
            };
            via.insert(
                0,
                serde_json::from_str(if *layer == "base64" { B64 } else { HEX }).unwrap(),
            );
        }
        let encoded = String::from_utf8(text).unwrap();
        let start = "ENCODED=".len();
        serde_json::from_value(json!({
            "id": id, "path": format!("rep/{id}.txt"),
            "content": format!("ENCODED={encoded}\n"),
            "expected": [{"start": start, "end": start + encoded.len(), "role": "secret",
                "decoded": {"via": via, "sha256": sha256_bytes(secret.as_bytes()),
                            "bytes": secret.len()}}],
            "grouping": {"kind": "must-redact", "tier": "T1", "group": "rep", "family": "github-pat"}
        }))
        .unwrap()
    }

    fn corpus() -> CorpusSnapshot {
        let plain: Case = serde_json::from_value(json!({
            "id": "plain", "path": "rep/plain.txt",
            "content": format!("GITHUB_TOKEN={}\n", token()),
            "expected": [{"start": 13, "end": 13 + token().len(), "role": "secret"}],
            "grouping": {"kind": "must-redact", "tier": "T1", "group": "rep", "family": "github-pat"}
        }))
        .unwrap();
        let mut snapshot = CorpusSnapshot::seal(
            "synthetic:representation-real".into(),
            "r1".into(),
            "synthetic-v1".into(),
            vec![
                plain,
                encoded_case("b64-depth-1", &["base64"]),
                encoded_case("b64-depth-2", &["base64", "base64"]),
                encoded_case("b64-depth-3", &["base64", "base64", "base64"]),
                encoded_case("hex-depth-1", &["hex"]),
                encoded_case("hex-over-b64", &["base64", "hex"]),
            ],
        );
        snapshot.identity.representation = Some(RepresentationContract);
        snapshot.validate().expect("valid representation facts");
        snapshot
    }

    fn outcome(run: &ScannerRun, id: &str) -> CaseMeasurement {
        run.cases
            .iter()
            .find(|c| c.case_id.as_str() == id)
            .unwrap()
            .measurement
            .clone()
    }

    fn exact(m: &CaseMeasurement) -> bool {
        matches!(m, CaseMeasurement::Positive { span_outcomes, .. } if span_outcomes == &[Outcome::Exact])
    }

    /// Decoded findings of the real Gitleaks 8.30.1 and TruffleHog 3.97.4 are
    /// placed on the original bytes where the rule can prove it, and nowhere
    /// else: no case is left unmeasured here, a case the scanner does not
    /// decode is a measured miss, and the semantic artifact is stable.
    #[test]
    fn real_peers_decoded_findings_map_to_source_segments() {
        if std::env::var("CREDENTIAL_EVAL_REAL_SCANNERS").as_deref() != Ok("1") {
            eprintln!("skipped: set CREDENTIAL_EVAL_REAL_SCANNERS=1 to run against real scanners");
            return;
        }
        let corpus = corpus();
        let env = AdapterEnv::from_process();
        let mut config = credential_eval_cli::default_config(
            &["gitleaks".to_owned(), "trufflehog".to_owned()],
            2,
        )
        .unwrap();
        for spec in &mut config.scanners {
            spec.configuration
                .insert("unmappable_findings".into(), json!("unmeasured-case"));
            spec.configuration
                .insert("decoded_mapping".into(), json!("source-segment"));
        }
        let out = run_with(&corpus, &config, &env);
        let again = run_with(&corpus, &config, &env);
        assert_eq!(semantic_text(&out.artifact), semantic_text(&again.artifact));
        assert_schema_valid(&out.artifact);
        let run = |id: &str| {
            out.artifact
                .scanners
                .iter()
                .find(|s| s.scanner.as_str() == id)
                .unwrap()
        };

        // Gitleaks decodes base64 and hex at any depth and reports the
        // decoded value: every encoded case is placed on its source segment.
        let gitleaks = run("gitleaks");
        assert_eq!(gitleaks.status, ScannerStatus::Complete);
        assert!(
            gitleaks.unmeasured_cases.is_empty(),
            "{:?}",
            gitleaks.unmeasured_cases
        );
        for id in [
            "plain",
            "b64-depth-1",
            "b64-depth-2",
            "b64-depth-3",
            "hex-depth-1",
            "hex-over-b64",
        ] {
            assert!(
                exact(&outcome(gitleaks, id)),
                "gitleaks {id}: {:?}",
                outcome(gitleaks, id)
            );
        }
        let mapped = |id: &str| {
            gitleaks
                .cases
                .iter()
                .find(|c| c.case_id.as_str() == id)
                .unwrap()
                .actual
                .iter()
                .filter_map(|a| a.mapping.clone())
                .collect::<Vec<_>>()
        };
        assert!(
            mapped("plain").is_empty(),
            "a plain finding carries no mapping"
        );
        assert!(mapped("b64-depth-2").iter().any(|m| m.layers == 2));
        assert!(mapped("hex-over-b64").iter().any(|m| m.layers == 2));

        // TruffleHog decodes base64 only: those cases are placed, the hex
        // cases are measured misses (it never reported them), none is
        // unmeasured.
        let trufflehog = run("trufflehog");
        assert_eq!(trufflehog.status, ScannerStatus::Complete);
        assert!(
            trufflehog.unmeasured_cases.is_empty(),
            "{:?}",
            trufflehog.unmeasured_cases
        );
        for id in ["plain", "b64-depth-1", "b64-depth-2"] {
            assert!(exact(&outcome(trufflehog, id)), "trufflehog {id}");
        }
        let id = "hex-depth-1";
        assert!(
            matches!(outcome(trufflehog, id), CaseMeasurement::Positive { .. }),
            "trufflehog {id} is a measured case"
        );
        assert!(!exact(&outcome(trufflehog, id)), "trufflehog {id}");
    }
}
