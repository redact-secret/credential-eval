//! Whole-population accuracy reuse (ADR 0008): peers keep their recorded
//! observations and launch no scan, a changed fixture is refused, an
//! expectation-only change re-scores without rescanning, and every wrong
//! identity or receipt fails clearly.

#![cfg(unix)]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use common::*;
use credential_eval_adapters::process::CancelToken;
use credential_eval_cli::orchestrate::{self, ReuseRequest, RunError, RunOutput, RunRequest};
use credential_eval_contracts::artifact::ObservationOrigin;
use credential_eval_contracts::config::RunConfig;
use credential_eval_contracts::corpus::CorpusSnapshot;
use credential_eval_contracts::ids::ScannerId;
use credential_eval_contracts::observation::{ObservationResult, ObservationSet, Replays};

const ONE_ROW: &str = r#"echo "[{\"RuleID\":\"generic-api-key\",\"File\":\"$root/contracts-smoke/positive-exact.txt\",\"Secret\":\"EXAMPLE_FAKE_KEY_0123456789abcdef\",\"StartLine\":2,\"StartColumn\":1,\"Tags\":[]}]""#;

/// A fake scanner that appends one line to `mark` per scan (not per probe).
fn marked(dir: &Path, name: &str, version: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let mark = dir.join(format!("{name}.mark"));
    let scan = format!("echo scan >> '{}'\n{ONE_ROW}", mark.display());
    (fake_gitleaks(dir, name, version, &scan), mark)
}

fn scans(mark: &Path) -> usize {
    fs::read_to_string(mark).map_or(0, |t| t.lines().count())
}

fn run_reuse(
    corpus: &CorpusSnapshot,
    config: &RunConfig,
    source: &ObservationSet,
    fresh: &[&str],
) -> Result<RunOutput, RunError> {
    let fresh: BTreeSet<ScannerId> = fresh
        .iter()
        .map(|id| ScannerId::new(*id).unwrap())
        .collect();
    let reuse = ReuseRequest {
        source,
        fresh: &fresh,
    };
    orchestrate::run(&RunRequest {
        corpus,
        config,
        env: &env(),
        work_dir: None,
        cancel: &CancelToken::new(),
        enforce_pins: false,
        progress: &credential_eval_cli::progress::Silent,
        reuse: Some(&reuse),
    })
}

fn refused(result: Result<RunOutput, RunError>) -> String {
    match result {
        Err(RunError::ReuseRefused(message)) => message,
        Err(other) => panic!("expected a reuse refusal, got {other}"),
        Ok(_) => panic!("expected a reuse refusal"),
    }
}

fn two_scanner_config(peer: &Path, product: &Path) -> RunConfig {
    config(
        vec![
            gitleaks_spec("peer", peer),
            gitleaks_spec("product", product),
        ],
        2,
    )
}

#[test]
fn product_only_replay_runs_the_product_twice_and_no_peer_scan() {
    let dir = tempfile::tempdir().unwrap();
    let (peer, peer_mark) = marked(dir.path(), "peer", "8.30.1");
    let (product, product_mark) = marked(dir.path(), "product", "8.30.1");
    let corpus = smoke_corpus();
    let config = two_scanner_config(&peer, &product);
    let first = run(&corpus, &config);
    assert_eq!((scans(&peer_mark), scans(&product_mark)), (2, 2));

    let reused = run_reuse(&corpus, &config, &first.observations, &["product"]).unwrap();
    assert_eq!(scans(&peer_mark), 2, "the peer must launch no scan");
    assert_eq!(scans(&product_mark), 4, "the product runs twice, fresh");

    // Original receipts survive untouched, and the artifact agrees with a
    // fully fresh run of the same population.
    let source_peer = &first.observations.observations[0];
    assert_eq!(&reused.observations.observations[0], source_peer);
    assert_eq!(
        reused.artifact.semantic_digest(),
        first.artifact.semantic_digest()
    );
    assert_schema_valid(&reused.artifact);

    let diagnostics = reused.artifact.non_semantic.execution.as_ref().unwrap();
    let origin = |id: &str| {
        let t = &diagnostics.scanners[id];
        (t.origin, t.origin_reason.clone().unwrap(), t.tasks)
    };
    assert_eq!(
        origin("peer"),
        (Some(ObservationOrigin::Reused), "compatible".into(), 0)
    );
    assert_eq!(
        origin("product"),
        (Some(ObservationOrigin::Fresh), "forced".into(), 2)
    );
    assert!(diagnostics.reuse.is_some());
    // A run that offered nothing records no origin.
    let plain = first.artifact.non_semantic.execution.as_ref().unwrap();
    assert!(plain.reuse.is_none() && plain.scanners["peer"].origin.is_none());
}

#[test]
fn a_changed_scanner_runs_fresh_and_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let (peer, peer_mark) = marked(dir.path(), "peer", "8.30.1");
    let (product, _) = marked(dir.path(), "product", "8.30.1");
    let corpus = smoke_corpus();
    let first = run(&corpus, &two_scanner_config(&peer, &product));
    let (candidate, candidate_mark) = marked(dir.path(), "candidate", "8.30.1");
    let changed = two_scanner_config(&peer, &candidate);
    let out = run_reuse(&corpus, &changed, &first.observations, &[]).unwrap();
    assert_eq!(scans(&peer_mark), 2);
    assert_eq!(scans(&candidate_mark), 2);
    let timing = &out
        .artifact
        .non_semantic
        .execution
        .as_ref()
        .unwrap()
        .scanners["product"];
    assert_eq!(timing.origin, Some(ObservationOrigin::Fresh));
    let reason = timing.origin_reason.clone().unwrap();
    assert!(
        reason.starts_with("changed: ") && reason.contains("provenance"),
        "{reason}"
    );
}

#[test]
fn a_changed_fixture_is_never_given_stale_findings() {
    let dir = tempfile::tempdir().unwrap();
    let (peer, peer_mark) = marked(dir.path(), "peer", "8.30.1");
    let corpus = smoke_corpus();
    let config = config(vec![gitleaks_spec("peer", &peer)], 1);
    let first = run(&corpus, &config);

    let mut cases = corpus.cases.clone();
    cases[1].content.push_str("# appended\n");
    let changed = CorpusSnapshot::seal(
        corpus.identity.source.clone(),
        corpus.identity.revision.clone(),
        corpus.identity.evidence_schema.clone(),
        cases,
    );
    let message = refused(run_reuse(&changed, &config, &first.observations, &[]));
    assert!(message.contains("fixture inputs changed"), "{message}");
    assert_eq!(
        scans(&peer_mark),
        2,
        "nothing was scanned around the refusal"
    );

    // Removing a case changes the population too.
    let mut cases = corpus.cases.clone();
    cases.pop();
    let smaller = CorpusSnapshot::seal(
        corpus.identity.source.clone(),
        corpus.identity.revision.clone(),
        corpus.identity.evidence_schema.clone(),
        cases,
    );
    let message = refused(run_reuse(&smaller, &config, &first.observations, &[]));
    assert!(message.contains("fixture inputs changed"), "{message}");
}

#[test]
fn an_expectation_only_change_rescores_without_rescanning() {
    let dir = tempfile::tempdir().unwrap();
    let (peer, peer_mark) = marked(dir.path(), "peer", "8.30.1");
    let corpus = smoke_corpus();
    let config = config(vec![gitleaks_spec("peer", &peer)], 1);
    let first = run(&corpus, &config);

    // A new evidence revision and a relabelled case: bytes are identical.
    let mut cases = corpus.cases.clone();
    cases[0].grouping.group = "relabelled".into();
    let relabelled = CorpusSnapshot::seal(
        corpus.identity.source.clone(),
        "a-newer-revision".into(),
        corpus.identity.evidence_schema.clone(),
        cases,
    );
    assert_ne!(
        relabelled.identity.corpus_digest,
        corpus.identity.corpus_digest
    );
    let reused = run_reuse(&relabelled, &config, &first.observations, &[]).unwrap();
    assert_eq!(scans(&peer_mark), 2, "no rescan");
    assert_eq!(
        reused.observations.corpus_digest, relabelled.identity.corpus_digest,
        "the artifact is bound to the new corpus"
    );
    let fresh = run(&relabelled, &config);
    assert_eq!(scans(&peer_mark), 4);
    assert_eq!(
        reused.artifact.semantic_digest(),
        fresh.artifact.semantic_digest()
    );
    assert_ne!(
        reused.artifact.semantic_digest(),
        first.artifact.semantic_digest()
    );
}

#[test]
fn wrong_identity_corrupt_data_and_weak_receipts_fail_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let (peer, peer_mark) = marked(dir.path(), "peer", "8.30.1");
    let corpus = smoke_corpus();
    let config = config(vec![gitleaks_spec("peer", &peer)], 1);
    let first = run(&corpus, &config);
    let try_with = |edit: &dyn Fn(&mut ObservationSet)| {
        let mut source = first.observations.clone();
        edit(&mut source);
        refused(run_reuse(&corpus, &config, &source, &[]))
    };

    let message = try_with(&|s| s.measurement = None);
    assert!(message.contains("no measurement binding"), "{message}");
    let message = try_with(&|s| s.measurement.as_mut().unwrap().protocol_version = "p/0".into());
    assert!(message.contains("p/0"), "{message}");
    let message = try_with(&|s| {
        s.measurement.as_mut().unwrap().restriction = Some(
            credential_eval_contracts::canonical::sha256_bytes(b"another allowlist"),
        );
    });
    assert!(message.contains("allowlist"), "{message}");
    let message = try_with(&|s| {
        if let ObservationResult::Complete { findings, .. } = &mut s.observations[0].result {
            findings[0].end = 1_000_000;
        }
    });
    assert!(message.contains("corrupt"), "{message}");
    let message = try_with(&|s| {
        if let ObservationResult::Complete { replays, .. } = &mut s.observations[0].result {
            *replays = Replays {
                count: 1,
                agreed: true,
            };
        }
    });
    assert!(message.contains("replay"), "{message}");
    let message = try_with(&|s| {
        s.observations[0].result = ObservationResult::Timeout { timeout_ms: 5 };
    });
    assert!(
        message.contains("timeout") && message.contains("--fresh peer"),
        "{message}"
    );
    assert_eq!(scans(&peer_mark), 2, "no refusal scanned anything");

    // A scanner the config does not have cannot be forced.
    let err = run_reuse(&corpus, &config, &first.observations, &["ghost"])
        .err()
        .unwrap();
    assert!(err.to_string().contains("ghost"), "{err}");

    // An absent peer simply runs fresh.
    let (other, other_mark) = marked(dir.path(), "other", "8.30.1");
    let both = two_scanner_config(&peer, &other);
    let out = run_reuse(&corpus, &both, &first.observations, &[]).unwrap();
    let t = &out
        .artifact
        .non_semantic
        .execution
        .as_ref()
        .unwrap()
        .scanners["product"];
    assert_eq!(t.origin_reason.as_deref(), Some("no-recorded-observation"));
    assert_eq!(scans(&other_mark), 2);
}
