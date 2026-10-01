//! Official and exploratory runs (`docs/official-runs.md`): evidence-release
//! verification, scanner pins, and the run and publication classes. Every
//! input is synthetic: the contracts-smoke corpus, a fake Gitleaks and a
//! release manifest written by the test.

#![cfg(unix)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::*;
use credential_eval_cli::official::{self, SNAPSHOT_ENTRY};
use credential_eval_contracts::artifact::{Publication, RunArtifact, RunClass};
use credential_eval_contracts::canonical::sha256_bytes;
use credential_eval_contracts::config::{RunConfig, ScannerPin};
use credential_eval_contracts::ids::{ScannerId, Sha256Digest};
use credential_eval_contracts::observation::ScannerBuild;
use serde_json::json;

const TAG: &str = "snapshot-2026.10.01";

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_credential-eval"))
}

struct Setup {
    _dir: tempfile::TempDir,
    dir: PathBuf,
    corpus: PathBuf,
    manifest: PathBuf,
    manifest_digest: Sha256Digest,
    scanner: PathBuf,
}

impl Setup {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().to_path_buf();
        let corpus = dir.join("corpus-snapshot.json");
        fs::copy(
            repo().join("tests/fixtures/contracts-smoke/corpus-snapshot.json"),
            &corpus,
        )
        .unwrap();
        let snapshot_digest = sha256_bytes(&fs::read(&corpus).unwrap());
        let manifest = dir.join("release-manifest.json");
        let manifest_digest = write_manifest(&manifest, TAG, &snapshot_digest);
        let scanner = fake_gitleaks(&dir, "gitleaks-fake", "8.30.1", "echo '[]'");
        Self {
            _dir: tmp,
            dir,
            corpus,
            manifest,
            manifest_digest,
            scanner,
        }
    }

    fn scanner_digest(&self) -> Sha256Digest {
        sha256_bytes(&fs::read(&self.scanner).unwrap())
    }

    /// A one-scanner config file pinned to `pin` (or unpinned).
    fn config(&self, name: &str, pin: Option<ScannerPin>) -> PathBuf {
        let mut spec = gitleaks_spec("gitleaks", &self.scanner);
        spec.pin = pin;
        self.write_config(name, config(vec![spec], 1))
    }

    fn write_config(&self, name: &str, config: RunConfig) -> PathBuf {
        let path = self.dir.join(name);
        fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        path
    }

    fn pin(&self, version: &str) -> Option<ScannerPin> {
        Some(ScannerPin {
            version: version.into(),
            sha256: Some(self.scanner_digest()),
        })
    }

    fn evidence_args(&self) -> Vec<String> {
        vec![
            "--evidence-release".into(),
            TAG.into(),
            "--evidence-manifest".into(),
            self.manifest.to_str().unwrap().into(),
            "--evidence-manifest-digest".into(),
            self.manifest_digest.to_string(),
        ]
    }

    /// Run with `config`, writing `<name>.json`; returns the output and the
    /// artifact path.
    fn run(&self, name: &str, config: &Path, extra: &[String]) -> (Output, PathBuf) {
        let out = self.dir.join(format!("artifact-{name}.json"));
        let _ = fs::remove_file(&out);
        let output = bin()
            .args(["run", "--corpus"])
            .arg(&self.corpus)
            .arg("--config")
            .arg(config)
            .arg("--out")
            .arg(&out)
            .args(extra)
            .output()
            .unwrap();
        (output, out)
    }
}

fn write_manifest(path: &Path, tag: &str, snapshot: &Sha256Digest) -> Sha256Digest {
    let bytes = serde_json::to_vec_pretty(&json!({
        "tag": tag,
        "source_revision": "0000000000000000000000000000000000000000",
        "files": [{ "path": SNAPSHOT_ENTRY, "sha256": snapshot.to_string() }]
    }))
    .unwrap();
    fs::write(path, &bytes).unwrap();
    sha256_bytes(&bytes)
}

fn official(extra: Vec<String>) -> Vec<String> {
    let mut args = vec!["--run-class".to_owned(), "official".to_owned()];
    args.extend(extra);
    args
}

fn artifact(path: &Path) -> RunArtifact {
    let artifact: RunArtifact = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    assert_schema_valid(&artifact);
    artifact
}

fn assert_refused(output: &Output, out: &Path, code: i32, needle: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(code), "{stderr}");
    assert!(stderr.contains(needle), "{stderr}");
    assert!(!out.exists(), "a refused run must not write an artifact");
}

#[test]
fn official_run_with_verified_inputs_is_public() {
    let s = Setup::new();
    let config = s.config("pinned.json", s.pin("8.30.1"));
    let (output, out) = s.run("official", &config, &official(s.evidence_args()));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("run class official · publication public"));
    let artifact = artifact(&out);
    let manifest = &artifact.manifest;
    assert_eq!(manifest.run_class, Some(RunClass::Official));
    assert_eq!(manifest.publication, Some(Publication::Public));
    let release = manifest
        .evidence
        .release
        .as_ref()
        .expect("release recorded");
    assert_eq!(release.tag.as_str(), TAG);
    assert_eq!(release.manifest_digest, s.manifest_digest);
    assert_eq!(manifest.scanners[0].build, Some(ScannerBuild::Released));
    assert_eq!(manifest.scanners[0].version.as_deref(), Some("8.30.1"));

    // Repeating the official run yields the same semantic artifact.
    let (again, out) = s.run("official-again", &config, &official(s.evidence_args()));
    assert!(again.status.success());
    assert_eq!(
        semantic_text(&artifact),
        semantic_text(&self::artifact(&out))
    );
}

#[test]
fn official_run_refuses_a_mismatched_evidence_snapshot() {
    let s = Setup::new();
    let config = s.config("pinned.json", s.pin("8.30.1"));

    // The manifest is not the one whose digest was pinned.
    let mut args = s.evidence_args();
    args[5] = sha256_bytes(b"another manifest").to_string();
    let (output, out) = s.run("wrong-manifest", &config, &official(args));
    assert_refused(&output, &out, 4, "does not match the pinned");

    // The manifest lists a different snapshot.
    let other = s.dir.join("other-manifest.json");
    let digest = write_manifest(&other, TAG, &sha256_bytes(b"another snapshot"));
    let args = vec![
        "--evidence-release".into(),
        TAG.into(),
        "--evidence-manifest".into(),
        other.to_str().unwrap().into(),
        "--evidence-manifest-digest".into(),
        digest.to_string(),
    ];
    let (output, out) = s.run("wrong-snapshot", &config, &official(args));
    assert_refused(&output, &out, 4, "corpus snapshot digest");

    // The pinned tag is not the manifest's tag.
    let mut args = s.evidence_args();
    args[1] = "snapshot-2026.09.30".into();
    let (output, out) = s.run("wrong-tag", &config, &official(args));
    assert_refused(&output, &out, 4, "is for tag");

    // Evidence verification is missing or incomplete.
    let (output, out) = s.run("no-evidence", &config, &official(Vec::new()));
    assert_refused(&output, &out, 2, "pinned evidence release");
    let partial = s.evidence_args()[..4].to_vec();
    let (output, out) = s.run("partial", &config, &official(partial));
    assert_refused(&output, &out, 2, "go together");
}

#[test]
fn official_run_refuses_a_mismatched_scanner() {
    let s = Setup::new();
    let evidence = official(s.evidence_args());

    // Resolved version differs from the pin (a self-updated scanner).
    let config = s.config("version.json", s.pin("8.30.0"));
    let (output, out) = s.run("version", &config, &evidence);
    assert_refused(
        &output,
        &out,
        4,
        "resolved version 8.30.1 does not match pin 8.30.0",
    );

    // Executable bytes differ from the pinned checksum.
    let config = s.config(
        "checksum.json",
        Some(ScannerPin {
            version: "8.30.1".into(),
            sha256: Some(sha256_bytes(b"the released binary")),
        }),
    );
    let (output, out) = s.run("checksum", &config, &evidence);
    assert_refused(&output, &out, 4, "executable digest");

    // The pinned scanner is not installed: nothing resolved.
    let mut spec = gitleaks_spec("gitleaks", &s.dir.join("missing-binary"));
    spec.pin = s.pin("8.30.1");
    let config = s.write_config("missing.json", common::config(vec![spec], 1));
    let (output, out) = s.run("missing", &config, &evidence);
    assert_refused(&output, &out, 4, "could not be resolved");

    // A scanner without a pin.
    let config = s.config("unpinned.json", None);
    let (output, out) = s.run("unpinned", &config, &evidence);
    assert_refused(&output, &out, 2, "unpinned: gitleaks");
}

#[test]
fn exploratory_runs_are_marked_internal_and_ignore_pins() {
    let s = Setup::new();
    // A mismatched pin does not stop an exploratory run (the default class).
    let config = s.config("mismatched.json", s.pin("8.30.0"));
    let (output, out) = s.run("exploratory", &config, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("run class exploratory · publication internal"));
    let plain = artifact(&out);
    assert_eq!(plain.manifest.run_class, Some(RunClass::Exploratory));
    assert_eq!(plain.manifest.publication, Some(Publication::Internal));
    assert!(plain.manifest.evidence.release.is_none());

    // Verified evidence is recorded, but the artifact stays internal.
    let mut args = vec!["--run-class".to_owned(), "exploratory".to_owned()];
    args.extend(s.evidence_args());
    let (output, out) = s.run("exploratory-verified", &config, &args);
    assert!(output.status.success());
    let verified = artifact(&out);
    assert_eq!(verified.manifest.publication, Some(Publication::Internal));
    assert_eq!(
        verified
            .manifest
            .evidence
            .release
            .as_ref()
            .unwrap()
            .tag
            .as_str(),
        TAG
    );

    // A release that does not verify is refused in any run class.
    let mut args = s.evidence_args();
    args[5] = sha256_bytes(b"another manifest").to_string();
    let (output, out) = s.run("exploratory-mismatch", &config, &args);
    assert_refused(&output, &out, 4, "evidence release refused");

    // Unknown run class.
    let (output, out) = s.run(
        "bad-class",
        &config,
        &["--run-class".into(), "public".into()],
    );
    assert_refused(
        &output,
        &out,
        2,
        "--run-class takes official or exploratory",
    );
}

#[test]
fn a_snapshot_may_not_declare_its_own_release() {
    let s = Setup::new();
    let mut snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(&s.corpus).unwrap()).unwrap();
    snapshot["identity"]["release"] = json!({
        "tag": TAG,
        "manifest_digest": s.manifest_digest.to_string(),
    });
    fs::write(&s.corpus, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let config = s.config("pinned.json", s.pin("8.30.1"));
    let (output, out) = s.run("declared", &config, &[]);
    assert_refused(
        &output,
        &out,
        1,
        "identity.release is recorded by the evaluator",
    );
}

#[test]
fn a_candidate_build_is_never_public() {
    // A Redact Secret scanner configured from a candidate root. Without the
    // root it is unavailable, but its build is still recorded, and any
    // candidate build makes the artifact internal.
    let adapter = credential_eval_adapters::find("redact-secret").unwrap();
    let mut candidate = adapter.default_spec();
    candidate
        .configuration
        .insert("package_source".into(), json!("candidate"));
    let s = Setup::new();
    let released = gitleaks_spec("gitleaks", &s.scanner);
    let output = run(&smoke_corpus(), &config(vec![candidate, released], 1));
    let mut artifact = output.artifact;
    let build = |id: &str| {
        artifact
            .manifest
            .scanners
            .iter()
            .find(|s| s.id == ScannerId::new(id).unwrap())
            .and_then(|s| s.build)
    };
    assert_eq!(build("redact-secret"), Some(ScannerBuild::Candidate));
    assert_eq!(build("gitleaks"), Some(ScannerBuild::Released));
    official::stamp(&mut artifact, RunClass::Official);
    assert_eq!(artifact.manifest.publication, Some(Publication::Internal));
    assert_schema_valid(&artifact);
}
