//! `credential-eval perf plan` (ADR 0010): reuse and invalidation decisions
//! over stored performance artifacts, planned without launching a scanner.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::{Value, json};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_credential-eval"))
}

fn subject(id: &str, script: &str) -> Value {
    json!({
        "id": id, "version": "test", "program": "/bin/sh",
        "args": ["-c", script], "delivery": "stdin", "ok_exit_codes": [0],
    })
}

/// Scanners that leave a trace whenever one of them is launched.
fn config(mark: &Path, candidate_tag: &str, units: u32) -> Value {
    let script = |tag: &str| format!("cat >/dev/null; echo {tag} >> {}", mark.display());
    json!({
        "schema": "credential-eval/performance-config/v1",
        "baseline": subject("scanner-a", &script("a")),
        "candidate": subject("scanner-b", &script(candidate_tag)),
        "workloads": [{"id": "repeated-short-log-lines", "units": units}],
        "shapes": ["whole"], "chunk_bytes": 1024,
        "rounds": 3, "batch_invocations": 1, "warmup_invocations": 1,
        "limits": {"timeout_ms": 10000, "max_input_bytes": 1048576,
                   "max_response_bytes": 65536, "max_diagnostic_bytes": 4096},
        "toolchain": [],
    })
}

fn write(path: &Path, value: &Value) -> PathBuf {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    path.to_path_buf()
}

fn measure(config_path: &Path, out: &Path) {
    let status = bin()
        .args(["perf", "run", "--config"])
        .arg(config_path)
        .arg("--out")
        .arg(out)
        .status()
        .unwrap();
    assert!(status.success());
}

fn plan(config_path: &Path, store: &Path, extra: &[&str]) -> Value {
    let out = bin()
        .args(["perf", "plan", "--kind", "latency", "--config"])
        .arg(config_path)
        .arg("--store")
        .arg(store)
        .args(extra)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

/// Latency cells need a CPU model; a host that reports none cannot reuse.
fn host_reports_cpu_model() -> bool {
    credential_eval_perf::host::cpu_model().is_some()
}

struct Fixture {
    dir: tempfile::TempDir,
    mark: PathBuf,
    store: PathBuf,
}

/// Two independent runs of one pair in a store directory.
fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mark = dir.path().join("launched");
    let store = dir.path().join("store");
    fs::create_dir(&store).unwrap();
    let cfg = write(&dir.path().join("config.json"), &config(&mark, "b", 40));
    measure(&cfg, &store.join("run1.json"));
    measure(&cfg, &store.join("run2.json"));
    assert!(mark.exists(), "the measurements did launch scanners");
    // Wall-clock directions of two real runs are noise on a busy host; pin
    // them so the tests exercise identity, not the host's load.
    for name in ["run1.json", "run2.json"] {
        let path = store.join(name);
        let mut artifact: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        for result in artifact["latency"].as_array_mut().unwrap() {
            result["direction"] = json!("faster");
        }
        write(&path, &artifact);
    }
    fs::remove_file(&mark).unwrap();
    Fixture { dir, mark, store }
}

#[test]
fn an_unchanged_pair_is_reused_and_plans_zero_invocations() {
    if !host_reports_cpu_model() {
        return;
    }
    let f = fixture();
    let cfg = write(&f.dir.path().join("same.json"), &config(&f.mark, "b", 40));
    let first = plan(&cfg, &f.store, &[]);
    let cell = &first["cells"][0];
    assert_eq!(cell["decision"], "reuse-comparison");
    assert_eq!(cell["reason"], "unchanged");
    assert_eq!(cell["confirmation"], "confirmed-faster");
    assert_eq!(cell["reused_from"].as_array().unwrap().len(), 2);
    assert_eq!(first["projected_invocations"], 0);
    assert!(!f.mark.exists(), "planning launched a scanner");
    // Deterministic across repeats.
    assert_eq!(first, plan(&cfg, &f.store, &[]));
    // The operator can still force a controlled measurement.
    let forced = plan(&cfg, &f.store, &["--fresh-all"]);
    assert_eq!(forced["cells"][0]["reason"], "forced-fresh");
    assert!(forced["projected_invocations"].as_u64().unwrap() > 0);
    let one = plan(&cfg, &f.store, &["--fresh", "scanner-b"]);
    assert_eq!(one["cells"][0]["decision"], "measure-fresh");
    assert!(!f.mark.exists());
}

#[test]
fn a_changed_candidate_or_workload_is_invalidated_and_never_certified_from_history() {
    if !host_reports_cpu_model() {
        return;
    }
    let f = fixture();
    let candidate = write(&f.dir.path().join("cand.json"), &config(&f.mark, "c", 40));
    let p = plan(&candidate, &f.store, &[]);
    let cell = &p["cells"][0];
    assert_eq!(cell["decision"], "measure-fresh");
    assert_eq!(cell["reason"], "identity-changed");
    assert_eq!(
        cell["invalidated_by"],
        json!(["candidate.subject.invocation_digest"])
    );
    assert!(cell["direction"].is_null());
    assert_eq!(cell["fresh_runs_required"], 2);
    let history = cell["historical"].as_array().unwrap();
    assert!(!history.is_empty());
    assert!(history.iter().all(|h| h["claim"] == "none"));
    assert!(history.iter().all(|h| h["subject"] == "scanner-a"));
    assert!(
        history
            .iter()
            .all(|h| h["origin"]["started_at"].is_string())
    );

    let bigger = write(&f.dir.path().join("big.json"), &config(&f.mark, "b", 80));
    let p = plan(&bigger, &f.store, &[]);
    let diff = p["cells"][0]["invalidated_by"].as_array().unwrap();
    assert!(diff.iter().any(|d| d == "baseline.input_digest"));
    assert!(diff.iter().any(|d| d == "candidate.bytes"));
    assert!(!f.mark.exists(), "planning launched a scanner");
}

#[test]
fn corrupt_and_foreign_files_are_rejected_or_ignored_never_used() {
    if !host_reports_cpu_model() {
        return;
    }
    let f = fixture();
    fs::write(f.store.join("truncated.json"), b"{\"schema\": \"cre").unwrap();
    let mut broken: Value =
        serde_json::from_slice(&fs::read(f.store.join("run1.json")).unwrap()).unwrap();
    broken["latency"] = json!([]);
    write(&f.store.join("inconsistent.json"), &broken);
    write(&f.store.join("schema.json"), &{
        let mut v = broken.clone();
        v["manifest"] = json!("nope");
        v
    });
    write(
        &f.store.join("other.json"),
        &json!({"schema": "something-else"}),
    );
    // A copy of a run is one run, not an independent one.
    fs::copy(f.store.join("run1.json"), f.store.join("copy.json")).unwrap();
    fs::remove_file(f.store.join("run2.json")).unwrap();

    let cfg = write(&f.dir.path().join("same.json"), &config(&f.mark, "b", 40));
    let p = plan(&cfg, &f.store, &[]);
    let rejected = p["rejected_evidence"].as_array().unwrap();
    assert_eq!(rejected.len(), 3, "{rejected:?}");
    let cell = &p["cells"][0];
    assert_eq!(cell["decision"], "measure-fresh");
    assert_eq!(cell["reason"], "insufficient-independent-runs");
    assert_eq!(cell["fresh_runs_required"], 1);
}

#[test]
fn allocation_cannot_be_planned_here() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = write(
        &dir.path().join("c.json"),
        &config(&dir.path().join("m"), "b", 40),
    );
    let out = bin()
        .args(["perf", "plan", "--kind", "allocation", "--config"])
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}
