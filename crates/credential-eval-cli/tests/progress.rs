//! Per-scanner timings and bounded progress (issue #39), exercised with
//! controlled slow and failing fake scanners: phases are named, a slow scan
//! stays observably active, failures name scanner and phase, operational
//! timings stay out of the semantic digest, and stderr never carries fixture
//! text, matched values or scanner output.

#![cfg(unix)]

mod common;

use std::fs;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use common::*;
use credential_eval_adapters::process::CancelToken;
use credential_eval_cli::orchestrate::{self, RunRequest};
use credential_eval_cli::progress::{Event, Kind, Phase, Progress, Silent, format_line};
use credential_eval_contracts::artifact::{FailedPhase, RunArtifact};
use credential_eval_contracts::observation::ScannerStatus;

/// Tests here run one at a time: on macOS a child forked by one test can
/// briefly inherit another test's freshly created pipe and keep it open for
/// as long as its `sleep` runs, which would stretch an unrelated scan.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run a freshly written script once so the OS finishes its first-exec
/// checks before a bounded scan clock starts (on macOS that can take seconds).
fn warm(bin: &std::path::Path) {
    let _ = Command::new(bin).arg("version").output();
}

const ROWS: &str = r#"echo "[{\"RuleID\":\"generic-api-key\",\"File\":\"$root/contracts-smoke/positive-exact.txt\",\"Secret\":\"EXAMPLE_FAKE_KEY_0123456789abcdef\",\"StartLine\":2}]""#;

/// Collects every event as its stderr line, with a fast heartbeat.
struct Recording {
    interval: Option<Duration>,
    lines: Mutex<Vec<String>>,
}

impl Recording {
    fn new(interval: Option<Duration>) -> Self {
        Self {
            interval,
            lines: Mutex::new(Vec::new()),
        }
    }
}

impl Progress for Recording {
    fn heartbeat_interval(&self) -> Option<Duration> {
        self.interval
    }

    fn event(&self, event: &Event<'_>) {
        self.lines.lock().unwrap().push(format_line(event));
    }
}

fn run_with_progress(
    config: &credential_eval_contracts::config::RunConfig,
    progress: &dyn Progress,
) -> RunArtifact {
    for spec in &config.scanners {
        if let Some(bin) = spec.configuration.get("binary").and_then(|b| b.as_str()) {
            warm(std::path::Path::new(bin));
        }
    }
    orchestrate::run(&RunRequest {
        corpus: &smoke_corpus(),
        config,
        env: &env(),
        work_dir: None,
        cancel: &CancelToken::new(),
        enforce_pins: false,
        progress,
        reuse: None,
    })
    .expect("run")
    .artifact
}

#[test]
fn timings_name_phase_size_and_completion_per_scanner() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let mut slow = gitleaks_spec(
        "hung",
        &fake_gitleaks(d, "hung", "8.30.1", "sleep 3; echo '[]'"),
    );
    slow.limits.timeout_ms = 1_500;
    let config = config(
        vec![
            gitleaks_spec("ok", &fake_gitleaks(d, "ok", "8.30.1", ROWS)),
            slow,
            gitleaks_spec(
                "garbled",
                &fake_gitleaks(d, "garbled", "8.30.1", "echo nope"),
            ),
            gitleaks_spec("missing", &d.join("not-installed")),
        ],
        4,
    );
    let artifact = run_with_progress(&config, &Silent);
    assert_schema_valid(&artifact);
    let execution = artifact.non_semantic.execution.as_ref().unwrap();

    let ok = &execution.scanners["ok"];
    assert_eq!(ok.completion, ScannerStatus::Complete);
    assert_eq!(ok.failed_phase, None);
    assert_eq!(ok.tasks, 2); // both replays
    assert_eq!(ok.findings, 1);
    assert!(ok.received_bytes > 0);
    assert!(ok.fixtures > 0);
    assert!(ok.end_ms >= ok.start_ms);

    let hung = &execution.scanners["hung"];
    assert_eq!(hung.completion, ScannerStatus::Timeout);
    assert_eq!(hung.failed_phase, Some(FailedPhase::Scan));
    assert!(hung.process_ms >= 1_500, "process_ms {}", hung.process_ms);

    let garbled = &execution.scanners["garbled"];
    assert_eq!(garbled.completion, ScannerStatus::Malformed);
    assert_eq!(garbled.failed_phase, Some(FailedPhase::Normalize));
    assert_eq!(garbled.received_bytes, 10); // "nope\n" per replay

    let missing = &execution.scanners["missing"];
    assert_eq!(missing.completion, ScannerStatus::Unavailable);
    assert_eq!(missing.failed_phase, Some(FailedPhase::Prepare));
    assert_eq!(missing.tasks, 0);

    let phases = execution.phases.as_ref().unwrap();
    assert_eq!(phases.cases, phases.fixtures); // a plain run scans its cases
    assert_eq!(phases.generate_ms, 0);
    assert!(phases.scan_ms >= 1_500);
    assert!(phases.scan_ms <= execution.wall_ms);
}

#[test]
fn slow_scan_stays_observably_active_and_failures_name_scanner_and_phase() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let mut hung = gitleaks_spec(
        "hung",
        &fake_gitleaks(d, "hung", "8.30.1", "sleep 3; echo '[]'"),
    );
    hung.limits.timeout_ms = 1_200;
    let config = config(
        vec![
            gitleaks_spec("quick", &fake_gitleaks(d, "quick", "8.30.1", ROWS)),
            hung,
        ],
        2,
    );
    let progress = Recording::new(Some(Duration::from_millis(200)));
    let _ = run_with_progress(&config, &progress);
    let lines = progress.lines.lock().unwrap().clone();

    let beats = lines
        .iter()
        .filter(|l| l.contains("scanner=hung") && l.contains("phase=scan event=heartbeat"))
        .count();
    assert!(
        beats >= 3,
        "expected heartbeats during the slow scan: {lines:#?}"
    );
    assert!(
        lines.iter().any(|l| {
            l.contains("scanner=hung")
                && l.contains("phase=scan event=failed")
                && l.contains("status=timeout")
        }),
        "failure must name scanner, phase and status: {lines:#?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("scanner=quick") && l.contains("event=end"))
    );
    // Heartbeats stop when the run ends: bounded by duration / interval per task.
    assert!(
        lines.len() < 60,
        "progress must stay bounded: {}",
        lines.len()
    );
    // Only fixed vocabulary and numbers: no fixture text, value or scanner output.
    for line in &lines {
        assert!(line.starts_with("progress run_ms="), "{line}");
        assert!(!line.contains("EXAMPLE_FAKE"), "{line}");
        assert!(!line.contains("contracts-smoke"), "{line}");
    }
}

#[test]
fn heartbeats_can_be_disabled() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let config = config(
        vec![gitleaks_spec(
            "slow",
            &fake_gitleaks(dir.path(), "slow", "8.30.1", "sleep 1; echo '[]'"),
        )],
        1,
    );
    let progress = Recording::new(None);
    let _ = run_with_progress(&config, &progress);
    let lines = progress.lines.lock().unwrap();
    assert!(!lines.iter().any(|l| l.contains("event=heartbeat")));
    assert!(
        lines
            .iter()
            .any(|l| l.contains("phase=materialize event=end"))
    );
    assert!(lines.iter().any(|l| l.contains("phase=evaluate event=end")));
}

#[test]
fn operational_timings_never_enter_the_semantic_digest() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let flag = d.join("slow");
    let bin = fake_gitleaks(
        d,
        "g",
        "8.30.1",
        &format!("if [ -f {} ]; then sleep 0.3; fi; {ROWS}", flag.display()),
    );
    let one = config(vec![gitleaks_spec("g", &bin)], 1);
    let eight = config(vec![gitleaks_spec("g", &bin)], 8);
    fs::write(&flag, "").unwrap();
    let a = run_with_progress(&one, &Silent);
    fs::remove_file(&flag).unwrap();
    let b = run_with_progress(&eight, &Recording::new(Some(Duration::from_millis(50))));
    let (ta, tb) = (
        &a.non_semantic.execution.as_ref().unwrap().scanners["g"],
        &b.non_semantic.execution.as_ref().unwrap().scanners["g"],
    );
    assert_ne!(ta.process_ms, tb.process_ms, "the runs must differ in time");
    assert_eq!(semantic_text(&a), semantic_text(&b));
    assert_eq!(a.semantic_digest(), b.semantic_digest());
}

#[test]
fn cli_writes_bounded_progress_to_stderr_and_nothing_to_stdout() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let config = config(
        vec![
            gitleaks_spec("quick", &fake_gitleaks(d, "q", "8.30.1", ROWS)),
            gitleaks_spec(
                "slow",
                &fake_gitleaks(d, "s", "8.30.1", &format!("sleep 2.5; {ROWS}")),
            ),
        ],
        2,
    );
    let config_path = d.join("run-config.json");
    fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let corpus = repo().join("tests/fixtures/contracts-smoke/corpus-snapshot.json");
    let run = |extra: &[&str], name: &str| {
        let out = d.join(name);
        let output = Command::new(env!("CARGO_BIN_EXE_credential-eval"))
            .args(["run", "--corpus"])
            .arg(&corpus)
            .arg("--config")
            .arg(&config_path)
            .arg("--out")
            .arg(&out)
            .args(extra)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let artifact: RunArtifact = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
        (output, artifact)
    };

    let (loud, a) = run(&["--progress-interval", "1"], "a.json");
    let stderr = String::from_utf8_lossy(&loud.stderr);
    assert!(loud.stdout.is_empty(), "stdout stays the machine protocol");
    assert!(
        stderr.contains("scanner=slow phase=scan event=heartbeat")
            || stderr.contains("phase=scan event=heartbeat scanner=slow"),
        "{stderr}"
    );
    assert!(stderr.contains("phase=serialize event=end"), "{stderr}");
    assert!(stderr.contains("timing slow:"), "{stderr}");
    assert!(stderr.contains("phases: materialize"), "{stderr}");
    assert!(!stderr.contains("EXAMPLE_FAKE"));
    assert!(stderr.lines().count() < 60);

    let (quiet, b) = run(&["--no-progress"], "b.json");
    let stderr = String::from_utf8_lossy(&quiet.stderr);
    assert!(!stderr.contains("progress run_ms="), "{stderr}");
    assert!(stderr.contains("semantic digest sha256:"));
    // The same run, with or without progress, keeps its semantic digest.
    assert_eq!(a.semantic_digest(), b.semantic_digest());

    for bad in ["x", "-1", "99999"] {
        let status = Command::new(env!("CARGO_BIN_EXE_credential-eval"))
            .args(["run", "--progress-interval", bad])
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(2), "{bad}");
    }
}

#[test]
fn phase_names_are_stable() {
    let _serial = serial();
    let names: Vec<&str> = [
        Phase::Materialize,
        Phase::Generate,
        Phase::Prepare,
        Phase::Scan,
        Phase::Normalize,
        Phase::Evaluate,
        Phase::Serialize,
    ]
    .iter()
    .map(|p| p.name())
    .collect();
    assert_eq!(
        names,
        [
            "materialize",
            "generate",
            "prepare",
            "scan",
            "normalize",
            "evaluate",
            "serialize"
        ]
    );
    let _ = Kind::Start;
}
