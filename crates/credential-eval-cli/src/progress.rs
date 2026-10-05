//! Bounded operational progress for long runs.
//!
//! Progress is a side channel: it is written to stderr only (stdout stays the
//! machine protocol), it is never part of a semantic digest, and every line
//! is built from fixed vocabulary: a scanner id from the run configuration, a
//! phase name, an event kind, a status name and numbers. No fixture text, no
//! matched value and no scanner output (stdout or stderr) can reach it.
//!
//! The volume is bounded. A scan task emits one start and one end line; while
//! it runs, one heartbeat line per running task is emitted per interval, and
//! at most `jobs` tasks run at once. Heartbeats can be turned off.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Phase of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Validation, binding and fixture materialization.
    Materialize,
    /// Evaluation-method variant generation.
    Generate,
    /// Scanner version probes.
    Prepare,
    /// The scanner process is running (including stdout transfer).
    Scan,
    /// Scanner output is being parsed and mapped to ranges.
    Normalize,
    /// Replay comparison, scoring or method evaluation.
    Evaluate,
    /// Writing the artifact.
    Serialize,
}

impl Phase {
    /// The stable name used on progress lines and in `failed_phase`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Materialize => "materialize",
            Self::Generate => "generate",
            Self::Prepare => "prepare",
            Self::Scan => "scan",
            Self::Normalize => "normalize",
            Self::Evaluate => "evaluate",
            Self::Serialize => "serialize",
        }
    }
}

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A phase or task began.
    Start,
    /// A phase or task is still running.
    Heartbeat,
    /// A phase or task finished.
    End,
    /// A scanner failed; `status` names the failure.
    Failed,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Heartbeat => "heartbeat",
            Self::End => "end",
            Self::Failed => "failed",
        }
    }
}

/// One progress event. Every field is fixed vocabulary or a number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event<'a> {
    /// Scanner id; `None` for a run-level phase.
    pub scanner: Option<&'a str>,
    /// Phase.
    pub phase: Phase,
    /// Event kind.
    pub kind: Kind,
    /// Time since the run started.
    pub run_elapsed: Duration,
    /// Time since this phase or task started, when it has a start.
    pub elapsed: Option<Duration>,
    /// `(done, total)` units, where the phase has a meaningful count (replay
    /// number of a scan, fixtures materialized, variants generated).
    pub processed: Option<(u64, u64)>,
    /// Scanner status name for [`Kind::Failed`] and scan [`Kind::End`].
    pub status: Option<&'static str>,
}

/// A receiver of progress events.
pub trait Progress: Sync {
    /// Interval between heartbeats of a running task; `None` disables them.
    fn heartbeat_interval(&self) -> Option<Duration>;
    /// Receive one event.
    fn event(&self, event: &Event<'_>);
}

/// Discards everything (library use, tests).
pub struct Silent;

impl Progress for Silent {
    fn heartbeat_interval(&self) -> Option<Duration> {
        None
    }

    fn event(&self, _: &Event<'_>) {}
}

/// Writes one `progress ...` line per event to stderr.
pub struct StderrProgress {
    interval: Option<Duration>,
}

impl StderrProgress {
    /// Progress on stderr with a heartbeat every `interval` (`None`: none).
    pub fn new(interval: Option<Duration>) -> Self {
        Self { interval }
    }
}

/// Render an event as one stderr line.
pub fn format_line(event: &Event<'_>) -> String {
    let mut line = format!(
        "progress run_ms={} phase={} event={}",
        event.run_elapsed.as_millis(),
        event.phase.name(),
        event.kind.name()
    );
    if let Some(scanner) = event.scanner {
        line.push_str(&format!(" scanner={scanner}"));
    }
    if let Some(elapsed) = event.elapsed {
        line.push_str(&format!(" elapsed_ms={}", elapsed.as_millis()));
    }
    if let Some((done, total)) = event.processed {
        line.push_str(&format!(" processed={done}/{total}"));
    }
    if let Some(status) = event.status {
        line.push_str(&format!(" status={status}"));
    }
    line
}

impl Progress for StderrProgress {
    fn heartbeat_interval(&self) -> Option<Duration> {
        self.interval
    }

    fn event(&self, event: &Event<'_>) {
        eprintln!("{}", format_line(event));
    }
}

/// One running unit of work, as seen by the heartbeat.
struct Entry {
    scanner: String,
    phase: Phase,
    since: Instant,
    processed: Option<(u64, u64)>,
}

/// The set of currently running scanner tasks. The orchestrator registers a
/// task when it starts and removes it when it ends; the heartbeat thread
/// reports whatever is registered.
#[derive(Default)]
pub struct Activity {
    next: Mutex<(u64, BTreeMap<u64, Entry>)>,
}

impl Activity {
    /// Register a running task; returns its handle.
    pub fn begin(&self, scanner: &str, phase: Phase, processed: Option<(u64, u64)>) -> u64 {
        let mut state = self.next.lock().expect("activity lock");
        state.0 += 1;
        let id = state.0;
        state.1.insert(
            id,
            Entry {
                scanner: scanner.to_owned(),
                phase,
                since: Instant::now(),
                processed,
            },
        );
        id
    }

    /// Move a running task to its next phase (its clock restarts).
    pub fn advance(&self, id: u64, phase: Phase) {
        if let Some(entry) = self.next.lock().expect("activity lock").1.get_mut(&id) {
            entry.phase = phase;
            entry.since = Instant::now();
        }
    }

    /// Remove a finished task.
    pub fn end(&self, id: u64) {
        self.next.lock().expect("activity lock").1.remove(&id);
    }

    /// Emit one heartbeat per running task, in registration order.
    pub fn heartbeat(&self, progress: &dyn Progress, run_started: Instant) {
        let state = self.next.lock().expect("activity lock");
        for entry in state.1.values() {
            progress.event(&Event {
                scanner: Some(&entry.scanner),
                phase: entry.phase,
                kind: Kind::Heartbeat,
                run_elapsed: run_started.elapsed(),
                elapsed: Some(entry.since.elapsed()),
                processed: entry.processed,
                status: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_carry_only_fixed_vocabulary_and_numbers() {
        let line = format_line(&Event {
            scanner: Some("gitleaks"),
            phase: Phase::Scan,
            kind: Kind::Failed,
            run_elapsed: Duration::from_millis(1500),
            elapsed: Some(Duration::from_millis(900)),
            processed: Some((1, 2)),
            status: Some("timeout"),
        });
        assert_eq!(
            line,
            "progress run_ms=1500 phase=scan event=failed scanner=gitleaks \
             elapsed_ms=900 processed=1/2 status=timeout"
        );
    }

    #[test]
    fn run_level_lines_have_no_scanner() {
        let line = format_line(&Event {
            scanner: None,
            phase: Phase::Materialize,
            kind: Kind::Start,
            run_elapsed: Duration::ZERO,
            elapsed: None,
            processed: None,
            status: None,
        });
        assert_eq!(line, "progress run_ms=0 phase=materialize event=start");
    }
}
