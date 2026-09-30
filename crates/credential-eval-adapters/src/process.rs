//! Bounded subprocess execution.
//!
//! Every scanner process runs with an explicit program path and argument
//! vector (never a shell), a wall-clock timeout, a stdout byte cap and a
//! drained-and-discarded stderr. Exceeding the stdout cap or the timeout
//! kills the process. A [`CancelToken`] kills a running process early.
//! Nothing a process prints is logged by this module.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// Environment variables removed from every scanner process (legacy
/// `command()`, `scanners/index.mjs:41-44`): they would let the environment
/// override Gitleaks rules.
pub const REMOVED_ENV: &[&str] = &["GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML"];

/// Cooperative cancellation shared by every task of a run.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A fresh, uncancelled token.
    pub fn new() -> Self {
        Self::default()
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation was requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// One process to run.
#[derive(Debug, Clone)]
pub struct ProcessRequest {
    /// Program to execute (resolved path; no shell lookup of metacharacters).
    pub program: PathBuf,
    /// Argument vector.
    pub args: Vec<OsString>,
    /// Working directory.
    pub cwd: PathBuf,
    /// Bytes written to stdin (then closed); `None` gives an empty stdin.
    pub stdin: Option<Vec<u8>>,
    /// Wall-clock limit.
    pub timeout: Duration,
    /// Maximum stdout bytes retained; one more byte kills the process.
    pub max_stdout: u64,
    /// Maximum stderr bytes read before the rest is drained unread-counted.
    /// Stderr is never retained or published.
    pub max_stderr: u64,
}

/// How a process ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// Exited on its own. `stdout` is at most `max_stdout` bytes.
    Exited {
        /// Exit code, when the process was not killed by a signal.
        code: Option<i32>,
        /// Captured stdout (raw scanner output: drop it after normalizing).
        stdout: Vec<u8>,
        /// Whether stderr exceeded `max_stderr` (diagnostic only).
        stderr_truncated: bool,
    },
    /// Killed after exceeding the timeout.
    TimedOut,
    /// Killed after stdout exceeded `max_stdout`.
    StdoutOverflow,
    /// The program does not exist.
    NotFound,
    /// The program could not be started for another reason.
    SpawnFailed,
    /// Killed because the run was cancelled.
    Cancelled,
}

/// A finished process with its wall-clock time.
#[derive(Debug, Clone)]
pub struct ProcessRun {
    /// Outcome.
    pub outcome: ProcessOutcome,
    /// Wall-clock time from spawn to reap.
    pub elapsed: Duration,
}

/// Grace period for reader threads after the process is reaped. A grandchild
/// that inherited a pipe could otherwise keep a reader alive indefinitely.
const READER_GRACE: Duration = Duration::from_secs(2);
const CHUNK: usize = 64 * 1024;

/// Run one process under its bounds.
pub fn run(request: &ProcessRequest, cancel: &CancelToken) -> ProcessRun {
    let started = Instant::now();
    let mut command = Command::new(&request.program);
    command
        .args(&request.args)
        .current_dir(&request.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in REMOVED_ENV {
        command.env_remove(name);
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let outcome = if error.kind() == std::io::ErrorKind::NotFound {
                ProcessOutcome::NotFound
            } else {
                ProcessOutcome::SpawnFailed
            };
            return ProcessRun {
                outcome,
                elapsed: started.elapsed(),
            };
        }
    };

    // stdin: write on a thread so a child that does not read cannot deadlock us.
    let stdin_pipe = child.stdin.take();
    let input = request.stdin.clone().unwrap_or_default();
    thread::spawn(move || {
        if let Some(mut pipe) = stdin_pipe {
            let _ = pipe.write_all(&input);
        }
    });

    let overflow = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel::<Reader>();

    let stdout_pipe = child.stdout.take().expect("piped stdout");
    let max_stdout = request.max_stdout;
    let stdout_overflow = Arc::clone(&overflow);
    let tx = done_tx.clone();
    thread::spawn(move || {
        let mut pipe = stdout_pipe;
        let mut kept = Vec::new();
        let mut buf = vec![0u8; CHUNK];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdout_overflow.load(Ordering::SeqCst) {
                        continue; // drain without retaining
                    }
                    if kept.len() as u64 + n as u64 > max_stdout {
                        stdout_overflow.store(true, Ordering::SeqCst);
                        kept = Vec::new();
                    } else {
                        kept.extend_from_slice(&buf[..n]);
                    }
                }
            }
        }
        let _ = tx.send(Reader::Stdout(kept));
    });

    let stderr_pipe = child.stderr.take().expect("piped stderr");
    let max_stderr = request.max_stderr;
    let stderr_seen = Arc::new(AtomicU64::new(0));
    let seen = Arc::clone(&stderr_seen);
    thread::spawn(move || {
        let mut pipe = stderr_pipe;
        let mut buf = vec![0u8; CHUNK];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                // Stderr is never retained: count and discard.
                Ok(n) => {
                    seen.fetch_add(n as u64, Ordering::SeqCst);
                }
            }
        }
        let _ = done_tx.send(Reader::Stderr);
    });

    let mut backoff = Duration::from_millis(1);
    let killed: Option<ProcessOutcome> = loop {
        match child.try_wait() {
            Ok(Some(_)) => break None,
            Ok(None) => {}
            Err(_) => break Some(ProcessOutcome::SpawnFailed),
        }
        if overflow.load(Ordering::SeqCst) {
            break Some(ProcessOutcome::StdoutOverflow);
        }
        if started.elapsed() >= request.timeout {
            break Some(ProcessOutcome::TimedOut);
        }
        if cancel.is_cancelled() {
            break Some(ProcessOutcome::Cancelled);
        }
        thread::sleep(backoff.min(request.timeout.saturating_sub(started.elapsed())));
        backoff = (backoff * 2).min(Duration::from_millis(20));
    };
    if killed.is_some() {
        let _ = child.kill();
    }
    let status = child.wait().ok();
    let elapsed = started.elapsed();

    let mut stdout = None;
    let mut readers = 0;
    let deadline = Instant::now() + READER_GRACE;
    while readers < 2 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match done_rx.recv_timeout(remaining) {
            Ok(Reader::Stdout(bytes)) => {
                stdout = Some(bytes);
                readers += 1;
            }
            Ok(Reader::Stderr) => readers += 1,
            Err(_) => break,
        }
    }
    let outcome = if let Some(outcome) = killed {
        outcome
    } else if overflow.load(Ordering::SeqCst) {
        ProcessOutcome::StdoutOverflow
    } else if let Some(stdout) = stdout {
        ProcessOutcome::Exited {
            code: status.and_then(|s| s.code()),
            stdout,
            stderr_truncated: stderr_seen.load(Ordering::SeqCst) > max_stderr,
        }
    } else {
        // The process exited but a descendant kept stdout open past the grace
        // period: the output is incomplete.
        ProcessOutcome::TimedOut
    };
    ProcessRun { outcome, elapsed }
}

enum Reader {
    Stdout(Vec<u8>),
    Stderr,
}
