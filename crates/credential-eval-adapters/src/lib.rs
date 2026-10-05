//! Scanner adapters for `credential-eval`.
//!
//! An adapter owns everything scanner-specific and nothing else:
//!
//! 1. **prepare**: validate the scanner configuration, resolve the executable
//!    or package, record setup provenance (executable/package digests and
//!    versions, network posture) and probe the scanner version;
//! 2. **identity**: the recorded [`ScannerIdentity`];
//! 3. **scan**: build one bounded, shell-free process invocation over a
//!    materialized fixture root ([`Adapter::scan_invocation`]);
//! 4. **normalize**: map raw scanner output to [`NormalizedFinding`]s
//!    (half-open UTF-8 byte ranges plus an optional family/action), failing
//!    closed on anything it cannot map.
//!
//! Adapters never score. Raw output is handed to [`Adapter::normalize`] and
//! dropped by the caller immediately after; it is never logged or stored.
//! Every failure is an explicit [`ObservationResult`] state
//! (`unavailable`, `timeout`, `malformed`, `error`), never an empty `complete`.
//!
//! The built-in adapters port the legacy `scanners/index.mjs` at the pinned
//! oracle commit: [`gitleaks`], [`trufflehog`] and the npm-package scanners
//! in [`node`] (`redact-secret`, `flare-redact`, `openredaction`).

#![forbid(unsafe_code)]

pub mod binary;
pub mod decode;
pub mod families;
pub mod gitleaks;
pub mod locate;
pub mod node;
#[cfg(test)]
mod openredaction_audit;
mod openredaction_labels;
pub mod process;
pub mod provenance;
pub mod trufflehog;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use credential_eval_contracts::config::{
    AdapterIdentity, NetworkPolicy, ScannerLimits, ScannerSpec,
};
use credential_eval_contracts::ids::{ComponentId, FixturePath, ScannerId};
pub use credential_eval_contracts::observation::{
    NormalizedFinding, ObservationResult, ProvenanceComponent, ProvenanceKind, ScannerBuild,
    ScannerIdentity, ScannerObservation, ScannerProvenance,
};
use serde_json::Value;

pub use locate::{Fixtures, MapError};
use process::{CancelToken, ProcessOutcome, ProcessRequest, ProcessRun};

/// Host facts adapters may consult while preparing. Nothing here is hashed
/// into the configuration; what matters for reproduction is recorded as
/// provenance (digests and versions), never as host paths.
#[derive(Debug, Clone)]
pub struct AdapterEnv {
    /// `PATH` used to resolve configured program names.
    pub path: Option<OsString>,
    /// Directory of the Node shim (`shim.mjs`, `package.json`, lockfile and
    /// the published packages in `node_modules/`).
    pub node_dir: PathBuf,
    /// Package roots for scanners configured with `package_source:
    /// "candidate"`, by scanner id.
    pub candidate_roots: BTreeMap<String, PathBuf>,
    /// Working directory for version probes.
    pub cwd: PathBuf,
}

impl AdapterEnv {
    /// Environment from the current process: `PATH`, the Node shim directory
    /// from `CREDENTIAL_EVAL_NODE_DIR` or the in-repository `adapters/node`.
    pub fn from_process() -> Self {
        let node_dir = std::env::var_os("CREDENTIAL_EVAL_NODE_DIR").map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../adapters/node"),
            PathBuf::from,
        );
        Self {
            path: std::env::var_os("PATH"),
            node_dir,
            candidate_roots: BTreeMap::new(),
            cwd: std::env::temp_dir(),
        }
    }
}

/// A prepared scanner: identity plus what is needed to launch scans.
#[derive(Debug, Clone)]
pub struct Prepared {
    /// Reported scanner version.
    pub version: Option<String>,
    /// Recorded setup provenance.
    pub provenance: ScannerProvenance,
    /// Resolved program to execute.
    pub program: PathBuf,
    /// Leading arguments for every scan (e.g. the shim path).
    pub prefix_args: Vec<OsString>,
    /// Adapter-specific settings parsed from the configuration.
    pub settings: Value,
    /// Scanner processes run during preparation.
    pub processes: u64,
    /// Wall-clock time of those processes.
    pub process_time: Duration,
}

/// Why a scanner could not be prepared.
#[derive(Debug, Clone)]
pub struct PrepareFailure {
    /// The explicit non-complete result.
    pub result: ObservationResult,
    /// Version, if it was determined before the failure.
    pub version: Option<String>,
    /// Provenance recorded so far (at least the network posture).
    pub provenance: ScannerProvenance,
    /// Scanner processes run during preparation.
    pub processes: u64,
    /// Wall-clock time of those processes.
    pub process_time: Duration,
}

/// One scan invocation over a materialized root.
#[derive(Debug, Clone)]
pub struct Invocation {
    /// Program.
    pub program: PathBuf,
    /// Arguments (no shell interpretation).
    pub args: Vec<OsString>,
    /// Bytes for stdin.
    pub stdin: Option<Vec<u8>>,
}

/// The adapter protocol. Implementations must be deterministic: identical
/// output bytes normalize to identical findings in identical order.
pub trait Adapter: Send + Sync {
    /// Adapter id and implementation version. The version changes whenever
    /// invocation, parsing, offset conversion or family mapping changes.
    fn identity(&self) -> AdapterIdentity;

    /// The default scanner spec (legacy mode, configuration and limits).
    fn default_spec(&self) -> ScannerSpec;

    /// Whether `spec` runs a released or a candidate build. Decides the
    /// artifact's publication class, so an adapter that cannot tell reports
    /// [`ScannerBuild::Candidate`].
    fn build(&self, spec: &ScannerSpec) -> ScannerBuild;

    /// Validate the configuration, resolve executables/packages, record
    /// provenance and probe the version. Runs only bounded processes.
    fn prepare(
        &self,
        spec: &ScannerSpec,
        env: &AdapterEnv,
        cancel: &CancelToken,
    ) -> Result<Prepared, Box<PrepareFailure>>;

    /// The scan invocation for fixtures materialized under `root`
    /// (`paths` are relative, sorted).
    fn scan_invocation(&self, prepared: &Prepared, root: &Path, paths: &[&str]) -> Invocation;

    /// Map raw stdout to normalized findings, in a deterministic order.
    /// Must fail closed ([`MapError`]) on anything it cannot map exactly.
    fn normalize(
        &self,
        prepared: &Prepared,
        stdout: &[u8],
        fixtures: &Fixtures<'_>,
    ) -> Result<Vec<NormalizedFinding>, MapError>;

    /// Like [`Adapter::normalize`], for a run configuration that chose to
    /// report an unmappable finding as an unmeasured fixture instead of
    /// failing the whole scanner. The default never reports one: it fails
    /// closed exactly as `normalize` does. An adapter that overrides this
    /// attributes a failure to a known fixture path only; anything it cannot
    /// attribute (unparseable output, an unknown path) still fails closed.
    fn normalize_measured(
        &self,
        prepared: &Prepared,
        stdout: &[u8],
        fixtures: &Fixtures<'_>,
    ) -> Result<Measured, MapError> {
        self.normalize(prepared, stdout, fixtures)
            .map(|findings| Measured {
                findings,
                unmeasured: Vec::new(),
            })
    }

    /// The result for a process that exited with a non-zero status.
    fn exit_failure(&self, _code: Option<i32>) -> ObservationResult {
        ObservationResult::Error {
            reason: "scanner exited with a non-zero status; output suppressed".into(),
        }
    }
}

/// Findings of one scan plus the fixtures whose output could not be mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measured {
    /// Normalized findings, none of them on an unmeasured path.
    pub findings: Vec<NormalizedFinding>,
    /// Fixture paths that could not be mapped, sorted, unique, each with the
    /// adapter's fixed reason.
    pub unmeasured: Vec<(FixturePath, &'static str)>,
}

/// Every built-in adapter, sorted by id.
pub fn builtin() -> Vec<Box<dyn Adapter>> {
    vec![
        Box::new(node::NodeAdapter::flare_redact()),
        Box::new(gitleaks::Gitleaks),
        Box::new(node::NodeAdapter::openredaction()),
        Box::new(node::NodeAdapter::redact_secret()),
        Box::new(trufflehog::Trufflehog),
    ]
}

/// Diagnostic profiles of a built-in scanner. They are selectable by id like a
/// built-in adapter but are never part of the default scanner set, so a
/// default run, an official configuration and the default-options result are
/// unaffected (ADR 0013). Sorted by id.
pub fn diagnostic() -> Vec<Box<dyn Adapter>> {
    vec![
        Box::new(node::NodeAdapter::openredaction_credential_bearing()),
        Box::new(node::NodeAdapter::openredaction_credentials()),
        Box::new(node::NodeAdapter::openredaction_mapped()),
    ]
}

/// Look up a built-in or diagnostic adapter by id.
pub fn find(adapter_id: &str) -> Option<Box<dyn Adapter>> {
    builtin()
        .into_iter()
        .chain(diagnostic())
        .find(|a| a.identity().id.as_str() == adapter_id)
}

/// Map a scan process outcome to stdout bytes or an explicit failure state.
pub fn classify(
    adapter: &dyn Adapter,
    run: ProcessRun,
    limits: &ScannerLimits,
) -> Result<Vec<u8>, ObservationResult> {
    classify_with(run, limits, |code| adapter.exit_failure(code))
}

/// Map a version-probe outcome (non-zero exit is an `error`).
pub fn classify_probe(
    run: ProcessRun,
    limits: &ScannerLimits,
) -> Result<Vec<u8>, ObservationResult> {
    classify_with(run, limits, |_| ObservationResult::Error {
        reason: "scanner version probe failed; output suppressed".into(),
    })
}

fn classify_with(
    run: ProcessRun,
    limits: &ScannerLimits,
    exit_failure: impl Fn(Option<i32>) -> ObservationResult,
) -> Result<Vec<u8>, ObservationResult> {
    match run.outcome {
        ProcessOutcome::Exited {
            code: Some(0),
            stdout,
            ..
        } => Ok(stdout),
        ProcessOutcome::Exited { code, .. } => Err(exit_failure(code)),
        ProcessOutcome::TimedOut => Err(ObservationResult::Timeout {
            timeout_ms: limits.timeout_ms,
        }),
        ProcessOutcome::StdoutOverflow => Err(ObservationResult::Malformed {
            reason: "scanner stdout exceeded max_stdout_bytes; output discarded".into(),
        }),
        ProcessOutcome::NotFound => Err(ObservationResult::Unavailable {
            reason: "scanner executable not found".into(),
        }),
        ProcessOutcome::SpawnFailed => Err(ObservationResult::Error {
            reason: "scanner process could not be started".into(),
        }),
        ProcessOutcome::Cancelled => Err(ObservationResult::Error {
            reason: "run cancelled before the scanner finished".into(),
        }),
    }
}

/// Build a process request from an invocation and the scanner limits.
pub fn request(invocation: Invocation, cwd: &Path, limits: &ScannerLimits) -> ProcessRequest {
    ProcessRequest {
        program: invocation.program,
        args: invocation.args,
        cwd: cwd.to_path_buf(),
        stdin: invocation.stdin,
        timeout: Duration::from_millis(limits.timeout_ms),
        max_stdout: limits.max_stdout_bytes,
        max_stderr: limits.max_stderr_bytes,
    }
}

/// Legacy `versionNumber` (`index.mjs:108-110`): the first
/// `\d+\.\d+\.\d+(-[\w.]+)?`, or `"unknown"`.
pub fn version_number(output: &str) -> String {
    use std::sync::LazyLock;
    static VERSION: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9_.]+)?").expect("static regex")
    });
    VERSION
        .find(output)
        .map_or_else(|| "unknown".to_owned(), |m| m.as_str().to_owned())
}

/// Standard limits used by the default specs.
pub fn default_limits(max_stdout_bytes: u64) -> ScannerLimits {
    ScannerLimits {
        timeout_ms: 120_000,
        max_stdout_bytes,
        max_stderr_bytes: 1024 * 1024,
        concurrency: 2,
    }
}

pub(crate) fn spec(
    id: &str,
    adapter: AdapterIdentity,
    mode: &str,
    configuration: Value,
    limits: ScannerLimits,
) -> ScannerSpec {
    let Value::Object(map) = configuration else {
        unreachable!("configuration literals are objects")
    };
    ScannerSpec {
        id: ScannerId::new(id).expect("static scanner id"),
        adapter,
        mode: mode.to_owned(),
        configuration: map.into_iter().collect(),
        network: NetworkPolicy::Disabled,
        limits,
        pin: None,
    }
}

pub(crate) fn adapter_identity(id: &str, version: &str) -> AdapterIdentity {
    AdapterIdentity {
        id: ComponentId::new(id).expect("static adapter id"),
        version: version.to_owned(),
    }
}

/// A failure before any process ran.
pub(crate) fn fail(
    result: ObservationResult,
    provenance: ScannerProvenance,
) -> Box<PrepareFailure> {
    Box::new(PrepareFailure {
        result,
        version: None,
        provenance,
        processes: 0,
        process_time: Duration::ZERO,
    })
}

pub(crate) fn invalid_config(field: &'static str) -> ObservationResult {
    ObservationResult::Error {
        reason: format!("invalid scanner configuration: {field}"),
    }
}

/// Check that `configuration` has exactly the keys in `allowed` and that
/// every `fixed` key equals its adapter-owned value.
pub(crate) fn check_configuration(
    spec: &ScannerSpec,
    allowed: &[&'static str],
    fixed: &[(&'static str, Value)],
) -> Result<(), ObservationResult> {
    for key in spec.configuration.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(ObservationResult::Error {
                reason: "invalid scanner configuration: unknown key".into(),
            });
        }
    }
    for (key, value) in fixed {
        if spec.configuration.get(*key) != Some(value) {
            return Err(invalid_config(key));
        }
    }
    Ok(())
}

pub(crate) fn config_str<'a>(
    spec: &'a ScannerSpec,
    key: &'static str,
) -> Result<&'a str, ObservationResult> {
    spec.configuration
        .get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_config(key))
}

pub(crate) fn config_opt_str<'a>(
    spec: &'a ScannerSpec,
    key: &'static str,
) -> Result<Option<&'a str>, ObservationResult> {
    match spec.configuration.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if !s.is_empty() => Ok(Some(s)),
        Some(_) => Err(invalid_config(key)),
    }
}
