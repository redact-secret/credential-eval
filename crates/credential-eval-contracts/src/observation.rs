//! Adapter output contract: normalized scanner observations.
//!
//! An [`ObservationSet`] is what adapters hand to the kernel (or what a
//! snapshot replays). It is bound to one corpus digest so stale observations
//! can never be scored against changed fixture bytes. It contains normalized
//! file/range findings only: never matched values, never raw stdout/stderr.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ContractError;
use crate::config::{AdapterIdentity, NetworkPolicy};
use crate::corpus::CorpusSnapshot;
use crate::ids::{FixturePath, ScannerId, Sha256Digest};
use crate::range::ByteRange;
use crate::schema::ObservationSetSchema;

/// Observations of one or more scanners over one corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ObservationSet {
    /// Document tag: `credential-eval/observation-set/v1`.
    pub schema: ObservationSetSchema,
    /// Digest of the corpus the scanners observed.
    pub corpus_digest: Sha256Digest,
    /// One entry per scanner, unique by `scanner.id`.
    pub observations: Vec<ScannerObservation>,
}

/// Recorded identity of an executed scanner.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ScannerIdentity {
    /// Scanner id.
    pub id: ScannerId,
    /// Reported scanner version; `null` when it could not be determined
    /// (e.g. the scanner is unavailable).
    pub version: Option<String>,
    /// Scanner mode as configured.
    pub mode: String,
    /// Adapter identity.
    pub adapter: AdapterIdentity,
    /// Canonical digest of the scanner configuration.
    pub configuration_hash: Sha256Digest,
    /// Setup provenance recorded by the adapter: the network posture and the
    /// digests of the executables and packages that actually ran. Absent in
    /// replayed or canned observations that did not record it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ScannerProvenance>,
    /// Whether the scanner is a released or a candidate build, as its adapter
    /// reports from the configuration (revision v1.1). Absent in observations
    /// that did not record it; a reader treats absence as unknown, never as
    /// `released`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<ScannerBuild>,
}

/// Release state of the scanner build that ran.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum ScannerBuild {
    /// A published release (a released binary or a published package).
    Released,
    /// An unreleased candidate build (e.g. packages from a candidate root).
    Candidate,
}

/// How a scanner was set up for a run. Every field is a reproduction
/// identity: it names bytes (by digest) and versions, never host paths.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ScannerProvenance {
    /// Network posture the adapter ran the scanner under.
    pub network: NetworkPolicy,
    /// What the adapter did to keep the posture, e.g.
    /// `["--no-verification", "--no-update"]`. Sorted, unique.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub network_controls: Vec<String>,
    /// Executables, runtimes and packages that ran, sorted by `(kind, name)`.
    pub components: Vec<ProvenanceComponent>,
}

/// One executable, runtime or package that took part in a scan.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceComponent {
    /// Component kind.
    pub kind: ProvenanceKind,
    /// Name: the configured program name, or the npm package name.
    pub name: String,
    /// Version, when the component reports or declares one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// SHA-256 of the component's bytes (an executable file, a lockfile, or a
    /// package tree digest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256Digest>,
    /// npm Subresource Integrity string from the lockfile, for packages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
}

/// Kind of a [`ProvenanceComponent`].
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum ProvenanceKind {
    /// A scanner executable resolved from the configured program.
    Executable,
    /// A language runtime that hosts a shim (e.g. `node`).
    Runtime,
    /// A shim script the adapter runs.
    Shim,
    /// A lockfile pinning the packages.
    Lockfile,
    /// An installed npm package.
    NpmPackage,
}

/// One scanner's observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScannerObservation {
    /// Scanner identity.
    pub scanner: ScannerIdentity,
    /// Outcome of executing the scanner.
    pub result: ObservationResult,
    /// Wall-clock scanner time in milliseconds. Non-semantic diagnostics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Result of executing a scanner. Every non-`complete` state is explicit and
/// is never scored as `MISS`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ObservationResult {
    /// The scanner ran, replays agreed, and output was normalized.
    Complete {
        /// Normalized findings (any order; the kernel deduplicates and sorts).
        findings: Vec<NormalizedFinding>,
        /// Stability replay record.
        replays: Replays,
        /// Fixture paths the adapter could not map to ranges, under a run
        /// configuration that explicitly chose per-case handling (v1.2). The
        /// scanner's findings on these paths are discarded and the cases are
        /// not measured: never a `MISS`, never a zero detection. Empty (and
        /// absent from the document) for a scanner that mapped every finding.
        /// Sorted by path, unique.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unmeasured: Vec<UnmeasuredPath>,
    },
    /// Replays over identical input disagreed; findings are discarded.
    Unstable {
        /// Stability replay record (`agreed` is false).
        replays: Replays,
        /// Paths whose findings differed between replays. Sorted.
        divergent_paths: Vec<FixturePath>,
    },
    /// The adapter cannot produce source byte ranges for this scanner/mode.
    Unsupported {
        /// Fixed, sanitized reason.
        reason: String,
    },
    /// The scanner binary/package is not installed or not runnable.
    Unavailable {
        /// Fixed, sanitized reason.
        reason: String,
    },
    /// The scanner exceeded its wall-clock limit.
    Timeout {
        /// The limit that was exceeded, in milliseconds.
        timeout_ms: u64,
    },
    /// The scanner ran but its output could not be parsed or mapped to ranges
    /// (including output-size limit overflow).
    Malformed {
        /// Fixed, sanitized reason. Never raw output.
        reason: String,
    },
    /// Any other execution failure.
    Error {
        /// Fixed, sanitized reason. Never raw output.
        reason: String,
    },
}

impl ObservationResult {
    /// The status discriminant.
    pub fn status(&self) -> ScannerStatus {
        match self {
            Self::Complete { .. } => ScannerStatus::Complete,
            Self::Unstable { .. } => ScannerStatus::Unstable,
            Self::Unsupported { .. } => ScannerStatus::Unsupported,
            Self::Unavailable { .. } => ScannerStatus::Unavailable,
            Self::Timeout { .. } => ScannerStatus::Timeout,
            Self::Malformed { .. } => ScannerStatus::Malformed,
            Self::Error { .. } => ScannerStatus::Error,
        }
    }
}

/// Status of a scanner within a run.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum ScannerStatus {
    /// Observed; findings are scored.
    Complete,
    /// Replays disagreed; not measured.
    Unstable,
    /// Adapter cannot produce ranges; not measured.
    Unsupported,
    /// Scanner not available; not measured.
    Unavailable,
    /// Timed out; not measured.
    Timeout,
    /// Output unparseable or over limits; not measured.
    Malformed,
    /// Other failure; not measured.
    Error,
}

/// Stability replay record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Replays {
    /// Number of scans over identical input.
    pub count: u32,
    /// Whether all replays produced identical normalized findings.
    pub agreed: bool,
}

/// A normalized finding: a file and a UTF-8 byte range, plus optional
/// scanner-reported classification. Never the matched value.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct NormalizedFinding {
    /// Fixture path the finding is in.
    pub path: FixturePath,
    /// Inclusive start byte offset.
    pub start: u64,
    /// Exclusive end byte offset.
    pub end: u64,
    /// Credential family the adapter mapped the scanner's rule to, when the
    /// mapping is known. Unmapped rules carry no family (never guessed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    /// Disposition the scanner itself reported for the finding (e.g. a
    /// redaction action), when it reports one. Observation only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

impl NormalizedFinding {
    /// The finding's range.
    pub const fn range(&self) -> ByteRange {
        ByteRange::new(self.start, self.end)
    }
}

/// A fixture path whose scanner output could not be mapped to ranges.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct UnmeasuredPath {
    /// Fixture path.
    pub path: FixturePath,
    /// Fixed, sanitized reason (an adapter constant). Never raw output.
    pub reason: String,
}

impl ObservationSet {
    /// Validate that these observations belong to `corpus` and that every
    /// finding names a known path with a valid range (legacy `score`
    /// validation, `benchmarks/lib/scoring.ts:91-96`).
    pub fn validate_against(&self, corpus: &CorpusSnapshot) -> Result<(), ContractError> {
        if self.corpus_digest != corpus.identity.corpus_digest {
            return Err(ContractError::StaleObservations {
                expected: corpus.identity.corpus_digest.to_string(),
                found: self.corpus_digest.to_string(),
            });
        }
        let content: BTreeMap<&FixturePath, &str> = corpus
            .cases
            .iter()
            .map(|c| (&c.path, c.content.as_str()))
            .collect();
        let mut seen = BTreeSet::new();
        for observation in &self.observations {
            if !seen.insert(&observation.scanner.id) {
                return Err(ContractError::DuplicateScanner(
                    observation.scanner.id.to_string(),
                ));
            }
            if let ObservationResult::Complete {
                findings,
                unmeasured,
                ..
            } = &observation.result
            {
                let mut previous: Option<&FixturePath> = None;
                for entry in unmeasured {
                    let known = content.contains_key(&entry.path);
                    let ordered = previous.is_none_or(|p| p < &entry.path);
                    if !known || !ordered {
                        return Err(ContractError::InvalidUnmeasured {
                            path: entry.path.to_string(),
                        });
                    }
                    previous = Some(&entry.path);
                }
                for finding in findings {
                    if unmeasured.iter().any(|u| u.path == finding.path) {
                        return Err(ContractError::InvalidUnmeasured {
                            path: finding.path.to_string(),
                        });
                    }
                    let valid = content
                        .get(&finding.path)
                        .is_some_and(|text| finding.range().is_valid_in(text));
                    if !valid {
                        return Err(ContractError::InvalidFinding {
                            path: finding.path.to_string(),
                            start: finding.start,
                            end: finding.end,
                        });
                    }
                }
            }
        }
        Ok(())
    }
}
