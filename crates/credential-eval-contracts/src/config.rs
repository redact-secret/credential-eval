//! Input contract: scanner execution inputs and run configuration.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::canonical::sha256_canonical;
use crate::ids::{ComponentId, ScannerId, Sha256Digest};
use crate::schema::RunConfigSchema;

/// Everything besides the corpus and scanner binaries that determines a run.
/// Its canonical digest is the run's `config_hash`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunConfig {
    /// Document tag: `credential-eval/run-config/v1`.
    pub schema: RunConfigSchema,
    /// Scanners to execute, in any order (results are sorted by id).
    pub scanners: Vec<ScannerSpec>,
    /// Evaluation methods to apply (e.g. `twin`, `benign`, `mutation`,
    /// `metamorphic`, `differential`). Sorted, unique.
    pub methods: Vec<ComponentId>,
    /// Global execution bounds.
    pub execution: ExecutionBounds,
    /// Accounting parameters (engine v1.1 semantics).
    pub accounting: AccountingConfig,
}

impl RunConfig {
    /// Canonical digest of this configuration.
    ///
    /// Two normalizations keep the hash about semantics, not presentation:
    ///
    /// * scheduling bounds (`execution.jobs` and each scanner's
    ///   `limits.concurrency`) are set to their serial value `1`: by the
    ///   determinism rule they cannot change semantic output, so a run with
    ///   `--jobs 8` has the identity of the equivalent serial run;
    /// * scanners are sorted by id, since their order is not semantic.
    ///
    /// Every other field, including timeouts and output caps, is hashed as given.
    pub fn config_hash(&self) -> Sha256Digest {
        let mut identity = self.clone();
        identity.scanners.sort_by(|a, b| a.id.cmp(&b.id));
        identity.execution.jobs = 1;
        for scanner in &mut identity.scanners {
            scanner.limits.concurrency = 1;
        }
        sha256_canonical(&identity)
    }
}

/// Global, explicit execution bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBounds {
    /// Maximum concurrently running scanner jobs across all scanners (>= 1).
    pub jobs: u32,
}

/// How one scanner is to be executed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScannerSpec {
    /// Scanner id, unique within the run.
    pub id: ScannerId,
    /// Adapter that executes and normalizes this scanner.
    pub adapter: AdapterIdentity,
    /// Human-readable scanner mode (e.g. "directory scan, default rules").
    pub mode: String,
    /// Adapter-specific configuration. Recorded verbatim and hashed; it must
    /// not contain credentials.
    #[serde(default)]
    pub configuration: BTreeMap<String, Value>,
    /// Whether the scanner may use the network. Verification calls are off
    /// unless a run explicitly authorizes them.
    pub network: NetworkPolicy,
    /// Per-scanner resource bounds.
    pub limits: ScannerLimits,
}

impl ScannerSpec {
    /// Canonical digest of `configuration` (the scanner's configuration hash).
    pub fn configuration_hash(&self) -> Sha256Digest {
        sha256_canonical(&self.configuration)
    }
}

/// Identity of a scanner adapter.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct AdapterIdentity {
    /// Adapter id (e.g. `gitleaks`).
    pub id: ComponentId,
    /// Adapter implementation version. Changes whenever parsing or offset
    /// conversion changes.
    pub version: String,
}

/// Network permission for a scanner.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    /// No network access is expected or permitted (default posture).
    Disabled,
    /// The run explicitly authorizes network access (e.g. verification).
    Allowed,
}

/// Per-scanner bounds. Every limit is explicit; there are no unbounded defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScannerLimits {
    /// Wall-clock timeout per scanner invocation, in milliseconds.
    pub timeout_ms: u64,
    /// Maximum captured stdout bytes; exceeding it is a `malformed`/`error` state.
    pub max_stdout_bytes: u64,
    /// Maximum captured stderr bytes (never published).
    pub max_stderr_bytes: u64,
    /// Maximum concurrent invocations of this scanner (>= 1).
    pub concurrency: u32,
}

/// Engine v1.1 accounting parameters (legacy `AccountingConfig`,
/// `benchmarks/types.ts:55-58`, values in `qualification/suite-v1.json`).
/// Floors withhold rates as `insufficient-evidence`/`insufficient-coverage`;
/// they are measurement rules, not support thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AccountingConfig {
    /// Smallest denominator for which a rate is published.
    pub min_denominator: u32,
    /// Minimum resolved share per method stratum.
    pub resolved_rate_floor: Floor,
    /// Minimum measurable (non-T0) share per kind.
    pub measurable_share_floor: Floor,
    /// Minimum twin coverage (pairs / positives) per kind.
    pub twin_coverage_floor: Floor,
    /// Stability replays per scanner (>= 2).
    pub replays: u32,
    /// z value of the Wilson interval.
    pub interval_z: f64,
    /// Decimal places of published points and bounds (1..=12).
    pub interval_precision: u32,
}

/// A floor: one value, or a default plus per-key overrides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum Floor {
    /// The same floor for every key.
    Uniform(f64),
    /// A default with per-key overrides.
    Keyed {
        /// Floor for keys without an override.
        default: f64,
        /// Per-key overrides.
        #[serde(flatten)]
        overrides: BTreeMap<String, f64>,
    },
}

impl Floor {
    /// The floor for `key` (legacy `floorFor`, `accounting/shared/primitives.ts:24`).
    pub fn for_key(&self, key: &str) -> f64 {
        match self {
            Self::Uniform(value) => *value,
            Self::Keyed { default, overrides } => overrides.get(key).copied().unwrap_or(*default),
        }
    }
}
