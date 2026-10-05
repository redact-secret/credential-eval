//! The pinned Redact Secret core builds, driven through their public API only
//! (`DetectorRegistry`, `DefaultPolicy`, `scan`).
//!
//! Nothing crate-private is reachable from here, by construction: where a perf
//! card measured a private helper, the path is recorded as lost
//! ([`crate::report::lost_paths`]) rather than widened in the core.

use credential_eval_contracts::ids::{GitRevision, ReleaseTag, ScannerId, Sha256Digest};
use credential_eval_contracts::performance::{AllocationCounts, SubjectIdentity};
use credential_eval_perf::workloads;
use sha2::{Digest, Sha256};

use crate::{Activity, counted};

/// One pinned core build.
pub struct Core {
    /// Subject id (`redact-secret-<revision prefix>`).
    pub id: &'static str,
    /// Version label of the build.
    pub version: &'static str,
    /// Full source revision.
    pub revision: &'static str,
    /// Scan `text` twice (the first scan warms lazily initialised statics),
    /// count the second, and return the activity, the number of findings and
    /// a digest of their debug rendering.
    pub measure: fn(&str) -> (Activity, u64, Sha256Digest),
}

fn fingerprint(rendered: &str) -> Sha256Digest {
    let hash = Sha256::digest(rendered.as_bytes());
    let mut hex = String::from("sha256:");
    for byte in hash {
        hex.push_str(&format!("{byte:02x}"));
    }
    Sha256Digest::new(hex).expect("a SHA-256 renders as a valid digest")
}

macro_rules! core {
    ($krate:ident, $id:literal, $version:literal, $revision:literal) => {
        Core {
            id: $id,
            version: $version,
            revision: $revision,
            measure: |text| {
                use $krate::{DefaultPolicy, DetectorRegistry, scan};
                let registry = DetectorRegistry::with_built_in([]).expect("built-in registry");
                let policy = DefaultPolicy;
                // Warm lazily initialised statics outside the counted region.
                drop(scan(text, &registry, &policy));
                let (found, activity) = counted(|| scan(text, &registry, &policy));
                let found = found.expect("synthetic workload scans");
                let count = found.len() as u64;
                let digest = fingerprint(&format!("{found:?}"));
                (activity, count, digest)
            },
        }
    };
}

/// Baseline of #1121 and of PR #1136.
pub fn before() -> Core {
    core!(
        core_before,
        "redact-secret-44382b3f",
        "0.1.0-beta.12",
        "44382b3f3006a3a34a2bab917711d00e2e53284a"
    )
}

/// PR #1136 merge: cards #1121 to #1130.
pub fn mid() -> Core {
    core!(
        core_mid,
        "redact-secret-be5fee95",
        "0.1.0-beta.12",
        "be5fee9597311ee01cb33bcdc5c064d5cbb667ff"
    )
}

/// PR #1150 merge: cards #1131 to #1135.
pub fn after() -> Core {
    core!(
        core_after,
        "redact-secret-ad877c03",
        "0.1.0-beta.12",
        "ad877c036825a926f93478c2104e675d9c301326"
    )
}

impl Core {
    /// The subject identity recorded in the artifact.
    pub fn identity(&self) -> SubjectIdentity {
        SubjectIdentity {
            id: ScannerId::new(self.id).expect("constant id"),
            version: ReleaseTag::new(self.version).expect("constant version"),
            revision: Some(GitRevision::new(self.revision).expect("constant revision")),
            executable_sha256: None,
            invocation_digest: None,
            role: None,
        }
    }

    /// Measure `text` and convert to contract counters.
    pub fn counts(&self, text: &str) -> AllocationCounts {
        let (activity, finding_count, findings_digest) = (self.measure)(text);
        AllocationCounts {
            alloc_requests: activity.alloc_requests,
            realloc_requests: activity.realloc_requests,
            requests: activity.alloc_requests + activity.realloc_requests,
            allocated_bytes: activity.allocated_bytes,
            realloc_net_bytes: activity.realloc_net_bytes,
            finding_count,
            findings_digest,
        }
    }
}

/// Generate `id` for the allocation harness. The limit is the harness's own
/// explicit bound.
pub fn input(id: credential_eval_contracts::performance::WorkloadId, units: u32) -> String {
    workloads::generate(id, units, MAX_INPUT_BYTES).expect("harness workloads fit the bound")
}

/// Largest generated input, in bytes.
pub const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
