//! Scope accounting of retained findings (revision v1.8, ADR 0016).
//!
//! A finding's `family` is a derived credential classification and its
//! `native_labels` are what the scanner said (ADR 0011). Neither says whether
//! an unmapped finding is a credential nobody mapped, personal data, a resource
//! identifier or unknown. This module is the engine-owned, versioned answer: a
//! reviewed per-native-type disposition table (ADR 0012) and a deterministic
//! count of one scanner's retained findings by disposition.
//!
//! The accounting only describes. It never removes a finding, changes a
//! family, an outcome, a denominator or a floor, and it is not a sensitivity
//! verdict: `unresolved` stays unresolved.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{NativeLabel, ScannerId, UNRECOGNIZED_NATIVE_LABEL};
use crate::observation::NormalizedFinding;

/// Version of the accounting contract and of its classification rules.
pub const SCOPE_ACCOUNTING_VERSION: &str = "1";

/// Scope of a native type, as reviewed.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum Scope {
    /// A credential or a part of one.
    Credential,
    /// An identifier that accompanies a credential but is not the secret.
    IdentifierOfCredential,
    /// A session identifier or cookie; needs an explicit scope decision.
    Session,
    /// Scope cannot be decided from the type.
    Ambiguous,
    /// A resource identifier (not a credential).
    ResourceIdentifier,
    /// Personal data.
    Pii,
    /// Personal data or a generic identifier.
    PiiOrIdentifier,
}

/// Review status of a native type.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum DispositionStatus {
    /// The adapter maps the type to a family.
    Mapped,
    /// Credential-bearing or ambiguous; no family is claimed.
    Unresolved,
    /// Not a credential by scope.
    NotCredential,
}

/// One reviewed native type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeEntry {
    /// Native label.
    pub label: &'static str,
    /// Reviewed scope.
    pub scope: Scope,
    /// Review status.
    pub status: DispositionStatus,
    /// Reviewed reason (static text; never derived from input).
    pub reason: &'static str,
}

/// A reviewed disposition table for one exact scanner package.
#[derive(Debug, Clone, Copy)]
pub struct ScopeTable {
    /// Table id, e.g. `openredaction-1.1.5`.
    pub id: &'static str,
    /// Package name.
    pub package: &'static str,
    /// Package version.
    pub version: &'static str,
    /// Package integrity the review was made against.
    pub integrity: &'static str,
    /// Entries sorted by label.
    pub entries: &'static [ScopeEntry],
}

static OPENREDACTION: ScopeTable = ScopeTable {
    id: "openredaction-1.1.5",
    package: crate::scope_table_openredaction::PACKAGE,
    version: crate::scope_table_openredaction::VERSION,
    integrity: crate::scope_table_openredaction::INTEGRITY,
    entries: crate::scope_table_openredaction::ENTRIES,
};

impl ScopeTable {
    /// The reviewed table of a scanner id, or `None` when the scanner has no
    /// reviewed set (its findings read as "not accounted", never as zero).
    /// The OpenRedaction default and its diagnostic profiles share one table.
    pub fn for_scanner(id: &ScannerId) -> Option<&'static ScopeTable> {
        let id = id.as_str();
        (id == "openredaction" || id.starts_with("openredaction-")).then_some(&OPENREDACTION)
    }

    /// The entry of a label.
    pub fn entry(&self, label: &str) -> Option<&'static ScopeEntry> {
        self.entries
            .binary_search_by(|e| e.label.cmp(label))
            .ok()
            .map(|i| &self.entries[i])
    }
}

/// How one finding is read. Exactly one per finding.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum FindingDisposition {
    /// The finding carries a family.
    MappedCredential,
    /// No family, and every label is reviewed credential-related and unresolved.
    CredentialRelatedUnmapped,
    /// No family, and every label is reviewed as not a credential.
    OutOfScope,
    /// No family and the reviewed labels disagree or their scope is ambiguous.
    Ambiguous,
    /// No native label (older observation, or an adapter without a reviewed set).
    NativeLabelUnavailable,
    /// The only label is the unrecognized marker (outside the reviewed set).
    UnrecognizedLabel,
}

/// Finding counts by disposition. Every key is always present; a zero is a
/// measured zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DispositionCounts {
    /// Findings carrying a family.
    pub mapped_credential: u64,
    /// Unmapped, credential-related, unresolved.
    pub credential_related_unmapped: u64,
    /// Unmapped, reviewed as not a credential (personal data, resource identifiers).
    pub out_of_scope: u64,
    /// Unmapped with conflicting or ambiguous scope.
    pub ambiguous: u64,
    /// No native label.
    pub native_label_unavailable: u64,
    /// Only an unrecognized label.
    pub unrecognized_label: u64,
}

impl DispositionCounts {
    fn add(&mut self, d: FindingDisposition) {
        let slot = match d {
            FindingDisposition::MappedCredential => &mut self.mapped_credential,
            FindingDisposition::CredentialRelatedUnmapped => &mut self.credential_related_unmapped,
            FindingDisposition::OutOfScope => &mut self.out_of_scope,
            FindingDisposition::Ambiguous => &mut self.ambiguous,
            FindingDisposition::NativeLabelUnavailable => &mut self.native_label_unavailable,
            FindingDisposition::UnrecognizedLabel => &mut self.unrecognized_label,
        };
        *slot += 1;
    }

    /// Sum of all dispositions; equals the finding count.
    pub fn total(&self) -> u64 {
        self.mapped_credential
            + self.credential_related_unmapped
            + self.out_of_scope
            + self.ambiguous
            + self.native_label_unavailable
            + self.unrecognized_label
    }
}

/// Identity of the reviewed table the counts were made with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeTableIdentity {
    /// Table id.
    pub id: String,
    /// Package name.
    pub package: String,
    /// Package version.
    pub version: String,
    /// Package integrity.
    pub integrity: String,
}

/// Findings carrying one native label. A finding with several labels counts
/// under each, so label counts can exceed the finding count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LabelAccount {
    /// Native label (reviewed, or the unrecognized marker).
    pub label: NativeLabel,
    /// Findings carrying the label.
    pub findings: u64,
    /// Of those, findings that carry a family.
    pub with_family: u64,
    /// Reviewed scope; absent for the unrecognized marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// Review status; absent for the unrecognized marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<DispositionStatus>,
    /// Reviewed reason; absent for the unrecognized marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Scope accounting of one scanner's retained findings (revision v1.8).
///
/// Present only when the scanner completed and has a reviewed table. Absent
/// means "not accounted" (legacy artifact, other scanner, or not measured),
/// never zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeAccounting {
    /// Contract and classification-rule version ([`SCOPE_ACCOUNTING_VERSION`]).
    pub version: String,
    /// The reviewed table used.
    pub table: ScopeTableIdentity,
    /// Retained findings counted; equals `scanners[].findings` length.
    pub findings: u64,
    /// One disposition per finding; sums to `findings`.
    pub by_disposition: DispositionCounts,
    /// Findings with two or more native labels.
    pub multi_label_findings: u64,
    /// Findings whose reviewed labels disagree on scope or status, whatever
    /// their primary disposition.
    pub conflicting_label_findings: u64,
    /// Per-label counts, sorted by label.
    pub by_label: Vec<LabelAccount>,
}

/// Disposition class of one reviewed label.
fn class_of(entry: &ScopeEntry) -> u8 {
    match (entry.status, entry.scope) {
        (DispositionStatus::Mapped, _) => 0,
        (DispositionStatus::Unresolved, Scope::Ambiguous) => 3,
        (DispositionStatus::Unresolved, _) => 1,
        (DispositionStatus::NotCredential, _) => 2,
    }
}

/// Classify one finding against `table`.
pub fn classify(table: &ScopeTable, finding: &NormalizedFinding) -> (FindingDisposition, bool) {
    let has_family = finding.family.is_some();
    let mut classes = std::collections::BTreeSet::new();
    let mut unrecognized = false;
    for label in &finding.native_labels {
        if label.as_str() == UNRECOGNIZED_NATIVE_LABEL {
            unrecognized = true;
        } else if let Some(entry) = table.entry(label.as_str()) {
            classes.insert(class_of(entry));
        } else {
            // A label the adapter recorded but this table has not reviewed.
            unrecognized = true;
        }
    }
    let conflicting = classes.len() > 1 || (unrecognized && !classes.is_empty());
    let disposition = if has_family {
        FindingDisposition::MappedCredential
    } else if finding.native_labels.is_empty() {
        FindingDisposition::NativeLabelUnavailable
    } else if classes.is_empty() {
        FindingDisposition::UnrecognizedLabel
    } else if conflicting || classes.contains(&3) || classes.contains(&0) {
        // A mapped label on a finding with no family is table drift; never hide it.
        FindingDisposition::Ambiguous
    } else if classes.contains(&1) {
        FindingDisposition::CredentialRelatedUnmapped
    } else {
        FindingDisposition::OutOfScope
    };
    (disposition, conflicting)
}

/// Account `findings` (the deduplicated, retained findings of a complete
/// scanner) against `table`. Pure and order independent.
pub fn account(table: &ScopeTable, findings: &[NormalizedFinding]) -> ScopeAccounting {
    let mut counts = DispositionCounts::default();
    let mut multi = 0u64;
    let mut conflicting_total = 0u64;
    let mut labels: BTreeMap<&str, (u64, u64)> = BTreeMap::new();
    for f in findings {
        let (d, conflicting) = classify(table, f);
        counts.add(d);
        if f.native_labels.len() > 1 {
            multi += 1;
        }
        if conflicting {
            conflicting_total += 1;
        }
        for l in &f.native_labels {
            let slot = labels.entry(l.as_str()).or_default();
            slot.0 += 1;
            if f.family.is_some() {
                slot.1 += 1;
            }
        }
    }
    let by_label = labels
        .into_iter()
        .filter_map(|(label, (n, fam))| {
            let native = NativeLabel::new(label).ok()?;
            let entry = if label == UNRECOGNIZED_NATIVE_LABEL {
                None
            } else {
                table.entry(label)
            };
            Some(LabelAccount {
                label: native,
                findings: n,
                with_family: fam,
                scope: entry.map(|e| e.scope),
                status: entry.map(|e| e.status),
                reason: entry.map(|e| e.reason.to_owned()),
            })
        })
        .collect();
    ScopeAccounting {
        version: SCOPE_ACCOUNTING_VERSION.to_owned(),
        table: ScopeTableIdentity {
            id: table.id.to_owned(),
            package: table.package.to_owned(),
            version: table.version.to_owned(),
            integrity: table.integrity.to_owned(),
        },
        findings: findings.len() as u64,
        by_disposition: counts,
        multi_label_findings: multi,
        conflicting_label_findings: conflicting_total,
        by_label,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::FixturePath;

    const DISPOSITIONS: &str = include_str!("../../../tools/openredaction-audit/dispositions.json");

    fn finding(labels: &[&str], family: Option<&str>) -> NormalizedFinding {
        NormalizedFinding {
            path: FixturePath::new("a.txt").unwrap(),
            start: 0,
            end: 1,
            family: family.map(str::to_owned),
            action: None,
            mapping: None,
            native_labels: labels
                .iter()
                .map(|l| NativeLabel::new(*l).unwrap())
                .collect(),
        }
    }

    fn table() -> &'static ScopeTable {
        ScopeTable::for_scanner(&ScannerId::new("openredaction").unwrap()).unwrap()
    }

    #[test]
    fn the_generated_table_equals_the_reviewed_dispositions() {
        let doc: serde_json::Value = serde_json::from_str(DISPOSITIONS).unwrap();
        let rows = doc["types"].as_array().unwrap();
        let entries = table().entries;
        assert_eq!(rows.len(), entries.len());
        assert!(entries.windows(2).all(|w| w[0].label < w[1].label));
        for (row, entry) in rows.iter().zip(entries) {
            assert_eq!(row["type"], entry.label);
            assert_eq!(row["reason"], entry.reason);
            let status = match entry.status {
                DispositionStatus::Mapped => "mapped",
                DispositionStatus::Unresolved => "unresolved",
                DispositionStatus::NotCredential => "not-credential",
            };
            assert_eq!(row["status"], status, "{}", entry.label);
        }
        assert_eq!(doc["integrity"], table().integrity);
    }

    #[test]
    fn profiles_share_the_table_and_other_scanners_have_none() {
        for id in [
            "openredaction",
            "openredaction-credentials",
            "openredaction-mapped",
            "openredaction-credential-bearing",
        ] {
            assert!(ScopeTable::for_scanner(&ScannerId::new(id).unwrap()).is_some());
        }
        for id in ["gitleaks", "trufflehog", "flare-redact", "redact-secret"] {
            assert!(ScopeTable::for_scanner(&ScannerId::new(id).unwrap()).is_none());
        }
    }

    #[test]
    fn each_disposition_is_reached() {
        let t = table();
        let d = |labels: &[&str], family| classify(t, &finding(labels, family)).0;
        assert_eq!(
            d(&["GITHUB_TOKEN"], Some("github-token")),
            FindingDisposition::MappedCredential
        );
        assert_eq!(
            d(&["DOCKER_AUTH"], None),
            FindingDisposition::CredentialRelatedUnmapped
        );
        assert_eq!(d(&["EMAIL"], None), FindingDisposition::OutOfScope);
        assert_eq!(d(&["AWS_ARN"], None), FindingDisposition::OutOfScope);
        assert_eq!(d(&["PAYMENT_TOKEN"], None), FindingDisposition::Ambiguous);
        assert_eq!(d(&[], None), FindingDisposition::NativeLabelUnavailable);
        assert_eq!(
            d(&["~unrecognized"], None),
            FindingDisposition::UnrecognizedLabel
        );
    }

    #[test]
    fn conflicting_labels_are_ambiguous_and_never_lost() {
        let t = table();
        let (d, conflict) = classify(t, &finding(&["DOCKER_AUTH", "EMAIL"], None));
        assert_eq!(d, FindingDisposition::Ambiguous);
        assert!(conflict);
        // A family wins the primary reading but the conflict stays visible.
        let (d, conflict) = classify(
            t,
            &finding(&["EMAIL", "GITHUB_TOKEN"], Some("github-token")),
        );
        assert_eq!(d, FindingDisposition::MappedCredential);
        assert!(conflict);
        let (d, conflict) = classify(t, &finding(&["EMAIL", "~unrecognized"], None));
        assert_eq!(d, FindingDisposition::Ambiguous);
        assert!(conflict);
    }

    #[test]
    fn accounting_reconciles_and_zero_findings_is_a_measured_zero() {
        let t = table();
        let zero = account(t, &[]);
        assert_eq!(zero.findings, 0);
        assert_eq!(zero.by_disposition, DispositionCounts::default());
        assert!(zero.by_label.is_empty());

        let fs = vec![
            finding(&["GITHUB_TOKEN"], Some("github-token")),
            finding(&["EMAIL"], None),
            finding(&["EMAIL", "DOCKER_AUTH"], None),
            finding(&[], None),
            finding(&["~unrecognized"], None),
        ];
        let a = account(t, &fs);
        assert_eq!(a.findings, 5);
        assert_eq!(a.by_disposition.total(), 5);
        assert_eq!(a.multi_label_findings, 1);
        assert_eq!(a.conflicting_label_findings, 1);
        let email = a
            .by_label
            .iter()
            .find(|l| l.label.as_str() == "EMAIL")
            .unwrap();
        assert_eq!(email.findings, 2);
        assert_eq!(email.scope, Some(Scope::PiiOrIdentifier));
        let marker = a
            .by_label
            .iter()
            .find(|l| l.label.as_str() == "~unrecognized")
            .unwrap();
        assert!(marker.scope.is_none() && marker.reason.is_none());
        // Order independent.
        let mut rev = fs.clone();
        rev.reverse();
        assert_eq!(account(t, &rev), a);
    }
}
