//! Differential observation between a reference scanner and its peers
//! (legacy `evaluation/domains/credential/methods/differential.ts`).
//!
//! Neither scanner is ground truth. Legacy hard-codes the reference as
//! `redact-secret`; here it is a run parameter, and the `redact-secret-only`
//! label is `reference-only` (the compatibility layer maps it back).

use std::collections::BTreeMap;

use credential_eval_contracts::artifact::{
    ComparisonStatus, DifferentialComparison, Disagreement, ObservedRange,
};
use credential_eval_contracts::ids::{CaseId, ScannerId};
use credential_eval_contracts::observation::{NormalizedFinding, ScannerStatus};
use credential_eval_contracts::range::ByteRange;
use serde::{Deserialize, Serialize};

use super::assertions::{ScannerView, actual_on_path};
use super::model::GeneratedVariant;

/// A deduplicated range with the sorted families that reported it
/// (legacy `ObservedRange`, `engine/types.ts:62`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClassifiedRange {
    /// Start byte.
    pub start: u64,
    /// End byte.
    pub end: u64,
    /// Families, sorted and unique.
    pub families: Vec<String>,
    /// Whether some finding on this range had no family.
    pub unmapped: bool,
}

/// Per-range classifications of one path's findings (`differential.ts:9-19`).
pub fn classifications(findings: &[&NormalizedFinding]) -> Vec<ClassifiedRange> {
    let mut groups: BTreeMap<(u64, u64), (std::collections::BTreeSet<String>, bool)> =
        BTreeMap::new();
    for f in findings {
        let row = groups.entry((f.start, f.end)).or_default();
        match &f.family {
            Some(family) if !family.is_empty() => {
                row.0.insert(family.clone());
            }
            _ => row.1 = true,
        }
    }
    groups
        .into_iter()
        .map(|((start, end), (families, unmapped))| ClassifiedRange {
            start,
            end,
            families: families.into_iter().collect(),
            unmapped,
        })
        .collect()
}

/// A disagreement to review.
#[derive(Debug, Clone, PartialEq)]
pub struct DisagreementEntry {
    /// Variant.
    pub variant: GeneratedVariant,
    /// Peer scanner.
    pub peer: ScannerId,
    /// Disagreement kind (never `none`).
    pub disagreement: Disagreement,
    /// Family-blind ranges of the reference and the peer.
    pub reference_ranges: Vec<ByteRange>,
    /// Peer ranges.
    pub peer_ranges: Vec<ByteRange>,
    /// Reference classifications.
    pub reference_classes: Vec<ClassifiedRange>,
    /// Peer classifications.
    pub peer_classes: Vec<ClassifiedRange>,
}

/// One scanner's view of one variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VariantObservation {
    /// Variant id.
    pub id: String,
    /// Deduplicated findings on the variant.
    pub actual: Vec<ObservedRange>,
    /// Classifications.
    pub classifications: Vec<ClassifiedRange>,
}

/// Output of the differential method for one case.
#[derive(Debug, Clone, PartialEq)]
pub struct DifferentialResult {
    /// Comparisons, one per variant × peer.
    pub comparisons: Vec<DifferentialComparison>,
    /// Disagreements to review.
    pub queue: Vec<DisagreementEntry>,
    /// Per-scanner observations (empty for non-complete scanners).
    pub observations: BTreeMap<ScannerId, (ScannerStatus, Vec<VariantObservation>)>,
    /// Whether the reference completed and every comparison is complete.
    pub complete: bool,
}

fn ranges(findings: &[&NormalizedFinding]) -> Vec<ByteRange> {
    actual_on_path(findings)
        .into_iter()
        .map(|r| ByteRange::new(r.start, r.end))
        .collect()
}

/// Compare the reference with every other scanner on every variant
/// (`differential.ts:24-61`). Peers are ordered by scanner id.
pub fn evaluate_differential(
    case_id: &CaseId,
    variants: &[GeneratedVariant],
    scanners: &[ScannerView<'_>],
    reference: &ScannerId,
) -> DifferentialResult {
    let primary = scanners.iter().find(|s| s.id == reference);
    let mut peers: Vec<&ScannerView<'_>> = scanners.iter().filter(|s| s.id != reference).collect();
    peers.sort_by(|a, b| a.id.cmp(b.id));
    let mut comparisons = Vec::new();
    let mut queue = Vec::new();
    for v in variants {
        for peer in &peers {
            let primary_status = primary.map(|p| p.status);
            let (Some(p), true) = (
                primary.filter(|p| p.status == ScannerStatus::Complete),
                peer.status == ScannerStatus::Complete,
            ) else {
                let unsupported = primary_status == Some(ScannerStatus::Unsupported)
                    || peer.status == ScannerStatus::Unsupported;
                comparisons.push(DifferentialComparison {
                    case_id: case_id.clone(),
                    variant: v.id.clone(),
                    reference: reference.clone(),
                    peer: peer.id.clone(),
                    status: if unsupported {
                        ComparisonStatus::Unsupported
                    } else {
                        ComparisonStatus::Incomplete
                    },
                    disagreement: None,
                    classification_compared: None,
                });
                continue;
            };
            let (pf, qf) = (p.on(v), peer.on(v));
            let (a, b) = (ranges(&pf), ranges(&qf));
            let (ac, bc) = (classifications(&pf), classifications(&qf));
            let equal = a == b;
            let classifiable = equal
                && !ac.is_empty()
                && ac
                    .iter()
                    .chain(&bc)
                    .all(|r| !r.unmapped && !r.families.is_empty());
            let disagreement = if !equal {
                if b.is_empty() {
                    Disagreement::ReferenceOnly
                } else if a.is_empty() {
                    Disagreement::PeerOnly
                } else {
                    Disagreement::RangeDisagreement
                }
            } else if classifiable && ac != bc {
                Disagreement::ClassificationDisagreement
            } else {
                Disagreement::None
            };
            comparisons.push(DifferentialComparison {
                case_id: case_id.clone(),
                variant: v.id.clone(),
                reference: reference.clone(),
                peer: peer.id.clone(),
                status: ComparisonStatus::Complete,
                disagreement: Some(disagreement),
                classification_compared: Some(classifiable),
            });
            if disagreement != Disagreement::None {
                queue.push(DisagreementEntry {
                    variant: v.clone(),
                    peer: peer.id.clone(),
                    disagreement,
                    reference_ranges: a,
                    peer_ranges: b,
                    reference_classes: ac,
                    peer_classes: bc,
                });
            }
        }
    }
    let observations = scanners
        .iter()
        .map(|s| {
            let seen = if s.status == ScannerStatus::Complete {
                variants
                    .iter()
                    .map(|v| {
                        let f = s.on(v);
                        VariantObservation {
                            id: v.id.to_string(),
                            actual: actual_on_path(&f),
                            classifications: classifications(&f),
                        }
                    })
                    .collect()
            } else {
                Vec::new()
            };
            (s.id.clone(), (s.status, seen))
        })
        .collect();
    let complete = primary.is_some_and(|p| p.status == ScannerStatus::Complete)
        && !comparisons.is_empty()
        && comparisons
            .iter()
            .all(|c| c.status == ComparisonStatus::Complete);
    DifferentialResult {
        comparisons,
        queue,
        observations,
        complete,
    }
}
