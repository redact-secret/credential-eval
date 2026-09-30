//! Scanner-neutral review queue (legacy `execution.ts:93-99`,
//! `evaluation/domains/credential/review.ts`, `evaluation/substrate/review-state.ts`).
//!
//! The queue lists what needs an authored decision: every differential
//! disagreement, and every variant whose expectation could not be derived.
//! It never records a scanner as right or wrong.
//!
//! Entry ids are canonical digests. A disagreement id excludes the reference
//! scanner's identity except its id, so a new release of the reference scanner
//! does not re-key reviewed disagreements. Legacy strips only `redact-secret`;
//! here the configured reference is stripped.

use std::collections::BTreeMap;

use credential_eval_contracts::artifact::Disagreement;
use credential_eval_contracts::canonical::sha256_canonical;
use credential_eval_contracts::ids::{CaseId, ComponentId, FixturePath, ScannerId, Sha256Digest};
use credential_eval_contracts::observation::ScannerIdentity;
use credential_eval_contracts::range::ByteRange;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::differential::{ClassifiedRange, DisagreementEntry};
use super::model::{GeneratedVariant, MethodId};

/// Fixed reason for variants whose expectation needs an authored decision.
pub const PENDING_EXPECTATION: &str = "Mutation expectation requires an authored decision.";

/// The input a disagreement was observed on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewInput {
    /// Variant path.
    pub path: FixturePath,
    /// Digest of the variant content.
    pub content_hash: Sha256Digest,
    /// Digest of the variant fixture.
    pub fixture_hash: Sha256Digest,
}

/// Evidence of a disagreement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEvidence {
    /// Input.
    pub input: ReviewInput,
    /// Identities of the reference and the peer.
    pub tools: Vec<ScannerIdentity>,
}

/// One review-queue entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewEntry {
    /// Stable id.
    pub id: Sha256Digest,
    /// Evaluation case.
    pub case_id: CaseId,
    /// Method.
    pub method: MethodId,
    /// Case targets.
    pub targets: Vec<String>,
    /// Variant.
    pub variant: ComponentId,
    /// Always `review-required`.
    pub status: ReviewRequired,
    /// Reference scanner (disagreements only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<ScannerId>,
    /// Peer scanner (disagreements only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<ScannerId>,
    /// Disagreement (disagreements only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disagreement: Option<Disagreement>,
    /// Family-blind ranges by scanner (disagreements only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observations: Option<BTreeMap<ScannerId, Vec<ByteRange>>>,
    /// Classifications by scanner (disagreements only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classifications: Option<BTreeMap<ScannerId, Vec<ClassifiedRange>>>,
    /// Evidence (disagreements only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<ReviewEvidence>,
    /// Fixed reason (pending expectations only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The `review-required` status tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ReviewRequired {
    /// `review-required`.
    #[default]
    #[serde(rename = "review-required")]
    ReviewRequired,
}

/// Queue a differential disagreement. `tools` holds the identities of the
/// scanners involved; the one whose id is `reference` contributes only its id
/// to the entry id (`review.ts:4-10`).
pub fn disagreement_entry(
    case_id: &CaseId,
    source_hash: &Sha256Digest,
    targets: &[String],
    entry: &DisagreementEntry,
    reference: &ScannerId,
    reference_identity: &ScannerIdentity,
    peer_identity: &ScannerIdentity,
) -> ReviewEntry {
    let observations = BTreeMap::from([
        (reference.clone(), entry.reference_ranges.clone()),
        (entry.peer.clone(), entry.peer_ranges.clone()),
    ]);
    let classifications = BTreeMap::from([
        (reference.clone(), entry.reference_classes.clone()),
        (entry.peer.clone(), entry.peer_classes.clone()),
    ]);
    let input = ReviewInput {
        path: entry.variant.fixture.path.clone(),
        content_hash: entry.variant.provenance.content_hash.clone(),
        fixture_hash: entry.variant.provenance.fixture_hash.clone(),
    };
    let tools = vec![reference_identity.clone(), peer_identity.clone()];
    let keyed_tools: Vec<serde_json::Value> = tools
        .iter()
        .map(|t| {
            if &t.id == reference {
                json!({ "id": t.id })
            } else {
                serde_json::to_value(t).expect("identity serializes")
            }
        })
        .collect();
    let id = sha256_canonical(&json!({
        "case": case_id,
        "source": source_hash,
        "variant": entry.variant.id,
        "peer": entry.peer,
        "disagreement": entry.disagreement,
        "status": ReviewRequired::ReviewRequired,
        "observations": observations,
        "classifications": classifications,
        "evidence": { "input": input, "tools": keyed_tools },
    }));
    ReviewEntry {
        id,
        case_id: case_id.clone(),
        method: MethodId::Differential,
        targets: targets.to_vec(),
        variant: entry.variant.id.clone(),
        status: ReviewRequired::ReviewRequired,
        reference: Some(reference.clone()),
        peer: Some(entry.peer.clone()),
        disagreement: Some(entry.disagreement),
        observations: Some(observations),
        classifications: Some(classifications),
        evidence: Some(ReviewEvidence { input, tools }),
        reason: None,
    }
}

/// Queue a variant whose expectation needs an authored decision
/// (`execution.ts:95-99`). Its id binds the case, variant and fixture digest.
pub fn pending_expectation_entry(
    case_id: &CaseId,
    method: MethodId,
    targets: &[String],
    variant: &GeneratedVariant,
) -> ReviewEntry {
    ReviewEntry {
        id: sha256_canonical(&json!({
            "case": case_id,
            "variant": variant.id,
            "hash": variant.provenance.fixture_hash,
        })),
        case_id: case_id.clone(),
        method,
        targets: targets.to_vec(),
        variant: variant.id.clone(),
        status: ReviewRequired::ReviewRequired,
        reference: None,
        peer: None,
        disagreement: None,
        observations: None,
        classifications: None,
        evidence: None,
        reason: Some(PENDING_EXPECTATION.to_owned()),
    }
}

impl ReviewEntry {
    /// Project onto the run-artifact contract.
    pub fn occurrence(&self) -> credential_eval_contracts::artifact::ReviewOccurrence {
        credential_eval_contracts::artifact::ReviewOccurrence {
            id: self.id.clone(),
            case_id: self.case_id.clone(),
            method: self.method.component(),
            variant: self.variant.clone(),
            baseline: None,
            candidate: None,
            reference: self.reference.clone(),
            peer: self.peer.clone(),
            disagreement: self.disagreement,
        }
    }
}

/// Status of a ledger entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LedgerStatus {
    /// Awaiting a decision.
    Open,
    /// Decided.
    Resolved,
    /// Decided as not assertable.
    NotAssertable,
}

/// One ledger entry as the reducer reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LedgerEntry {
    /// Status.
    pub status: LedgerStatus,
    /// Run in which the entry first appeared.
    pub first_seen_run: String,
}

/// Queue state against an immutable ledger (`review-state.ts:6-15`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewState {
    /// Open entries.
    pub open: u64,
    /// Resolved entries.
    pub resolved: u64,
    /// Not-assertable entries.
    pub not_assertable: u64,
    /// Entries absent from the ledger.
    pub unknown: u64,
    /// Smallest `first_seen_run` among open entries.
    pub oldest_open_run: Option<String>,
}

/// Reduce a queue against a ledger without interpreting why entries exist.
pub fn review_state<'a>(
    queue: impl IntoIterator<Item = &'a Sha256Digest>,
    ledger: &BTreeMap<Sha256Digest, LedgerEntry>,
) -> ReviewState {
    let mut state = ReviewState::default();
    for id in queue {
        match ledger.get(id) {
            None => state.unknown += 1,
            Some(row) => {
                match row.status {
                    LedgerStatus::Open => state.open += 1,
                    LedgerStatus::Resolved => state.resolved += 1,
                    LedgerStatus::NotAssertable => state.not_assertable += 1,
                }
                if row.status == LedgerStatus::Open
                    && state
                        .oldest_open_run
                        .as_ref()
                        .is_none_or(|oldest| row.first_seen_run < *oldest)
                {
                    state.oldest_open_run = Some(row.first_seen_run.clone());
                }
            }
        }
    }
    state
}
