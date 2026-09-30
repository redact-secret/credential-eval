//! Evaluation evidence files (`credential-eval/evaluation-evidence/v1`).
//!
//! The kernel embeds no family, pattern, segment layout, validator or
//! taxonomy vocabulary (kernel-deltas N4-N8); an evaluation run reads them
//! from this file, produced by the evidence owner (during migration, by
//! `tools/legacy-export/export.mts`). Its canonical digest is recorded in the
//! run config (`evaluation.evidence_digest`), so it is part of `config_hash`.
//!
//! ```json
//! {
//!   "schema": "credential-eval/evaluation-evidence/v1",
//!   "families": { "<family>": { "pattern": "^...$", "segments": {"delimiter": ".", "removable": [1]} } },
//!   "validators": { "<family>": "legacy:<name>" },
//!   "benign_taxonomies": ["placeholder", "..."],
//!   "classification_allowlist": true
//! }
//! ```
//!
//! Validators are code and are resolved by name; the only provider today is
//! the removable migration crate (`credential_eval_compat::validators`).

use std::collections::{BTreeMap, BTreeSet};

use credential_eval_contracts::canonical::sha256_canonical;
use credential_eval_contracts::ids::Sha256Digest;
use credential_eval_kernel::evaluation::{EvaluationEvidence, FamilyContract, FamilyContracts};
use serde::Deserialize;

/// Schema tag of an evidence file.
pub const EVIDENCE_SCHEMA: &str = "credential-eval/evaluation-evidence/v1";

/// Largest accepted evidence file (bytes).
pub const MAX_EVIDENCE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceFile {
    schema: String,
    families: BTreeMap<String, FamilyContract>,
    #[serde(default)]
    validators: BTreeMap<String, String>,
    #[serde(default)]
    benign_taxonomies: Option<Vec<String>>,
    #[serde(default)]
    classification_allowlist: bool,
}

/// A loaded evidence file.
pub struct LoadedEvidence {
    /// Kernel evidence.
    pub evidence: EvaluationEvidence,
    /// Family allowlist, when the file asks for the `eval` classification rule.
    pub allowlist: Option<BTreeSet<String>>,
    /// Canonical digest of the file content.
    pub digest: Sha256Digest,
}

/// Parse and resolve an evidence file.
pub fn load(bytes: &[u8]) -> Result<LoadedEvidence, String> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid evidence JSON: {e}"))?;
    let digest = sha256_canonical(&value);
    let file: EvidenceFile =
        serde_json::from_value(value).map_err(|e| format!("invalid evidence file: {e}"))?;
    if file.schema != EVIDENCE_SCHEMA {
        return Err(format!(
            "evidence schema must be {EVIDENCE_SCHEMA:?}, found {:?}",
            file.schema
        ));
    }
    let families: BTreeSet<String> = file.families.keys().cloned().collect();
    let mut contracts = FamilyContracts::new(file.families).map_err(|e| e.to_string())?;
    for (family, name) in &file.validators {
        if !families.contains(family) {
            return Err(format!("validator for unknown family {family:?}"));
        }
        let validator = credential_eval_compat::validators::named(name)
            .ok_or_else(|| format!("unknown validator {name:?} for family {family:?}"))?;
        contracts = contracts.with_validator(family.clone(), validator);
    }
    let benign_taxonomies = match file.benign_taxonomies {
        None => None,
        Some(list) => {
            if list.iter().any(|t| t.trim().is_empty()) {
                return Err("blank benign taxonomy".into());
            }
            Some(list.into_iter().collect())
        }
    };
    Ok(LoadedEvidence {
        evidence: EvaluationEvidence {
            contracts,
            benign_taxonomies,
        },
        allowlist: file.classification_allowlist.then_some(families),
        digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_and_digests_canonically() {
        let a = br#"{"schema":"credential-eval/evaluation-evidence/v1","families":{"x":{"pattern":"^a+$"}},"validators":{"x":"legacy:discord-bot-token"},"classification_allowlist":true}"#;
        let b = br#"{"families":{"x":{"pattern":"^a+$"}},"classification_allowlist":true,"validators":{"x":"legacy:discord-bot-token"},"schema":"credential-eval/evaluation-evidence/v1"}"#;
        let (la, lb) = (load(a).unwrap(), load(b).unwrap());
        assert_eq!(la.digest, lb.digest);
        assert_eq!(la.allowlist, Some(BTreeSet::from(["x".to_owned()])));
        assert!(la.evidence.contracts.has_pattern("x"));
    }

    #[test]
    fn refuses_unknown_names_and_fields() {
        let unknown = br#"{"schema":"credential-eval/evaluation-evidence/v1","families":{"x":{}},"validators":{"x":"nope"}}"#;
        assert!(load(unknown).err().unwrap().contains("unknown validator"));
        let orphan = br#"{"schema":"credential-eval/evaluation-evidence/v1","families":{},"validators":{"x":"legacy:discord-bot-token"}}"#;
        assert!(load(orphan).err().unwrap().contains("unknown family"));
        let extra =
            br#"{"schema":"credential-eval/evaluation-evidence/v1","families":{},"extra":1}"#;
        assert!(load(extra).is_err());
        let schema = br#"{"schema":"other","families":{}}"#;
        assert!(load(schema).is_err());
        let bad = br#"{"schema":"credential-eval/evaluation-evidence/v1","families":{"x":{"pattern":"("}}}"#;
        assert!(load(bad).is_err());
    }
}
