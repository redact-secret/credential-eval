//! Evidence inputs of the evaluation methods.
//!
//! Legacy operators read the product format-contract table
//! (`evaluation/domains/credential/assessment.ts`, `contracts`) and hard-code
//! product family names (`operators/structural.ts:27-29`). Here that knowledge
//! is **explicit input data**: the kernel embeds no family, pattern, segment
//! layout or taxonomy vocabulary. See `docs/migration/kernel-deltas.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use fancy_regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

use crate::twin_probe::UnprobeableRecord;

/// How a segmented family's value may lose one segment
/// (`structural.remove-segment`). Replaces the legacy hard-coded
/// `sendgrid-token` (`.`, segments 1-2) and `slack-token` (`-`, segments 1-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentRule {
    /// Segment delimiter (non-empty).
    pub delimiter: String,
    /// Segment indices that may be removed.
    pub removable: Vec<u64>,
}

/// One family's format contract, as evidence data.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyContract {
    /// Lexical pattern of the family's value. Interpreted with the
    /// `fancy-regex` crate (backtracking, `regex` syntax plus look-around);
    /// the ECMAScript subset used by the legacy contracts (anchors, classes,
    /// counted repetition, non-capturing groups, alternation and look-ahead)
    /// has the same meaning there. Lexical operators require it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Segment layout, when the family has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub segments: Option<SegmentRule>,
    /// Un-probeable record for the twin probe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unprobeable: Option<UnprobeableRecord>,
}

/// An additional structural validator for a family value (legacy
/// `FormatContract.validate`, `benchmarks/types.ts:94`). Validators are code,
/// not data, so the evidence owner supplies them explicitly.
pub type ValueValidator = Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// Backtracking bound of one contract-pattern match (explicit execution
/// bound; the legacy contract patterns need a few hundred steps at most).
pub const BACKTRACK_LIMIT: usize = 1_000_000;

/// The family contract table the methods consult.
#[derive(Clone, Default)]
pub struct FamilyContracts {
    families: BTreeMap<String, FamilyContract>,
    compiled: BTreeMap<String, Regex>,
    validators: BTreeMap<String, ValueValidator>,
}

impl fmt::Debug for FamilyContracts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FamilyContracts")
            .field("families", &self.families)
            .field("validators", &self.validators.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// A contract table could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidContract {
    /// Family id.
    pub family: String,
    /// Fixed reason.
    pub reason: &'static str,
}

impl fmt::Display for InvalidContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid family contract {}: {}",
            self.family, self.reason
        )
    }
}

impl std::error::Error for InvalidContract {}

impl FamilyContracts {
    /// Build a table, compiling every pattern.
    pub fn new(families: BTreeMap<String, FamilyContract>) -> Result<Self, InvalidContract> {
        let mut compiled = BTreeMap::new();
        for (family, contract) in &families {
            if let Some(pattern) = &contract.pattern {
                let regex = RegexBuilder::new(pattern)
                    .backtrack_limit(BACKTRACK_LIMIT)
                    .build()
                    .map_err(|_| InvalidContract {
                        family: family.clone(),
                        reason: "pattern does not compile",
                    })?;
                compiled.insert(family.clone(), regex);
            }
            if let Some(rule) = &contract.segments {
                if rule.delimiter.is_empty() {
                    return Err(InvalidContract {
                        family: family.clone(),
                        reason: "empty segment delimiter",
                    });
                }
            }
        }
        Ok(Self {
            families,
            compiled,
            validators: BTreeMap::new(),
        })
    }

    /// Attach a structural validator to `family`.
    #[must_use]
    pub fn with_validator(mut self, family: impl Into<String>, validator: ValueValidator) -> Self {
        self.validators.insert(family.into(), validator);
        self
    }

    /// The family's contract, if known.
    pub fn get(&self, family: &str) -> Option<&FamilyContract> {
        self.families.get(family)
    }

    /// Known family ids (the classification allowlist of the `eval` pipeline,
    /// `evaluation/domains/credential/normalization.ts:7`).
    pub fn families(&self) -> BTreeSet<String> {
        self.families.keys().cloned().collect()
    }

    /// Un-probeable records by family.
    pub fn unprobeable(&self) -> BTreeMap<String, UnprobeableRecord> {
        self.families
            .iter()
            .filter_map(|(k, v)| v.unprobeable.clone().map(|u| (k.clone(), u)))
            .collect()
    }

    /// Whether the family has a lexical pattern.
    pub fn has_pattern(&self, family: &str) -> bool {
        self.compiled.contains_key(family)
    }

    /// Whether `value` satisfies the family's pattern and validator
    /// (`operators/lexical.ts:21`). `false` for families without a pattern,
    /// and for a match that exceeds the backtracking bound (the variant is
    /// then `review-required`, never silently `derived`).
    pub fn is_valid(&self, family: &str, value: &str) -> bool {
        self.compiled
            .get(family)
            .is_some_and(|r| r.is_match(value).unwrap_or(false))
            && self.validators.get(family).is_none_or(|v| v(value))
    }
}

/// All evidence inputs of the evaluation methods.
#[derive(Debug, Clone, Default)]
pub struct EvaluationEvidence {
    /// Family contract table.
    pub contracts: FamilyContracts,
    /// Benign-control taxonomy vocabulary (legacy `AXES ∪ REAL_WORLD_AXES`,
    /// `methods/benign.ts:7`). `None` accepts any non-blank taxonomy.
    pub benign_taxonomies: Option<BTreeSet<String>>,
}
