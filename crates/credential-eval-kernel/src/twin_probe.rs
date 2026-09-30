//! Per-family twin probe (legacy `twinProbe`, `benchmarks/lib/twin-probe.ts:25-44`).
//!
//! Puts every family in exactly one state, so a family without an authored
//! twin cannot silently leave the twin-rate denominator. A pair is scored
//! under the v1.1 strict rule used by [`crate::accounting::account_groups`].
//!
//! The family list and the un-probeable records are **evidence inputs**
//! (legacy reads them from the product `contracts` table,
//! `evaluation/domains/credential/assessment.ts`); the kernel never embeds
//! them.

use std::collections::BTreeMap;

use credential_eval_contracts::artifact::{CaseMeasurement, CaseResult};
use credential_eval_contracts::corpus::{CaseKind, EvidenceTier};
use credential_eval_contracts::ids::CaseId;
use serde::{Deserialize, Serialize};

use crate::KernelError;
use crate::lattice::is_acceptable;

/// Probe state of one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TwinProbeStatus {
    /// Every scored pair: positive acceptable and twin not flagged.
    Discriminated,
    /// At least one scored pair failed.
    NotDiscriminated,
    /// No twin authored; the evidence records why.
    UnProbeable,
    /// Twins exist but no pair was scored.
    NotMeasured,
    /// Neither a twin nor an un-probeable record: a corpus gap.
    Unrecorded,
}

impl TwinProbeStatus {
    /// Every status, in legacy count order.
    pub const ALL: [Self; 5] = [
        Self::Discriminated,
        Self::NotDiscriminated,
        Self::UnProbeable,
        Self::NotMeasured,
        Self::Unrecorded,
    ];
}

/// Evidence that a family cannot be probed with an authored twin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UnprobeableRecord {
    /// Why no twin can be authored.
    pub reason: String,
    /// When the evidence was observed.
    pub observed_at: String,
}

/// A fixture as the probe sees it: its primary family (legacy
/// `detectors[0]`) and twin lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeFixture {
    /// Case id (same id space as the case results).
    pub id: CaseId,
    /// Primary family the fixture targets, if any.
    pub family: Option<String>,
    /// Positive this fixture is a twin of.
    pub twin_of: Option<CaseId>,
}

/// One family's probe entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TwinProbeEntry {
    /// Family id.
    pub id: String,
    /// State.
    pub status: TwinProbeStatus,
    /// Authored twins.
    pub twins: u64,
    /// Scored pairs.
    pub pairs: u64,
    /// Strictly discriminated pairs.
    pub discriminated: u64,
    /// Un-probeable reason, when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Un-probeable observation date, when recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

/// The probe over all families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TwinProbe {
    /// One entry per family, in input order.
    pub entries: Vec<TwinProbeEntry>,
    /// Entries per status (every status present).
    pub counts: BTreeMap<TwinProbeStatus, u64>,
}

/// Run the probe. `cases` is `None` when no scanner run is available (every
/// family with twins is then `not-measured`).
pub fn twin_probe(
    families: &[String],
    fixtures: &[ProbeFixture],
    cases: Option<&[CaseResult]>,
    unprobeable: &BTreeMap<String, UnprobeableRecord>,
) -> Result<TwinProbe, KernelError> {
    let by_id: BTreeMap<&CaseId, &CaseResult> = cases
        .unwrap_or(&[])
        .iter()
        .map(|c| (&c.case_id, c))
        .collect();
    let mut entries = Vec::with_capacity(families.len());
    for id in families {
        let twins: Vec<&ProbeFixture> = fixtures
            .iter()
            .filter(|f| f.twin_of.is_some() && f.family.as_deref() == Some(id.as_str()))
            .collect();
        let record = unprobeable.get(id);
        if !twins.is_empty() && record.is_some() {
            return Err(KernelError::UnprobeableWithTwins(id.clone()));
        }
        if twins.is_empty() {
            entries.push(TwinProbeEntry {
                id: id.clone(),
                status: if record.is_some() {
                    TwinProbeStatus::UnProbeable
                } else {
                    TwinProbeStatus::Unrecorded
                },
                twins: 0,
                pairs: 0,
                discriminated: 0,
                reason: record.map(|r| r.reason.clone()),
                observed_at: record.map(|r| r.observed_at.clone()),
            });
            continue;
        }
        let (mut pairs, mut discriminated) = (0, 0);
        for fixture in &twins {
            let twin = by_id.get(&fixture.id);
            let positive = fixture.twin_of.as_ref().and_then(|p| by_id.get(p));
            let (Some(twin), Some(positive)) = (twin, positive) else {
                continue;
            };
            if twin.tier == EvidenceTier::T0
                || positive.tier == EvidenceTier::T0
                || positive.kind == CaseKind::MustNotFlag
            {
                continue;
            }
            let CaseMeasurement::Positive { span_outcomes, .. } = &positive.measurement else {
                continue;
            };
            pairs += 1;
            let flagged = match &twin.measurement {
                CaseMeasurement::Control { flagged, .. } => *flagged,
                // Legacy reads `!twin.flagged` on an unscored row as "not flagged".
                _ => false,
            };
            if span_outcomes.iter().all(|o| is_acceptable(*o)) && !flagged {
                discriminated += 1;
            }
        }
        let status = if pairs == 0 {
            TwinProbeStatus::NotMeasured
        } else if discriminated == pairs {
            TwinProbeStatus::Discriminated
        } else {
            TwinProbeStatus::NotDiscriminated
        };
        entries.push(TwinProbeEntry {
            id: id.clone(),
            status,
            twins: twins.len() as u64,
            pairs,
            discriminated,
            reason: None,
            observed_at: None,
        });
    }
    let mut counts: BTreeMap<TwinProbeStatus, u64> =
        TwinProbeStatus::ALL.iter().map(|s| (*s, 0)).collect();
    for entry in &entries {
        *counts.entry(entry.status).or_insert(0) += 1;
    }
    Ok(TwinProbe { entries, counts })
}
