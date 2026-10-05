//! Performance reuse identity, evidence lookup and dry-run planning (ADR 0010).
//!
//! Performance and accuracy are separate axes. A *cell* is one subject
//! measured on one workload in one shape; its [`CellKey`] holds exactly what
//! the measurement depends on and nothing else:
//!
//! * the scanner build and how it is invoked (executable digest, revision,
//!   version, invocation digest: arguments, delivery, exit codes);
//! * the workload (generator id and version, workload id, units, byte size and
//!   input digest) and shape;
//! * the measurement kind, performance protocol and schedule (rounds, batching,
//!   warm-up, chunking);
//! * the toolchain and instrumentation (rustc, valgrind, ...), the target
//!   (OS, architecture) and, for wall-clock latency, the host class (CPU model
//!   and logical CPU count).
//!
//! The accuracy corpus release, labels, expectations, policy, the engine
//! version, the consumer view and the subject's *name* are not in the key.
//! Nothing here launches a process: [`plan`] is a pure function of a request
//! and the stored artifacts.
//!
//! **Pairwise conclusions.** A latency or instruction direction is a statement
//! about two builds measured together (A/B/A in one run). A subject's own
//! timings are reusable evidence of *that subject*; a direction is only reused
//! when a stored run measured the same pair, with both cells unchanged
//! ([`Decision::ReuseComparison`]). A new pair is never certified from
//! historical peers: the old peer is listed as a [`Historical`] measurement
//! with its date and host, and the comparison is [`Decision::MeasureFresh`].

use std::collections::{BTreeMap, BTreeSet};

use credential_eval_contracts::canonical::sha256_canonical;
use credential_eval_contracts::ids::{GitRevision, ReleaseTag, ScannerId, Sha256Digest};
use credential_eval_contracts::performance::{
    Direction, GenerationContract, InstructionArm, MeasurementKind, PerformanceArtifact, ScanShape,
    Schedule, SubjectIdentity, SubjectRole, ToolchainEntry, WorkloadId, WorkloadIdentity,
};
use serde::Serialize;
use serde_json::Value;

/// Version of the identity definition. Changing what a [`CellKey`] holds
/// changes this and invalidates every stored cell, on purpose.
pub const IDENTITY_VERSION: &str = "credential-eval-performance-identity/1";

/// Document tag of a [`Plan`] (a report, not a frozen contract document).
pub const PLAN_TAG: &str = "credential-eval/performance-plan/v1";

/// Independent runs a latency direction needs before it is a result
/// (`perf confirm`).
pub const LATENCY_CONFIRMATION_RUNS: u32 = 2;

/// Everything of a build that its measurement depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SubjectKey {
    /// Version label.
    pub version: ReleaseTag,
    /// Source revision.
    pub revision: Option<GitRevision>,
    /// Executable digest (external-process subjects).
    pub executable_sha256: Option<Sha256Digest>,
    /// Arguments, delivery and exit codes ([`SubjectIdentity::invocation_digest`]).
    pub invocation_digest: Option<Sha256Digest>,
}

/// The schedule fields that matter for one kind and shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScheduleKey {
    /// Rounds.
    pub rounds: u32,
    /// Invocations per batch (latency; 0 otherwise).
    pub batch_invocations: u32,
    /// Warm-up invocations (latency; 0 otherwise).
    pub warmup_invocations: u32,
    /// Chunk size (latency chunked shape; 0 otherwise).
    pub chunk_bytes: u32,
}

/// Target and, for latency, host class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Environment {
    /// OS family.
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// Latency only: the CPU model. Instruction counts and allocation counts
    /// do not depend on it.
    pub cpu_model: Option<String>,
    /// Latency only: logical CPUs.
    pub cpus: Option<u32>,
}

/// The identity of one cell. Equal keys mean the same measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CellKey {
    /// [`IDENTITY_VERSION`].
    pub identity: String,
    /// Measurement kind.
    pub kind: MeasurementKind,
    /// Performance protocol version.
    pub protocol: String,
    /// Workload generator id and version.
    pub generator: String,
    /// Workload id.
    pub workload: WorkloadId,
    /// Generator units.
    pub units: u32,
    /// Generated input size.
    pub bytes: u64,
    /// Generated input digest.
    pub input_digest: Sha256Digest,
    /// Shape (absent for allocation).
    pub shape: Option<ScanShape>,
    /// Schedule (absent for allocation).
    pub schedule: Option<ScheduleKey>,
    /// The build.
    pub subject: SubjectKey,
    /// Toolchain and instrumentation.
    pub toolchain: Vec<ToolchainEntry>,
    /// Target and host class.
    pub environment: Environment,
}

impl CellKey {
    /// Content address of the key.
    pub fn digest(&self) -> Sha256Digest {
        sha256_canonical(self)
    }

    /// Why this key cannot identify reusable evidence, when it cannot: an
    /// identity that is not fully known is never matched.
    pub fn gap(&self) -> Option<&'static str> {
        match self.kind {
            MeasurementKind::Allocation => {
                if self.subject.revision.is_none() {
                    return Some("allocation subject has no source revision");
                }
                if self.toolchain.is_empty() {
                    return Some("allocation harness records no toolchain");
                }
            }
            MeasurementKind::Latency | MeasurementKind::Instructions => {
                if self.subject.executable_sha256.is_none() {
                    return Some("subject has no executable digest");
                }
                if self.subject.invocation_digest.is_none() {
                    return Some("subject has no invocation digest (artifact predates it)");
                }
                if self.schedule.is_none() {
                    return Some("no schedule recorded");
                }
                if self.kind == MeasurementKind::Latency
                    && (self.environment.cpu_model.is_none() || self.environment.cpus.is_none())
                {
                    return Some("latency host class is unknown (no CPU model)");
                }
            }
        }
        None
    }

    /// Dotted paths of the fields in which `self` differs from `other`.
    pub fn differences(&self, other: &CellKey) -> Vec<String> {
        let (mut a, mut b) = (BTreeMap::new(), BTreeMap::new());
        flatten(
            "",
            &serde_json::to_value(self).unwrap_or(Value::Null),
            &mut a,
        );
        flatten(
            "",
            &serde_json::to_value(other).unwrap_or(Value::Null),
            &mut b,
        );
        let paths: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
        paths
            .into_iter()
            .filter(|p| a.get(*p) != b.get(*p))
            .cloned()
            .collect()
    }
}

fn flatten(prefix: &str, value: &Value, out: &mut BTreeMap<String, Value>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten(&path, inner, out);
            }
        }
        other => {
            out.insert(prefix.to_owned(), other.clone());
        }
    }
}

/// What every cell of one run shares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyContext {
    /// Kind.
    pub kind: MeasurementKind,
    /// Performance protocol.
    pub protocol: String,
    /// Workload generator.
    pub generation: GenerationContract,
    /// Schedule of the run.
    pub schedule: Option<Schedule>,
    /// Toolchain (sorted).
    pub toolchain: Vec<ToolchainEntry>,
    /// OS family.
    pub os: String,
    /// CPU architecture.
    pub arch: String,
    /// CPU model, when reported.
    pub cpu_model: Option<String>,
    /// Logical CPUs.
    pub cpus: u32,
}

impl KeyContext {
    /// The context a stored artifact was measured under.
    pub fn of(artifact: &PerformanceArtifact) -> Self {
        let host = &artifact.non_semantic.host;
        let mut toolchain = artifact.manifest.toolchain.clone();
        toolchain.sort();
        Self {
            kind: artifact.manifest.kind,
            protocol: artifact.manifest.performance_protocol.clone(),
            generation: artifact.manifest.generation.clone(),
            schedule: artifact.manifest.schedule.clone(),
            toolchain,
            os: host.os.to_string(),
            arch: host.arch.to_string(),
            cpu_model: host.cpu_model.clone(),
            cpus: host.cpus,
        }
    }

    /// The key of one subject on one workload.
    pub fn key(
        &self,
        subject: &SubjectKey,
        workload: &WorkloadIdentity,
        shape: Option<ScanShape>,
    ) -> CellKey {
        let latency = self.kind == MeasurementKind::Latency;
        let schedule = self.schedule.as_ref().and_then(|s| match self.kind {
            MeasurementKind::Allocation => None,
            MeasurementKind::Instructions => Some(ScheduleKey {
                rounds: s.rounds,
                batch_invocations: 0,
                warmup_invocations: 0,
                chunk_bytes: 0,
            }),
            MeasurementKind::Latency => Some(ScheduleKey {
                rounds: s.rounds,
                batch_invocations: s.batch_invocations,
                warmup_invocations: s.warmup_invocations,
                chunk_bytes: if shape == Some(ScanShape::Chunked) {
                    s.chunk_bytes
                } else {
                    0
                },
            }),
        });
        CellKey {
            identity: IDENTITY_VERSION.to_owned(),
            kind: self.kind,
            protocol: self.protocol.clone(),
            generator: format!("{}@{}", self.generation.id, self.generation.version),
            workload: workload.id,
            units: workload.units,
            bytes: workload.bytes,
            input_digest: workload.digest.clone(),
            shape,
            schedule,
            subject: subject.clone(),
            toolchain: self.toolchain.clone(),
            environment: Environment {
                os: self.os.clone(),
                arch: self.arch.clone(),
                cpu_model: if latency {
                    self.cpu_model.clone()
                } else {
                    None
                },
                cpus: latency.then_some(self.cpus),
            },
        }
    }
}

fn subject_key(subject: &SubjectIdentity) -> SubjectKey {
    SubjectKey {
        version: subject.version.clone(),
        revision: subject.revision.clone(),
        executable_sha256: subject.executable_sha256.clone(),
        invocation_digest: subject.invocation_digest.clone(),
    }
}

/// Where and when evidence came from. Provenance, never identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Provenance {
    /// SHA-256 of the stored artifact (content address).
    pub artifact_digest: Sha256Digest,
    /// Recorded start time.
    pub started_at: Option<String>,
    /// Recorded finish time.
    pub finished_at: Option<String>,
    /// Engine version that produced it.
    pub engine_version: String,
    /// OS family.
    pub os: String,
    /// Architecture.
    pub arch: String,
    /// CPU model, when recorded.
    pub cpu_model: Option<String>,
    /// Logical CPUs.
    pub cpus: u32,
}

impl Provenance {
    fn of(artifact: &PerformanceArtifact, digest: &Sha256Digest) -> Self {
        let host = &artifact.non_semantic.host;
        Self {
            artifact_digest: digest.clone(),
            started_at: artifact.non_semantic.started_at.clone(),
            finished_at: artifact.non_semantic.finished_at.clone(),
            engine_version: artifact.manifest.engine.version.clone(),
            os: host.os.to_string(),
            arch: host.arch.to_string(),
            cpu_model: host.cpu_model.clone(),
            cpus: host.cpus,
        }
    }
}

/// One subject's measurement cell recovered from a stored artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCell {
    /// The cell's identity.
    pub key: CellKey,
    /// Content address of `key`.
    pub digest: Sha256Digest,
    /// The subject's id in that run.
    pub subject: ScannerId,
    /// The arm, for a pairwise run.
    pub role: Option<SubjectRole>,
    /// The other subject's cell, for a pairwise run.
    pub partner: Option<Sha256Digest>,
    /// The direction the run reported for the pair (latency, instructions).
    pub direction: Option<Direction>,
    /// `Err` when the evidence is not usable, with the reason.
    pub usable: Result<(), String>,
    /// Origin.
    pub origin: Provenance,
}

/// Why an artifact was not accepted as evidence at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rejected {
    /// Content address of the artifact, when it could be computed.
    pub artifact_digest: Option<Sha256Digest>,
    /// Reason. Never contains document text.
    pub reason: String,
}

/// Check an artifact's internal consistency before any of it is used. A
/// corrupt or truncated artifact is rejected whole.
pub fn validate(artifact: &PerformanceArtifact) -> Result<(), String> {
    let kind = artifact.manifest.kind;
    let (l, i, a) = (
        artifact.latency.len(),
        artifact.instructions.len(),
        artifact.allocation.len(),
    );
    let consistent = match kind {
        MeasurementKind::Latency => l > 0 && i == 0 && a == 0,
        MeasurementKind::Instructions => i > 0 && l == 0 && a == 0,
        MeasurementKind::Allocation => a > 0 && l == 0 && i == 0,
    };
    if !consistent {
        return Err("results do not match the recorded measurement kind".into());
    }
    let known: BTreeSet<WorkloadId> = artifact.workloads.iter().map(|w| w.id).collect();
    let used = artifact
        .latency
        .iter()
        .map(|r| r.workload)
        .chain(artifact.instructions.iter().map(|r| r.workload))
        .chain(artifact.allocation.iter().map(|r| r.workload));
    if used.into_iter().any(|w| !known.contains(&w)) {
        return Err("a result names a workload that has no recorded identity".into());
    }
    if kind != MeasurementKind::Allocation && artifact.manifest.schedule.is_none() {
        return Err("no schedule recorded".into());
    }
    Ok(())
}

fn arm_exact(arm: &InstructionArm, rounds: u32) -> Result<(), String> {
    if arm.counts.len() != rounds as usize {
        return Err("fewer repeats than the schedule's rounds".into());
    }
    if arm.spread != 0 {
        return Err("instruction counts are not exact (non-zero spread)".into());
    }
    Ok(())
}

/// One pairwise result row: workload, shape, direction and evidence quality.
type PairRow = (WorkloadId, Option<ScanShape>, Direction, Result<(), String>);

/// The cells of a stored artifact, `Err` if the artifact itself is invalid.
pub fn cells_of(artifact: &PerformanceArtifact) -> Result<Vec<StoredCell>, String> {
    validate(artifact)?;
    let digest = sha256_canonical(artifact);
    let origin = Provenance::of(artifact, &digest);
    let ctx = KeyContext::of(artifact);
    let rounds = artifact.manifest.schedule.as_ref().map_or(0, |s| s.rounds);
    let workload = |id: WorkloadId| {
        artifact
            .workloads
            .iter()
            .find(|w| w.id == id)
            .expect("validated")
    };
    let by_role = |role: SubjectRole| {
        artifact
            .manifest
            .subjects
            .iter()
            .find(|s| s.role == Some(role))
    };
    let mut cells = Vec::new();
    match artifact.manifest.kind {
        MeasurementKind::Latency | MeasurementKind::Instructions => {
            let (Some(base), Some(cand)) = (
                by_role(SubjectRole::Baseline),
                by_role(SubjectRole::Candidate),
            ) else {
                return Err("pairwise artifact does not record its subjects' roles".into());
            };
            let rows: Vec<PairRow> = if artifact.manifest.kind == MeasurementKind::Latency {
                artifact
                    .latency
                    .iter()
                    .map(|r| {
                        let samples = [&r.baseline, &r.candidate, &r.control];
                        let usable = if r.failed_invocations != 0 {
                            Err("an invocation failed".to_owned())
                        } else if samples
                            .iter()
                            .any(|s| s.samples_ns.len() != rounds as usize)
                        {
                            Err("fewer samples than the schedule's rounds".to_owned())
                        } else {
                            Ok(())
                        };
                        (r.workload, Some(r.shape), r.direction, usable)
                    })
                    .collect()
            } else {
                artifact
                    .instructions
                    .iter()
                    .map(|r| {
                        let usable = if r.failed_invocations != 0 {
                            Err("an invocation failed".to_owned())
                        } else {
                            [&r.baseline, &r.candidate, &r.control]
                                .iter()
                                .try_for_each(|arm| arm_exact(arm, rounds))
                                .and_then(|()| {
                                    if r.control.net == r.baseline.net {
                                        Ok(())
                                    } else {
                                        Err("the control disagrees with the baseline".into())
                                    }
                                })
                        };
                        (r.workload, Some(ScanShape::Whole), r.direction, usable)
                    })
                    .collect()
            };
            for (id, shape, direction, usable) in rows {
                let w = workload(id);
                let (kb, kc) = (
                    ctx.key(&subject_key(base), w, shape),
                    ctx.key(&subject_key(cand), w, shape),
                );
                let (db, dc) = (kb.digest(), kc.digest());
                for (subject, role, key, digest_self, partner) in [
                    (base, SubjectRole::Baseline, kb, db.clone(), dc.clone()),
                    (cand, SubjectRole::Candidate, kc, dc, db),
                ] {
                    let usable = match key.gap() {
                        Some(gap) => Err(gap.to_owned()),
                        None => usable.clone(),
                    };
                    cells.push(StoredCell {
                        key,
                        digest: digest_self,
                        subject: subject.id.clone(),
                        role: Some(role),
                        partner: Some(partner),
                        direction: Some(direction),
                        usable,
                        origin: origin.clone(),
                    });
                }
            }
        }
        MeasurementKind::Allocation => {
            for result in &artifact.allocation {
                for id in [&result.baseline, &result.candidate] {
                    let subject = artifact
                        .manifest
                        .subjects
                        .iter()
                        .find(|s| &s.id == id)
                        .ok_or("an allocation result names an unrecorded subject")?;
                    let key = ctx.key(&subject_key(subject), workload(result.workload), None);
                    let usable = key.gap().map_or(Ok(()), |g| Err(g.to_owned()));
                    cells.push(StoredCell {
                        digest: key.digest(),
                        key,
                        subject: id.clone(),
                        role: None,
                        partner: None,
                        direction: None,
                        usable,
                        origin: origin.clone(),
                    });
                }
            }
        }
    }
    Ok(cells)
}

/// One requested pairwise cell: both subjects on one workload and shape.
#[derive(Debug, Clone)]
pub struct RequestedCell {
    /// Workload.
    pub workload: WorkloadId,
    /// Shape.
    pub shape: ScanShape,
    /// Baseline subject id and key.
    pub baseline: (ScannerId, CellKey),
    /// Candidate subject id and key.
    pub candidate: (ScannerId, CellKey),
    /// Process invocations of one fresh run of this cell.
    pub invocations_per_run: u64,
}

/// Planning options.
#[derive(Debug, Clone, Default)]
pub struct PlanOptions {
    /// Measure everything fresh.
    pub force_fresh: bool,
    /// Measure fresh every cell in which one of these subjects takes part.
    pub fresh_subjects: BTreeSet<ScannerId>,
}

/// What to do with a requested cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// Keep a qualified stored comparison of this exact pair; launch nothing.
    ReuseComparison,
    /// Measure the pair together (A/B/A, and independent confirmation for
    /// latency).
    MeasureFresh,
}

/// Why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    /// A stored comparison of this exact pair is qualified (latency:
    /// independent runs agree; instructions: exact counts).
    Unchanged,
    /// Nothing stored for these subjects on this workload.
    NoStoredEvidence,
    /// A stored cell exists and differs in `invalidated_by`.
    IdentityChanged,
    /// Stored evidence of this identity is unusable (see `evidence_notes`).
    IncompleteEvidence,
    /// Latency: fewer independent runs than confirmation needs.
    InsufficientIndependentRuns,
    /// Latency: stored independent runs disagree.
    UnconfirmedEvidence,
    /// Requested by the operator.
    ForcedFresh,
}

/// A stored independent measurement of one requested subject. It supports no
/// faster or slower claim against anything it was not measured with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Historical {
    /// The requested subject.
    pub subject: ScannerId,
    /// Origin of the measurement.
    pub origin: Provenance,
    /// Always `none`: a historical measurement carries no direction claim.
    pub claim: &'static str,
}

/// The plan for one pairwise cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CellPlan {
    /// Workload.
    pub workload: WorkloadId,
    /// Shape.
    pub shape: ScanShape,
    /// Decision.
    pub decision: Decision,
    /// Reason.
    pub reason: Reason,
    /// Fields of the identity that changed against the nearest stored cell.
    pub invalidated_by: Vec<String>,
    /// Why stored evidence of this identity was not accepted.
    pub evidence_notes: Vec<String>,
    /// Latency: how the stored independent runs combine.
    pub confirmation: Option<&'static str>,
    /// The stored runs a reused comparison stands on.
    pub reused_from: Vec<Provenance>,
    /// The stored direction a reused comparison keeps.
    pub direction: Option<Direction>,
    /// Stored independent measurements of the requested subjects.
    pub historical: Vec<Historical>,
    /// Fresh runs of this cell required.
    pub fresh_runs_required: u32,
    /// Process invocations those runs launch.
    pub projected_invocations: u64,
}

/// A dry-run plan. Planning launches no process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Plan {
    /// [`PLAN_TAG`].
    pub schema: &'static str,
    /// [`IDENTITY_VERSION`].
    pub identity: &'static str,
    /// Kind planned.
    pub kind: MeasurementKind,
    /// One entry per requested cell, in request order.
    pub cells: Vec<CellPlan>,
    /// Cells whose stored comparison is kept.
    pub reused_cells: u32,
    /// Cells to measure.
    pub fresh_cells: u32,
    /// Process invocations the plan would launch in total.
    pub projected_invocations: u64,
    /// Stored artifacts that were not accepted as evidence.
    pub rejected_evidence: Vec<Rejected>,
}

fn status_of(directions: &[Direction]) -> &'static str {
    let first = directions[0];
    if directions.iter().all(|d| *d == first) {
        match first {
            Direction::Faster => "confirmed-faster",
            Direction::Slower => "confirmed-slower",
            Direction::Indistinguishable => "no-evidence",
        }
    } else {
        "unconfirmed"
    }
}

/// Plan a request against stored cells. Pure: no I/O, no process.
pub fn plan(
    kind: MeasurementKind,
    requested: &[RequestedCell],
    stored: &[StoredCell],
    rejected: Vec<Rejected>,
    options: &PlanOptions,
) -> Plan {
    let mut cells = Vec::new();
    for req in requested {
        let (bid, bkey) = &req.baseline;
        let (cid, ckey) = &req.candidate;
        let (bd, cd) = (bkey.digest(), ckey.digest());
        let mut notes = Vec::new();
        for (key, label) in [(bkey, "baseline"), (ckey, "candidate")] {
            if let Some(gap) = key.gap() {
                notes.push(format!("{label}: {gap}"));
            }
        }
        let identity_gap = !notes.is_empty();

        // Stored cells of this exact pair, by artifact.
        let mut pair: BTreeMap<&Sha256Digest, &StoredCell> = BTreeMap::new();
        for cell in stored {
            if cell.digest == bd
                && cell.role == Some(SubjectRole::Baseline)
                && cell.partner.as_ref() == Some(&cd)
            {
                pair.insert(&cell.origin.artifact_digest, cell);
            }
        }
        let mut usable: Vec<&StoredCell> = Vec::new();
        for cell in pair.values() {
            match &cell.usable {
                Ok(()) => usable.push(cell),
                Err(reason) => notes.push(format!(
                    "stored run {}: {reason}",
                    short(&cell.origin.artifact_digest)
                )),
            }
        }

        // Independent per-subject measurements: never a comparison.
        let mut historical = Vec::new();
        let mut seen = BTreeSet::new();
        for (id, digest) in [(bid, &bd), (cid, &cd)] {
            for cell in stored
                .iter()
                .filter(|c| &c.digest == digest && c.usable.is_ok())
            {
                if seen.insert((id.clone(), cell.origin.artifact_digest.clone())) {
                    historical.push(Historical {
                        subject: id.clone(),
                        origin: cell.origin.clone(),
                        claim: "none",
                    });
                }
            }
        }

        historical.sort_by(|a, b| {
            (&a.subject, &a.origin.artifact_digest).cmp(&(&b.subject, &b.origin.artifact_digest))
        });
        let forced = options.force_fresh
            || options.fresh_subjects.contains(bid)
            || options.fresh_subjects.contains(cid);
        let fresh = |reason: Reason, runs: u32| (Decision::MeasureFresh, reason, runs);
        let mut confirmation = None;
        let mut direction = None;
        let mut reused_from = Vec::new();
        let mut invalidated_by = Vec::new();

        let (decision, reason, runs) = if forced {
            fresh(Reason::ForcedFresh, runs_for(kind, 0))
        } else if identity_gap {
            fresh(Reason::IncompleteEvidence, runs_for(kind, 0))
        } else if !usable.is_empty() {
            match kind {
                MeasurementKind::Latency => {
                    let directions: Vec<Direction> =
                        usable.iter().filter_map(|c| c.direction).collect();
                    if (directions.len() as u32) < LATENCY_CONFIRMATION_RUNS {
                        fresh(
                            Reason::InsufficientIndependentRuns,
                            LATENCY_CONFIRMATION_RUNS - directions.len() as u32,
                        )
                    } else {
                        let status = status_of(&directions);
                        if status == "unconfirmed" {
                            confirmation = Some(status);
                            fresh(Reason::UnconfirmedEvidence, LATENCY_CONFIRMATION_RUNS)
                        } else {
                            confirmation = Some(status);
                            direction = Some(directions[0]);
                            reused_from = usable.iter().map(|c| c.origin.clone()).collect();
                            (Decision::ReuseComparison, Reason::Unchanged, 0)
                        }
                    }
                }
                _ => {
                    direction = usable[0].direction;
                    reused_from = vec![usable[0].origin.clone()];
                    (Decision::ReuseComparison, Reason::Unchanged, 0)
                }
            }
        } else if !pair.is_empty() {
            // Stored evidence of exactly this pair exists but none is usable.
            fresh(Reason::IncompleteEvidence, runs_for(kind, 0))
        } else {
            // Nearest stored cell of each requested subject, to say what changed.
            let mut near = false;
            for (id, key, label) in [(bid, bkey, "baseline"), (cid, ckey, "candidate")] {
                let nearest = stored
                    .iter()
                    .filter(|c| {
                        &c.subject == id
                            && c.key.kind == key.kind
                            && c.key.workload == key.workload
                            && c.key.shape == key.shape
                    })
                    .map(|c| key.differences(&c.key))
                    .min_by_key(Vec::len);
                if let Some(diff) = nearest {
                    near = true;
                    invalidated_by.extend(diff.into_iter().map(|p| format!("{label}.{p}")));
                }
            }
            if near && invalidated_by.is_empty() {
                // Same subject cells, but never measured together.
                invalidated_by.push("pair: subjects were not measured together".into());
            }
            invalidated_by.sort();
            invalidated_by.dedup();
            if near {
                fresh(Reason::IdentityChanged, runs_for(kind, 0))
            } else {
                fresh(Reason::NoStoredEvidence, runs_for(kind, 0))
            }
        };
        cells.push(CellPlan {
            workload: req.workload,
            shape: req.shape,
            decision,
            reason,
            invalidated_by,
            evidence_notes: notes,
            confirmation,
            reused_from,
            direction,
            historical,
            fresh_runs_required: runs,
            projected_invocations: req.invocations_per_run.saturating_mul(u64::from(runs)),
        });
    }
    Plan {
        schema: PLAN_TAG,
        identity: IDENTITY_VERSION,
        kind,
        reused_cells: cells
            .iter()
            .filter(|c| c.decision == Decision::ReuseComparison)
            .count() as u32,
        fresh_cells: cells
            .iter()
            .filter(|c| c.decision == Decision::MeasureFresh)
            .count() as u32,
        projected_invocations: cells.iter().map(|c| c.projected_invocations).sum(),
        cells,
        rejected_evidence: rejected,
    }
}

/// Fresh runs a new pair needs: a latency direction is only a result when
/// independent runs agree; instruction counts are exact in one run.
fn runs_for(kind: MeasurementKind, have: u32) -> u32 {
    match kind {
        MeasurementKind::Latency => LATENCY_CONFIRMATION_RUNS.saturating_sub(have),
        _ => 1,
    }
}

fn short(digest: &Sha256Digest) -> String {
    digest.to_string().chars().take(19).collect()
}

/// Process invocations of one fresh latency run of one cell: `pieces`
/// processes per pass, `rounds * 3` batches of `batch` passes and two arms'
/// warm-ups.
pub fn latency_invocations(pieces: u64, rounds: u32, batch: u32, warmup: u32) -> u64 {
    pieces.saturating_mul(u64::from(rounds) * 3 * u64::from(batch) + 2 * u64::from(warmup))
}

/// Process invocations of one instruction-count run of one workload: three
/// arms and two startup measurements, `rounds` runs each.
pub fn instruction_invocations(rounds: u32) -> u64 {
    5 * u64::from(rounds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use credential_eval_contracts::artifact::EngineIdentity;
    use credential_eval_contracts::ids::ComponentId;
    use credential_eval_contracts::performance::{
        AllocationCounts, AllocationResult, HostDiagnostics, InstructionResult, LatencyResult,
        PerformanceManifest, PerformanceNonSemantic, TimingSummary,
    };
    use credential_eval_contracts::schema::PerformanceArtifactSchema;

    fn digest(n: u8) -> Sha256Digest {
        Sha256Digest::new(format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }

    fn id(s: &str) -> ScannerId {
        ScannerId::new(s).unwrap()
    }

    /// Per-test knobs for a stored pairwise run.
    #[derive(Clone)]
    struct Spec {
        kind: MeasurementKind,
        base_exe: u8,
        cand_exe: u8,
        invocation: u8,
        input: u8,
        bytes: u64,
        cpu: Option<&'static str>,
        direction: Direction,
        failed: u32,
        spread: u64,
        started: &'static str,
        engine: &'static str,
        cand_id: &'static str,
    }

    fn spec(kind: MeasurementKind) -> Spec {
        Spec {
            kind,
            base_exe: 1,
            cand_exe: 2,
            invocation: 7,
            input: 9,
            bytes: 100,
            cpu: Some("Test CPU"),
            direction: Direction::Faster,
            failed: 0,
            spread: 0,
            started: "2026-10-01T00:00:00Z",
            engine: "0.1.0",
            cand_id: "cand",
        }
    }

    fn summary(rounds: usize) -> TimingSummary {
        TimingSummary {
            min_ns: 1,
            median_ns: 1,
            samples_ns: vec![1; rounds],
        }
    }

    fn arm(spread: u64) -> InstructionArm {
        InstructionArm {
            counts: vec![10, 10 + spread, 10],
            startup: 1,
            net: 9,
            spread,
        }
    }

    fn subject(name: &str, exe: u8, invocation: u8, role: SubjectRole) -> SubjectIdentity {
        SubjectIdentity {
            id: id(name),
            version: ReleaseTag::new("1.0.0").unwrap(),
            revision: None,
            executable_sha256: Some(digest(exe)),
            invocation_digest: Some(digest(invocation)),
            role: Some(role),
        }
    }

    fn artifact(s: &Spec) -> PerformanceArtifact {
        let latency = s.kind == MeasurementKind::Latency;
        PerformanceArtifact {
            schema: PerformanceArtifactSchema,
            manifest: PerformanceManifest {
                engine: EngineIdentity {
                    name: "credential-eval".into(),
                    version: s.engine.into(),
                },
                performance_protocol: "credential-eval-performance/1".into(),
                kind: s.kind,
                config_hash: Some(digest(5)),
                generation: GenerationContract {
                    id: ComponentId::new("gen").unwrap(),
                    version: 1,
                },
                subjects: vec![
                    subject("base", s.base_exe, s.invocation, SubjectRole::Baseline),
                    subject(s.cand_id, s.cand_exe, s.invocation, SubjectRole::Candidate),
                ],
                toolchain: vec![],
                schedule: Some(Schedule {
                    rounds: 3,
                    batch_invocations: 1,
                    warmup_invocations: 1,
                    chunk_bytes: 1024,
                }),
            },
            workloads: vec![WorkloadIdentity {
                id: WorkloadId::SparseUnicode,
                units: 10,
                bytes: s.bytes,
                digest: digest(s.input),
            }],
            latency: if latency {
                vec![LatencyResult {
                    workload: WorkloadId::SparseUnicode,
                    shape: ScanShape::Whole,
                    baseline: summary(3),
                    candidate: summary(3),
                    control: summary(3),
                    median_ratio: 0.9,
                    min_ratio: 0.9,
                    noise_band: 0.05,
                    direction: s.direction,
                    failed_invocations: s.failed,
                }]
            } else {
                vec![]
            },
            allocation: vec![],
            instructions: if latency {
                vec![]
            } else {
                vec![InstructionResult {
                    workload: WorkloadId::SparseUnicode,
                    baseline: arm(s.spread),
                    candidate: arm(s.spread),
                    control: arm(s.spread),
                    ratio: 0.9,
                    noise_band: 0.001,
                    direction: s.direction,
                    failed_invocations: s.failed,
                }]
            },
            lost_paths: vec![],
            non_semantic: PerformanceNonSemantic {
                started_at: Some(s.started.into()),
                finished_at: None,
                host: HostDiagnostics {
                    os: ComponentId::new("linux").unwrap(),
                    arch: ComponentId::new("x86-64").unwrap(),
                    cpus: 4,
                    cpu_model: s.cpu.map(str::to_owned),
                    load_before: None,
                    load_after: None,
                },
            },
        }
    }

    /// The pair `spec` describes, requested now on the same host.
    fn request(s: &Spec, art: &PerformanceArtifact) -> Vec<RequestedCell> {
        let ctx = KeyContext::of(art);
        let w = &art.workloads[0];
        let shape = Some(ScanShape::Whole);
        let b = subject_key(&art.manifest.subjects[0]);
        let c = subject_key(&art.manifest.subjects[1]);
        vec![RequestedCell {
            workload: w.id,
            shape: ScanShape::Whole,
            baseline: (id("base"), ctx.key(&b, w, shape)),
            candidate: (id(s.cand_id), ctx.key(&c, w, shape)),
            invocations_per_run: 100,
        }]
    }

    fn stored(arts: &[&PerformanceArtifact]) -> Vec<StoredCell> {
        arts.iter().flat_map(|a| cells_of(a).unwrap()).collect()
    }

    fn run_plan(
        kind: MeasurementKind,
        requested: &[RequestedCell],
        store: &[StoredCell],
        options: &PlanOptions,
    ) -> Plan {
        plan(kind, requested, store, vec![], options)
    }

    /// Two independent runs of one pair (different start times, so different
    /// content addresses).
    fn two_runs(base: &Spec) -> (PerformanceArtifact, PerformanceArtifact) {
        let a = artifact(base);
        let b = artifact(&Spec {
            started: "2026-10-02T00:00:00Z",
            ..base.clone()
        });
        (a, b)
    }

    #[test]
    fn an_unchanged_confirmed_pair_is_reused_and_launches_nothing() {
        let base = spec(MeasurementKind::Latency);
        let (a, b) = two_runs(&base);
        let p = run_plan(
            MeasurementKind::Latency,
            &request(&base, &a),
            &stored(&[&a, &b]),
            &PlanOptions::default(),
        );
        let cell = &p.cells[0];
        assert_eq!(cell.decision, Decision::ReuseComparison);
        assert_eq!(cell.reason, Reason::Unchanged);
        assert_eq!(cell.confirmation, Some("confirmed-faster"));
        assert_eq!(cell.reused_from.len(), 2);
        assert_eq!(cell.reused_from[0].cpu_model.as_deref(), Some("Test CPU"));
        assert!(cell.reused_from[0].started_at.is_some());
        assert_eq!((p.fresh_cells, p.projected_invocations), (0, 0));
    }

    #[test]
    fn identity_ignores_names_engine_version_and_corpus() {
        // Engine version and the subject's name are provenance, not identity:
        // an unrelated evaluator release must not invalidate anything.
        let base = spec(MeasurementKind::Latency);
        let (a, b) = two_runs(&Spec {
            engine: "9.9.9",
            ..base.clone()
        });
        let p = run_plan(
            MeasurementKind::Latency,
            &request(&base, &artifact(&base)),
            &stored(&[&a, &b]),
            &PlanOptions::default(),
        );
        assert_eq!(p.cells[0].decision, Decision::ReuseComparison);
        let renamed = Spec {
            cand_id: "renamed",
            ..base.clone()
        };
        let p = run_plan(
            MeasurementKind::Latency,
            &request(&renamed, &artifact(&renamed)),
            &stored(&[&a, &b]),
            &PlanOptions::default(),
        );
        assert_eq!(p.cells[0].decision, Decision::ReuseComparison);
    }

    #[test]
    fn one_run_is_not_a_confirmed_result() {
        let base = spec(MeasurementKind::Latency);
        let a = artifact(&base);
        let p = run_plan(
            MeasurementKind::Latency,
            &request(&base, &a),
            &stored(&[&a]),
            &PlanOptions::default(),
        );
        let cell = &p.cells[0];
        assert_eq!(cell.decision, Decision::MeasureFresh);
        assert_eq!(cell.reason, Reason::InsufficientIndependentRuns);
        assert_eq!(cell.fresh_runs_required, 1);
        assert_eq!(cell.projected_invocations, 100);
        assert!(cell.direction.is_none());
    }

    #[test]
    fn disagreeing_runs_are_unconfirmed_and_not_promoted() {
        let base = spec(MeasurementKind::Latency);
        let a = artifact(&base);
        let b = artifact(&Spec {
            started: "2026-10-02T00:00:00Z",
            direction: Direction::Slower,
            ..base.clone()
        });
        let p = run_plan(
            MeasurementKind::Latency,
            &request(&base, &a),
            &stored(&[&a, &b]),
            &PlanOptions::default(),
        );
        assert_eq!(p.cells[0].reason, Reason::UnconfirmedEvidence);
        assert_eq!(p.cells[0].decision, Decision::MeasureFresh);
        assert!(p.cells[0].direction.is_none());
        assert_eq!(p.cells[0].fresh_runs_required, 2);
    }

    #[test]
    fn a_new_candidate_never_borrows_a_comparison_from_historical_peers() {
        let base = spec(MeasurementKind::Latency);
        let (a, b) = two_runs(&base);
        // A new candidate build against the same baseline.
        let new = Spec {
            cand_exe: 3,
            ..base.clone()
        };
        let p = run_plan(
            MeasurementKind::Latency,
            &request(&new, &artifact(&new)),
            &stored(&[&a, &b]),
            &PlanOptions::default(),
        );
        let cell = &p.cells[0];
        assert_eq!(cell.decision, Decision::MeasureFresh);
        assert_eq!(cell.reason, Reason::IdentityChanged);
        assert!(cell.direction.is_none() && cell.reused_from.is_empty());
        assert_eq!(cell.fresh_runs_required, 2, "A/B/A twice, independently");
        assert_eq!(
            cell.invalidated_by,
            vec!["candidate.subject.executable_sha256".to_owned()]
        );
        // The unchanged baseline is shown as history only: dated, hosted, no claim.
        assert_eq!(cell.historical.len(), 2);
        assert!(cell.historical.iter().all(|h| h.subject == id("base")));
        assert!(cell.historical.iter().all(|h| h.claim == "none"));
    }

    #[test]
    fn instructions_of_a_new_candidate_also_need_a_same_run_comparison() {
        let base = spec(MeasurementKind::Instructions);
        let a = artifact(&base);
        let new = Spec {
            cand_exe: 3,
            ..base.clone()
        };
        let p = run_plan(
            MeasurementKind::Instructions,
            &request(&new, &artifact(&new)),
            &stored(&[&a]),
            &PlanOptions::default(),
        );
        assert_eq!(p.cells[0].decision, Decision::MeasureFresh);
        assert_eq!(p.cells[0].fresh_runs_required, 1);
    }

    #[test]
    fn changed_workload_options_and_environment_invalidate_the_affected_cell() {
        let base = spec(MeasurementKind::Latency);
        let (a, b) = two_runs(&base);
        let store = stored(&[&a, &b]);
        let cases: [(&str, Spec, &str); 5] = [
            (
                "bytes",
                Spec {
                    bytes: 101,
                    ..base.clone()
                },
                "baseline.bytes",
            ),
            (
                "input digest",
                Spec {
                    input: 8,
                    ..base.clone()
                },
                "baseline.input_digest",
            ),
            (
                "options",
                Spec {
                    invocation: 6,
                    ..base.clone()
                },
                "baseline.subject.invocation_digest",
            ),
            (
                "scanner build",
                Spec {
                    base_exe: 4,
                    ..base.clone()
                },
                "baseline.subject.executable_sha256",
            ),
            (
                "host class",
                Spec {
                    cpu: Some("Other CPU"),
                    ..base.clone()
                },
                "baseline.environment.cpu_model",
            ),
        ];
        for (name, changed, path) in cases {
            let p = run_plan(
                MeasurementKind::Latency,
                &request(&changed, &artifact(&changed)),
                &store,
                &PlanOptions::default(),
            );
            assert_eq!(p.cells[0].decision, Decision::MeasureFresh, "{name}");
            assert!(
                p.cells[0].invalidated_by.iter().any(|d| d == path),
                "{name}: {:?}",
                p.cells[0].invalidated_by
            );
        }
        // A changed schedule and a changed protocol are changes too.
        let mut sched = artifact(&base);
        sched.manifest.schedule.as_mut().unwrap().rounds = 5;
        let p = run_plan(
            MeasurementKind::Latency,
            &request(&base, &sched),
            &store,
            &PlanOptions::default(),
        );
        assert!(
            p.cells[0]
                .invalidated_by
                .iter()
                .any(|d| d == "baseline.schedule.rounds")
        );
    }

    #[test]
    fn instruction_counts_do_not_depend_on_the_host_class() {
        let base = spec(MeasurementKind::Instructions);
        let a = artifact(&base);
        let elsewhere = Spec {
            cpu: Some("Other CPU"),
            ..base.clone()
        };
        let p = run_plan(
            MeasurementKind::Instructions,
            &request(&elsewhere, &artifact(&elsewhere)),
            &stored(&[&a]),
            &PlanOptions::default(),
        );
        assert_eq!(p.cells[0].decision, Decision::ReuseComparison);
        assert_eq!(p.cells[0].fresh_runs_required, 0);
    }

    #[test]
    fn corrupt_incomplete_and_failed_evidence_is_never_promoted() {
        let base = spec(MeasurementKind::Latency);
        let (good_a, good_b) = two_runs(&base);

        // A failed invocation makes the run's cells unusable.
        let failed = artifact(&Spec {
            failed: 1,
            ..base.clone()
        });
        let failed2 = artifact(&Spec {
            failed: 1,
            started: "2026-10-02T00:00:00Z",
            ..base.clone()
        });
        let p = run_plan(
            MeasurementKind::Latency,
            &request(&base, &good_a),
            &stored(&[&failed, &failed2]),
            &PlanOptions::default(),
        );
        assert_eq!(p.cells[0].decision, Decision::MeasureFresh);
        assert_eq!(p.cells[0].reason, Reason::IncompleteEvidence);
        assert!(p.cells[0].historical.is_empty());

        // Truncated samples.
        let mut short = artifact(&base);
        short.latency[0].baseline.samples_ns.pop();
        assert_eq!(
            run_plan(
                MeasurementKind::Latency,
                &request(&base, &good_a),
                &stored(&[&short, &short.clone()]),
                &PlanOptions::default(),
            )
            .cells[0]
                .decision,
            Decision::MeasureFresh
        );

        // An artifact that predates the invocation digest or the roles.
        let mut old = artifact(&base);
        old.manifest.subjects[0].invocation_digest = None;
        let c = cells_of(&old).unwrap();
        assert!(c[0].usable.is_err() && c[1].usable.is_ok());
        assert_eq!(c[0].role, Some(SubjectRole::Baseline));
        old.manifest.subjects[0].role = None;
        assert!(cells_of(&old).is_err());

        // A kind that contradicts the results, and a result without a workload.
        let mut kind = artifact(&base);
        kind.manifest.kind = MeasurementKind::Instructions;
        assert!(cells_of(&kind).is_err());
        let mut orphan = artifact(&base);
        orphan.workloads.clear();
        assert!(cells_of(&orphan).is_err());

        // A single good run beside bad ones is still not a confirmation.
        let p = run_plan(
            MeasurementKind::Latency,
            &request(&base, &good_a),
            &stored(&[&good_a, &failed2]),
            &PlanOptions::default(),
        );
        assert_eq!(p.cells[0].reason, Reason::InsufficientIndependentRuns);
        let _ = good_b;
    }

    #[test]
    fn a_latency_cell_without_a_cpu_model_is_never_matched() {
        let base = Spec {
            cpu: None,
            ..spec(MeasurementKind::Latency)
        };
        let (a, b) = two_runs(&base);
        let p = run_plan(
            MeasurementKind::Latency,
            &request(&base, &a),
            &stored(&[&a, &b]),
            &PlanOptions::default(),
        );
        assert_eq!(p.cells[0].decision, Decision::MeasureFresh);
        assert_eq!(p.cells[0].reason, Reason::IncompleteEvidence);
    }

    #[test]
    fn inexact_instruction_counts_are_not_reused() {
        let base = Spec {
            spread: 3,
            ..spec(MeasurementKind::Instructions)
        };
        let a = artifact(&base);
        let p = run_plan(
            MeasurementKind::Instructions,
            &request(&base, &a),
            &stored(&[&a]),
            &PlanOptions::default(),
        );
        assert_eq!(p.cells[0].decision, Decision::MeasureFresh);
        assert_eq!(p.cells[0].reason, Reason::IncompleteEvidence);
    }

    #[test]
    fn force_fresh_overrides_reuse_for_everything_or_one_subject() {
        let base = spec(MeasurementKind::Instructions);
        let a = artifact(&base);
        let req = request(&base, &a);
        let store = stored(&[&a]);
        let kept = run_plan(
            MeasurementKind::Instructions,
            &req,
            &store,
            &PlanOptions::default(),
        );
        assert_eq!(kept.cells[0].decision, Decision::ReuseComparison);
        for options in [
            PlanOptions {
                force_fresh: true,
                ..Default::default()
            },
            PlanOptions {
                fresh_subjects: BTreeSet::from([id("cand")]),
                ..Default::default()
            },
        ] {
            let p = run_plan(MeasurementKind::Instructions, &req, &store, &options);
            assert_eq!(p.cells[0].reason, Reason::ForcedFresh);
            assert_eq!(p.projected_invocations, 100);
        }
        let other = PlanOptions {
            fresh_subjects: BTreeSet::from([id("unrelated")]),
            ..Default::default()
        };
        assert_eq!(
            run_plan(MeasurementKind::Instructions, &req, &store, &other).cells[0].decision,
            Decision::ReuseComparison
        );
    }

    #[test]
    fn planning_is_deterministic() {
        let base = spec(MeasurementKind::Latency);
        let (a, b) = two_runs(&base);
        let req = request(&base, &a);
        let one = run_plan(
            MeasurementKind::Latency,
            &req,
            &stored(&[&a, &b]),
            &PlanOptions::default(),
        );
        let two = run_plan(
            MeasurementKind::Latency,
            &req,
            &stored(&[&b, &a]),
            &PlanOptions::default(),
        );
        assert_eq!(one, two);
    }

    #[test]
    fn allocation_cells_are_per_build_and_need_a_revision() {
        let mut art = artifact(&spec(MeasurementKind::Instructions));
        art.manifest.kind = MeasurementKind::Allocation;
        art.manifest.schedule = None;
        art.manifest.toolchain = vec![ToolchainEntry {
            name: ComponentId::new("rustc").unwrap(),
            version: ReleaseTag::new("1.90.0").unwrap(),
        }];
        art.instructions.clear();
        for s in &mut art.manifest.subjects {
            s.executable_sha256 = None;
            s.invocation_digest = None;
            s.role = None;
            s.revision = Some(GitRevision::new("a".repeat(40)).unwrap());
        }
        let counts = AllocationCounts {
            alloc_requests: 1,
            realloc_requests: 0,
            requests: 1,
            allocated_bytes: 1,
            realloc_net_bytes: 0,
            finding_count: 0,
            findings_digest: digest(1),
        };
        art.allocation = vec![AllocationResult {
            card: ComponentId::new("card").unwrap(),
            workload: WorkloadId::SparseUnicode,
            baseline: id("base"),
            candidate: id("cand"),
            baseline_counts: counts.clone(),
            candidate_counts: counts,
            request_delta: 0,
            findings_identical: true,
        }];
        art.manifest.subjects[1].revision = Some(GitRevision::new("b".repeat(40)).unwrap());
        let cells = cells_of(&art).unwrap();
        assert_eq!(cells.len(), 2);
        assert!(cells.iter().all(|c| c.usable.is_ok() && c.role.is_none()));
        // The same build on the same workload is one identity, whichever card.
        assert_ne!(cells[0].digest, cells[1].digest);
        art.manifest.subjects[0].revision = None;
        assert!(cells_of(&art).unwrap()[0].usable.is_err());
    }
}
