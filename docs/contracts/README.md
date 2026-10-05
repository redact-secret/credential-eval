# Evaluation contracts (v1)

This directory documents the boundary between evidence, scanners and the
evaluator. The Rust types in `crates/credential-eval-contracts` are normative.
The JSON Schemas in `schemas/` are generated from those types, and a test
fails when the committed schemas drift from them. This prose explains the
types and does not override them.

| Document | Type | Schema | Direction |
|---|---|---|---|
| Corpus snapshot | `corpus::CorpusSnapshot` | `schemas/corpus-snapshot-v1.schema.json` | input (from `credential-evidence`) |
| Run configuration | `config::RunConfig` | `schemas/run-config-v1.schema.json` | input |
| Observation set | `observation::ObservationSet` | `schemas/observation-set-v1.schema.json` | adapter → kernel |
| Run artifact | `artifact::RunArtifact` | `schemas/run-artifact-v1.schema.json` | output |
| Performance configuration | `performance::PerformanceConfig` | `schemas/performance-config-v1.schema.json` | input (latency mode) |
| Performance artifact | `performance::PerformanceArtifact` | `schemas/performance-artifact-v1.schema.json` | output ([../performance-measurement.md](../performance-measurement.md)) |
| Direction confirmation | `performance::DirectionConfirmation` | `schemas/direction-confirmation-v1.schema.json` | output (`perf confirm`) |

Each document has a top-level `schema` tag, such as
`credential-eval/run-artifact/v1`, and a reader rejects any other tag. The
schema versions, the measurement protocol version
(`PROTOCOL_VERSION = "credential-eval-protocol/1"`) and the crate/engine
versions are separate and change independently.

**The v1 schemas are frozen** ([ADR 0001](../decisions/0001-freeze-v1-contracts.md)).
v1 never changes incompatibly: every document valid under a v1 schema stays
valid, with the same meaning, under every later v1 schema. New optional
fields are minor revisions, listed under [Revisions](#revisions). A breaking
change is v2, with new schema tags and files. The frozen baselines are in
`crates/credential-eval-contracts/tests/frozen-v1/`, and
`tests/frozen_v1.rs` fails on an incompatible edit.

The two performance documents are a separate kind of measurement, added by
[ADR 0002](../decisions/0002-performance-measurement-kinds.md). They are not
part of the four documents ADR 0001 froze, no existing schema changed, and they
are frozen the same way from their first revision.

Related documents:

- [ranges.md](ranges.md): the one range convention.
- [identity.md](identity.md): ids, digests and reproduction identities.
- [outcomes.md](outcomes.md): the outcome lattice, per-case measurements and failure states.
- [determinism.md](determinism.md): ordering and the semantic digest.
- [representation.md](representation.md): the representation contract (v1.3): facts about encoded, transformed and fragmented inputs, how a decoded finding is placed on the original bytes, and what the artifact reports.

## Input contract

### `CorpusSnapshot`

| Field | Meaning |
|---|---|
| `identity.source` | The evidence source, e.g. `credential-evidence` (or `legacy:redact-secret-benchmarks` during migration). |
| `identity.revision` | The immutable revision (commit or tag) of the source. |
| `identity.evidence_schema` | The format label of the source evidence. |
| `identity.corpus_digest` | `sha256:` digest of the cases ([identity.md](identity.md)). |
| `identity.representation` | v1.3, optional. The string `credential-eval/representation/1`; required when any case carries a representation fact ([representation.md](representation.md)). |
| `identity.release` | v1.1, optional. The verified evidence release `{tag, manifest_digest}`. Only the evaluator writes it, after verifying the snapshot file against the release manifest; a snapshot input that declares it is rejected ([../official-runs.md](../official-runs.md)). |
| `cases[]` | The evaluation cases. Their order carries no meaning. |

Each `Case` has these fields:

- `id`: a lowercase slug, unique in the snapshot.
- `path`: a safe relative path, unique in the snapshot. The fixture is materialized at this path.
- `content`: the exact fixture text. Ranges index its UTF-8 bytes.
- `expected[]`: the authored spans, sorted and disjoint. Each span has
  `start`, `end`, `role` (`secret` | `companion`) and an optional
  `envelope {start, end, reason}`. Controls have an empty list.
- `grouping`: metadata used only for grouping. It holds `kind`
  (`must-redact` | `must-not-flag` | `policy`), `tier` (`T0` to `T3`, where
  `T0` means pending and is never scored), `group`, and the optional
  `family`, `evidence_class`, `targets[]` and `taxonomy`. Grouping never
  changes an outcome. A twin's `family` scopes its false-alarm reading.
- `twin`: optional lineage of an authored negative twin, `{twin_of, mutation, mutation_kind}`.
- `representation` (v1.3, optional): facts about the input as a whole,
  `{input_validity?, derivation?, transformation?, chunking?}`. Each `expected[]`
  span of role `secret` may also carry `base`, `fragments` and `decoded`. See
  [representation.md](representation.md).

`CorpusSnapshot::validate` enforces the legacy corpus rules: unique ids and
safe unique paths, and valid UTF-8 ranges, sorted and disjoint. An envelope
must contain its span, give a non-blank reason and not overlap another span.
A twin must point at a positive, must carry no secret itself, and must have a
non-blank mutation. Finally the declared digest must equal the recomputed one.

The snapshot carries no product support status, release decision or
scanner-specific expectation. Unknown fields are rejected.

### `RunConfig`

Scanner execution inputs:

- `scanners[]`: each entry has `{id, adapter {id, version}, mode,
  configuration, network, limits}`.
  - `network` is `disabled` unless the run explicitly allows network access.
  - `limits` are explicit: `timeout_ms`, `max_stdout_bytes`,
    `max_stderr_bytes` and `concurrency`. Nothing is unbounded by default.
  - `pin` (v1.1, optional): `{version, sha256?}`, the version and executable
    digest an official run requires; enforced before any scan
    ([../official-runs.md](../official-runs.md)).
- `methods[]`: the evaluation methods to apply (sorted, unique). Empty for a
  plain corpus measurement.
- `evaluation`: present exactly when `methods` is non-empty.
  `{reference?, seed, evidence_digest, family_allowlist}`: the differential
  reference scanner, the seed naming convention (`case-id`, or
  `legacy-category` for migration parity runs), the canonical digest of the
  evaluation evidence file (family contracts, validator names, benign
  taxonomy vocabulary; `credential-eval/evaluation-evidence/v1`) and whether
  finding families are restricted to that contract table before evaluation.
  Each of them can change a result, so all are hashed.
- `execution.jobs`: the global concurrency bound.
- `accounting`: the engine v1.1 accounting parameters (`min_denominator`,
  the floors, `replays`, `interval_z`, `interval_precision`). The floors
  withhold figures. They are measurement rules, not support thresholds.

The canonical digest of the typed config is the run's `config_hash`.

### `ObservationSet`

This is what adapters produce, or what a replayed snapshot supplies. It is
bound to a `corpus_digest`, and scoring rejects observations recorded against
a different corpus.

Each `ScannerObservation` has:

- `scanner`: `{id, version, mode, adapter, configuration_hash, provenance?}`.
  `provenance` records the network posture and the digests and versions of
  what ran (see [../adapters.md](../adapters.md#provenance)).
- `result`: tagged by `status`. The statuses are `complete` (findings plus
  replay record), `unstable` (replays disagreed; findings discarded),
  `unsupported`, `unavailable`, `timeout`, `malformed` and `error`.
- `duration_ms`: optional and non-semantic.

A `NormalizedFinding` is `{path, start, end, family?, action?, mapping?}`.
`mapping` (v1.3) is present when an adapter placed a finding the scanner
reported in decoded coordinates on the original bytes; the range is then a bound
([representation.md](representation.md#mapping-a-decoded-finding-to-the-original-bytes)).
It never contains the matched value. Reasons are fixed, sanitized strings and never
raw scanner output.

## Output contract: `RunArtifact`

| Field | Meaning |
|---|---|
| `manifest` | The reproduction identities: `engine {name, version}`, `protocol_version`, `evidence` (snapshot identity including the corpus digest, and the verified `release` when one was pinned), `config_hash`, `accounting`, `methods[]`, and `scanners[]` (identity, version, mode, adapter, configuration hash and `build` for each scanner, including failed ones). Since v1.1 also `run_class` and the derived `publication` ([../official-runs.md](../official-runs.md)); only `public` artifacts may be consumed outside product qualification. |
| `scanners[]` | One entry per scanner. Each has `status`, a sanitized `detail`, `replays`, deduplicated `findings[]`, `cases[]` (one `CaseResult` per corpus case), `assertions[]` (method assertions) and `aggregates`. |
| `variants[]` | Lineage of generated variants: method, operator, parameters, strategy, relation, content digest. |
| `comparisons[]` | Differential observations between a reference scanner and each peer. |
| `non_semantic` | `run_id`, timestamps, host, durations and execution diagnostics (jobs, wall, scanner-process and evaluator time). It is excluded from the semantic digest. |

A `CaseResult` embeds `expected` (spans and envelopes, without reasons) and
`actual` (the finding ranges on that path). A consumer can therefore
recompute each `measurement` without fixture bytes. The `measurement` field
is tagged by `type` and takes one of these values:

- `positive`: `{span_outcomes[], leaked_bytes, collateral_bytes}`
- `control`: `{flagged, findings, co_detected, action_counts?}`
- `pending`: the case is `T0`.
- `not-measured`: `{status}`, when the scanner did not complete. This is never `MISS`.

`aggregates.groups` is keyed `<kind>/<tier>`, and all `T0` cases fall under
`pending/T0`. Each group has a `population` tag:

- `pending`
- `control`: false-alarm rate, mean findings per flagged file, diagnostics.
- `positive`: outcome counts, measurable share, envelope width, leaked-span,
  leaked-byte and collateral figures, and twin discrimination.

A published figure is `null` when the denominator is zero. Otherwise it is a
rate `{point, bound, n, direction}`, or the withheld value
`"insufficient-evidence"` or `"insufficient-coverage"`. No figure is summed
across groups, and no score ranks scanners.

`aggregates.resolution` holds the counts that resolve assertions per method
stratum.

**Evaluation-method runs.** When `manifest.methods` is non-empty, the scanned
corpus is the variant corpus the kernel generated from the snapshot (every
variant is materialized at `cases/<case>/<variant>.txt`), while
`manifest.evidence` still names the base snapshot. `scanners[].cases` then
holds one `CaseResult` per generated variant, read with the method
observation rule (an authored `must-flip` variant is scoped to its family),
`scanners[].findings` are the findings on the variant corpus (after the
family allowlist when `evaluation.family_allowlist` is set), and
`aggregates.groups`/`by_target` are empty: variants repeat their seeds, so
per-group v1.1 figures are published only by plain corpus runs. Method runs
fill `assertions`, `aggregates.resolution*`, `variants`, `comparisons` and
`review_queue`.

### What a consumer needs

A consumer needs the artifact and `schemas/run-artifact-v1.schema.json`. It
does not need fixture bytes, the kernel or product code. One artifact covers
one corpus; a consumer that combines artifacts of several corpora follows
[../multi-corpus-qualification.md](../multi-corpus-qualification.md). The test
`crates/credential-eval-kernel/tests/contracts_smoke.rs` shows this: it
validates the committed smoke artifact with only the schema, then interprets
it from plain JSON.

`aggregates.by_target` holds, for every target family, the `<kind>/<tier>`
groups of the cases that target it. They are accounted over the corpus
groups that hold those cases, and a selected positive's twin and the
selection's `T0` cases travel with the group (legacy `selectionGroups`).
`aggregates.resolution_by_target` is the per-target assertion resolution,
keyed like `resolution`.

Each `CaseResult` also carries the grouping it was measured under: `group`,
`targets` (omitted when empty), `taxonomy`, `evidence_class` and
`twin_mutation_kind`. A consumer can select cases by target without loading
the snapshot.

`review_queue[]` lists occurrences that need an authored decision: differential
disagreements (`reference`, `peer`, `disagreement`) and generated variants
whose expectation could not be derived. Each has a stable canonical `id` that
excludes every part of the reference scanner's identity except its id, so a
new reference release does not re-key reviewed entries. An occurrence is
never a verdict on either scanner.

### Implementation status

Issue #3 fills every section: `cases[]` and `aggregates` (`build_artifact`),
and, for evaluation methods, `assertions`, `aggregates.resolution*`,
`variants`, `comparisons` and `review_queue`
(`evaluation::EvaluationReport::artifact_parts`). Intentional differences from
the legacy engine are listed in
[../migration/kernel-deltas.md](../migration/kernel-deltas.md).

## Revisions

| Revision | Change | Issue |
|---|---|---|
| v1.0 | Frozen baseline: the four schemas in `crates/credential-eval-contracts/tests/frozen-v1/`, including P1 (`CaseResult` grouping fields), P2 (`review_queue`) and P3 (`aggregates.by_target`, `aggregates.resolution_by_target`). | #2, #3, #13 |
| v1.1 | Official-run inputs ([../official-runs.md](../official-runs.md)), all optional: `SnapshotIdentity.release {tag, manifest_digest}` (the verified evidence release, written only by the evaluator), `ScannerSpec.pin {version, sha256?}`, `ScannerIdentity.build` (`released` \| `candidate`), `RunManifest.run_class` (`official` \| `exploratory`) and `RunManifest.publication` (`public` \| `internal`). Absent `run_class`/`publication` read as `exploratory`/`internal`; absent `build` is never `released`. | #14 |

| v1.2 | Per-case unmeasured handling ([ADR 0003](../decisions/0003-unmappable-findings-leave-the-case-unmeasured.md)), all optional: `ObservationResult.complete.unmeasured[] {path, reason}` and `ScannerRun.unmeasured_cases[] {case_id, reason}`. Absent reads as every case measured. Written only when a scanner's configuration chose `unmappable_findings: unmeasured-case` (Gitleaks, and TruffleHog since [ADR 0004](../decisions/0004-per-case-unmeasured-handling-in-methods-and-trufflehog.md)); in a methods run the unmeasured cases are variants, which carry no assertion or comparison. | credential-evidence#150, redact-secret-benchmarks#680 |
| v1.3 | Representation contract ([ADR 0005](../decisions/0005-representation-contract.md), [representation.md](representation.md)), all optional: `SnapshotIdentity.representation`, `Case.representation` (`input_validity`, `derivation`, `transformation`, `chunking`), `ExpectedSpan.{base, fragments, decoded}`, `NormalizedFinding.mapping` and `ObservedRange.mapping` (`{bound, layers, codecs}`), and `RunManifest.representation` (what the snapshot carried: a facts digest and counts). Absent reads as an ordinary raw input: every earlier document keeps its meaning, corpus digest and semantic digest. A snapshot that carries a fact declares `identity.representation`; `credential-eval capabilities` prints the revision. Adapters place decoded findings only under the opt-in scanner configuration key `decoded_mapping: "source-segment"` (Gitleaks, TruffleHog). | #34, credential-evidence#150 |
| v1.4 | Registry pin of npm scanners ([ADR 0006](../decisions/0006-pin-the-product-build-by-registry-integrity.md)), all optional: `ScannerSpec.pin.integrity` (`sha512-` Subresource Integrity) and `ScannerSpec.pin.resolved` (registry tarball URL). An official run refuses an npm scanner whose lockfile entry, npm's install record or provenance disagrees with them. Absent reads as the v1.1 pin (version only). No artifact field is added: version, `integrity`, the package tree digest and the lockfile digest were already in `scanners[].provenance`. | redact-secret-benchmarks#697 |
| v1.5 | Operational telemetry ([ADR 0007](../decisions/0007-per-scanner-timings-and-bounded-progress.md)), all optional and inside `non_semantic.execution`: `phases` (`cases`, `fixtures`, `materialize_ms`, `generate_ms`, `prepare_ms`, `scan_ms`, `evaluate_ms`) and `scanners` (per scanner id: `prepare_ms`, `queue_ms`, `start_ms`, `end_ms`, `process_ms`, `normalize_ms`, `tasks`, `fixtures`, `received_bytes`, `findings`, `completion`, `failed_phase`). Never part of the semantic digest. No semantic field, config field or scoring rule changes; a v1.4 reader that rejects unknown `non_semantic.execution` fields must update to read a v1.5 artifact. | #39 |
| v1.6 | Accuracy observation reuse ([ADR 0008](../decisions/0008-accuracy-observation-reuse.md)), all optional: `ObservationSet.measurement {input_digest, protocol_version, restriction}` and, inside `non_semantic.execution`, `reuse {source_digest, input_digest}` and per-scanner `origin` (`fresh`\|`reused`) with `origin_reason`. Never part of the semantic digest; no scoring rule changes. A set without `measurement` is scored as before but never reused. | #40 |
| v1.7 | Safe native scanner labels ([ADR 0011](../decisions/0011-native-scanner-labels.md)), optional: `NormalizedFinding.native_labels` and `ObservedRange.native_labels` (`NativeLabel[]`, sorted, unique, at most 8; a label is `[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}` or the single marker `~unrecognized`). Kept apart from the derived `family`. Absent or empty reads as "native label unavailable"; nothing is reconstructed for older observations. Several findings on one range still merge into one finding, carrying the union. Written only by an adapter with a reviewed label set (`openredaction`, adapter version 2). No scoring rule or outcome changes. | #48 |
| (new documents) | `PerformanceConfig` and `PerformanceArtifact`, frozen at their first revision ([ADR 0002](../decisions/0002-performance-measurement-kinds.md)). Not a revision of the four documents above. | #23 |
| (new document) | `DirectionConfirmation`, frozen at its first revision. | #25 |
| (revision of `PerformanceArtifact`) | Optional `HostDiagnostics.cpu_model` (sanitized CPU model name). | #25 |
| (revision of `PerformanceArtifact`) | `MeasurementKind::Instructions` and optional `instructions[]` (`InstructionResult`, `InstructionArm`): exact instruction counts under callgrind. | #26 |
| (revision of `PerformanceArtifact`) | Optional `SubjectIdentity.invocation_digest` and `SubjectIdentity.role` (`baseline`\|`candidate`), so a subject's measurement can be matched without the pair's whole config ([ADR 0010](../decisions/0010-performance-reuse-identity.md)). No result field or rule changes. | #42 |

A reader validates with the schema of the engine version that wrote the
document, or with any later v1 schema. Every struct sets
`additionalProperties: false`, so an older schema rejects a newer optional
field (ADR 0001, "Reader guidance").

## No plaintext or raw output

No v1 document has a field for a matched value or for raw scanner output.
`crates/credential-eval-contracts/tests/schema_guarantees.rs` enforces this
on the schemas. It walks every property of the four schemas and fails on:

- a property whose name contains a token such as `value`, `match`, `secret`,
  `raw`, `stdout`, `stderr`, `line`, `text`, `content`, `output` or `token`;
- a property that admits a free-form string or free-form JSON (no `pattern`,
  `enum`, `const` or `$ref` to a constrained id type).

The one exception is a property listed, per schema file, in the test's
`ALLOWLIST` with the reason it cannot carry either. A new property in either
category fails until it is reviewed and listed. The allowlisted properties
fall into five groups:

| Source | Properties | Why they are safe |
|---|---|---|
| Evidence input (corpus snapshot only) | `TransformStep.line_break` (an enum of line-break kinds; a name hit on `line`), `Case.content`, `Envelope.reason`, `TwinLineage.mutation`, `TwinLineage.mutation_kind`, `Grouping.{group, family, targets, taxonomy, evidence_class}`, `SnapshotIdentity.{source, revision, evidence_schema}` | Synthetic or documented public-test evidence owned by `credential-evidence`. Fixture text (`content`) and authored reasons never reach observations or artifacts; a test checks that no `content` property exists outside the input schemas. |
| Evidence labels copied into the artifact | `CaseResult.{group, family, targets, taxonomy, evidence_class, twin_mutation_kind}` (P1) | Copies of the grouping labels above. |
| Run configuration | `ScannerSpec.{configuration, mode}`, `ScannerIdentity.mode`, `AdapterIdentity.version`, `ScannerLimits.{max_stdout_bytes, max_stderr_bytes}` | Operator input. A configuration must not contain credentials, and only its digest reaches observations and artifacts. The two limits are byte counts. |
| Engine and adapter code | `EngineIdentity.{name, version}`, `RunManifest.protocol_version`, `MeasurementBinding.protocol_version`, `ScannerTiming.origin_reason`, `ObservationResult.reason`, `UnmeasuredPath.reason`, `UnmeasuredCase.reason`, `ScannerRun.detail`, `Assertion.reason`, `VariantRecord.{property, parameters}`, `ScannerProvenance.network_controls`, `ProvenanceComponent.{name, version, integrity}`, `ScannerIdentity.version`, `NonSemantic.{run_id, started_at, finished_at, host}`, `GroupAggregate.secret_bytes`, `VariantRecord.content_digest` | Fixed sanitized strings, identifiers, versions, timestamps, digests and counts. Operator parameters keep boolean and number values only. A scanner version is the first semantic-version match of the version probe, never the probe output. |
| Performance run configuration and artifact | `PerfSubject.{program, args}` (config), `PerformanceManifest.performance_protocol`, `PerformanceNonSemantic.{started_at, finished_at}`, `HostDiagnostics.cpu_model`, and `EngineIdentity.{name, version}` in the performance artifact | Operator input (an executable path and its arguments, hashed and never an output), an engine constant, and timestamps. A performance artifact holds counts, sizes, timings, digests and identities only: no workload text, no matched value, no scanner output. |
| Scanner-reported labels on findings | `NormalizedFinding.{family, action}`, `ObservedRange.{family, action}` | `family` comes only from an adapter's fixed mapping tables. `action` is the disposition label a scanner reports (`redact`, `warn`, `block`), passed through by the adapter. |

Residual risk: `action` is the one value a scanner, rather than this
repository, chooses. The schema bounds its position (a label on a range), but
not its text. An adapter for a scanner whose action labels are not a fixed
vocabulary must map them to one, or drop them.
