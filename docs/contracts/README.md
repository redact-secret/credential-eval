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

Related documents:

- [ranges.md](ranges.md): the one range convention.
- [identity.md](identity.md): ids, digests and reproduction identities.
- [outcomes.md](outcomes.md): the outcome lattice, per-case measurements and failure states.
- [determinism.md](determinism.md): ordering and the semantic digest.

## Input contract

### `CorpusSnapshot`

| Field | Meaning |
|---|---|
| `identity.source` | The evidence source, e.g. `credential-evidence` (or `legacy:redact-secret-benchmarks` during migration). |
| `identity.revision` | The immutable revision (commit or tag) of the source. |
| `identity.evidence_schema` | The format label of the source evidence. |
| `identity.corpus_digest` | `sha256:` digest of the cases ([identity.md](identity.md)). |
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

A `NormalizedFinding` is `{path, start, end, family?, action?}`. It never
contains the matched value. Reasons are fixed, sanitized strings and never
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
| Evidence input (corpus snapshot only) | `Case.content`, `Envelope.reason`, `TwinLineage.mutation`, `TwinLineage.mutation_kind`, `Grouping.{group, family, targets, taxonomy, evidence_class}`, `SnapshotIdentity.{source, revision, evidence_schema}` | Synthetic or documented public-test evidence owned by `credential-evidence`. Fixture text (`content`) and authored reasons never reach observations or artifacts; a test checks that no `content` property exists outside the input schemas. |
| Evidence labels copied into the artifact | `CaseResult.{group, family, targets, taxonomy, evidence_class, twin_mutation_kind}` (P1) | Copies of the grouping labels above. |
| Run configuration | `ScannerSpec.{configuration, mode}`, `ScannerIdentity.mode`, `AdapterIdentity.version`, `ScannerLimits.{max_stdout_bytes, max_stderr_bytes}` | Operator input. A configuration must not contain credentials, and only its digest reaches observations and artifacts. The two limits are byte counts. |
| Engine and adapter code | `EngineIdentity.{name, version}`, `RunManifest.protocol_version`, `ObservationResult.reason`, `ScannerRun.detail`, `Assertion.reason`, `VariantRecord.{property, parameters}`, `ScannerProvenance.network_controls`, `ProvenanceComponent.{name, version, integrity}`, `ScannerIdentity.version`, `NonSemantic.{run_id, started_at, finished_at, host}`, `GroupAggregate.secret_bytes`, `VariantRecord.content_digest` | Fixed sanitized strings, identifiers, versions, timestamps, digests and counts. Operator parameters keep boolean and number values only. A scanner version is the first semantic-version match of the version probe, never the probe output. |
| Scanner-reported labels on findings | `NormalizedFinding.{family, action}`, `ObservedRange.{family, action}` | `family` comes only from an adapter's fixed mapping tables. `action` is the disposition label a scanner reports (`redact`, `warn`, `block`), passed through by the adapter. |

Residual risk: `action` is the one value a scanner, rather than this
repository, chooses. The schema bounds its position (a label on a range), but
not its text. An adapter for a scanner whose action labels are not a fixed
vocabulary must map them to one, or drop them.
