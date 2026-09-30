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
versions are separate and change independently. The v1 schemas are not
frozen yet: issues #3 to #5 may still add fields. Freezing them is an
explicit, reviewed step.

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
- `methods[]`: the evaluation methods to apply.
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

- `scanner`: `{id, version, mode, adapter, configuration_hash}`.
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
| `manifest` | The reproduction identities: `engine {name, version}`, `protocol_version`, `evidence` (snapshot identity including the corpus digest), `config_hash`, `accounting`, `methods[]`, and `scanners[]` (identity, version, mode, adapter and configuration hash for each scanner, including failed ones). |
| `scanners[]` | One entry per scanner. Each has `status`, a sanitized `detail`, `replays`, deduplicated `findings[]`, `cases[]` (one `CaseResult` per corpus case), `assertions[]` (method assertions) and `aggregates`. |
| `variants[]` | Lineage of generated variants: method, operator, parameters, strategy, relation, content digest. |
| `comparisons[]` | Differential observations between a reference scanner and each peer. |
| `non_semantic` | `run_id`, timestamps, host and durations. It is excluded from the semantic digest. |

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

### What a consumer needs

A consumer needs the artifact and `schemas/run-artifact-v1.schema.json`. It
does not need fixture bytes, the kernel or product code. The test
`crates/credential-eval-kernel/tests/contracts_smoke.rs` shows this: it
validates the committed smoke artifact with only the schema, then interprets
it from plain JSON.

### Implementation status

In issue #2 the kernel fills `cases[]` using the exact legacy lattice port.
`aggregates`, `assertions`, `variants` and `comparisons` are left empty, and
issue #3 fills them under the shapes defined here.
