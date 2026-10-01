# Redact Secret cutover plan

This is the handoff plan for `redact-secret/redact-secret-benchmarks` to stop
running its own measurement engine and consume `credential-eval` run
artifacts instead. It is a plan, not a change to that repository: nothing
here opens issues or pull requests elsewhere, and the maintainers of
`redact-secret-benchmarks` decide when each step happens.

Legacy references are `file:line` at the pinned oracle commit
`c403475476647bc98cc5864bccd7265eddebeb91`, as in [legacy-map.md](legacy-map.md).
The boundary this plan implements is [../qualification-boundary.md](../qualification-boundary.md).

## 1. Removal rule (from epic #1)

Legacy engine code in `redact-secret-benchmarks` is **not removed** until all
four conditions hold:

| Condition | Delivered by | State at the time of writing |
|---|---|---|
| An explicit input/output contract exists | #2, #13 | done: v1 schemas in `schemas/`, frozen by [ADR 0001](../decisions/0001-freeze-v1-contracts.md) |
| Current scanners run through the extracted engine | #4 (adapters), #7 (CLI) | in progress |
| Result parity is demonstrated on a pinned corpus and toolchain | #5 | done for both pipelines: [../parity/parity-report.md](../parity/parity-report.md) |
| Redact Secret qualification consumes generated artifacts without importing engine internals | #6 (this plan and the boundary document), then the product-side switch | boundary and reference consumer done; product switch not started |

Until then the TypeScript engine stays the behavioral oracle and remains the
source of every published number. Parity differences are explained, never
"fixed" by changing an expected result (`AGENTS.md`).

## 2. Target shape

```text
credential-evidence snapshot (or the legacy corpus exported to CorpusSnapshot v1)
        │
        ▼
credential-eval run  ──▶  RunArtifact v1 (canonical, schema-validated)
        │                        │
        │                        ├──▶ compatibility writer (in credential-eval, isolated)
        │                        │        └─▶ legacy result files for the site and baselines
        │                        │
        │                        └──▶ Redact Secret qualification (stays in redact-secret-benchmarks)
        │                                 classify → support-status.json → matrix → drift → release workflow
        ▼
ObservationSet v1 (peer snapshots, replays)
```

The Redact Secret package is one scanner behind the `redact-secret` adapter
(#4). A candidate build is the same adapter with a different configuration
(candidate artifact digests), so it gets a different `configuration_hash`,
`version` and `mode`, and the adapter reports it as a `candidate` build, so
the artifact is `internal`. Peers stay pinned exactly as today (`gitleaks 8.30.1`,
`trufflehog 3.97.4`; `qualification/suite-v1.json:12-16`), now as `pin`
entries in the run configuration of an `official` run, which refuses any
other version or executable digest ([../official-runs.md](../official-runs.md)).

## 3. Entry points

"Engine part" is what moves to credential-eval. "Stays" is what remains in
`redact-secret-benchmarks`.

| Legacy entry point | Engine part → credential-eval | Stays in redact-secret-benchmarks | Compatibility output needed |
|---|---|---|---|
| `npm run bench` → `benchmarks/run.ts` (`package.json:19`; CI `validate.yml:130,191`, `publish-site.yml:199,213`) | corpus loading, scanner execution, replays, scoring, v1.0/v1.1 accounting, `accountingDelta` (`run.ts:124-187`) | candidate flag handling (`run.ts:35-75`), `reviewStatus`/`milestoneReview` stamping (`:197-200`), pinned-peer enforcement for claims | yes: `public/results/<category>.json` (schemaVersion 5), `summary.json`, `run.json` (legacy-map §4.1-4.2) |
| `npm run eval` → `benchmarks/evaluate.ts` (`package.json:20`; `validate.yml:60`, `publish-site.yml:241`) | case construction, methods, operators, assertions, differential, resolution, review occurrences | nothing engine-side | yes: `results-output/evaluation.json` (schemaVersion 3) and its public projection (legacy-map §4.3) |
| `npm run eval:classify` → `benchmarks/classify-support.ts` (`validate.yml:187`, `publish-site.yml:297-303`) | the in-process `runEvaluation` call (`classify-support.ts:116-125`) becomes "read a RunArtifact" | all classification: `support/status.ts`, `status-criteria.json`, `support/evidence.ts`, profiles, policy-qualified, empirical, taxonomy | no; it reads the canonical artifact, including the P1-P3 fields (boundary §5) |
| `npm run eval:matrix`, `eval:publish:matrix`, `eval:matrix:drift` | none | everything; inputs are `support-status.json` and saved matrices | no; provenance fields switch to artifact identities (boundary §3.2) |
| `npm run eval:candidate` → `benchmarks/candidate.ts` (`publish-site.yml:274`) | scanning and scoring of the candidate (`candidate.ts:120-133`) | tarball provenance (`scripts/qualified-candidate.mjs`), baseline comparison, candidate evidence record | a rendering of per-case outcomes in the legacy `encodeOutcome` form (`lib/lattice.ts:185-190`) to compare with `baselines/*.json` |
| `npm run eval:qualify` → `benchmarks/qualify.ts` (`publish-site.yml:244`) | development-method execution (`qualify.ts:43-44`) | milestone gate, holdout lifecycle, completeness verdict (`:26-31, :45-68`) | no |
| `npm run queue:check`, `ledger:decisions:check`, `ledger:provenance:check` (`validate.yml:82-84,189`) | emitting review occurrences with stable ids | the ledger, its ADR map and every decision | the legacy `reviewEntryId` (`review.ts:4-10`) until the ledger is re-keyed (see §5) |
| `npm run promotion:check`, `pins:check`, `scorer-promotion:check` (`validate.yml:92,170`) | none | everything | no |
| `scripts/baseline.mjs` (`npm run baseline`) | none | everything | reads the compatibility `bench` outputs until baselines are re-based on artifacts |
| holdout, blind, MCP, PII, performance, release records | none | everything (legacy-map §3: #6 or out) | no |

## 4. Compatibility writer

Required so the site, saved baselines and legacy checks keep working while the
engine switches underneath them. It lives in credential-eval (the legacy
schemas are an output format of this engine), in one clearly named, removable
module; the canonical model is never reshaped around it (`ARCHITECTURE.md`,
Compatibility). It is written by #5 alongside parity, because parity compares
through it: `crates/credential-eval-compat` (`bench`: artifact → per-category
files and `summary.json`, via `credential-eval compat legacy-bench`; `eval`:
report → the semantic subset of `evaluation.json`, via `run --legacy-eval-out`)
plus the legacy exporter `tools/legacy-export/export.mts`. Its duties, all
taken from [legacy-map.md](legacy-map.md):

- **Failure-state folding.** The contract distinguishes `timeout`,
  `malformed` and `error`; legacy has only `error` (legacy-map §2.10,
  §4.5, §6 hazard 7; `scanners/index.mjs:54-58`). The writer folds
  `timeout` and `malformed` into `error` with the fixed sanitized message.
  `unstable`, `unsupported` and `unavailable` map one to one. The canonical
  artifact is never folded.
- **Reference scanner naming.** `reference-only` becomes `redact-secret-only`
  when the reference scanner is `redact-secret` (§2.11, hazard 1).
- **Row shape.** Split `<category>--<id>` case ids back into per-category
  files and rows; re-add `group` from the snapshot's grouping; drop
  `coDetected: false` (§2.5); re-add the constant `comparable: false` in
  diagnostics (§4.5); map `Withheld::InsufficientCoverage` to
  `'insufficient-coverage'`; T0 rows carry no score fields; failed scanners
  carry no rows (§4.1).
- **Per-category aggregates.** `bench` publishes groups per category; the
  writer needs aggregates over a `grouping.group` subset (§4.5) and the
  cross-suite `selectionGroups` for `summary.json` (§4.2).
- **v1.0 figures.** `accountingDelta` (§2.8) if the canonical artifact does
  not carry v1.0 figures.
- **Legacy digests.** Raw-file `corpusHash`, insertion-order variant
  provenance hashes and `reviewEntryId` are reproduced with the legacy
  algorithms inside the writer only (§2.12); canonical digests stay canonical.
- **Volatile fields.** `runId`, timestamps, `durationMs` (rounded to 0.01 in
  `bench`) come from `non_semantic`; they are excluded from parity (§4.1).
- **Family allowlist.** `eval` keeps a family only if it is a key of the
  product `contracts` table (§2.3/§6 hazard 6). The writer, not the kernel,
  applies that product allowlist when it renders `eval` output; the list is a
  product input to the writer.

The writer is deleted when nothing reads the legacy schemas any more.

## 5. Sequence

1. **Now (#2, #6).** Contracts, boundary, reference consumer. Legacy
   unchanged.
2. **Engine and adapters (#3, #4, #7).** The kernel fills aggregates,
   assertions, variants and comparisons; adapters run all five scanners with
   the pinned versions. The additive contract proposals P1-P3 from the
   boundary document landed here (#3), and v1 was then frozen (#13).
3. **Shadow dual-run (#5).** Export the pinned legacy corpus to a
   `CorpusSnapshot` (record the legacy commit and corpus digest), run both
   engines on the same peer observations (legacy peer snapshots become
   `ObservationSet` replays bound to the corpus digest) and on live
   scanners, and compare through the compatibility writer. Known parity
   risks: path prefixing across categories (§4.5), TruffleHog 3.97.6 re-keying
   results, the `bench`/`eval` replay-equality difference (hazard 5), and the
   family allowlist (hazard 6). Every difference is explained in
   `docs/parity/`.
4. **Shadow consumption.** `eval:classify` gains a mode that reads a
   RunArtifact instead of calling `runEvaluation`, and CI diffs the resulting
   `support-status.json` against the in-process one on the same pinned
   inputs. Distribution, reasons and per-family evidence must match. The
   review ledger join is checked here: if the canonical occurrence id differs
   from `reviewEntryId`, the ledger is re-keyed once with a reviewed mapping
   (the legacy repository already has `scripts/rekey-review-ledger.ts` for
   this kind of move), never by silently dropping decisions.
5. **Switch.** `bench` and `eval` invoke the pinned credential-eval CLI (by
   version and checksum) and the compatibility writer; `eval:classify`,
   `eval:candidate` and `eval:qualify` read artifacts. The legacy engine stays
   in the tree as a fallback for one release while outputs are compared.
6. **Removal.** Only when §1 holds in full: delete the modules classified
   **#3** and **#4** in legacy-map §3 from `redact-secret-benchmarks`, and the
   compatibility writer from credential-eval when its last reader is gone.
   Everything classified **#6** stays with the product.

## 6. Identity the product must record

Every product record derived from a run replaces its legacy engine provenance
(`revision`, `dirty`, `runtime`, `scannerObservations`, `fixtureIndex`) with
the artifact identities: `schema`, `manifest.engine`,
`manifest.protocol_version`, `manifest.evidence` (including
`corpus_digest`), `manifest.config_hash` and `manifest.scanners[]`, plus the
digest of the artifact bytes it read. A record that compares two runs
refuses different `protocol_version` or `corpus_digest` values unless its own
policy says otherwise (boundary §4).
