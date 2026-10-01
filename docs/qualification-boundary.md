# Qualification boundary

`credential-eval` measures. Product qualification interprets. This document
states where that line runs, lists every piece of Redact Secret qualification
policy that stays outside this repository, and defines the one interface that
policy may consume: the run artifact.

Legacy references are `file:line` in `redact-secret/redact-secret-benchmarks`
at the pinned oracle commit **`c403475476647bc98cc5864bccd7265eddebeb91`**
(the same pin as [migration/legacy-map.md](migration/legacy-map.md)). Paths
are relative to the legacy repository root unless they start with `crates/`,
`docs/`, `schemas/`, `examples/` or `tests/`.

## 1. The rule

```text
credential-evidence snapshot ──▶ credential-eval ──▶ run artifact A (v1 JSON + schema)
product-owned corpus (each)  ──▶ credential-eval ──▶ run artifact B, C, ... ──┐
                                                          │                    │
             product evidence, thresholds, ledgers ──▶ product qualification ◀─┘──▶ status / matrix / release decision
```

The public `credential-evidence` snapshot is one input to qualification, not
the only one. A product may measure any number of corpora it owns, each in
its own run and artifact, and combine them only in its own policy. That case,
and the consumer contract for it, is
[multi-corpus-qualification.md](multi-corpus-qualification.md).

- The engine runs every scanner, Redact Secret included, through the same
  adapter protocol and the same measurement protocol. It never reads a support
  status, threshold, ledger decision, known-gap record or release pin.
- Product qualification reads **only** the run artifact, validated against
  `schemas/run-artifact-v1.schema.json`, plus its own product-side inputs. It
  never imports a crate, a Rust type or an internal file of this repository.
- A qualification change (a threshold, a route, a ledger decision, a new
  status) is a change to the consumer. It never requires a change to the
  lattice, accounting, normalization or artifact semantics. If it seems to,
  the request is either a protocol revision (reviewed on its own, per
  `ARCHITECTURE.md`) or a product rule that belongs downstream.

Vocabulary follows `CONVENTIONS.md`: *qualification*, *support status*,
*stable/provisional/pending/unsupported*, *release blocker* and *promotion*
are downstream words. Nothing in this repository emits them.

## 2. Ownership

| Concern | Owner | Never in credential-eval because |
|---|---|---|
| Span lattice, per-case measurement, accounting, Wilson bounds, withholding floors | credential-eval (`crates/credential-eval-kernel`) | — (protocol) |
| Accounting parameters (`min_denominator`, floors, `replays`, `interval_z`, `interval_precision`) | credential-eval run config, recorded in `manifest.accounting` | — they withhold figures; they are not support thresholds (legacy-map §2.7) |
| Case facts, expected spans, tiers, twin lineage, taxonomy axes, evidence class | `credential-evidence` (public snapshot) or the product (its own corpora) | evidence, not measurement |
| Which corpora qualify a product, and how their artifacts are combined and counted | Redact Secret qualification | product policy ([multi-corpus-qualification.md](multi-corpus-qualification.md)) |
| Support-status thresholds and routes | Redact Secret qualification | product policy (§3.1) |
| Support matrix and release drift | Redact Secret qualification / release workflow | product publication and release gating (§3.2) |
| Candidate-build acceptance | Redact Secret qualification | product release process (§3.3) |
| Shadow-scorer promotion gates | Redact Secret qualification | private product model policy (§3.4) |
| Known-gap lifecycle and blocker disposition | Redact Secret qualification | product defect governance (§3.5) |
| Review-ledger decisions (`resolved`, `not-assertable`) | Redact Secret qualification (expectation decisions may move to `credential-evidence`) | human decisions, not measurement (§3.6) |
| Engine-qualification completeness, milestones, release records, performance budgets | Redact Secret qualification / release tooling | release governance (§3.7) |

## 3. Policy that stays outside

Each subsection names the legacy code, what it decides, the credential-eval
artifact fields it needs, and whether those fields exist in the v1 artifact
(`crates/credential-eval-contracts/src/artifact.rs`). "Product input" lists
what the policy reads that is not, and will never be, a credential-eval output.

Field paths use `S` for one element of `scanners[]` and `C` for one element
of `S.cases[]`.

### 3.1 Support-status thresholds (stable / provisional / pending / unsupported)

Legacy:

- Entry point `benchmarks/classify-support.ts` (`npm run eval:classify`,
  `package.json:53`). It runs the full evaluation in-process
  (`classify-support.ts:116-125`), then for every scored family builds
  evidence and classifies it (`:137-153`), and writes
  `results-output/support-status.json` with the status distribution
  (`:154-173`).
- Thresholds: `benchmarks/support/status-criteria.json`. `stable` routes and
  floors are at `:3-76` (documented T1 `:4-13`, empirical T2 `:14-39`, zero
  twin failures `:40-43`, benign case/axis/false-alarm floors `:44-57`,
  metamorphic `:58-63`, mutation `:64-69`, differential `:70-75`);
  `provisional` `:77-80`; `pending` (tier T0) `:81-84`; `unsupported`
  `:85-88`.
- Decision logic: `benchmarks/support/status.ts` — `SupportStatus` `:23`,
  `behavioralFailures` `:165-180`, `empiricalRoute` `:200-216`,
  `qualificationFailures` `:221-264`, `classifyFamilySupport` `:272-284`.
- Evidence bridge: `benchmarks/support/evidence.ts` — hard-coded product
  scanner `PRODUCT = 'redact-secret'` `:16`, assertion totals from
  `byDetector` `:19-28`, ledger-settled statuses `:37`, queue counting
  `:39-41`, fixture profile cells `:51-74`, `familyEvidence` `:76-123`.
- Fixture-profile floors: `benchmarks/support/profiles.ts`
  (`measureFixtureCells` `:73-95`, `profileFailures` `:144`) and
  `support/fixture-profiles.json`.
- T3 policy-qualified route: `benchmarks/support/policy-qualified.ts`
  (`POLICY_FAMILIES` `:7`, `policyBehaviorAggregate` `:49-95`), which reads
  product fixture metadata `expectedAction`, `policyConformance` and
  `contextAxis` (`:63-88`).

Credential-eval inputs it needs:

| Legacy evidence field (`evidence.ts`) | Artifact source | v1 status |
|---|---|---|
| `twinPairs`, `twinFailures` (`:80, :105-106`: twin method, `must-flip` assertions, pass/fail) | `S.assertions[]` with `method = "twin"`, `assertion = "must-flip"`, `status`; family attribution through the case's `C.targets`, or `S.aggregates.resolution_by_target` | present (P1, P3) |
| `benignCases`, `benignFalseAlarms` (`:81, :107-108`) | `S.assertions[]` `method = "benign"`; or per case `C.measurement` (`type = control`, `flagged`) with `C.twin_of` absent | present (per-case route works today via `C.family`) |
| `metamorphicCriticalFailures`, `mutationUnresolvedCritical` (`:82-83, :111-114`) | `S.assertions[]` `method ∈ {metamorphic, mutation}`, `status = fail`; plus unresolved review occurrences in `review_queue[]` | present (P2) |
| `differentialUnresolvedContractDisagreements` (`:115`) | review occurrences of the differential method (`review_queue[]` with `method = "differential"`), joined with the ledger on `id` | present (P2) |
| `benignAxes`, `benignAxisIds`, `controlAxes` (`:84, :101, :109-110`: `axesByDetector`) | benign-control taxonomy per case: `C.taxonomy` | present (P1) |
| `positiveCases`, `positiveAxes`, `totalFixtures`, `contextTwinPairs`, `confusionAxes` (`:51-74`) | per case: `C.kind`, `C.twin_of`, `C.group`, `C.targets`, `C.twin_mutation_kind` | present (P1) |
| Per-family selection by `targets` (`byDetector` keys, `:78`; `profiles.ts:75`) | the families a case targets: `C.targets`; per-target accounting in `S.aggregates.by_target` | present (P1, P3); `C.family` alone is the case's own contract |
| T3 span outcomes, collateral, actions (`policy-qualified.ts:63-88`) | `C.actual[]` (`family`, `action`), `C.measurement.span_outcomes`, `collateral_bytes` | present |
| Scanner completeness / identity for the report (`classify-support.ts:169-170`) | `manifest.scanners[]`, `S.status`, `S.replays` | present |
| Unstable / not-measured distinction | `S.status`, `C.measurement.type = "not-measured"` | present |

Product input (never from credential-eval): the family list and contract
table (`scoredContractIds`, `contracts[family].tier/providerSource/
unprobeable/supportedContext`, `classify-support.ts:42, :144`), empirical
observations and corroboration (`support/empirical.ts`,
`support/empirical-observations.json`), the taxonomy
(`support/taxonomy.json`), fixture-profile claims, the T3 policy profile and
its authored expected actions, the policy holdout receipt
(`classify-support.ts:50-53`), disputed properties, and the review ledger.

### 3.2 Support-matrix generation and release drift acceptance

Legacy:

- `benchmarks/generate-support-matrix.ts` (`npm run eval:matrix`) reads
  `support-status.json` (`:18-24`) and projects it onto the taxonomy with
  `buildSupportMatrix` (`:25`; `benchmarks/support/matrix.ts:167-196`, which
  refuses a family without an evidence-derived result, `:186`). Source
  provenance is carried verbatim (`generate-support-matrix.ts:33-43`).
- `benchmarks/support-matrix-drift.ts` (`npm run eval:matrix:drift`) diffs a
  baseline matrix against a candidate matrix (`:45-57`) with
  `buildSupportMatrixDrift` (`benchmarks/support/drift.ts:65`). It reports
  regressions, improvements, unclassified families and stale provider
  provenance (`drift.ts:47-53`) and explicitly decides nothing:
  "nothing here decides whether a regression blocks a release … the product
  release workflow owns that gate" (`support-matrix-drift.ts:14-16`,
  `drift.ts:10-11`).
- Performance drift acceptance is separate:
  `benchmarks/lib/regression-budgets.ts:1-26` sorts changes into
  `within-budget` / `regression` / `accepted-tradeoff` /
  `invalid-measurement`, with accepted tradeoffs recorded in
  `benchmarks/accepted-regressions.json`.

Credential-eval inputs it needs: **none directly.** Both consume
`support-status.json` (§3.1 output) or product performance measurements. The
only credential-eval identities that must survive into the matrix's
`sourceReport` are the reproduction identities: `schema`,
`manifest.engine`, `manifest.protocol_version`, `manifest.evidence`
(including `corpus_digest`), `manifest.config_hash` and
`manifest.scanners[]`. All present. They replace the legacy
`scannerObservations` and `fixtureIndex`/`revision` provenance fields.

Acceptance of drift (whether a regression blocks a release) is not in the
legacy benchmark repository either; it lives in the product release workflow
and stays there.

### 3.3 Redact Secret-only candidate acceptance

Legacy:

- `benchmarks/candidate.ts` (`npm run eval:candidate`): installs candidate
  tarballs (`:120`, via `scanners/candidate.mjs`), compares every row's
  `encodeOutcome` with the newest saved baseline
  (`:96-98`, `:129-133`), and emits a `candidate` evidence record with
  `supportClaims: false` (`:142-163`).
- `scripts/qualified-candidate.mjs:1-27`: resolves and verifies the product's
  qualified binaries before they reach `eval:candidate`.
- The same four candidate flags swap only the `redact-secret` scanner in
  `bench` (`benchmarks/run.ts:35-75`, `:194`, `:249`) and in `eval:classify`
  (`classify-support.ts:62-90`).

What the engine provides: a candidate build is **just another scanner
identity**. The Redact Secret adapter (#4) is configured with the candidate
artifact digests; the digests enter the adapter `configuration` and so
`manifest.scanners[].configuration_hash`, and the scanner's `version` and
`mode` name the build. The measurement kernel does not know the build is a
candidate. Since v1.1 the adapter reports `manifest.scanners[].build =
"candidate"`, which only makes the artifact's publication class `internal`
([official-runs.md](official-runs.md)); it changes no measurement.

Credential-eval inputs it needs:

| Need | Artifact source | v1 status |
|---|---|---|
| Per-case outcome for baseline comparison (legacy `encodeOutcome`, `benchmarks/lib/lattice.ts:185-190`) | `C.measurement` (all four types) | present (the compact code is a consumer-side rendering) |
| Candidate identity | `manifest.scanners[]` `{id, version, mode, adapter, configuration_hash}` | present |
| Same corpus as the baseline | `manifest.evidence.corpus_digest` | present |
| Completeness (`status: complete/incomplete/failed`, `candidate.ts:144`) | `S.status`, number of `S.cases` vs corpus | present |
| Filtering to one detector (`--filter`, `candidate.ts:112`, `fixture-detectors.json`) | the families a case targets: `C.targets` | present (P1) |

Product input: tarballs and their provenance, the saved release baselines
(`baselines/*.json`), product pins.

### 3.4 Private shadow-scorer promotion policy

Legacy:

- `benchmarks/lib/scorer-promotion.ts` (`:1-22` scope; required dimensions
  `:37-41`; forbidden keys `:67`; `evidenceIdentityProblems` `:331-347`;
  `evaluatePromotion` `:417-430`) judges an evidence bundle against
  `benchmarks/scorer-promotion-contract.json` (scope `:12`, identity fields
  `:42-43`, questions `:87`, gates `:119` onward) and
  `schemas/scorer-promotion-contract-v1.json`. CI: `npm run
  scorer-promotion:check` (`.github/workflows/validate.yml:92`).
- Gates are deltas between a *candidate* (scorer allowed to set confidence and
  action) and the *legacy* deterministic path on the same frozen corpus
  (contract `:12-17`).

Credential-eval inputs it needs: two measurements of the same corpus, one per
product mode. In credential-eval terms that is two scanner entries (or two
artifacts) with different `mode`/`configuration_hash` and equal
`manifest.evidence.corpus_digest`.

| Gate metric (contract) | Artifact source | v1 status |
|---|---|---|
| `corpus.leakedSpanRate`, `corpus.falseAlarmRate`, `corpus.collateralRatio` deltas (`:233`, `:246`) | `S.aggregates.groups[*]` `leaked_span_rate`, `false_alarm_rate`, `collateral_ratio` (with `point`, `bound`, `n`) | present in the schema; filled by #3 |
| `ambiguous.twinDiscriminationRate`, `ambiguous.measurableShare` (`:181`) | `twins.rate`, `measurable_share`, **restricted to the scored specificities** | rates present; **the specificity stratum is product metadata** (see below) |
| `corpus.leakedOnlyUnderCandidate`, `corpus.invariantSpecificityChangedOutcomes`, `corpus.deterministicPositivesRemoved` | per-case join of two scanner runs on `C.case_id`: `C.measurement.span_outcomes` | present |
| `corpus.unstableCases` (`:308`) | `S.status = unstable` | present |
| `corpus.unreviewedChangedOutcomes` (`:320`) | changed per-case outcomes joined with `review_queue[]` and the ledger | present (P2) |

Product input: specificity strata (`contextual`, `entropy`, …), calibration
and confidence (`q1-*`), the #289 evasion aggregate (`q4-*`), model and
scoring-artifact identities (contract `:43`), holdout, runtime, performance
and size budgets (`q5-*`). None of these are credential-eval outputs, and
confidence is deliberately **not** a normalized-finding field: it is product
scoring state, and adding it would shape the neutral model around one
product. If a stratum such as specificity is needed per case, the product
keys it by `case_id` on its side.

### 3.5 Known gaps and product-specific blocker disposition

Legacy:

- `benchmarks/known-gaps.json` (header `:1-7`): one record per product issue,
  with lifecycle `observed → reviewed → promoted → fixed → verified` or the
  terminal `rejected` / `policy-decision` (`benchmarks/lib/promotion.ts:1-8`,
  `:59-60`).
- `validateKnownGaps` (`promotion.ts:90-209`) enforces that each record names
  a `redact-secret/redact-secret` issue (`:112`) and the
  `@redact-secret/core` package (`:119`), carries per-fixture observation
  evidence `{fixture, corpusHash, expected, actual}` (`:147-153`), and that a
  terminal record carries a `disposition {reason, evidence}` (`:199-206`).
  That disposition is the product's blocker decision.
- Cross-repository consistency with the product manifest:
  `benchmarks/lib/lifecycle-consistency.ts:20-72` (`npm run
  promotion:check`, `validate.yml:170`); release pin drift:
  `benchmarks/lib/pin-drift.ts` (`npm run pins:check`).

Credential-eval inputs it needs:

| Known-gap field | Artifact source | v1 status |
|---|---|---|
| `evidence[].fixture` | `C.case_id` (`<category>--<fixture-id>` for migrated cases) | present |
| `evidence[].corpusHash` | `manifest.evidence.corpus_digest` | present (a new digest scheme; legacy values are raw-file SHA-256, legacy-map §2.12) |
| `evidence[].expected[{start,end}]` | `C.expected[]` | present |
| `evidence[].actual[{start,end,type,action}]` | `C.actual[]` `{start, end, family, action}` | present, except `confidence` (product-only, see §3.4) |
| `candidate.version`, `sourceCommit` | `manifest.scanners[]` version / configuration | present |

Product input: issue numbers and URLs, lifecycle history, the product
manifest, fix commits, dispositions.

### 3.6 Review-ledger decisions

Legacy:

- `benchmarks/review-ledger.json` holds a human decision per review
  occurrence: `open`, `resolved` or `not-assertable`
  (`benchmarks/engine/review-ledger.ts:1`, entry shape `:25-35`).
- `not-assertable` is a per-class decision that must be backed by an ADR in
  `benchmarks/ledger-decisions.json` (`scripts/check-ledger-decisions.mjs:1-22`,
  `npm run ledger:decisions:check`, `validate.yml:82`).
- The decisions feed qualification: only `resolved` and `not-assertable`
  settle an occurrence (`support/evidence.ts:37`), and an unknown occurrence
  makes engine qualification incomplete
  (`benchmarks/evaluation/domains/credential/evidence.ts:18-24`).
- Occurrence ids are `reviewEntryId`
  (`benchmarks/evaluation/domains/credential/review.ts:4-10`): a hash of the
  case, source and queue entry with the `redact-secret` tool identity reduced
  to `{id}` so product releases do not re-key reviews. Legacy-map §6 hazard 2
  generalizes this to "the configured reference scanner".

Split:

- **Mechanics stay in credential-eval (#3):** emitting occurrences with
  stable ids, and the generic ledger validation/observation functions
  (`engine/review-ledger.ts:49-98`). Legacy-map §3.2 already classifies these
  as kernel.
- **Decisions stay outside:** the ledger file content, the ADR map, and the
  rule that turns an unsettled occurrence into a qualification failure.
  Expectation-level decisions ("the corpus expectation was wrong") belong in
  `credential-evidence` as corpus changes, never as engine exceptions.

Credential-eval inputs it needs: a list of review occurrences with a stable
id, the case, the method, the variant, and (for differential) reference, peer
and disagreement kind. **Present (P2):** the top-level `review_queue[]`,
sorted by its canonical `id`.

### 3.7 Engine qualification, milestones and release records

Legacy: `benchmarks/qualify.ts` (`npm run eval:qualify`) refuses to run while
the milestone is open (`:26-31`) or when a pinned scanner version differs
(`:39`), runs development methods plus the protected holdout, and labels the
result `execution-qualified` / `incomplete` with `supportClaims: false`
(`:62-68`). Release records bind credential and PII evidence to one release
commit (`benchmarks/evaluation/release-record.ts:1-11`) and forbid
cross-domain aggregate keys (`:33-44`). Performance budgets:
§3.2. Holdout lifecycle, blind evaluation, MCP and PII qualification are
listed as #6/out in legacy-map §3.

Credential-eval inputs they need: completeness (`S.status`, assertion
`resolution` counts in `S.aggregates.resolution`, present), the per-method
unresolved strata (derivable from `S.aggregates.resolution[*].resolved_rate`
and `manifest.accounting.resolved_rate_floor`, present), and reproduction
identities (present). The milestone, holdout custody, release binding and
pins are product input.

### 3.8 What the engine must not learn

The v1 contracts already exclude every item above. Keep it that way:

- no `status`, `support`, `stable`, `blocker`, `release` or `promotion` field
  in any credential-eval document;
- no product scanner id special-cased in the kernel (differential and review
  ids take the reference scanner as a run parameter, legacy-map §6 hazards
  1-2);
- no product thresholds in `RunConfig`; the accounting floors there only
  withhold figures;
- product fixture metadata that is policy (T3 expected action, conformance
  flags, specificity) is keyed by `case_id` on the product side, not added to
  the corpus snapshot.

## 4. The consumer API

The only interface is the run artifact:

- **Document:** one JSON file whose top-level `schema` is
  `credential-eval/run-artifact/v1`.
- **Contract:** `schemas/run-artifact-v1.schema.json` (JSON Schema draft
  2020-12, generated from the Rust types and drift-checked in CI). The prose
  is [contracts/README.md](contracts/README.md); ranges, identities, outcomes
  and ordering are in `docs/contracts/`.
- **No internals:** consumers do not link, import or vendor any crate or
  source file from this repository, and do not parse CLI logs or scanner
  output.

Consumer obligations:

1. **Reject unknown documents.** Check the `schema` tag, then validate the
   whole document against the schema. `additionalProperties: false`
   everywhere means an unexpected field is an error, not something to ignore.
   v1 is frozen ([ADR 0001](decisions/0001-freeze-v1-contracts.md)): it never
   changes incompatibly, but minor revisions add optional fields. Validate
   with the schema file of the engine version that wrote the artifact (or a
   later v1 schema), never an older one.
2. **Bind identities.** Record `manifest.engine`, `manifest.protocol_version`,
   `manifest.evidence` (with `corpus_digest`), `manifest.config_hash` and
   `manifest.scanners[]` in every derived record, and refuse to compare
   artifacts whose `protocol_version` or `corpus_digest` differ unless the
   policy explicitly allows it.
3. **Ignore `non_semantic`.** Timestamps, run ids, host and durations are not
   evidence.
4. **Treat non-complete as not measured.** `S.status ≠ complete` and
   `C.measurement.type = "not-measured"` are never a miss and never a pass.
   The compatibility layer, not the consumer, folds `timeout`/`malformed`
   into legacy `error` (§2.10 of the legacy map).
5. **Do not re-score.** Read `span_outcomes`, `flagged` and the aggregates as
   published. The lattice is implemented once (Rust kernel). A consumer may
   *count* outcomes; it must not recompute them from ranges.
6. **Respect withheld figures.** A published figure is `null` (zero
   denominator), a rate `{point, bound, n, direction}`, or
   `"insufficient-evidence"` / `"insufficient-coverage"`. Policy decides what
   a withheld figure means for it; it must not substitute a point estimate.
7. **Never sum across groups or scanners** into a single score. Legacy
   release records enforce the same rule (`release-record.ts:33-44`).
8. **Respect the publication class.** Only an artifact with
   `manifest.publication = "public"` (an official run of released scanner
   builds) may be consumed outside product qualification, for example by a
   scanner-observation view on `credential-evidence-site`. An `internal`
   artifact is every exploratory run and every run that includes a
   candidate build, and it stays within Redact Secret qualification. A
   missing `publication` (a pre-v1.1 artifact) means `internal`
   ([official-runs.md](official-runs.md)). `public` is necessary but not
   sufficient: an artifact over a protected population stays inside
   qualification whatever its publication class
   ([multi-corpus-qualification.md](multi-corpus-qualification.md) §5).

These obligations apply to each artifact. A consumer that combines artifacts
of several corpora also follows the consumer contract in
[multi-corpus-qualification.md](multi-corpus-qualification.md) §6: bind each
artifact to its population, key cases by `(population, case_id)`, and keep
counts per population unless its policy defines a combination explicitly.

### 4.1 Family view (schema-level projection)

Legacy qualification is organised per family, while the artifact is
organised per case and per `kind/tier` group. The projection below turns one
into the other. It is a **view**, specified at the schema level: it is a pure
function of the artifact, so it adds no measurement semantics and needs no
contract change. The reference consumer implements it in
`examples/qualification-consumer/family-view.mjs`.

Document tag `credential-eval/family-view/v1`:

```text
{
  schema:  "credential-eval/family-view/v1",
  source:  { artifact_schema, engine, protocol_version, evidence, config_hash },   // copied from the artifact
  scanners: [                                  // sorted by scanner id
    { scanner, status,                         // S.scanner, S.status
      families: [                              // sorted by family (byte order); cases without C.family → "(no-family)"
        { family,
          cases,                               // count of C
          pending,                             // C.measurement.type = pending (T0)
          not_measured,                        // C.measurement.type = not-measured
          positives: {                         // C.measurement.type = positive, split by C.kind
            "must-redact": { cases, spans, outcomes{EXACT,COVERED,OVERBROAD,PARTIAL,MISS},
                             leaked_spans /* PARTIAL+MISS */, leaked_bytes, collateral_bytes },
            "policy":      { …same… } },
          benign: { cases, flagged, findings },    // control, C.twin_of absent
          twins:  { pairs, discriminated, flagged, co_detected } } ] } ] }
```

Derivation rules:

- Every count sums per-case fields; nothing is recomputed from ranges.
- A twin pair is counted when the twin's `C.measurement` is `control` and the
  case named by `C.twin_of` has a `positive` measurement in the same scanner
  run. It is `discriminated` under the protocol v1.1 strict rule: every
  positive span is `EXACT` or `COVERED` and the twin is not flagged
  (legacy-map §2.7). The pair is attributed to the twin's `C.family`.
- Rates are deliberately absent. A consumer that needs bounded rates reads
  `S.aggregates.groups` (per `kind/tier`) or the per-target aggregates
  `S.aggregates.by_target` (P3), which carry the protocol's Wilson bounds and
  withholding. A consumer must not invent its own interval arithmetic for
  published claims.
- The view can also be keyed by `C.targets` (P1) instead of `family`, which is
  what legacy `byDetector` does.

## 5. Additive contract changes (P1-P4)

These were proposed here for the orchestrator to schedule. None is a protocol
revision: each adds data the kernel already has and changes no outcome and
no existing field. P1-P3 landed with the kernel (#3, PR #11) before the v1
freeze, so they are part of the frozen v1.0 schemas
([ADR 0001](decisions/0001-freeze-v1-contracts.md)). P4 was not taken.

| Id | Decision | Contract fields | Tests |
|---|---|---|---|
| **P1** grouping passthrough | **Landed** (#3) | `CaseResult.group` (required), `targets` (sorted, unique; omitted when empty), `taxonomy`, `evidence_class`, `twin_mutation_kind` (from `Case.twin.mutation_kind`) in `crates/credential-eval-contracts/src/artifact.rs` | `crates/credential-eval-kernel/tests/rules.rs::scanner_aggregates_fill_groups_and_targets_only_when_complete` (group and twin mutation kind per case); `crates/credential-eval-contracts/tests/output_contract.rs::every_variant_validates_and_round_trips`; the contracts-smoke golden artifact (`crates/credential-eval-kernel/tests/contracts_smoke.rs`) |
| **P2** review queue | **Landed** (#3) | top-level `RunArtifact.review_queue: Vec<ReviewOccurrence>`, each `{id, case_id, method, variant, baseline?, candidate?, reference?, peer?, disagreement?}`, sorted by `id`. The `id` is a canonical digest that keeps only the reference scanner's id, so a new reference release does not re-key reviews. | `rules.rs::differential_reference_is_a_run_parameter` (ids unchanged by a reference version bump, changed by a peer version bump, no queue without a reference); `crates/credential-eval-kernel/tests/oracle.rs::evaluation_matches_legacy` (queue entries match the legacy engine); `crates/credential-eval-cli/tests/methods.rs::method_runs_are_deterministic_schema_valid_and_complete` |
| **P3** per-target aggregates | **Landed** (#3) | `Aggregates.by_target: {family: {"<kind>/<tier>": GroupAggregate}}` under the legacy `selectionGroups` rule, and `Aggregates.resolution_by_target: {family: {"<method>/<kind>:<tier>/<assertion>": AccountedCounts}}` (cases without targets under `unassigned`) | `oracle.rs::selection_groups_match_legacy` (`by_target` equals legacy `byDetector`); `rules.rs::scanner_aggregates_fill_groups_and_targets_only_when_complete`; `rules.rs::assertions_follow_the_protocol` (`resolution_by_target`) |
| P4 sanitized scanner `configuration` in `manifest.scanners[]` | **Rejected for v1.0 (deferred)** | none | none |

Why P4 was not taken: nothing guarantees that an adapter configuration is
free of host paths. The built-in binary adapters accept a `binary` path, and
candidate package roots are host directories. Recording the object would
need a sanitization rule per adapter. A field that is safe for one adapter
and unsafe for another is the kind of field the v1 plaintext guarantee
(`docs/contracts/README.md`, "No plaintext or raw output") exists to exclude.
`configuration_hash` already binds the configuration: a product keeps its own
copy of the configuration it passed in and checks it against the hash with
the canonical encoding (`docs/contracts/identity.md`). If a consumer still
needs the object, it can return as an optional field in a minor v1 revision,
with a per-adapter allowlist of keys.

Not proposed, on purpose: a `confidence` field, a support-status field, any
product action expectation in the corpus snapshot, or a per-family
qualification summary emitted by the engine.

Further proposals for multi-corpus consumption (P5 population label, P6
composed-corpus partitions, P7 corpus publishability) are listed, unscheduled,
in [multi-corpus-qualification.md](multi-corpus-qualification.md) §8.

## 6. Reference consumer

`examples/qualification-consumer/` is a standalone Node program (Node 22, no
dependencies) that proves the boundary on the committed smoke artifact:

- `consume.mjs` reads a run artifact, checks the schema tag, validates it
  against `schemas/run-artifact-v1.schema.json`, builds the family view and
  applies a policy;
- `validate.mjs` is a small draft 2020-12 validator for the keywords the
  generated schemas use (it fails loudly on any other keyword);
- `family-view.mjs` is the §4.1 projection;
- `toy-policy.mjs` + `toy-policy.json` are an **illustrative toy policy**.
  Its labels (`toy-meets-bar`, `toy-below-bar`, `toy-no-scored-evidence`,
  `toy-not-measured`) and thresholds are arbitrary. It is not the Redact
  Secret support policy and must not be read as a recommendation;
- `consumer.test.mjs` shows that editing the policy file changes verdicts
  while the artifact and the family view stay byte-identical, that a
  non-complete scanner is reported as not measured rather than as a miss,
  and that malformed artifacts are rejected.

CI runs it in the `qualification-consumer` job of `.github/workflows/ci.yml`.

## 7. Acceptance for #6

| Acceptance item | Where it is met |
|---|---|
| The generic engine can evaluate Redact Secret without knowing its support policy | §1, §3.3 (a candidate is a scanner identity), §3.8; the v1 contracts carry no policy field |
| Redact Secret qualification can change without changing generic scoring semantics | §4 consumer API; the reference consumer's policy-change test |
| The ownership boundary is documented | §2, §3 and [migration/redact-secret-cutover.md](migration/redact-secret-cutover.md) |

The additive contract proposals P1-P3 have landed and v1 is frozen (§5,
ADR 0001), so a Redact Secret consumer can reproduce §3.1 and §3.3 from the
artifact alone, without joining the corpus snapshot.
