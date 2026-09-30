# Legacy engine map

This is an inventory of the TypeScript evaluation engine in
`redact-secret/redact-secret-benchmarks` at the pinned oracle commit
**`c403475476647bc98cc5864bccd7265eddebeb91`** (origin/develop). All
`file:line` references are to that commit. Paths are relative to the legacy
repository root unless they start with `crates/` or `docs/`.

The agents for issues #3 (kernel), #4 (adapters), #5 (parity) and
#6 (qualification separation) work from this document. The kernel's
intentional differences from what is described here are listed in
[kernel-deltas.md](kernel-deltas.md). The contracts they
target are in `docs/contracts/` and `crates/credential-eval-contracts`.

Classification legend:

- **#3 kernel**: generic measurement. Port it to `credential-eval-kernel`.
- **#4 adapter**: scanner execution and parsing. Port it to `credential-eval-adapters`.
- **#6 policy**: Redact Secret product qualification. It stays in the legacy
  repository or with the product and never moves here.
- **out**: site/UI, corpus authoring (belongs to `credential-evidence`), PII
  domain, or tooling that is irrelevant to this repository.

---

## 1. Two legacy pipelines

The legacy engine has two entry points that share the lattice. Parity must
cover both.

| | `npm run bench` → `benchmarks/run.ts` | `npm run eval` → `benchmarks/evaluate.ts` |
|---|---|---|
| Profile | `measurement-v4` (per-category comparison) | `evaluation-v1` (method-based discovery) |
| Unit | category corpus × scanner → scored rows | case × method → variants × scanner → assertions |
| Scoring | `scoreReport` (`lib/reporting.ts:10-14`) = `score` + `accountGroups` + `accountingDelta` | `observe` (`evaluation/domains/credential/assertions.ts:8-19`) + `absolute`/`relation` |
| Replays compare | sorted `path:start:end` only (`run.ts:150-152`) | whole normalized finding: path + sha256(JSON of the finding) (`evaluation/substrate/runtime.ts:24-28`) |
| Family filter | none: adapter families pass through unchanged | `normalizeFinding` keeps `family` only if it is a key of `contracts` and `capabilities.classification !== false` (`evaluation/domains/credential/normalization.ts:5-9`) |
| `unsupported` status | never emitted | emitted when `capabilities.ranges === false` (`runtime.ts:82-86`) |
| Outputs | `public/results/<category>.json`, `summary.json`, `run.json` | `results-output/evaluation.json` (and the public projection `public/results/evaluation-v1.json`) |
| Concurrency | none (sequential scanners) | none (sequential scanners) |

---

## 2. Measurement semantics (protocol; port exactly)

### 2.1 Ranges

- Every offset is a **UTF-8 byte offset**, and every range is **half-open
  `[start, end)`**. `types.ts:1` says "Offsets are UTF-8 bytes, never
  characters". Overlap is `a.start < b.end && b.start < a.end`
  (`lib/lattice.ts:10`), so touching ranges do not overlap. Containment is
  `outer.start <= inner.start && outer.end >= inner.end` (`lattice.ts:11`).
- The validity rule `validRange` (`lib/scoring.ts:34-35`) requires integer
  offsets, `start >= 0`, `end > start` (never empty), `end <= byteLength`,
  and both endpoints on a code point boundary.
- Boundaries are computed by `computeByteBoundaries` (`scoring.ts:6-18`),
  which walks UTF-16 code units. A lone surrogate counts 3 bytes, like
  Node's `Buffer`. Rust `String` cannot hold lone surrogates, so this edge
  case disappears once content is valid UTF-8. A corpus exporter must reject
  or flag any fixture containing one.
- The boundary cache (`scoring.ts:22-32`) is a 64-entry performance detail
  and not semantic.

This maps to `crates/credential-eval-contracts/src/range.rs` and
`docs/contracts/ranges.md`.

### 2.2 Corpus validation: `validateCorpus` (`lib/scoring.ts:42-84`)

- Corpus: `fixtures` must be a non-empty array (43-44).
- Fixture id: `^[a-z0-9-]+$` and unique (48-49).
- Path: `^[a-zA-Z0-9_./-]+$`, no leading `/`, no empty, `.` or `..`
  segment, unique (50-57).
- `content` is a string and `expected` is an array (60-61).
- Expected spans: each must be a `validRange`, and they must be sorted and
  disjoint (`r.start < previous end` is an error; touching is allowed)
  (64-66). `role ∈ {secret, companion}` is required (67).
- Envelope: a `validRange` with `e.start <= r.start`, `e.end >= r.end`, a
  non-blank `reason`, and no overlap with any *other* expected span (68-72).
- Twin (`twinOf` set): the positive must exist, must not be the fixture
  itself, and must have a secret span. The twin must have no secret span,
  a non-blank `mutation` string, and a `mutationKind` string (76-82).

This is ported in `CorpusSnapshot::validate`
(`crates/credential-eval-contracts/src/corpus.rs`).

`bench` additionally requires `schemaVersion === 2` (`run.ts:110`). Both
pipelines also require `assessment` to deep-equal
`classifyFixture(category, f)` (`run.ts:113`, `cases.ts:51`) and
`validateStructures` to pass. Those two checks are **evidence authoring**
checks (`evaluation/domains/credential/assessment.ts`, `lib/validate-structures.ts`).
They belong to `credential-evidence` or to the exporter, not to the kernel.

### 2.3 Finding validation and deduplication: `score` (`lib/scoring.ts:87-126`)

- Every finding must name a known fixture path and satisfy `validRange`.
  Anything else throws `"Invalid normalized finding"` (93-96). There is no
  clamping.
- Dedupe key: `` `${path}:${start}:${end}` `` via `Map.set` (97). The **last**
  duplicate's `family`/`action` wins, and the first insertion order is kept.
  The Rust `score::dedupe` port keeps last-wins and then sorts by
  `(path, start, end)`.
- Per-row `actual` carries `{start, end, family?, action?}` (109-110), and
  `expected` carries `{start, end, role, envelope?{start,end}}` without the
  envelope reason (111).
- Row: `{id, path, group, kind?, tier?, contract?, twinOf?, expected, actual}`
  (113-121). A T0 row stops there, unscored (122). Other rows add
  `scoreRow(expected, actual, f.twinOf ? a?.contract : undefined)` (123).

### 2.4 Span lattice: `spanOutcome` (`lib/lattice.ts:44-50`)

```
envelope = span.envelope ?? span
EXACT      if any finding == span
COVERED    else if some finding contains span, and some containing finding ⊆ envelope
OVERBROAD  else if some finding contains span (none of them inside the envelope)
PARTIAL    else if some finding overlaps span
MISS       otherwise
```

- `isLeaked = PARTIAL | MISS` (52). `isCovered = !isLeaked` (58) is the
  leak axis only.
- *Acceptable* = `EXACT | COVERED` (`evaluation/domains/credential/accounting.ts:58`,
  `lib/twin-probe.ts:22`, `assertions.ts:26`).

This is ported exactly in `crates/credential-eval-kernel/src/lattice.rs`.

### 2.5 Row scoring: `scoreRow` (`lib/lattice.ts:76-97`)

- `secrets` = spans with `(role ?? 'secret') === 'secret'` (77).
- **Control** (no secrets) (78-92):
  - `actionCounts` tallies `a.action` values. It is present only when
    non-empty, and it never changes `flagged` or `findings` (82-86).
  - Scoped (twin with `scopeFamily`): `other` = the findings whose `family`
    is defined and differs from the scope. `flagged = other < actual.length`,
    and `coDetected` is set only when `other > 0` (87-90). A finding with no
    family therefore flags, so the rule fails closed.
  - Unscoped: `flagged = actual.length > 0` (91).
  - `findings = actual.length` in both cases.
- **Positive** (93-96):
  - `spanOutcomes` has one outcome per secret, in span order.
  - `leakedBytes` = Σ over *leaked* secrets of `bytesOutside([secret], actual)`.
  - `collateralBytes` = `bytesOutside(actual, expected.map(e => e.envelope ?? e))`.
    The acceptable cover includes companions and every expected span.
- `union` (15-24) sorts by `(start, end)` and merges when `r.start <= last.end`,
  so touching ranges merge. `bytesOutside` (27-41) is the sweep.

Scoping differs between the pipelines. In `bench`, a row is scoped when the
fixture has `twinOf` and its assessment has a `contract` (`scoring.ts:123`).
In `eval`, a variant is scoped when `transformation.relation === 'must-flip'`
and `fixture.assessment.contract` is set (`assertions.ts:16-17`), because
generated variants never carry `twinOf`.

Porting notes:

- In `bench`, `family` is whatever the adapter mapped, with no allowlist, so a
  twin's "known other family" can be any mapped label. In `eval`, the label
  must also be a key of the product `contracts` table (see §6).
- The contract `CaseMeasurement` renders `coDetected` as an always-present
  boolean and `actionCounts` as a map that is omitted when empty. The
  compatibility writer must drop `coDetected: false` to reproduce the legacy
  row bytes.

### 2.6 v1.0 group aggregation: `aggregateGroups` (`lib/lattice.ts:113-182`)

- `groupKey(kind, tier)` = `'pending/T0'` if the tier is T0, otherwise
  `` `${kind}/${tier}` `` (99). There are no cross-group totals.
- The positive population is `tier !== 'T0' && kind !== 'must-not-flag'` (116).
  Twins are mapped to their positive only if both are non-T0 and the
  positive is not `must-not-flag` (117-123).
- T0 rows count `{files, scored:false}` (126-130).
- `must-not-flag` groups (131-138):
  - `files`, `findings += row.findings`, `flaggedFiles`.
  - diagnostics: `exact.fp += row.findings`, and `tn` counts the unflagged rows.
- Positive groups (140-164):
  - `files`, `spans`, `secretBytes`, `outcomes[o]++`, `leakedSpans`,
    `leakedBytes`, `collateralBytes`.
  - diagnostics: `tp` = EXACT count, `fn` = secrets − tp, and `fp` = the
    actual findings not *equal* to any secret span.
  - `twins`: `positives++` per positive row, and `pairs++` per twin of the
    row. `discriminated++` when `every(isCovered)` (**v1.0 lenient:
    OVERBROAD counts**) and the twin is not flagged. `coDetected++` when the
    twin is co-detected.
- Rates (166-177): `rate(n, d) = d ? n/d : null`.
  - `falseAlarmRate` = flaggedFiles/files.
  - `meanFindingsPerFlagged` = findings/flaggedFiles.
  - `leakedSpanRate` = leakedSpans/spans.
  - `leakedByteRate` = leakedBytes/secretBytes.
  - `collateralRatio` = collateralBytes/secretBytes.
  - `twins.rate` = discriminated/pairs.
- Invariant (179-180): the sum of `twins.positives` must equal the positive
  population. Otherwise it throws.
- Output keys are sorted with `localeCompare` (181). The keys are ASCII
  `kind/tier`, so this matches byte order.

### 2.7 v1.1 accounting: `accountGroups` (`evaluation/domains/credential/accounting.ts:65-115`)

Counts come from `aggregateGroups`, except as noted.

- `pending[kind]` counts T0 rows by their proposed `kind` (69-70).
- `strict[key]` counts twin pairs whose positive is all-**acceptable**
  (`EXACT|COVERED`) and whose twin is unflagged (71-78). This is the v1.1
  rule: an OVERBROAD positive does not discriminate.
- `envelopes[key]` counts secret spans with an envelope, plus the sum of
  `(envelope width − span width)` over non-T0, non-must-not-flag rows (79-83).
- `pending/T0` becomes `{files, scored:false, candidateKinds}`, with keys
  sorted (86).
- `must-not-flag/*` (87-92):
  - `falseAlarmRate = proportion(flaggedFiles, files, 'upper')`.
  - `meanFindingsPerFlagged = ratio(findings, flaggedFiles, n = files)`.
  - `diagnostics` are carried over.
- Positive groups (94-112):
  - `pendingFiles = pending[kind]`.
  - `measurableShare = proportion(files, files + pendingFiles, 'lower')`.
  - `measurable = files/(files+pendingFiles) >= measurableShareFloor[kind]`.
    When it is false, the leak and collateral rates become
    `'insufficient-evidence'`.
  - `leakedSpanRate = proportion(leakedSpans, spans, 'upper')`.
  - `leakedByteRate = proportion(leakedBytes, secretBytes, 'upper', n = spans)`.
  - `collateralRatio = ratio(collateralBytes, secretBytes, n = spans)`.
  - `twins.coverage = proportion(pairs, positives, 'lower')`.
  - `twins.rate`:
    - `null` when there are no pairs;
    - otherwise `'insufficient-evidence'` when the group is not measurable;
    - otherwise `'insufficient-coverage'` when `pairs/positives <
      twinCoverageFloor[kind]` or `positives == 0`;
    - otherwise `proportion(strict, pairs, 'lower')`.
  - `twins.discriminated` is the **strict** count.

Mechanics (`accounting/shared/primitives.ts`):

- `floorFor` (24): a number, or `floor[key] ?? floor.default`. The key is
  the **kind** (`key.split('/')[0]`) for groups and the **method** for
  resolution.
- `round(v, p) = Number(v.toFixed(p))` (25). Rust must reproduce JS
  `toFixed` rounding, which rounds the binary value half away from zero and
  is not banker's rounding.
- `wilson` (36-41):

  ```
  scale  = 1 + z²/n
  centre = (p + z²/2n) / scale
  spread = (z/scale) · √(p(1−p)/n + z²/4n²)
  ```

  The result is clamped to [0,1] and rounded. It is `centre + spread` for
  `'upper'` and `centre − spread` for `'lower'`.
- `proportion` (43-48): `null` if `!denominator || !n`;
  `'insufficient-evidence'` if `n < minDenominator`; otherwise
  `{point: round(num/den), bound: wilson(point, n, dir), n, direction}`.
  The bound is computed from the **unrounded** point.
- `ratio` (50-54): the same guards. It returns `{point, bound: null,
  n: denominator, direction: null}`. **The emitted `n` is the denominator,
  not the guard `n`**, so this quirk must be preserved.
- `accountCounts` (57-61): `resolved = pass+fail`,
  `total = resolved + review-required + not-measured`, and
  `resolvedRate = proportion(resolved, total, 'lower')`.
- `validateMechanicalAccounting` (27-33) and `validateAccounting`
  (`accounting.ts:43-54`) check: `version === '1.1'`, integer
  `minDenominator >= 1`, floors in [0,1], integer `replays >= 2`,
  `intervalZ > 0`, and integer `intervalPrecision` in 1..=12.
- The accounting identity is `{domain:'credential', evaluationProfile,
  domainAccountingVersion:'credential-v4'}`
  (`evaluation/domains/credential/identity.ts:2-7`, `accounting.ts:18-22`).
  Cross-profile aggregation is refused (`primitives.ts:63-74`).
- The pinned values (`qualification/suite-v1.json:21-38`) are
  `minDenominator 5`, `resolvedRateFloor {default .9, differential 0}`,
  `measurableShareFloor {default .7, policy 0}`, `twinCoverageFloor
  {default .5, policy 0}`, `replays 2`, `intervalZ 1.96` and
  `intervalPrecision 6`. These are measurement parameters (the contract's
  `AccountingConfig`), not support thresholds.

### 2.8 `accountingDelta` (`accounting.ts:124-153`) and comparability (161-165)

This is the dual-scorer transition record. For each non-T0 group it holds the
v1.0 figures (rounded) against the v1.1 published figures, together with the
set of causes that moved them: `overbroad-twin`, `twin-coverage`, `t0-share`
and `interval`. An unattributed point change throws (149). `bench` emits it
per scanner, and it is a parity target. `assertComparable` refuses to compare
records across accounting versions unless one of them carries a delta. It
belongs in the kernel (#3) as part of the accounting output, or in the
compatibility layer if the v1.0 figures are dropped from the canonical
artifact.

### 2.9 Twin probe: `twinProbe` (`lib/twin-probe.ts:25-44`)

The probe assigns one status to each detector family:

- `discriminated`: every scored pair passes the v1.1 strict rule.
- `not-discriminated`
- `un-probeable`: no twin, plus a contract `unprobeable` record.
- `not-measured`: twins exist but no scored pair does.
- `unrecorded`

A family that has twins *and* an un-probeable record throws (30). The
generic mechanics are **#3**. The family list and the `unprobeable` records
come from the product `contracts` table, which is evidence. The probe must
take them as input.

### 2.10 Observation runtime: `executeRuntime` (`evaluation/substrate/runtime.ts:30-122`)

- Scanner ids across fresh and reused observations must be non-empty and
  unique (50-51). A reused snapshot observation must be `complete`, have
  `source:'snapshot'`, and carry in-bounds findings (61-68).
- Materialization: `mkdtemp(<scratch>/secret-evaluation-)`, each input
  written at mode 0600, and the directory removed in `finally` (70-76, 119-121).
- Each scanner runs **sequentially** (77):
  - `configuration` defaults to `{mode}`, and
    `configurationHash = hash(configuration)` (79-80).
  - `capabilities.ranges === false` gives `unsupported` (82-86).
  - Otherwise: `version()`, then `replays` × `scan()`. Each pass runs
    `validateFindings` (= `score`, which throws on an invalid range) and
    then `normalizeFinding` (88-94).
  - If any replay's multiset of (path, finding-hash) tuples differs, the
    result is `unstable`: findings are discarded, and `divergentPaths` is
    sorted (95-105).
  - Otherwise the result is `complete`, with `durationMs` (rounded; it
    includes `version()`), `replays {count, agreed:true}` and
    `observation {source:'fresh', observedAt, sourceRunId}` (106-108).
- Errors: when the message is `"unavailable"` the status is `unavailable`.
  Anything else is `error`, with a fixed sanitized message (109-112).
- The contract splits the legacy `error` into `timeout` / `malformed` /
  `error`. The compatibility writer folds them back into `error`.

`bench` duplicates this loop inline (`benchmarks/run.ts:124-187`):

- The replay comparison is ranges-only (150-152).
- A peer version mismatch throws `peer-version-mismatch` (145).
- `durationMs` is rounded to 0.01 (147, 158).
- A peer snapshot is reused unless `--live-peers`/`--refresh-peer-snapshots`
  is given (132-142). It is validated against `inputIdentity` and
  `repositoryPeerIdentity` (`lib/peer-observations.ts:71-145, 165-196`).

### 2.11 Evaluation-v1 cases, methods, operators and assertions

**Case construction.** `loadCases`
(`evaluation/domains/credential/cases.ts:22-103`) creates, for every fixture
of every non-`calibrationOnly` category, these cases with id
`` `${category}--${fixtureId}--${method}` `` (76):

- `differential` for every fixture (84).
- `twin` when the fixture has `twinOf`. The seed is the *positive*, `twin` is
  the fixture, and `operators: [authored.twin]` (85-87).
- `benign` when the fixture has no `twinOf` and no secret. Its taxonomy is
  the control axis (88).
- For non-twin fixtures (91-98):
  - `metamorphic` with every `context.*` and `encoding.*` operator.
  - `mutation` with every `lexical.*`, `boundary.*` and `structural.*`
    operator, plus `authored.twin` when a twin exists.

`provenance.sourceHash = hash(fixture)`, re-keyed to `hash(seed)` for twin
cases (72, 80). `corpusHash = hash(corpus)` is kept out of case identity (64).

**Generation.**

- `generateCase` (`engine/model.ts:52-62`) calls `validateCase` (21-31) and
  `method.validateCase`, then `method.generate`. It requires variant ids to
  be non-empty and unique, and runs `validateCorpus` over all variants.
- The common `generate` (`methods/common.ts:5-35`):
  - The first variant is always `canonical` (operator `identity` v1).
  - Then each operator either produces an `unsupported` attempt (via
    `supports`) or generates a variant, and a throw becomes an `error`
    attempt with a suppressed reason.
  - `expectationEffect` defaults to `defer` for review-required,
    `invalidate` for must-flip and `preserve` otherwise (25).
- `variant()` (`engine/model.ts:33-50`):
  - The id is `^[a-z0-9.-]+$`.
  - The fixture id becomes `` `${case}--${variant with . → -}` ``, and the
    path becomes `` `cases/${case}/${variant}.txt` ``.
  - The `review-required` strategy rewrites the assessment to T0 and
    `must-redact`/`must-not-flag`, based on whether `expected` is non-empty.
  - Provenance comes from `generatedVariant` (`substrate/variant-lifecycle.ts:1-29`):
    `{seed, sourceHash, fixtureHash: hash(fixture), contentHash:
    hash(content), transformationHash: hash(transformation)}`.

**Methods.** `createMethods` registers twin, benign, metamorphic, mutation and
differential (`methods/index.ts:8-12`).

| Method | Version | `validateCase` | evaluate |
|---|---|---|---|
| `twin` (`methods/twin.ts:4-8`) | 1 | the seed has a secret and exactly one operator | common |
| `benign` (`methods/benign.ts:8-13`) | 1 | no secret, `must-not-flag`, and a taxonomy in `AXES ∪ REAL_WORLD_AXES` | common |
| `metamorphic` (`methods/metamorphic.ts:3-5`) | 1 | at least one operator | common |
| `mutation` (`methods/mutation.ts:3-5`) | 1 | at least one operator | common |
| `differential` (`methods/differential.ts:21-62`) | **2** | no operators | pairwise comparison (below) |
| `holdout` (`methods/holdout.ts:5-17`) | 1 | holdout visibility, no operators and no twin | common. Registered separately. **#6 lifecycle** |

The common `evaluate` is `evaluateAssertions` (`assertions.ts:42-56`):

- A non-complete scanner gives one `{type:'absolute', status:'not-measured',
  reason: status}` per variant, and no rows (45-46).
- Otherwise `observe` scores each variant (8-19; must-flip variants are
  scoped to the contract family). There is one `absolute` assertion per
  variant, and for `i ≥ 1` a `relation` assertion against `variants[0]` when
  the transformation declares a relation (47-52).
- `absolute` (21-29):
  - It is `review-required` when the strategy is review-required or the
    tier is T0.
  - For a positive, the type is `present-within-envelope` and it passes iff
    every outcome is EXACT/COVERED **and `collateralBytes === 0`**.
  - For a control, the type is `absent` and it passes iff the variant is
    not flagged.
- `relation` (31-40):
  - It is review-required if either side is.
  - It passes only if both absolutes pass. For `must-flip`, the baseline
    must also have a secret and the candidate must not. For
    `same-detection`, `JSON.stringify(spanOutcomes ?? flagged)` must be
    equal on both sides.

**Differential** (`methods/differential.ts:21-62`):

- `classifications` (9-19) builds per-range family sets. It dedupes by
  `start:end`, sets an `unmapped` flag when some finding lacks a family,
  sorts families, and sorts ranges by `(start, end)`.
- For each variant × peer, the comparison is `incomplete` or `unsupported`
  unless both scanners are complete (29-33).
- Range sets are compared family-blind (38-40). The disagreement is one of
  `redact-secret-only`, `peer-only`, `range-disagreement`,
  `classification-disagreement` (only when ranges are equal, both sides
  have ranges, and every range is fully mapped), or `none` (41-44).
- Every disagreement is queued as `review-required`, with the ranges,
  classifications and tool identity (47-52).
- `complete` requires the primary to be complete and every comparison to be
  complete (60).
- **Neutrality hazard.** The primary is hard-coded as `'redact-secret'`
  (26, 28, 32, 43, 48-49). #3 must make the reference scanner a run
  parameter (`DifferentialComparison.reference`) and rename
  `redact-secret-only` to `reference-only`. The compatibility writer maps
  it back.

**Operators.** `createOperators` registers them in this order: authoredTwin,
the context operators, the lexical operators, boundary and structural
(`operators/index.ts:8-12`).

- `authored.twin` v1 (`operators/authored-twin.ts:6-44`):
  - The twin must have `twinOf === seed.id`, different content, the same
    contract, and exactly one secret in the seed (13-19).
  - `mutationKind === 'context'`: the value is preserved byte-for-byte, it
    occurs once, and the edit lies wholly outside the secret (23-31).
  - Otherwise: the prefix is the same, the `trimEnd` suffix is the same, and
    only the secret changes (33-38).
  - Result: strategy `authored`, relation `must-flip`, and integrity
    `authored-single-property`.
- Context operators (`operators/context.ts:25-40`), all v1, strategy
  `derived`, relation `same-detection`, and no parameters allowed:
  - `context.unicode-prefix`: prefix `'# 🔑 密钥 café\n'`.
  - `context.indent`: 4 spaces.
  - `encoding.crlf`: lone `\n` becomes `\r\n`, if there is one.
  - `context.json`: `{"value":"…"}`, only if no `"`, `\` or control character.
  - `context.quote`, `context.single-quote` and `context.yaml`
    (`value: '…'\n`): only if safe.
  - `context.markdown`: backticks, only if there is no backtick or newline.
  - `mapFixture` (5-19) maps every original byte boundary through the
    transformation, and so remaps every span and envelope without searching
    for values.
- Lexical operators (`operators/lexical.ts`), all v1. `supportsLexical`
  (6-8) requires exactly one secret, tier T1/T2, and a contract `pattern`.
  - `mutate` (10-26) replaces the secret bytes and shifts every range that
    starts or ends at or after `span.end` by the byte delta. A replacement
    that still satisfies the contract `pattern`/`validate` is `derived` +
    `same-detection`. Otherwise it is `review-required`, with relation
    `null` and effect `defer`.
  - `lexical.length-minus-one`, `lexical.length-plus-one` (+`'A'`),
    `lexical.replace-last` (A↔B) and `lexical.invalid-alphabet` (last char
    → `!`) (28-38).
  - `lexical.prefix-change` (45-55) replaces the first character with
    `alphabet[choice]`. The alphabet is A–Z without the current first
    letter, and `choice` is a parameter in 0..25 or
    `seededChoice = parseInt(hash({seed, operator}).slice(0,12), 16) % 25` (41-43).
- Structural operators (`operators/structural.ts`):
  - `boundary.remove-delimiter` v1 (12-21) removes one `[._-]` at a seeded
    or explicit `index`.
  - `structural.remove-segment` v1 (25-37) applies only to the
    `sendgrid-token` (`.`, segments 1-2) and `slack-token` (`-`, segments
    1-3) contracts. **Product family names are hard-coded here.** #3 should
    take the eligible families and delimiters from evidence metadata.

**Reporting and summaries** (`evaluation/domains/credential/reporting.ts`):

- `describeVariant` (5-16) and `describeCase` (18-24) are allowlists. They
  never spread fixtures or raw errors.
- `summaries` (26-66) keys counts
  `` `${method}/${scanner}/${kind:tier[->kind:tier]}/${assertionType}` ``
  into `byMethod`, `byDetector`, `byTaxonomy` and `byOperator`, plus
  `axesByDetector`.

**Assembly** (`evaluation/domains/credential/execution.ts:69-114`):

- `ENGINE_VERSION = '1.1.0'` (34).
- `resolution = accountCounts` per `byMethod` key.
- `unresolvedGroups` (`accounting.ts:173-185`) lists strata below
  `resolvedRateFloor[method]`, skipping `:T0` strata, and adds
  `<method>/*` for methods that resolved nothing.
- `assertionDelta` (44-60).
- Review-queue ids are `reviewEntryId` (`review.ts:4-10`). It is a hash of
  the case, the source and the entry, with the **redact-secret tool entry
  reduced to `{id}`** so that product releases do not re-key reviews.
  **Neutrality hazard:** generalize this to "the reference scanner's
  identity is excluded".
- `review-required` variants are also queued (95-99).
- `exitCode` (`engine/runner.ts:11-14`).

### 2.12 Hashing and provenance

There are three incompatible legacy conventions:

| Helper | Algorithm | Serialization | Used for |
|---|---|---|---|
| `evaluation/substrate/hash.ts:4-6` `hash` | SHA-256 hex | a string or Buffer is hashed raw; anything else as compact `JSON.stringify` in **insertion order** | `configurationHash`, `casesHash`, `sourceHash`, the variant `fixtureHash`/`contentHash`/`transformationHash`, `parametersHash`, `rationaleHash`, review ids |
| `lib/peer-observations.ts:53-62` `digest` | SHA-256 | keys sorted by `localeCompare` | peer snapshot digests, `inputDigest`, `fixturesDigest` |
| `lib/fixture-index.ts:59-72` `digestJson` | SHA-256 | keys re-inserted in `localeCompare` order | fixture-index identity |

- `safeParameters` (`hash.ts:9-12`) keeps only keys matching
  `^[a-zA-Z][a-zA-Z0-9]*$` with boolean or finite-number values.
- The `bench` report `corpusHash` is SHA-256 of the **raw corpus file bytes**
  (`run.ts:108, 201`), and it equals `benchmarks/generated-corpora.json[id].sha256`.
- `runtimeProvenance` (`evaluation/substrate/provenance.ts:24-41`) hashes
  repository trees and `node_modules/@redact-secret`. That is
  legacy-layout-specific, so replace it with the snapshot/adapter identities
  in the contract.

`credential-eval` uses one canonical JSON digest (byte-order key sort) with a
`sha256:` prefix (`docs/contracts/identity.md`). **Legacy digests are not
parity targets**, but review-ledger ids and variant hashes are. Any
compatibility export that must reproduce them implements the legacy
`JSON.stringify` insertion order inside the compatibility module.

---

## 3. Module inventory and classification

### 3.1 `benchmarks/lib/`

| Module | Purpose | Class | Key functions |
|---|---|---|---|
| `lattice.ts` | span lattice, row scorer, v1.0 aggregation | **#3** | `union` 15, `bytesOutside` 27, `spanOutcome` 44, `isLeaked` 52, `isCovered` 58, `scoreRow` 76, `groupKey` 99, `aggregateGroups` 113, `encodeOutcome` 185 |
| `scoring.ts` | UTF-8 boundaries, corpus validation, finding validation/dedupe | **#3** | `computeByteBoundaries` 6, `validRange` 34, `validateCorpus` 42, `score` 87 |
| `accounting.ts` | re-export shim → `accounting/shared/primitives.ts` + `evaluation/domains/credential/accounting.ts` | **#3** | (1-4) |
| `findings-by-path.ts` | memoized per-path grouping | **#3** (perf detail) | `findingsForPath` 10 |
| `twin-probe.ts` | per-family twin status | **#3** (families and un-probeable records are inputs) | `twinProbe` 25 |
| `reporting.ts` | `scoreReport` = score + accountGroups + accountingDelta | **#3** | 10-14 |
| `run-summary.ts` | shim → `evaluation/domains/credential/run-summary.ts` | **#3** | cross-suite `selectionGroups` 39, `summarizeRun` 52 |
| `peer-observations.ts` | normalized peer snapshot I/O, input/peer identity | **#3** (snapshot and identity) + **#4** (`repositoryPeerIdentity` 117-145) | `digest` 53, `inputIdentity` 71, snapshot validate 165-196 |
| `fixture-index.ts` | corpus index and canonical identity | **out** (credential-evidence), with identity ideas feeding #3 | `digestJson` 59 |
| `validate-structures.ts`, `assessment.ts` (shim), `contract-sources.ts`, `crc32.ts`, `lexical-separability.ts`, `evidence-classes.ts`, `corpus-independence.ts`, `fixture-independence.ts` | evidence authoring and validation | **out** (credential-evidence) | |
| `promotion.ts`, `scorer-promotion.ts`, `lifecycle-consistency.ts`, `pin-drift.ts`, `pin-manifest.ts`, `regression-budgets.ts`, `baselines.ts`, `t3-comparison.ts`, `untargeted-action-split.ts`, `review-queue-handoff.ts` | known-gap lifecycle, release pins, budgets, product baselines, T3/action policy | **#6** | |
| `candidate-features.ts`, `evidence-features.ts`, `calibration-*.ts`, `tuning-manifest.ts` | product statistical-scorer calibration | **#6** | |
| `performance-*.ts`, `measured-performance.ts` | product performance acceptance | **#6** | |
| `adversarial-*.ts` | adversarial pack intake/adjudication | **out** (evidence lifecycle); the rerun mechanics may inform #3 later | |
| `mcp-qualification*.ts` | product MCP qualification | **#6** | |
| `score-evasion.ts`, `unit-diagnostics*.ts` | product-specific studies and diagnostics | **#6** / out | |

### 3.2 `benchmarks/engine/`, `methods/`, `operators/`, `accounting/`, `evaluation/`

The `engine/*.ts` (except `model.ts`, `types.ts`, `review-ledger.ts` and
`runner.ts`), `methods/*.ts` and `operators/*.ts` files are one-line
**compatibility re-exports** of `evaluation/domains/credential/**`. Port the
targets, not the shims.

| Module | Purpose | Class |
|---|---|---|
| `engine/model.ts` | `secrets` 10, `bytes` 11, `independentFixture` 12, `validateCase` 21, `variant` 33, `generateCase` 52 | **#3** |
| `engine/types.ts` | engine types (`Scanner` 41-47, `Observation` 51-56, `Assertion` 60, `ScannerResult` 61, `MethodResult` 69-74) | **#3** (shapes mapped into the contracts) |
| `engine/runner.ts` | holdout guard 5-9, `exitCode` 11-14 | **#3** |
| `engine/review-ledger.ts` | review ledger validation and observation | **#3** (mechanics); ledger *content* is evidence |
| `accounting/shared/primitives.ts` | Wilson, proportion, ratio, accountCounts, identity guard | **#3** |
| `evaluation/substrate/*` (`runtime`, `orchestration`, `case-lifecycle`, `variant-lifecycle`, `result-assembly`, `hash`, `registry`, `review-state`, `public-projection`) | domain-neutral orchestration | **#3** (`public-projection` → out) |
| `evaluation/substrate/provenance.ts` | repository tree hashing | replace with contract identities |
| `evaluation/domains/credential/{accounting,assertions,cases,execution,reporting,normalization,run-summary,review}.ts` | credential measurement | **#3** (`cases.ts` is the evidence → case bridge; its corpus reading becomes the snapshot loader) |
| `evaluation/domains/credential/methods/*`, `operators/*` | evaluation methods and variant operators | **#3** (see the §2.11 hazards) |
| `evaluation/domains/credential/assessment.ts` | format `contracts` table 366, `classifyFixture` 736, `validateAssessment` 846, axes 426-441, `MUTATION_KINDS` 394 | **out** (credential-evidence). The kernel receives contract patterns and axes as evidence metadata, never as product code |
| `evaluation/domains/credential/{evidence,qualification,holdout,holdout-corpus,public-report,contract}.ts`, `methods/holdout.ts` | qualification and holdout evidence gates, public projection, composition root | **#6** / out (`completenessReasons` in `evidence.ts:18` is generic) |
| `evaluation/domains/credential/mixed-parity/*`, `evaluation/domains/credential-policy/*` | product policy parity and holdout | **#6** |
| `evaluation/domains/pii/*` | PII domain | **out** (not credential) |
| `evaluation/release-record*.ts` | release record binding | **#6** |

### 3.3 Top-level `benchmarks/*.ts` and `scanners/`

| Module | Purpose | Class |
|---|---|---|
| `run.ts` | `bench` pipeline (§1) | **#3** (orchestration and report envelope) + **#6** (candidate flags, `reviewStatus`/milestone fields, pinned-peer enforcement) |
| `evaluate.ts` | `eval` CLI (§1) | **#3** |
| `types.ts` | shared data types (`Fixture` 11-27, `Finding` 32, `RowScore` 40, `ScoredRow` 41-44, `Group` 45-52, `AccountingConfig` 55-58, `Published` 61, `AccountedGroup` 62-71) | **#3** (mapped into contracts) |
| `classify-support.ts`, `generate-support-matrix.ts`, `support-matrix-drift.ts`, `qualify.ts`, `candidate.ts`, `holdout.ts`, `blind.ts`, `mcp-qualification.ts`, `generate-provider-dossiers.ts`, `evaluate-performance.ts`, `support/`, `blind/`, `mcp-qualification/` | support status, qualification, release and product dossiers | **#6. Never port** |
| `score-evasion.ts`, `unit-diagnostics.ts`, `calibration-experiments.ts`, `candidate-features.ts` | product studies | **#6** |
| `scanners/index.mjs` | adapters and process limits | **#4** (§5) |
| `scanners/families.mjs` | scanner label → family maps | **#4** (the product allowlist and `arrivalFindingTypes` lean **#6**) |
| `scanners/pins.mjs`, `peer-checksums.json`, `scripts/provision-peers.mjs` | peer pins, checksums, provisioning | **#4** |
| `scanners/candidate.mjs` | unreleased product build install | **#6** |
| `fixtures/**`, `corpora/**`, `benchmarks/categories.json`, `fixture-*.json`, `generated-corpora.json` | corpus | **out** (credential-evidence; the pinned migration corpus for #5) |
| `public/**`, `src/**`, `web/**` | site | **out** |

---

## 4. Legacy outputs and parity targets (#5)

### 4.1 `bench`: `public/results/<category>.json` (`run.ts:188-211`)

There is no JSON Schema for this file. Its shape exists only in code.

- Top level: `schemaVersion:5`, `accountingVersion:'1.1'`, `domain`,
  `evaluationProfile:'measurement-v4'`, `domainAccountingVersion`,
  `accounting`, `runId`, `candidate?`, `category`, `generatedAt`,
  `reviewStatus`, `scope?`, `references?`, `milestoneReview?`, `corpusHash`
  (raw file SHA-256), `lockHash`, `revision`, `dirty`, `runtime`,
  `fixtureCount`, `expectedCount`, `matching`, `scanners[]`.
- `scanners[]`: `{id, name, mode, version, status, durationMs, replays,
  observation, groups, accountingDelta, rows}`. A failed scanner has
  `{id, name, mode, version, status, message, replays?}` and **no rows**.
- `rows[]`: `{id, path, group, kind?, tier?, contract?, twinOf?,
  expected[], actual[]}`, plus `spanOutcomes`, `leakedBytes` and
  `collateralBytes` for positives, or `flagged`, `findings`, `coDetected?`
  and `actionCounts?` for controls. T0 rows carry no score fields.

**Parity key.** Compare `(category--row.id, scanner.id)`: `expected`,
`actual` **sorted by (start, end)** (legacy order is emission/first-insertion
order), and every score field. Also compare per scanner `groups`,
`accountingDelta`, `status` and `version`.

**Excluded as volatile:** `runId`, `generatedAt`, `startedAt`,
`finishedAt`, `durationMs`, `observation.*`, `revision`, `dirty`, `lockHash`
and `runtime`.

The compact oracle is `encodeOutcome` (`lattice.ts:185-190`):
`spanOutcomes.join(',')`, `flagged:<n>`, `clean` or `observed:<n>`.

### 4.2 `bench`: `summary.json` and `run.json`

- `summary.json` (`run-summary.ts:52-77`): `overall[scanner][group]` and
  `byDetector[detector][scanner][group]`. Both are accounted with
  `selectionGroups` (39-50) over rows re-slugged `${category}--${id}`, where
  a positive's twin and the selection's T0 rows "travel with" the group.
  This selection rule is itself accounting semantics, so port it as-is.
- `run.json` (`run.ts:238-253`): run-level identities, `partial`,
  `scannerVersions` and `scannerObservations`.

### 4.3 `eval`: `results-output/evaluation.json` (`substrate/result-assembly.ts:28-36`, `execution.ts:84-113`)

- Top level: `schemaVersion:3`, `engineVersion:'1.1.0'`,
  `accountingVersion`, `accounting`, the identity, `runId`, `startedAt`,
  `finishedAt`, `mode:'discovery'`, `scope`, `provenance`, `scanners[]`
  (observations without findings), `caseCount`, `variantCount`, `byMethod`,
  `byDetector`, `byTaxonomy`, `byOperator`, `axesByDetector`, `resolution`,
  `unresolvedGroups`, `accountingDelta`, `review`, `results[]`,
  `failures[]`, `generationErrors[]`, `reviewQueue[]`.
- Parity targets:
  - `results[].scanners[].{assertions, variants[].row}`
  - the summary counts
  - `resolution` and `unresolvedGroups`
  - `reviewQueue[].id`
  - the variant `provenance.*Hash`, which is insertion-order JSON; compare
    it only through the compatibility exporter.

### 4.4 Baselines

- `baselines/<version>.json` is written by `scripts/baseline.mjs --save`.
  Its shape is `{schemaVersion:2, accountingVersion, version, runId,
  savedAt, revision, scanners{id:version}, corpusHashes{cat},
  groups{cat:{scanner:groups}}, accountingDelta{cat:{scanner}},
  rows{"cat--id":{scanner:encodeOutcome}}}`. These are row-outcome oracles
  per release.
- `benchmarks/regression-baselines/*` hold product performance and
  operational data. **#6, not a parity oracle.**
- Deterministic peer inputs: `peer-observations/comparison/<category>/<peer>.json`
  are normalized findings. Rescoring the same findings in Rust must
  reproduce the `rows`, which lets #5 prove kernel parity without running
  binaries.

### 4.5 Mapping legacy rows to the contract

| Legacy | Contract (`RunArtifact`) |
|---|---|
| row `id` (per category) | `CaseResult.case_id` = `<category>--<id>` |
| `group` | `Case.grouping.group` (not repeated in `CaseResult`) |
| `kind`, `tier`, `contract`, `twinOf` | `kind`, `tier`, `family`, `twin_of` |
| `expected[{start,end,role,envelope?}]` | `expected[ScoredSpan]` |
| `actual[{start,end,family?,action?}]` | `actual[ObservedRange]`, sorted |
| `spanOutcomes, leakedBytes, collateralBytes` | `measurement: {type:"positive", span_outcomes, leaked_bytes, collateral_bytes}` |
| `flagged, findings, coDetected?, actionCounts?` | `measurement: {type:"control", flagged, findings, co_detected, action_counts}` |
| T0 row (no score) | `measurement: {type:"pending"}` |
| failed scanner (no rows) | `status` ≠ `complete`, and every case is `{type:"not-measured", status}` |
| `groups[key]` (AccountedGroup) | `aggregates.groups[key]`, tagged `population` |
| `Published` (`Rate` / `'insufficient-evidence'` / `null`) | `Option<Published>` (same JSON) |
| `twins.rate: 'insufficient-coverage'` | `Withheld::InsufficientCoverage` |
| `diagnostics.exact.{tp,fp,fn,tn}` + `comparable:false` | `diagnostics.{tp,fp,fn}` / `{fp,tn}` (the constant `comparable` is dropped) |
| `observation.status: error` | `error`, `timeout` or `malformed` (compat folds these into `error`) |
| differential `redact-secret-only` | `Disagreement::ReferenceOnly` |

Corpus notes for #5:

- Legacy fixture ids and paths are unique **per category**. A single
  multi-category snapshot needs case ids `<category>--<id>` and paths that
  are unique across categories. `eval` already requires that (`case-lifecycle.ts:4-14`).
- If an exporter prefixes paths, the scanners see different paths from those
  in `bench`. Gitleaks and TruffleHog rules can depend on the path, so this
  is a parity risk. Either materialize each category separately, or show
  that the prefix does not change the findings.
- Aggregates in `bench` are per category (`public/results/<category>.json`)
  and cross-suite (`summary.json`). The kernel must be able to aggregate over
  a `grouping.group` subset to reproduce the per-category files.

---

## 5. Scanner adapters (`scanners/`, for #4)

### 5.1 Shared execution (`scanners/index.mjs`)

- `processLimits = {timeout: 120_000 ms, maxBuffer: 16 MiB}` (7). Gitleaks
  gets `maxBuffer: 64 MiB` (8-11).
- `command(binary, args, cwd, limits)` (40-60):
  - It uses `execFile` with no shell.
  - It deletes `GITLEAKS_CONFIG` and `GITLEAKS_CONFIG_TOML` from the
    environment (43-44).
  - `ENOENT` throws `Error('unavailable')`. Every other failure (timeout,
    maxBuffer overflow, non-zero exit) throws a generic suppressed error
    (54-58).
  - The message string is the status channel.
- `versionNumber(output)` extracts the first `\d+\.\d+\.\d+(-[\w.]+)?`, or
  returns `"unknown"` (108-110).
- `locate(fixtures, root, file, raw, line, claim)` (73-106) maps a finding
  back to a byte range:
  - It relativizes the path, which must equal a fixture path (76-78).
  - It byte-searches `raw` in the fixture content with overlapping hits
    (81-91).
  - It filters by 1-based line: the count of `\n` in the prefix, plus 1 (89).
  - Repeated identical `(path, raw, line)` tuples within one scan take
    ascending unclaimed offsets (93-102).
  - Zero or several candidates throw `"Ambiguous or unmappable"` (103-104).
    **Scanner columns are ignored.**
- Every adapter declares `capabilities: {ranges: true, classification: true}`.

### 5.2 Per-scanner adapters

- **`redact-secret`** (336-365, **product**):
  - Runs in process: `@redact-secret/core` `initialize()`, then `scan(text)`
    per fixture, with the text re-read from scratch as UTF-8 (351).
  - UTF-16 indices are converted to bytes with
    `Buffer.byteLength(text.slice(0, i))` (355-356).
  - `family = findingFamily('redact-secret', detector, type)`.
  - It is the only adapter that passes `action` (360).
  - Configuration: `{adapterVersion:3, familyMappingVersion, detectors:'default', runtime:'node'}` (341).
  - Version comes from the `VERSION` export (342-345).
- **`gitleaks`** (366-387):
  - Invocation: `gitleaks dir <root> --no-banner --no-color --exit-code 0
    --report-format json --report-path -` (12).
  - Configuration: `{adapterVersion:2, binary, arguments, processLimits,
    rules:'default', environmentRuleOverrides:false}` (371).
  - Parsing:
    - Output is one JSON array (382-383).
    - `withoutDecodedDuplicates` (119-123) drops `decoded:base64` rows that
      duplicate a plain row, except `private-key`.
    - `normalizeGitleaks` (128-153) calls `locate(File, Secret, StartLine)`.
    - Decoded rows need `decode-depth:1` and go through PEM recovery
      (140-152) or `locateDecodedBase64` (163-192).
  - `family = findingFamily('gitleaks', RuleID)`.
  - The pin is **8.30.1**.
- **`trufflehog`** (388-412):
  - Invocation: `trufflehog filesystem <root> --json --no-verification
    --no-update --results=verified,unknown,unverified` (13).
  - Parsing:
    - Output is NDJSON (404-410), located via `SourceMetadata.Data.Filesystem.{file,line}`.
    - `normalizeTrufflehogFindings` (324-333) splits AWS into key and secret.
    - `normalizeTrufflehog` (257-320) handles:
      - Shopify composites;
      - Postgres (DetectorType 968), by re-parsing URIs;
      - the default `locateTrufflehog` (244-252);
      - a percent-encoded fallback (206-241).
  - `family = findingFamily('trufflehog', DetectorName)`.
  - The pin is **3.97.4**. 3.97.6 re-keys results, so never use it for parity.
- **`flare-redact`** (413-438):
  - Runs in process: `scan(text, {disable:['pii','generic_assignment'],
    includeValues:false})`.
  - UTF-16 indices are converted to bytes.
  - `family = findingFamily('flare-redact', detector)`.
- **`openredaction`** (439-467):
  - Runs `new OpenRedaction({}).detect(text)` and reads `.detections[].position`
    as UTF-16.
  - `family = findingFamily('openredaction', type)`.

### 5.3 Pins, families and candidate installs

- Package pins (`package.json:133-135`) are `@redact-secret/core
  0.1.0-beta.11`, `flare-redact 1.6.1` and `@openredaction/core 1.1.5`.
  The binary pins are in `qualification/suite-v1.json:12-16`.
- `peer-checksums.json` records per-platform archive SHA-256 values.
  `provision-peers.mjs` (54-83) downloads the release archive, verifies it,
  extracts it at mode 0555, re-checks the version, and makes the directory
  read-only.
- `families.mjs`:
  - `familyMappingVersion = 2` (3).
  - The native tables for gitleaks (34-79), trufflehog (80-124),
    flare-redact (145-163) and openredaction (236-243).
  - `findingFamily` (250-260): an unmapped label yields no family. It never
    guesses.
- `pins.mjs` (`peerVersionProblems` 11-32, `assertPinnedPeers` 35-38) handles
  peer version enforcement for claim-producing runs.
- `candidate.mjs` installs product candidate tarballs. It is **#6**.

---

## 6. Neutrality hazards and deviations to resolve

| # | Hazard | Location | Resolution owner |
|---|---|---|---|
| 1 | Differential primary hard-coded to `redact-secret`; `redact-secret-only` label | `methods/differential.ts:26-49` | #3: reference scanner is a run parameter; the compatibility layer maps names back |
| 2 | Review ids strip only the `redact-secret` tool identity | `review.ts:4-10` | #3: strip the configured reference scanner |
| 3 | `structural.remove-segment` hard-codes `sendgrid-token`/`slack-token` | `operators/structural.ts:27-29` | #3: eligibility from evidence metadata |
| 4 | Lexical operators and `normalizeFinding` read the product `contracts` table (patterns, validators, allowlist) | `operators/lexical.ts:3,20-21`; `normalization.ts:3,7` | #3/#4: contract patterns and the family allowlist arrive as evidence/adapter inputs |
| 5 | Replay equality differs between `bench` (ranges) and `eval` (full finding) | `run.ts:150-152` vs `runtime.ts:24-28` | #3 picks one (full finding is stricter); #5 documents the difference |
| 6 | `bench` has no family allowlist; `eval` does | `normalization.ts:7` | #5 must compare each pipeline with its own rule |
| 7 | Timeouts and output overflow fold into `error` | `scanners/index.mjs:54-58` | contract distinguishes `timeout`/`malformed`; compatibility folds them |
| 8 | Locale-sensitive key sorting in two digests | `peer-observations.ts:53-62`, `fixture-index.ts:59-72` | digests are not parity targets; the compatibility module only |
| 9 | JS `toFixed` rounding and `ratio().n = denominator` quirk | `primitives.ts:25, 53` | #3 must reproduce exactly |
| 10 | Assessment re-derivation (`classifyFixture`) at load time | `run.ts:113`, `cases.ts:51` | evidence concern; the exporter/credential-evidence validates it, not the kernel |
| 11 | `action` (product policy action) is threaded only by the redact-secret adapter | `scanners/index.mjs:360`, `lattice.ts:82-86` | kept as a generic scanner-reported observation; it never affects outcomes |

Anything in the classification tables marked **#6** stays out of this
repository. That covers support status (`stable`, `provisional`, `pending`),
support matrices, promotion, qualification, release records and their
thresholds. The engine publishes measurements, and a downstream policy
interprets them.
