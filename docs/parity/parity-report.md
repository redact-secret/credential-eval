# Dual-run parity report (issue #5)

> **Current pin: `1020d2b5905e8973098235e57c4cdca3359bba57`** (issue #20).
> The full dual-run below was recorded at `c403475`. The move to `1020d2b5`
> was re-proven minimally; see
> [Re-pin to 1020d2b5](#re-pin-to-1020d2b5-issue-20) for exactly what was
> and was not re-run, and [Coverage at 1020d2b5](#coverage-at-1020d2b5)
> for what proves equivalence for each scanner at this pin.

This report compares the legacy TypeScript engine of
`redact-secret/redact-secret-benchmarks` at the then-pinned oracle commit
`c403475476647bc98cc5864bccd7265eddebeb91` with `credential-eval` on the
same corpus, the same scanner versions and the same accounting parameters. It
covers both legacy pipelines, each with its own comparison rule
([legacy-map](../migration/legacy-map.md) §1, §6 hazards 5-6):

- `bench` (`benchmarks/run.ts`, profile `measurement-v4`): per-category rows,
  v1.1 group accounting, the v1.0 → v1.1 `accountingDelta`, cross-suite
  `summary.json`;
- `eval` (`benchmarks/evaluate.ts`, profile `evaluation-v1`): twin, benign,
  mutation, metamorphic and differential methods over generated variants.

**Result: no unexplained drift.** Every difference is one of two documented
kernel/adapter deltas, listed by id in
[parity-summary.json](parity-summary.json). Two credential-eval runs of each
pipeline produced identical semantic digests.

> **Scope.** Parity proves engine equivalence on the **legacy parity
> projection** only: a parity-only oracle snapshot exported from the legacy
> fixture corpus, whose case ids (`<category>--<fixtureId>`), grouping and
> family names are legacy coordinates. It is not a canonical corpus and says
> nothing about the canonical `credential-evidence` model, which is being
> re-modeled separately. Legacy coordinates stay inside `tools/legacy-export/`,
> `tools/parity/` and `crates/credential-eval-compat/`; a CI test
> (`crates/credential-eval-contracts/tests/canonical_boundary.rs`) keeps them
> out of canonical code, schemas and the smoke fixtures.

## Pinned inputs

| Input | Identity |
|---|---|
| Legacy engine | `redact-secret-benchmarks@c403475476647bc98cc5864bccd7265eddebeb91`, Node v22.16.0, `npm ci`, generated fixtures checked fresh by the exporter |
| Parity projection (snapshot) | source `redact-secret-benchmarks@c403475 (legacy parity projection)`, 5,925 cases from 67 non-calibration categories, corpus digest `sha256:32483b46ecdd2aaa5832cfe962e23d48c3c965d5894a0a303a5296b67250bbf0` |
| Evaluation evidence | 141 contract families, 4 named validators, 13 benign taxonomies, `eval` allowlist on; canonical digest `sha256:1af8d70c6891eddf749f741364b35ba0c46d510a888d7e39111be04ec2c49c91` |
| Variant corpus (eval) | 47,917 variants, digest `sha256:e3f3d837ea6345a452bc2c54e02162f0a4fa09c21e2db0362eba4a721da74bae` (legacy also generated 47,917) |
| Gitleaks | 8.30.1, darwin-arm64 archive `sha256:b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5`, binary `sha256:ba52fb1bfabbcde42f032afad3d6e0b19dff8ed105229a16e7caa338bbc0e84f` (verified against legacy `scanners/peer-checksums.json`) |
| TruffleHog | 3.97.4 (never 3.97.6), archive `sha256:57e2a41c1e196cf96cae49ca2151f5e9207be2f5c41349b5ea49cb5dcfc606b7`, binary `sha256:8c7af13e84f217bffd10aec09780fb7bbe59892187c99006291cef9c6f001beb` |
| npm scanners | `@redact-secret/core` 0.1.0-beta.11 (`sha512-CDJw3x121Dn4…`), `flare-redact` 1.6.1 (`sha512-13Htu6VPk2tt…`), `@openredaction/core` 1.1.5 (`sha512-SpQTBhVV4p3r…`); integrity identical to legacy `package-lock.json`; full values and installed-tree digests in the summary |
| credential-eval | this branch, `credential-eval 0.1.0`, protocol `credential-eval-protocol/1`, cargo 1.98.1 |
| Run config | [`tools/parity/run-config.json`](../../tools/parity/run-config.json) (built-in specs; Node-shim timeout 30 min and stdout cap 256 MiB, see below); `bench` config hash `sha256:79e8e4c4…`, `eval` config hash `sha256:fc299b4d…` |
| Accounting | legacy `qualification/suite-v1.json` values (`min_denominator 5`, floors, `replays 2`, `z 1.96`, precision 6) |

## Pin alignment with credential-evidence (issue #14)

credential-eval's parity was proven at legacy
`c403475476647bc98cc5864bccd7265eddebeb91`. credential-evidence proved its
projection parity at legacy `ade8a10bd7922765110a68986b0690eb3861f2e5`
(its `docs/migration/cutover.md`). `ade8a10` is an ancestor of `c403475`, 7
commits earlier. Both results have to describe the same legacy inputs before
`redact-secret-benchmarks` switches over.

**This is a path-diff proof, not a re-run.** Parity was not re-run at either
revision for this alignment. In the pinned legacy clone:

```bash
git diff --stat ade8a10 c403475 -- benchmarks/ scanners/ fixtures/ corpora/ schemas/ baselines/ \
  package.json package-lock.json scripts/generate-fixtures.mjs
#  benchmarks/feature-claims.json | 1090 ++++++++++++++++++++++++++++++++++++++++
#  1 file changed, 1090 insertions(+)
```

The paths cover everything either parity harness reads: the legacy engine,
`bench` and `eval` sources (`benchmarks/`), scanner adapters and peer pins
(`scanners/`), fixtures and their generator, corpora, schemas, baselines and
the npm dependency pins. The only change is a new data file,
`benchmarks/feature-claims.json`. Nothing on the parity path reads it:
`git grep -l feature-claims c403475` lists only the file itself, a decision
record, `tests/feature-claims.test.mjs` and the site under `web/`, and none of
the legacy engine, `bench`, `eval`, `tools/legacy-export/` or `tools/parity/`
refers to it.

So for every parity input the two revisions are byte-identical, and
credential-eval's parity (above) and credential-evidence's projection parity
hold at both `ade8a10` and `c403475`. The evidence is the path diff alone. If
either repository re-pins to another legacy revision, the alignment must be
proven again: by a new path diff that comes out clean in the same way, or,
if any parity input changed, by re-running parity at the new pin.

## Re-pin to 1020d2b5 (issue #20)

The legacy pin moved from `c403475476647bc98cc5864bccd7265eddebeb91` to
`1020d2b5905e8973098235e57c4cdca3359bba57`. That is the
`redact-secret-benchmarks` production revision that re-pinned to the
published `@redact-secret/core` 0.1.0-beta.12
(redact-secret-benchmarks#600, #601). credential-evidence re-pins to the
same revision (credential-evidence#20). The maintainer decided on a
**minimal re-proof**: a path diff, then `bench` parity on the changed
inputs only. This is not a full re-run.

### Path diff

In the pinned legacy clone, over the same paths as the issue #14 alignment
plus `qualification/`:

```bash
git diff --name-status c403475 1020d2b5 -- benchmarks/ scanners/ fixtures/ corpora/ schemas/ \
  baselines/ qualification/ package.json package-lock.json scripts/generate-fixtures.mjs
```

57 files change across 71 commits. Grouped by what reads them:

- **Engine and adapter code: unchanged.** `benchmarks/run.ts`,
  `benchmarks/evaluate.ts`, `benchmarks/engine/`, every existing module in
  `benchmarks/lib/` (scoring, lattice, accounting, reporting, run summary),
  `scanners/*.mjs` (adapters, `families.mjs`, pins),
  `scanners/peer-checksums.json` and `scripts/generate-fixtures.mjs` have no
  diff.
- **New or changed files that nothing on the parity path reads:**
  `benchmarks/lib/peer-rule-families.ts`, `scanners/peer-rule-families.json`,
  `scanners/peer-registry.json`,
  `benchmarks/evaluation/domains/pii/runtime-comparison.ts` and
  `peer-runtime-throughput.ts`, `benchmarks/evaluation/release-record*.ts`,
  `qualification/runtime-comparison-v2.json`, `baselines/0.1.0-beta.12.json`.
  None of these files is imported by `run.ts`, `evaluate.ts`, the
  `benchmarks/lib` engine paths, `scanners/*.mjs`, `tools/legacy-export/` or
  `tools/parity/`.
- **Changed inputs.** The runs below re-prove these:
  - `fixtures/generated/detector-coverage.mjs` adds 25 Stripe `sk_org_`
    fixtures (`stripe-token-policy-org-*`: 15 policy/T3 positives and 10
    controls). `benchmarks/generated-corpora.json` goes from 1,309 to 1,334
    fixtures, and `benchmarks/fixture-detectors.json` and
    `benchmarks/fixture-index.json` gain entries for them.
  - `benchmarks/evaluation/domains/credential/assessment.ts` adds
    classification rules for the `sk_org_` support-policy floor (field
    claims, one `classifyFixture` rule and one control rule). The rule also
    moves 3 existing fixtures, `stripe-token-shape-5-{bare,quoted,unicode-crlf}`,
    from `pending` to `policy`/T3. The contract table is unchanged: the
    exported `evidence.json` is byte-identical to the `c403475` export.
  - `@redact-secret/core` goes from 0.1.0-beta.11 to 0.1.0-beta.12 in
    `package.json`, `package-lock.json` and `qualification/suite-v1.json`.
- **Data that does not reach either engine's semantics:** provider
  dossiers, `feature-claims.json`, `detector-inventory.json`,
  `detectors.json` (source revision only), `pin-manifest.json`,
  `performance-criteria.json`, `review-ledger.json`,
  `accepted-regressions.json` and `support/taxonomy.json` (one note). Also
  `benchmarks/evaluation/domains/credential/evidence.ts` and
  `benchmarks/validate-evidence.ts`, where qualification-evidence validation
  now takes an optional frozen suite. That code is on neither the `bench`
  nor the `eval` path.

### What was re-run

In credential-eval, `adapters/node` pins `@redact-secret/core`
0.1.0-beta.12. All 12 lockfile entries match legacy's `package-lock.json`
at `1020d2b5` in version, `resolved` and `integrity`. The adapter version
stays `3`. [adapters.md](../adapters.md) bumps it only when invocation,
parsing, offset conversion or family mapping changes, and none of them did:
legacy `adapterVersion` is still 3, and `shim.mjs` and the configuration
hash are unchanged. The new pin is recorded in `ScannerIdentity`: version
0.1.0-beta.12, lockfile digest, package integrity and tree digest.

Inputs were validated first. The exporter passed at `1020d2b5` (5,950
cases from 67 categories, with fresh generated corpora and assessments).
Every adapter resolved its pinned version. A 26-case smoke over the new
fixtures completed for all five scanners. Then each run below ran once, in
sequence, with `--jobs 4`, TruffleHog 3.97.4 and Gitleaks 8.30.1 first on
`PATH`, and both engines in published mode:

| Run | Input | Scanners | Rows compared | Unexplained | Legacy | credential-eval |
|---|---|---|---|---|---|---|
| (a) `bench` | `detector-coverage` category, 1,334 fixtures: the 25 new `sk_org_` fixtures, the 3 reclassified shape-5 fixtures and the rest of that category | all five | 6,670 | 0 | 16 s | 9 s |
| (b) `bench` | full projection, 5,950 cases, 67 categories | `redact-secret` 0.1.0-beta.12 only | 5,950 | 0 | 31 s | 8 s |

Every dimension matched in both runs: corpus identity, scanner status and
version, row sets, row metadata, expected spans, byte ranges, normalized
findings, outcome lattice, group accounting, `accountingDelta`, and
`summary.json` overall and byDetector (5/5 and 550/550 in run (a), 1/1 and
110/110 in run (b)). No known-nondeterminism case occurred, and every
legacy row was a fresh observation.

Notes on scope:

- Legacy `bench` can only restrict by category (`--category=`). A category
  is also the smallest unit with its own corpus hash, group accounting and
  summary. Run (a) therefore covers the whole `detector-coverage` category
  rather than a filtered fixture list. credential-eval ran the same
  category: the full export, filtered by `grouping.group`, with the corpus
  digest recomputed and the legacy index filtered to that category.
- Legacy `bench` always runs every registered scanner. In run (b) it ran
  redact-secret live and reused its committed peer snapshots for the other
  scanners. Those peer rows were not compared:
  `compare.mjs bench --scanners redact-secret` limits the comparison to the
  scanner that was re-run.

### What was not re-run

- The `eval` pipeline, in either engine. Its engine code is unchanged and
  its evidence file is byte-identical. Its changed inputs are the same 25
  new fixtures, the 3 reclassified fixtures and beta.12.
- `bench` for Gitleaks, TruffleHog, flare-redact and OpenRedaction outside
  `detector-coverage`. Their binaries, packages, adapters and those
  fixtures are unchanged.
- A second run of each pipeline to check determinism digests, and any
  performance measurement.

### Commands

```sh
# Legacy clone at 1020d2b5, npm ci (which generates the fixtures); PEER_BIN first on PATH.
"$LEGACY/node_modules/.bin/tsx" tools/legacy-export/export.mts "$LEGACY" "$OUT/export"
# (a) detector-coverage subset of the export: cases with grouping.group ==
#     detector-coverage, corpus digest recomputed, index filtered -> $OUT/dc
(cd "$LEGACY" && npm run bench -- --category=detector-coverage --live-peers)
credential-eval run --corpus "$OUT/dc/snapshot.json" --config tools/parity/run-config.json \
  --node-dir adapters/node --jobs 4 --out a/bench-artifact.json --observations-out a/bench-observations.json
credential-eval compat legacy-bench --artifact a/bench-artifact.json --index "$OUT/dc/legacy-index.json" --out-dir a/bench-legacy
node tools/parity/compare.mjs bench "$LEGACY/public/results" a/bench-legacy --observations a/bench-observations.json
# (b) full corpus, redact-secret only
(cd "$LEGACY" && npm run bench)
credential-eval run --corpus "$OUT/export/snapshot.json" --config tools/parity/run-config.json \
  --scanner redact-secret --node-dir adapters/node --jobs 4 --out b/bench-artifact.json --observations-out b/bench-observations.json
credential-eval compat legacy-bench --artifact b/bench-artifact.json --index "$OUT/export/legacy-index.json" --out-dir b/bench-legacy
node tools/parity/compare.mjs bench "$LEGACY/public/results" b/bench-legacy --observations b/bench-observations.json --scanners redact-secret
```

### Identities

| Input | Identity |
|---|---|
| Parity projection | source `redact-secret-benchmarks@1020d2b (legacy parity projection)`, 5,950 cases, 67 categories, corpus digest `sha256:ff4b89214dbf1a84145c0ec666c4f1bce7790b753ed673df874e2f8e5a80981a` |
| `detector-coverage` subset (a) | 1,334 cases, corpus digest `sha256:fe9a02e1c0a99b0e4b06f92b5684c7123d1da415baef7d352373bd7deb08f62f` |
| `@redact-secret/core` | 0.1.0-beta.12, `sha512-fDVwt2U7VFSK…` (full values in the summary) |
| Config hash | (a) `sha256:79e8e4c4…` (the same as at `c403475`), (b) `sha256:d019847c…` (`--scanner redact-secret`) |
| Semantic digest | (a) `sha256:49e97800f70519a59733f90efcc4f29c897f2a4a16e80a8131973f2308a59c33`, (b) `sha256:e1110a7b6485e51c8423e5bd5a06b5ffdc2595d8b53383bc731ff54328b25a2f` |

The sanitized record is `repin_1020d2b5` in
[parity-summary.json](parity-summary.json). It holds counts, case ids and
digests only. The rest of that file records the `c403475` full run.

## Coverage at 1020d2b5

This section answers one question: at the current pin, what proves that
credential-eval measures each of the five scanners the way the legacy
engine does over the full corpus? Three pieces of evidence exist. Each
proves something different:

- **(a) Legacy engine vs credential-eval, re-run at `1020d2b5`.** Runs (a)
  and (b) [above](#what-was-re-run): the `detector-coverage` category
  (1,334 fixtures, every fixture that changed) for all five scanners, and
  the full 5,950-case projection for `redact-secret` 0.1.0-beta.12. Both
  have 0 unexplained differences.
- **(b) Path diff `c403475` → `1020d2b5`** ([above](#path-diff)). The legacy
  engine and adapter code, the peer binaries and checksums, the npm packages
  other than `@redact-secret/core`, and the fixtures of the other 66
  categories have no diff. So the full `c403475` dual run
  ([Results](#results), all five scanners, all 67 categories, 0 unexplained)
  still holds for those inputs at `1020d2b5`.
- **(c) credential-evidence's five-scanner dual run.** All 5,950 cases of the
  canonical snapshot vs the legacy corpus at `1020d2b5`, both measured
  through credential-eval `d5f2fb2` (this pin): identical findings and
  identical per-case measurement on 5,950 of 5,950 cases for every scanner,
  **0 unexplained**. The aggregate differences all come from documented
  tier and kind moves
  ([dual-run report](https://github.com/redact-secret/credential-evidence/blob/main/docs/migration/dual-run-report.md)).
  This compares two corpora on one engine. It is not engine parity: it proves
  that the canonical snapshot measures like the legacy corpus, which (a) and
  (b) tie to the legacy engine.

| Scanner (version) | (a) re-run at `1020d2b5` | (b) path diff carries `c403475` full parity | (c) dual run, 5,950 cases (findings) |
|---|---|---|---|
| `redact-secret` 0.1.0-beta.12 | full corpus (5,950) and `detector-coverage` | not needed: re-run on the full corpus | 0 unexplained (3,156) |
| `gitleaks` 8.30.1 | `detector-coverage` (1,334) | the other 66 categories | 0 unexplained (2,410) |
| `trufflehog` 3.97.4 | `detector-coverage` (1,334) | the other 66 categories | 0 unexplained (1,046) |
| `flare-redact` 1.6.1 | `detector-coverage` (1,334) | the other 66 categories | 0 unexplained (1,111) |
| `openredaction` 1.1.5 | `detector-coverage` (1,334) | the other 66 categories | 0 unexplained (27,253) |

So all 67 categories are covered for every scanner at `1020d2b5`, through
the corpus-measurement (`bench`) path that an official run uses (official
configurations have no `methods`). For the four peer scanners, the re-run
covers the changed category, and the path diff carries the other 66 over
from `c403475` without a re-run. The `eval` pipeline was last compared at
`c403475` ([What was not re-run](#what-was-not-re-run)).

## Reproduction

```sh
LEGACY=/path/to/redact-secret-benchmarks   # clean clone at 1020d2b5…, npm ci, npm run fixtures
PEER_BIN=/path/to/peer-bin                 # node $LEGACY/scripts/provision-peers.mjs output
OUT=/path/to/parity-out                    # never committed
sh tools/parity/run.sh all                 # or: export | legacy | ours | compare
```

`run.sh` runs, in order:

1. `tools/legacy-export/export.mts` (via the legacy `tsx`): snapshot, evidence
   and the legacy index sidecar. It refuses any other legacy commit, stale
   generated corpora, stale assessments, lone surrogates and unmapped legacy
   validators.
2. Legacy `npm run bench -- --live-peers` and
   `npm run eval -- --output=$OUT/legacy/evaluation.json`, with the pinned
   peers first on `PATH`.
3. `credential-eval run` twice per pipeline:

   ```sh
   credential-eval run --corpus snapshot.json --config tools/parity/run-config.json \
     --node-dir adapters/node --jobs $JOBS --out bench-artifact.json --observations-out …
   credential-eval run --corpus snapshot.json --config tools/parity/run-config.json \
     --node-dir adapters/node --jobs $JOBS \
     --methods twin,benign,mutation,metamorphic,differential --reference redact-secret \
     --evidence evidence.json --seed legacy-category \
     --legacy-eval-out eval-legacy.json --out eval-artifact.json --observations-out …
   credential-eval compat legacy-bench --artifact bench-artifact.json \
     --index legacy-index.json --out-dir bench-legacy
   ```

4. `tools/parity/compare.mjs` for both pipelines (exit 1 on any unexplained
   difference) and the four semantic digests.

The recorded run used `JOBS=2` on a heavily shared host (load average ≈ 30 on
10 cores); see the OpenRedaction note below.

## How the comparison works

- **Compatibility writer** (`crates/credential-eval-compat`, removable):
  `compat legacy-bench` renders the canonical bench artifact into the legacy
  `public/results/<category>.json` rows, groups, `accountingDelta` and
  `summary.json` (`overall`, `byDetector` over `fixture-detectors.json`),
  folding `timeout`/`malformed` into `error`, dropping `coDetected: false`,
  re-adding `scored: false` and `comparable: false`, restoring category-local
  ids and paths and the legacy row `group` label from the index.
  `run --legacy-eval-out` renders the evaluation report into the semantic
  subset of `evaluation.json` (it needs the generation attempts, which the
  canonical artifact does not publish), mapping `reference-only` back to
  `redact-secret-only`.
- **Parity settings** (kernel-deltas): reference `redact-secret` (N1-N3), the
  `sendgrid-token`/`slack-token` segment rules (N4), contract patterns and the
  four legacy validators (N5), the legacy benign vocabulary (N7), the contract
  allowlist for `eval` and none for `bench` (N8), `compat::legacy_seed` (H2).
- **Excluded as volatile or legacy-digest** (legacy-map §4.1, kernel-deltas
  H1): run ids, timestamps, durations, `observation`, `revision`, `dirty`,
  `lockHash`, `runtime`, `parametersHash`, variant provenance hashes, review
  entry ids and evidence. The review queue is compared **by membership**
  (case, method, targets, variant, peer, disagreement, family-blind ranges,
  classifications, reason). Actual findings are compared sorted (R1).
- **Classification of differences.** A difference is explained only by a rule
  in the comparator; everything else counts as unexplained and fails the run.

## Results

### `bench` pipeline

| Dimension | Matched / compared | Explained deltas |
|---|---|---|
| categories, corpus identity (raw-file hash, fixture and span counts) | 67/67, 67/67 | |
| scanner status + version + replays (category × scanner) | 335/335 | |
| row sets | 335/335 | |
| row metadata (path, group, kind, tier, contract, twinOf) | 29,625/29,625 | |
| expected spans | 29,625/29,625 | |
| byte ranges (actual, family-blind) | 29,625/29,625 | |
| normalized findings (ranges + family + action) | 29,624/29,625 | 1 known nondeterminism |
| outcome lattice (spanOutcomes, leaked/collateral bytes, flagged, findings, coDetected, actionCounts) | 29,625/29,625 | |
| group accounting (v1.1 groups) | 335/335 | |
| `accountingDelta` (v1.0 figures, causes) | 335/335 | |
| `summary.json` overall / byDetector | 5/5, 550/550 | |

Findings per scanner (deduplicated, whole corpus): flare-redact 1,111,
gitleaks 2,410, openredaction 27,249, redact-secret 2,986, trufflehog 1,046;
every scanner `complete` in both engines.

The bench snapshot prefixes every path with its category
(`<category>/<fixture path>`) so that one snapshot holds all categories, while
legacy materializes each category separately. Byte ranges and findings match
on every row, so the prefix does not change any scanner's findings on this
corpus (legacy-map §4.5).

### `eval` pipeline

| Dimension | Matched / compared | Explained deltas |
|---|---|---|
| scanner status + version, case/variant counts, case set | 1/1, 1/1, 1/1 | |
| case metadata (method, targets, taxonomy) | 18,488/18,488 | |
| generated variants (id, path, strategy, kind, tier, transformation) | 18,413/18,488 | 75 O2 (mutation) |
| generation attempts | 18,488/18,488 | |
| twin assertions (case × scanner) | 6,955/6,955 | |
| benign assertions | 10,520/10,520 | |
| metamorphic assertions | 22,670/22,670 | |
| mutation assertions | 22,611/22,670 | 59 O2 |
| variant rows: expected / byte ranges / outcome lattice / metadata | 209,280/209,280 each | |
| variant rows: findings | 209,263/209,280 | 17 known nondeterminism |
| variant rows of the O2 `authored.twin` variants | 0/680 | 680 O2 |
| differential comparisons (disagreement, classification) | 5,925/5,925 | |
| differential completeness | 5,925/5,925 | |
| differential observations (actual + classifications) | 5,922/5,925 | 3 known nondeterminism |
| review queue (membership) | 19,054/19,054 | |
| summaries byMethod / byDetector / byOperator | 200/250, 125/142, 15/16 | 50, 17, 1 O2 |
| summaries byTaxonomy / axesByDetector | 12/12, 142/142 | |
| summary self-consistency (each side recomputed from its own results) | 10/10 | |
| resolution (accounted counts) | 200/250 | 50 O2 |
| unresolved groups | identical (none in either engine) | |
| assertion `accountingDelta` groups | 1/8 | 7 O2 |
| failed assertions (multiset) | 83,976/84,036 | 60 O2 |
| generation errors | identical (0) | |

### Explained deltas

1. **O2: first authored twin by case id** ([kernel-deltas](../migration/kernel-deltas.md)
   O2). A mutation case attaches one authored twin of its seed. Legacy takes
   the first in corpus file order; the kernel takes the first by case id,
   because a snapshot's case order is not semantic. The choice differs for the
   75 seeds with more than one authored twin. For those 75 mutation cases the
   `authored.twin` variant is a different (equally valid) authored twin, so
   its row, its absolute and `must-flip` assertions, and the summary rows that
   count them differ. The comparator sets aside exactly those assertions,
   recomputes every summary from each side's results, and requires the rest to
   match; it does. Resolution, the assertion delta and the failure multiset
   differ only in strata whose byMethod rows are O2. Not fixed: reproducing
   file order would make case order semantic.
2. **Gitleaks same-range, different-rule findings** ([adapters](../adapters.md#determinism)).
   Gitleaks sometimes reports one range under two rules. Legacy keeps whichever
   rule it emitted last, which varies between runs; the adapter processes rows
   in a canonical order. The comparator accepts a family-only difference only
   when credential-eval's raw observations show the same scanner reporting that
   range under several families, the legacy family among them. In this run:
   1 bench row (`beta8-384b--aws-bedrock-long-term-api-key-curl-bearer`,
   range 111:243), 17 eval variant rows and 3 differential observations. No
   outcome, flag or group figure changed in this run; classifications (which
   keep every family) matched exactly.

### Deltas found and fixed in this issue

- **Look-ahead contract patterns** (kernel-deltas N6). Two pinned contracts,
  `composio-api-key` and `travisci-api-token`, use ECMAScript look-ahead. The
  `regex` crate rejected them, so no evaluation over the full contract table
  could start. Contract patterns now compile with `fancy-regex` under an
  explicit backtracking bound; regression test
  `look_ahead_contract_patterns_compile_and_match`.
- **Four legacy validators, not two** (kernel-deltas N5). Besides
  `discord-bot-token` and `confluent-cloud-api-secret`, the beta.8 arrival
  contracts `gitlab-runner-authentication-token` and
  `gitlab-routable-personal-access-token` carry validators. All four are ported
  (`crates/credential-eval-compat/src/validators.rs`), named by the evidence
  file, and the exporter refuses an unmapped one. Variant strategies match
  legacy on every case.

### Operational notes (not drift)

- **Node-shim bounds.** Legacy runs the npm scanners in process with no
  timeout or output cap. With the default 120 s bound, OpenRedaction over the
  47,917 eval variants timed out on the loaded host (`timeout`, correctly
  not-measured). The parity config raises the shim scanners' timeout to 30 min
  and stdout cap to 256 MiB; the binaries keep the defaults.
- **OpenRedaction wall-clock regex timeout.** OpenRedaction 1.1.5 abandons any
  regex execution slower than 100 ms. A `--jobs 8` eval run on the loaded host
  hit it on one long input in one replay; the replay rule marked OpenRedaction
  `unstable` and discarded its findings instead of scoring them. The recorded
  runs used `--jobs 2` and were stable. Legacy has the same exposure in
  process.

### Determinism

| Pipeline | Run 1 semantic digest | Run 2 semantic digest |
|---|---|---|
| bench | `sha256:e9fe5fba1d6a09b6316ad5c0c3d333069f97caa1a247fd573a82faa8b3e50509` | identical |
| eval | `sha256:623f7efba1bca061d9dcc2ab450ce9880d2f472484aee6082ae2520ac672640f` | identical |

Jobs-independence (1 vs 8) is covered by the CLI tests
(`tests/cli.rs`, `tests/methods.rs`); the digest excludes only `non_semantic`.

### Timing (indicative only; shared host)

Legacy: bench 520 s, eval 460 s (sequential, in-process npm scanners).
credential-eval, release build: bench 46 s (`--jobs 8`) / 103 s (`--jobs 2`),
eval 322-698 s (`--jobs 2`) under heavy external load. Performance evidence
belongs to #7.

## Machine-readable summary

[parity-summary.json](parity-summary.json) holds, per dimension, the compared
and matched counts, the explained delta ids by classification and the
unexplained count (0), plus every identity above. It contains counts, case/row
ids and digests only: no fixture content, matched values or scanner output.
