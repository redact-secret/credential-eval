# Legacy oracle goldens

Raw outputs of the legacy TypeScript engine on synthetic inputs. The Rust
kernel must reproduce them (`crates/credential-eval-kernel/tests/oracle.rs`).

- Legacy: `redact-secret/redact-secret-benchmarks` at
  `c403475476647bc98cc5864bccd7265eddebeb91` (recorded in every file's
  `provenance.legacyCommit`; the tests refuse any other commit).
- Generator: [`tools/oracle/generate.mts`](../../../tools/oracle/generate.mts).
  A seeded PRNG builds every input, so regeneration is byte-identical.
- Content: synthetic only. Credential-like values (`zq_…`, `SYN.…`,
  `syn-…`) match no real provider format, and the evaluation run replaces the
  two legacy families it touches (`sendgrid-token`, `slack-token`) with
  synthetic patterns.

| File | Legacy functions |
|---|---|
| `primitives.json` | `round` (JS `toFixed`), `wilson`, `proportion`, `ratio`, `accountCounts`, `unresolvedGroups` |
| `lattice.json` | `scoreRow`, `union`, `bytesOutside` |
| `accounting.json` | `score`, `accountGroups`, `aggregateGroups` (v1.0), `accountingDelta`, `encodeOutcome` over 90 random suites and four accounting configurations |
| `selection.json` | `summarizeRun` (`selectionGroups`: overall and by detector) |
| `twin-probe.json` | `twinProbe`, including the un-probeable-with-twins refusal |
| `evaluation.json` | case construction (a copy of `loadCases` without file I/O), `evaluationInputs`/`generateCase` with every operator, `executeEvaluation` with six fake scanners (complete, widened, partial, unstable, unavailable, range-unsupported): assertions, variant rows, differential comparisons and observations, review queue, summaries, resolution, unresolved groups, assertion delta, failures, exit code, seeded choices |

Regenerate (only when the pinned legacy commit changes):

```sh
LEGACY=/path/to/redact-secret-benchmarks   # checked out at the pinned commit, npm ci done
"$LEGACY/node_modules/.bin/tsx" tools/oracle/generate.mts "$LEGACY" tests/fixtures/oracle
```

Never edit a golden by hand, and never regenerate one to make a kernel change
pass: a mismatch is either a kernel bug or an intentional delta that belongs in
[`docs/migration/kernel-deltas.md`](../../../docs/migration/kernel-deltas.md)
and in the test's documented mapping.
