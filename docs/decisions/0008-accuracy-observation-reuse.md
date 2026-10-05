# ADR 0008: Whole-population accuracy observation reuse

- Status: accepted
- Date: 2026-10-04
- Issue: #40 (parent: redact-secret-benchmarks#704; performance is #42)
- Amends: nothing frozen. Adds optional fields to a v1 `ObservationSet` and to
  `non_semantic.execution` of a run artifact (revision v1.6,
  [ADR 0001](0001-freeze-v1-contracts.md)). The measurement protocol
  (`credential-eval-protocol/1`), scoring and every semantic field are unchanged.

## Context

Replaying a candidate product against an unchanged population re-scanned every
peer, although a peer's accuracy observation depends only on the bytes it was
shown and on the scanner that ran. An `ObservationSet` was bound to
`corpus_digest`, which also covers expectations and so changes with a label or
an evidence release.

## Decision

1. **Accuracy observation identity.** An observation may serve a run when all
   of these are equal:
   - fixture paths and exact bytes: `measurement.input_digest`
     (`corpus::input_digest`, SHA-256 over sorted `{path, sha256(content)}`).
     A methods run scans generated variants, so this is the variant bytes; the
     operator contract and seed are bound through those exact bytes;
   - measurement protocol: `measurement.protocol_version`;
   - the scanner's recorded `ScannerIdentity`: version, mode, adapter
     id/version (normalization semantics), `configuration_hash`
     (activation/options), provenance (executable, runtime, shim and package
     digests/integrity, which also bind platform) and build;
   - restriction: findings restricted by a family allowlist
     (`measurement.restriction`) only serve a run with the same allowlist;
     unrestricted findings serve any.
   The evidence release tag, expectations, labels and the engine version are
   **not** identity: unchanged measurements stay valid across them.
2. **Whole-population reuse.** `run --reuse-observations <set>` takes the
   `--observations-out` of an earlier run. After every scanner's version probe
   (a bounded `--version`, not a scan) a scanner whose identity is unchanged
   keeps its recorded observation and launches no scan task. A changed, new or
   `--fresh <id>` scanner runs fresh, with the reason recorded. The source is
   neither mutated nor re-verified by scanning: reuse never re-executes a
   verified observation, and its original receipt (replays, duration, identity)
   is carried into the new observation set verbatim. Newly accepted
   observations still need two agreeing fresh replays, as before.
3. **Fail clearly, never around.** Refused with exit 4 and no artifact: no
   measurement binding (written before v1.6), other protocol, different fixture
   inputs, incompatible restriction, content that fails validation, and a
   recorded observation of an unchanged scanner that is not a complete,
   agreed, sufficiently replayed one (unstable, timeout, malformed, ...).
   Per-case unmeasured paths stay in the carried observation, so they remain
   unmeasured, never findings or misses.
4. **Fixture changes.** Added, changed or removed inputs, paths or generated
   variants change `input_digest`: reuse is refused and the documented
   fallback is a fresh run of the changed population (omit the flag). The new
   artifact is bound to the new corpus; old artifacts are immutable and
   removed cases leave its denominators. Case-level reuse of unchanged inputs
   is deliberately not done: adapter independence and variant dependencies are
   not demonstrated, and the whole-population saving does not need it.
5. **Expectation-only changes re-score.** Labels, expected spans and
   accounting do not enter `input_digest`, so compatible observations are
   re-bound to the new `corpus_digest` and scored again without a scan.
6. **Nothing derived is cached.** Assertions, comparisons, relations, review
   queue, accounting and aggregates are recomputed from observations on every
   run, so a changed product or reference regenerates every dependent
   differential result. Only the observations are reused.
7. **Mixed origin.** A run mixing fresh and reused scanners is a valid
   exploratory run. Its semantic digest equals that of a fully fresh run on
   the same population, because origin is provenance
   (`non_semantic.execution.scanners.<id>.{origin, origin_reason}` and
   `execution.reuse.{source_digest, input_digest}`). An `official` run refuses
   `--reuse-observations`: its publication class asserts that every scanner
   was measured under that run's pins. Admitting reuse there needs its own
   decision.
8. **No performance claims.** Reuse is an accuracy contract. A reused scanner
   ran no scan task in the run; recorded durations are the source's
   non-semantic diagnostics and the timing record marks them `reused`. Neither
   feeds a performance benchmark, and latency confirmation is not waived
   (see #42).

## Consequences

- Peers must be resolvable on the host so their identity can be verified; an
  unresolvable peer runs fresh and records `unavailable`.
- `ObservationSet` files written before v1.6 cannot be reused.

## Verification

`crates/credential-eval-cli/tests/reuse.rs`: product-only replay launches no
peer scan and matches a fresh run's semantic digest with original receipts
intact; a changed scanner runs fresh and is named; changed or removed fixtures
are refused before any scan; an expectation-only change re-scores without a
scan and equals a fresh run; unbound, other-protocol, wrong-restriction,
corrupt, under-replayed and non-complete sources fail clearly.
