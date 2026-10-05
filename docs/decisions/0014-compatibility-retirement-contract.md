# ADR 0014: Compatibility retirement contract

- Status: accepted
- Date: 2026-10-05
- Issue: #33 (parent: redact-secret-benchmarks#651)
- Amends: nothing frozen. Documentation only: no code, contract, schema, CI or
  version change. No compatibility item is removed.

## Context

Compatibility and oracle code was added during the extraction (#5): legacy
result writers, legacy-only kernel views, a legacy seed convention, parity
tools and goldens. The benchmark repository is cutting over and cleaning up
(redact-secret-benchmarks#651). Deleting too early breaks a reader; keeping
everything forever shapes the canonical model around a legacy schema.

## Decision

1. The boundary, the consumer inventory, the retirement requirements, the
   support window and the deletion sequence are in
   [docs/migration/compatibility-retirement.md](../migration/compatibility-retirement.md).
2. **The legacy validators are not removable compatibility.** The product maps
   its value validators to `legacy:*` names, so they have an active reader. They
   move to canonical names first (step D1), with the old names as aliases for
   the support window.
3. **Deletion is gated by the recorded oracle exit, not by a CI change**, and by
   a last-reader check on every item, with owner confirmation. Parity and ADR
   history are kept and marked superseded.
4. **CI stays one test job.** The canonical gate is unchanged. The compatibility
   audit is a documented command, because a separate job would add billed runner
   minutes for about three seconds of tests and splitting targets by name could
   silently drop a new test. Revisit at step D5.
5. **pii-eval uses the documented seams** (ranges, observations, determinism,
   bounded execution, reuse identity), not a shared framework, and must not
   carry credential family semantics.
6. **Product qualification stays out of the engine.** No support verdict,
   threshold or denominator moves here.

## Consequences

- Removal pull requests cite the document's gates and list callers per file.
- The benchmark repository's file-level inventory (#653) and this inventory
  are two halves of one map; each links the other.
- If a consumer is found that reads a compatibility writer, the item moves from
  "remove" to "keep", and the inventory is corrected in the same pull request.
