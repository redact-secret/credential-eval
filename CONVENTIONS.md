# Conventions

## Language

Use **evidence** for canonical input facts, **observation** for scanner output,
**outcome** for the relationship between an expected range and normalized
findings, and **qualification** only for downstream product policy.

Do not call an observation ground truth or describe a scanner as supported,
stable, best, or release-ready from evaluator output alone.

## Measurement semantics

- Preserve `EXACT`, `COVERED`, `OVERBROAD`, `PARTIAL`, and `MISS`.
- Use one documented range indexing convention. Convert adapter-specific
  offsets at the adapter boundary.
- Empty, malformed, timed-out, unavailable, and failed scanner results are
  distinct states; none may silently become `MISS`.
- Aggregate counts must reconcile with their per-case records.

## Identity and determinism

Use stable, URL-safe IDs. Persist protocol and schema versions separately from
implementation versions. Sort serialized collections by stable semantic keys,
not filesystem enumeration or completion order. Digests cover the exact bytes
whose identity they claim.

## Adapters

Adapters own scanner preparation, identity, execution, and output parsing.
They do not own scoring or expected behavior. Bound subprocess duration and
output, avoid shell interpolation, and record scanner mode/configuration.

## Artifacts and logs

Public artifacts contain normalized safe metadata, never matched secret text
or unbounded stdout/stderr. Diagnostic logs should identify cases, paths, and
offsets without reproducing credential-shaped values.

## Compatibility

Put legacy readers and writers behind explicit compatibility modules. Mark
derived artifacts as generated and include source and schema identities.
