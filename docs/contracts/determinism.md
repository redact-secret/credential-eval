# Determinism rule

Suppose two runs have the same evidence snapshot, protocol version, scanner
versions and modes, adapter versions and configuration. Their artifacts must
then be identical everywhere except `non_semantic`. Parallel scheduling,
scanner completion order, filesystem enumeration and input ordering must not
change any semantic byte.

## Ordering: sort by semantic keys

`RunArtifact::canonicalize` applies the following order. Every writer must
call it, or produce the same order some other way.

| Collection | Sort key |
|---|---|
| `manifest.scanners` | `id` |
| `manifest.methods` | `(id, version)` |
| `scanners` | `scanner` |
| `scanners[].findings` | `(path, start, end, family, action)`, with duplicates removed |
| `scanners[].cases` | `case_id` |
| `scanners[].cases[].actual` | `(start, end, family, action)` |
| `scanners[].assertions` | `(case_id, method, variant, baseline, candidate, assertion, status, reason)` |
| `variants` | `(case_id, variant)` |
| `comparisons` | `(case_id, variant, reference, peer, ...)` |
| every map (`groups`, `resolution`, `action_counts`, `configuration`, ...) | key, in byte order |

Collections whose order *is* semantic keep their authored order. There is one
such collection: `span_outcomes`, which follows the order of the case's
secret spans. The case's spans are themselves sorted by `start`.

## Deduplication

The kernel deduplicates findings by `(path, start, end)`. When duplicates
differ in `family` or `action`, the value from the **last** one in adapter
emission order wins. Legacy does the same with `Map.set` in
`benchmarks/lib/scoring.ts:92-98`. Emission order can therefore matter only
when one scanner reports the same range twice with different
classifications. Adapters should emit their findings in a deterministic
order.

## Semantic digest

`RunArtifact::semantic_digest()` is the canonical-JSON SHA-256 of the
canonicalized artifact with `non_semantic` cleared. It is the equality check
for reproduction, dual-run and regression comparisons.

## Non-semantic metadata

Only `non_semantic` may vary between identical runs. It holds `run_id`,
`started_at`, `finished_at`, `host`, and per-scanner `durations_ms`.
Durations separate scanner execution time from evaluator overhead, and they
are diagnostics, never measurements.

## Verified by

- `crates/credential-eval-kernel/tests/contracts_smoke.rs` reverses the case,
  scanner and finding order and requires a byte-identical artifact, the same
  semantic digest, and equality with the committed golden artifact.
- `crates/credential-eval-contracts/tests/output_contract.rs` checks that the
  semantic digest ignores `non_semantic` and changes when a measurement changes.
