# Identity and digests

## Identifiers

Every id is validated when it is deserialized and carries a schema `pattern`.

| Type | Grammar | Max length | Used for |
|---|---|---|---|
| `CaseId` | `^[a-z0-9][a-z0-9-]*$` | 256 | cases (legacy fixture-id grammar) |
| `ScannerId` | `^[a-z0-9][a-z0-9-]*$` | 64 | scanners |
| `ComponentId` | `^[a-z0-9][a-z0-9.-]*$` | 128 | adapters, methods, operators, variants |
| `FixturePath` | ASCII `[A-Za-z0-9_./-]`, relative, no empty, `.` or `..` segment | 512 | materialization paths |
| `Sha256Digest` | `^sha256:[0-9a-f]{64}$` | 71 | every digest |

A case migrated from the legacy corpus takes the id
`<category>--<fixture-id>`. This is the legacy cross-suite slug
(`evaluation/domains/credential/run-summary.ts:27`), so ids stay unique across
categories.

## Canonical JSON

A digest over structured data covers its **canonical JSON**. That is compact
JSON with object keys sorted by byte order at every depth, strings escaped by
`serde_json`, and numbers in `serde_json` form: integers verbatim, floats in
shortest round-trip form. The encoder is
`crates/credential-eval-contracts/src/canonical.rs`.

The encoding does not depend on the order of struct fields or on map
insertion order. The value is always re-serialized from the typed contract,
so equivalent spellings digest the same way: `0` and `0.0` are the same
float, and a missing optional field is the same as an absent one.

> This deliberately differs from the legacy hashes, and there are three of
> them. `substrate/hash.ts` hashes `JSON.stringify` in insertion order.
> `lib/peer-observations.ts` and `lib/fixture-index.ts` sort keys with the
> locale-sensitive `localeCompare`. Parity work (#5) compares normalized
> results, not legacy digests. A compatibility exporter that must emit a
> legacy digest reproduces the legacy algorithm inside its compatibility
> module.

## Corpus digest

```
corpus_digest = "sha256:" + hex(SHA-256(canonical_json(cases sorted by id)))
```

The digest covers every case field: id, path, exact content, expected spans
and envelopes (including reasons), grouping and twin lineage. It excludes the
`identity` block, which contains the digest. Changing any fixture byte or any
expectation changes the digest. Reordering cases does not. The reference
implementation is `corpus::corpus_digest`, and `CorpusSnapshot::validate`
checks that the declared digest matches.

## Configuration hashes

- `ScannerSpec::configuration_hash()` is the canonical digest of the
  scanner's `configuration` object. It is recorded as
  `ScannerIdentity.configuration_hash`. Legacy records the equivalent
  `hash(configuration)` in `substrate/runtime.ts:80`.
- `RunConfig::config_hash()` is the canonical digest of the whole typed run
  configuration: scanners, methods, execution bounds and accounting. It is
  recorded as `manifest.config_hash`.

## Stale-result protection

An `ObservationSet` names the `corpus_digest` it was observed against.
`ObservationSet::validate_against` rejects a set whose digest differs from
the snapshot's. It also rejects any finding on an unknown path or with an
invalid range. So scanner results are never applied to changed fixture bytes.

## Reproduction identities in a run artifact

| Identity | Field |
|---|---|
| engine | `manifest.engine {name, version}` |
| protocol | `manifest.protocol_version` |
| artifact schema | top-level `schema` |
| evidence snapshot | `manifest.evidence {source, revision, evidence_schema, corpus_digest}` |
| scanner | `manifest.scanners[] {id, version, mode}` |
| adapter | `manifest.scanners[].adapter {id, version}` |
| scanner configuration | `manifest.scanners[].configuration_hash` |
| run configuration | `manifest.config_hash` (plus `manifest.accounting` inline) |
| methods | `manifest.methods[] {id, version}` |

Together these identify a run for reproduction. Two runs with equal
identities must produce equal semantic digests ([determinism.md](determinism.md)).
