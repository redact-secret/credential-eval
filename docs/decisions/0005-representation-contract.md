# ADR 0005: A representation contract for encoded and fragmented inputs

- Status: accepted
- Date: 2026-10-04
- Issue: #34, with credential-evidence#150 (the exporter) and redact-secret-benchmarks#680
- Amends: nothing frozen. Adds optional fields to three v1 documents (revision v1.3, [ADR 0001](0001-freeze-v1-contracts.md)). Builds on [ADR 0003](0003-unmappable-findings-leave-the-case-unmeasured.md) and [ADR 0004](0004-per-case-unmeasured-handling-in-methods-and-trufflehog.md).
- Normative text: [../contracts/representation.md](../contracts/representation.md)

## Context

credential-evidence schema 1.6.0 (its ADR 0016) states, for an input that is
encoded, fragmented or malformed, what the closed v1 snapshot cannot: the
original bytes, the transformation lineage, the source ranges of a fragmented
secret, the decode steps with the decoded length and digest, the input's
validity and its chunking. Its snapshot exporter (its ADR 0017) therefore
carries none of it, and keeps only what v1 can hold: the facts exist in
`fixtures-materialized-manifest.json` and nowhere a consumer reads them.

Audit of what is exported and what is consumed (snapshot-2026.10.04, 6,454
materialized fixtures, 6,449 exported):

| Fact | In the materialized manifest | In the v1 snapshot | Read by the engine (alpha.1 to alpha.3) |
| --- | --- | --- | --- |
| `fragments` (9 spans) | yes | no: one `[start, end)` per span | no |
| `decoded` (7 spans, all `strip-codepoints`) | yes | no | no |
| `inputValidity` (3 `unpaired-surrogate-split`, 5 `invalid-utf8`) | yes | no; the 5 `invalid-utf8` are not exported | no |
| `chunking` (9) | yes | no | no |
| `derivation` (347), `transformation` (286, of them 60 base64/hex encodings, none with a span) | yes | no | no |

Every v1 struct sets `additionalProperties: false`, so an engine from before
this decision refuses a snapshot that carries any of these. The engine also
cannot place a decoded scanner finding: Gitleaks reports base64, hex and nested
findings with the *decoded* value, which is absent from the file. alpha.2 and
alpha.3 made such a finding leave its case unmeasured instead of failing the
scan; on snapshot-2026.10.04 that is 10 of 6,449 cases for Gitleaks (nine T0
representation projections and one T1 authored case).

## Decision

### 1. An additive revision, v1.3, with an explicit version signal

The contract is a minor revision of the v1 documents, not a v2. Every new field
is optional and absent from a document that does not use it, so every earlier
document keeps its meaning, its corpus digest and its semantic digest. The
signal for a consumer is `identity.representation =
"credential-eval/representation/1"` in a snapshot (required when any fact is
present), `manifest.representation.contract` in an artifact, and
`credential-eval capabilities` for a pinned engine. An engine that predates the
revision refuses such a snapshot (ADR 0001, "Reader guidance"); that refusal is
the compatibility check, so nothing is silently dropped. The protocol stays
`credential-eval-protocol/1`: no outcome, denominator or accounting rule
changes.

### 2. The vocabulary is evidence's, bounded and closed

The wire names are evidence's, in the evaluator's snake_case, with the same
bounded vocabulary: transformation steps `encode`, `insert-codepoints`,
`normalize`, `fragment`, `embed`, `escape`, `place`, `repeat`; decode steps
`base64`, `hex`, `strip-codepoints`, `normalize`; validity `valid`,
`invalid-utf8`, `unpaired-surrogate-split`; chunk units `utf8-byte`,
`utf16-code-unit`. Free text is limited to short lowercase slugs (`mechanism`,
`carrier`, `style`, bases) with a pattern. An unknown value is refused, never
ignored, so a newer exporter cannot lose a fact against an older engine without
an error. A digest is `sha256:<hex>` as everywhere in the evaluator.

### 3. Where the facts live

- `cases[].representation` (case level): `input_validity`, `derivation`,
  `transformation`, `chunking`. Present only when it says something.
- `cases[].expected[]` (span level, secret spans only): `base`, `fragments`,
  `decoded {via, sha256, bytes}`.
- `identity.representation`: the declaration.

All offsets are UTF-8 byte offsets into the original `content`, the one range
convention of the protocol. The decoded value itself is never carried (the
schema has no place for it and a test checks it): only its length and digest,
as in evidence.

### 4. Validate by re-deriving, fail closed

A snapshot that carries facts is validated at load. `decoded` is re-derived from
the original bytes strictly (declared alphabet, padding and letter case,
canonical base64, even hex, listed code points present) and its length and digest
must match; `fragments` have the geometry evidence defines and must be valid
UTF-8 ranges; `input_validity` is checked against the bytes and the chunk
boundaries in both directions. A step this build cannot re-derive (`normalize`,
which needs Unicode tables) is carried, shape-checked and counted as unverified.
So an exporter that corrupts or drops a fact is refused with a message naming
the case, never its content. Checked against the real
snapshot-2026.10.04 facts, converted: 342 cases, 7 decoded spans verified, 9
fragmented spans, 3 expected rejections, all valid.

`invalid-utf8` is in the vocabulary and refused: a snapshot holds an input as a
JSON string, so these bytes cannot be carried and the case stays "not
exported", counted by the exporter's `evalExport.notExported`, as in its
ADR 0017. A representation-aware v2 could carry bytes; that is not made here.

### 5. Facts never assert

Expectation certainty, review state, syntax validity and scanner execution state
stay separate. An input whose validity is not `valid` is an **expected
rejection**: no spans and tier `T0`, so it is never a true positive, false
negative or false alarm. A pending projection (tier `T0`) keeps its lineage and
is never scored. A case a scanner left unmeasured is in no denominator and is
never a zero detection ([ADR 0003](0003-unmappable-findings-leave-the-case-unmeasured.md)).
Per-case adapter errors never become zero detections. The facts add no outcome
and change no existing one.

### 6. Range-mapping rules: provable placement, as a bound

A decoded finding is placed on the original bytes by one scanner-neutral rule
(`crates/credential-eval-adapters/src/decode.rs`), used by the Gitleaks adapter
(base64, hex, nested, from its `decoded:*` and `decode-depth` tags) and the
TruffleHog adapter (its `BASE64` decoder, one to four layers). A source segment
is a maximal run of encoded text on the reported line that **decodes strictly,
through a chain of the reported codecs and depth, to text containing the
reported value**. The finding is placed only when exactly one segment
qualifies (identical repeated reports claim identical segments in ascending
order, as `locate` does). The range is the **whole segment**, recorded as
`mapping {bound: source-segment, layers, codecs}`: the finding lies somewhere
inside the segment's decoded text, and nothing narrower is claimed. The
scanner's own offsets are never consulted, and no expected span is ever
consulted. Consequently a mapped finding is `EXACT` against a span authored as
the encoded run, and scored by the unchanged lattice otherwise.

This is bounded work: decoding is attempted only for rows the scanner reports
as decoded, on the reported line, with at most 4 layers, 4,096 candidate runs
and 30 chains per finding. The full snapshot-2026.10.04 plain run costs the same
wall time as before (7.8 s against 8.5 s, two scanners, four jobs).

### 7. What stays unmeasured

Everything the rule cannot prove is not guessed: a codec other than base64 and
hex (percent-encoding, UTF-16, escaped Unicode), a depth beyond four, text that
is not strictly the declared encoding, a value the segment does not decode to
(including one that crosses into text outside the segment), no or no unclaimed
segment, and an unknown file (which still fails the scanner). Such a finding is
what `unmappable_findings` made it before: the fixture or variant is unmeasured,
in no denominator, with the fixed reason; with the key absent the scanner is
`malformed`. Nothing here maps a finding to part of a segment (a base64 byte
range inside a run could be computed, but the scanners do not report decoded
offsets, so it would be a guess about the finding rather than a bound).

### 8. Interaction with the alpha.2/alpha.3 unmeasured policy

The mapping is a second, independent, **opt-in** choice: the scanner
configuration key `decoded_mapping` (`"off"`, the default, or
`"source-segment"`) for Gitleaks and TruffleHog, part of the scanner
configuration and so of `config_hash`, like `unmappable_findings`. Absent or
`"off"`, the adapters behave byte for byte as in alpha.3 (a test compares
artifacts), and `adapter.version` stays `"2"`. With it on, a decoded-tagged row
runs the new rule first and the older rules are the fallback, so opting in only
**adds** mappings: it can move a case from unmeasured to measured, never the
reverse, and only where the placement was re-derived. `unmappable_findings`
keeps its meaning for what remains. The official configurations set both for
Gitleaks and TruffleHog; `config_hash` changes with the engine version, as it
does for every engine bump.

Findings placed by the rules that predate this decision (depth-one base64 with
the extension over adjacent bytes; PEM blocks with a base64 body) get
`bound: source-segment-extended` / `source-block` only when the choice is on, so
they are visible as mapped; with it off they carry no `mapping`.

Measured effect (snapshot-2026.10.04, real Gitleaks 8.30.1 and TruffleHog
3.97.4, both choices on, darwin-arm64): Gitleaks plain run 10 of 6,449 cases
unmeasured to 0. The nine T0 representation projections are now observed
(`pending`, in no denominator), and the T1 case
`structured-credential-files-authored/kubeconfig-client-key-data-encoded-pem`
is measured `EXACT`; no other case changed (a per-case diff of the two
artifacts). TruffleHog had none unmeasured on the plain run and reports none of
these cases (it does not decode hex), so no change. The methods run
(differential, metamorphic, mutation over the 35,322 variants, same configuration
plus the evaluation evidence of redact-secret-benchmarks, differential reference
Gitleaks): Gitleaks 60 of 35,322 variants unmeasured (differential 10,
metamorphic 40, mutation 10) to 0, which adds 80 assertions, 10 comparisons and
10 review occurrences; TruffleHog's 1 unmeasured variant (a percent-encoded
value, metamorphic) is unchanged, because percent-encoding is not supported.

### 9. Fragments are carried, validated and reported; scoring is unchanged

A fragmented span is scored on its enclosing range `[start, end)` by the
unchanged lattice. A scanner that reports the joined secret as one range is
`EXACT` on it, which counts the separator bytes as part of the secret. Reading
coverage per fragment and separators as outside-secret bytes (what evidence
defines) is a protocol revision, because it changes what leaked bytes mean; it is
left to a reviewed revision, and the facts are in the artifact manifest so that
revision and any consumer policy can use them.

### 10. What the artifact proves

`manifest.representation` (present exactly when the snapshot declares the
contract or carries a fact) reports `contract`, a `facts_digest` and counts:
cases with facts, transformed, chunked, expected rejections, fragmented spans
and fragments, decoded spans, verified and unverified. `facts_digest` is the
SHA-256 of the canonical JSON of all facts sorted by case id, so an exporter
computes the same digest from what it wrote and a consumer can prove which facts
reached the engine. Each mapped finding carries its `mapping`, so a consumer can
see which ranges are bounds and which are plain. An old snapshot produces no
`representation` key anywhere, and its semantic digest is unchanged by this
revision except for the engine version.

### 11. Generated variants do not inherit facts

A variant has different bytes, so its seed's decoded values, fragments and
validity do not hold for it. Evaluation cases are built from seeds without facts,
which also keeps `source_hash` (and the review-queue ids derived from it) a
function of the seed's bytes and spans only: adding facts to evidence does not
re-key reviewed variants.

### 12. Out of scope

Product decoding policy, depth and size limits, rejection codes and the
stable/provisional status stay downstream, as the issue says. The evaluator
neither decides that a scanner should detect an encoded value nor ranks one that
does not.

## Consequences

- credential-evidence#150 can export the facts against a stable, validated
  contract and prove them with `facts_digest`; the exact mapping is in
  [../contracts/representation.md](../contracts/representation.md#what-an-exporter-emits).
- redact-secret-benchmarks pins an engine tag at or after v0.1.0-alpha.4, reads
  `credential-eval capabilities`, and gets `manifest.representation` and
  per-finding `mapping` in the artifact; its adapter reads `v1.3` fields only
  when it pins that engine (an older schema rejects them).
- The official configurations gain `decoded_mapping`; `config_hash` and the
  semantic digest of a run change, as with every engine bump. Old snapshots and
  artifacts still load, and a run of an old snapshot without the choice is
  identical to alpha.3 except for the engine version.
- Percent-encoded, Unicode-escaped and UTF-16 findings, such as the one
  TruffleHog variant of the methods run, remain unmeasured by design.
- A later v2 could carry invalid bytes and fragment-aware scoring (a protocol
  revision).
