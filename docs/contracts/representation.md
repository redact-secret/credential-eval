# Representation contract (v1.3)

The facts a corpus snapshot may carry about encoded, transformed and
fragmented inputs, the rules that validate them, how a decoded scanner finding
is placed on the original bytes, and what a run artifact reports about both.
The decisions behind it are in
[ADR 0005](../decisions/0005-representation-contract.md); the Rust types in
`crates/credential-eval-contracts/src/representation.rs` and `corpus.rs` are
normative.

Everything here is **additive and optional**. A document that carries none of
it is a v1.0 to v1.2 document with the same meaning, the same corpus digest and
the same semantic digest. It adds no outcome, no denominator and no support
status. A fact never asserts that a scanner should detect anything.

## Version signal

| Signal | Value | Who reads it |
|---|---|---|
| Contract revision | `1.5` (`credential-eval capabilities` → `contract_revision`; the last row of the "Revisions" table) | a consumer pinning an engine |
| Representation contract | `credential-eval/representation/1` (`identity.representation` in a snapshot; `manifest.representation.contract` in an artifact; `capabilities` → `representation.contract`) | an exporter, a consumer |
| Engine | a tag at or after `v0.1.0-alpha.4` (alpha.5 adds the v1.4 registry pin, which does not touch representation) | benchmarks pin |

`identity.representation` is **required** when any case carries a fact, and
optional otherwise. Declaring it with no facts is allowed: it says the exporter
supports the contract, so "no facts" is then a statement and not an omission.
An engine that predates v1.3 refuses such a snapshot (every v1 struct sets
`additionalProperties: false`), which is the compatibility signal working as
intended: a consumer needing the facts pins an engine that writes and reads them
(ADR 0001, "Reader guidance").

## Snapshot fields

### `identity.representation`

The string `credential-eval/representation/1`.

### `cases[].representation`

Present only when the case carries a case-level fact. At least one of:

| Field | Meaning |
|---|---|
| `input_validity` | `valid` (default, never written), `unpaired-surrogate-split`, or `invalid-utf8` (refused: a snapshot cannot carry such bytes in the `content` string; the case stays "not exported", see below). Anything but `valid` makes the case an **expected rejection**: `expected` is empty and `grouping.tier` is `T0`. |
| `derivation` | `{kind: authored-base \| projection, bases[]}`. A projection names one to 64 base ids (evidence fixture ids; they need not be cases of this snapshot); an authored base names none. |
| `transformation` | `{steps[]}`, one to 16 input-level steps in forward order (base to input). Descriptive: the evaluator checks each step's shape, not that the content was produced by it. |
| `chunking` | `{unit: utf8-byte \| utf16-code-unit, boundaries[]}`, strictly increasing, inside the content. |

Transformation steps are tagged by `op`: `encode` (`codec` `base64` with
`alphabet` and `padding`, or `hex` with `case`), `insert-codepoints`
(`code_points`, `positions`), `normalize` (`form`), `fragment` (`mechanism`,
`line_break`, `width`, `reconstruction`), `embed` (`mode`, `carrier`), `escape`
(`style`), `place` (`placement`, `filler_bytes`), `repeat` (`count`). An unknown
`op`, field or enum value is refused, never ignored.

### `cases[].expected[]` additions

Only on a span of role `secret`:

| Field | Meaning |
|---|---|
| `base` | The authored base fixture the span's value comes from. |
| `fragments` | `[{start, end}]`: the secret bytes inside `[start, end)` when the value is not contiguous. At least two, sorted, disjoint, separated by at least one byte, each a valid UTF-8 range; the first starts at `start` and the last ends at `end`. The rest of the range is separators. |
| `decoded` | `{via[], sha256, bytes}`: how the source bytes (the fragments concatenated, else `[start, end)`) decode to the credential value. `via` is one to eight steps in **decode order**: `base64` (`alphabet`, `padding`), `hex` (`case`), `strip-codepoints` (`code_points`), `normalize` (`form`). `sha256` is `sha256:<hex>` of the decoded value and `bytes` its length. **The decoded value is never carried.** |

`start`, `end` and every fragment boundary are UTF-8 byte offsets into the
original `content` ([ranges.md](ranges.md)).

## Validation

`CorpusSnapshot::validate` re-derives what it can, so an exporter that loses or
corrupts a fact is refused at load, with a message that names the case and
never its content:

- every `decoded` is **re-derived from the original bytes**: each step is
  applied strictly (the declared alphabet, padding and letter case, canonical
  base64, even hex length, listed code points actually present) and the final
  length and digest must equal `bytes` and `sha256`. `normalize` cannot be
  re-derived here: it is carried, its shape is checked, and it is counted in
  `decoded_unverified`;
- `fragments` geometry (above), and fragments only on secret spans;
- `input_validity` against the bytes and boundaries **in both directions**: a
  `valid` input with a UTF-16 boundary inside a surrogate pair is refused, and
  `unpaired-surrogate-split` without one is refused;
- an expected rejection has no spans and tier `T0`;
- chunk boundaries are inside the content and strictly increasing;
- step lists are bounded and every step fits its codec (`encode` base64 takes
  `alphabet` and `padding`, hex takes `case`);
- a snapshot with any fact declares `identity.representation`.

Facts never change the case's expectation. Expectation certainty (`tier`,
`kind`), review state, input syntax validity and scanner execution state stay
separate: a `T0` case, an expected rejection, a pending projection and a case a
scanner left unmeasured are each in **no** TP/FN denominator, and none is ever a
zero detection.

## Mapping a decoded finding to the original bytes

Some scanners decode part of an input (base64, hex, nested) and report the
decoded value, which is absent from the file. An adapter places such a finding
on the original bytes **only when it can re-derive the placement**
([`crates/credential-eval-adapters/src/decode.rs`](../../crates/credential-eval-adapters/src/decode.rs)):

1. A *source segment* is a maximal run of encoded text on the reported line:
   `[A-Za-z0-9+/_-]{8,}={0,2}` for base64, `[0-9A-Fa-f]{16,}` for hex.
2. The segment must decode **strictly** (declared alphabet and padding read off
   the run, canonical form, valid UTF-8) through a chain of the reported codecs
   and depth (Gitleaks: `decoded:*` and `decode-depth:N` tags; TruffleHog: the
   `BASE64` decoder, one to four layers). Layers after the first expand every
   strictly decodable run of their codec inside the previous layer's text and
   leave the rest, as the scanners do. Every chain of the codec set is tried in
   a fixed order.
3. The final text must **contain the reported value**. Only then is the segment
   a candidate.
4. The finding maps only when exactly one segment qualifies, or when several
   identical ones do and the report claims them in ascending order (the repeated
   report rule of `locate`). Otherwise the finding is unmappable.

The range is the **whole segment**, and the finding carries
`mapping: {bound, layers, codecs}`. The finding lies somewhere inside the
segment's decoded text; nothing narrower is claimed, so a mapped finding is
`EXACT` against a span authored as the encoded run, `COVERED` against a wider
envelope, and `OVERBROAD` or `PARTIAL` otherwise, by the unchanged lattice.

| `bound` | Meaning |
|---|---|
| `source-segment` | The range is exactly the encoded segment (this rule). |
| `source-segment-extended` | The depth-one base64 rule that predates the contract: the segment extended over adjacent literal bytes the finding also matched. |
| `source-block` | The PEM rule that predates the contract: a block whose body is base64. |

The two legacy bounds are recorded only when `decoded_mapping` is chosen; with
it off, the findings they place carry no `mapping`, byte for byte as before.

### What stays unmeasured

A finding the rule cannot place is **not** guessed, and stays what
`unmappable_findings` made it ([ADR 0003](../decisions/0003-unmappable-findings-leave-the-case-unmeasured.md),
[ADR 0004](../decisions/0004-per-case-unmeasured-handling-in-methods-and-trufflehog.md)):
the fixture (or variant) is unmeasured, in no denominator, never a zero
detection, and with `unmappable_findings` absent the scanner is `malformed`.
That covers: a codec other than base64 and hex (percent-encoding, UTF-16,
escaped Unicode), a depth beyond four, text that is not strictly the declared
encoding, a value the segment does not decode to (including one that crosses
into text outside the segment), no segment or no unclaimed segment on the
line, more than 4,096 candidate runs, and any row whose file is unknown (which
still fails the scanner).

The mapping is **opt-in** per scanner, through the configuration key
`decoded_mapping` (`"off"`, the default, or `"source-segment"`) for Gitleaks
and TruffleHog. It is part of the scanner configuration, hence of
`config_hash`; with it absent the adapters behave byte for byte as in
v0.1.0-alpha.3. It only adds mappings: for a decoded-tagged row the new rule
runs first and the older rules are the fallback.

## Scoring a fragmented span

The lattice is unchanged (protocol 1): a span is scored on its enclosing range
`[start, end)`. A scanner that reports the joined secret as one range is `EXACT`
on it, which counts the separator bytes between the fragments as part of the
secret. Fragment-aware reading (coverage of each fragment, separators as
outside-secret bytes) is a protocol revision and is not made here. The facts
are carried, validated and reported so that revision, and any consumer policy,
can use them.

## What a run artifact reports

| Field | Meaning |
|---|---|
| `manifest.evidence.representation` | The declaration copied from the snapshot. |
| `manifest.representation` | Present exactly when the snapshot declares the contract or carries a fact: `contract`, `facts_digest`, and the counts `cases`, `transformed_cases`, `chunked_cases`, `expected_rejections`, `fragmented_spans`, `fragments`, `decoded_spans`, `decoded_verified`, `decoded_unverified`. |
| `scanners[].findings[].mapping`, `scanners[].cases[].actual[].mapping` | How an adapter placed a decoded finding. Absent on a finding located directly. |

`facts_digest` is the SHA-256 of the canonical JSON of every case's facts
(`{case_id, representation, spans: [{index, base, fragments, decoded}]}`, only
cases and spans that carry facts, sorted by case id; canonical JSON as in
[identity.md](identity.md)). An exporter computes the same digest from what it
wrote, so a consumer can **prove which facts reached the engine**. When two
findings share a range, the artifact keeps the smallest `mapping` (so it does
not depend on emission order).

Generated variants (evaluation methods) start from seeds **without** facts: a
variant is a different input, and the seed's decoded values and fragments do
not hold for it. `source_hash` of a case is therefore a function of its bytes
and spans only, as before.

## What an exporter emits

From the credential-evidence `fixtures-materialized-manifest.json` (schema
1.6.0) item `i` and its snapshot case, with snake_case names:

| Evidence (`expected.spans[]`, item) | Snapshot |
|---|---|
| `base` | `expected[].base` |
| `fragments[{start,end}]` | `expected[].fragments[{start,end}]` |
| `decoded.via[]` (`codec`, `alphabet`, `padding`, `case`, `codePoints`, `form`) | `expected[].decoded.via[]` (`codec`, `alphabet`, `padding`, `case`, `code_points`, `form`) |
| `decoded.sha256` (bare hex), `decoded.bytes` | `expected[].decoded.sha256` (`sha256:` + hex), `.bytes` |
| `inputValidity` (other than `valid`) | `representation.input_validity` |
| `derivation` | `representation.derivation` |
| `transformation.steps[]` (`lineBreak`, `codePoints`, `fillerBytes`) | `representation.transformation.steps[]` (`line_break`, `code_points`, `filler_bytes`) |
| `chunking` | `representation.chunking` |
| (the contract) | `identity.representation` = `credential-eval/representation/1` |

Rules: preserve every fact the item states (a fact lost on export is a defect;
compare `facts_digest`); a span that evidence states with a `decoded` fact keeps
its `decoded` and its `fragments` as the same span; `inputValidity: invalid-utf8`
items are still **not exported** (counted in `evalExport.notExported`, reason
`invalid-utf8`) because their bytes are not a JSON string; a fixture whose bytes
are valid UTF-8 and whose `inputValidity` is `unpaired-surrogate-split` **is**
exported, with `content` and the chunking; an unresolved or `not-assertable`
expectation stays tier `T0` with no spans; review state and support status are
never inferred and never exported here.

Exporter output must pass `CorpusSnapshot::validate`, and the corpus digest is
over the cases including these facts.
