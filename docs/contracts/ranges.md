# Range convention

Every range in every contract document is a **half-open interval
`[start, end)` of UTF-8 byte offsets** into the exact bytes of the case
`content`.

- `start` is inclusive and `end` is exclusive. The length is `end - start`.
- Ranges are never empty: `start < end`.
- `end <= len(content in UTF-8 bytes)`.
- Both endpoints fall on a UTF-8 code point boundary. An offset inside a
  multi-byte character is invalid.
- Touching ranges (`a.end == b.start`) do not overlap. Two ranges overlap
  exactly when `a.start < b.end && b.start < a.end`.

This is the legacy convention (`benchmarks/types.ts:1`, "Offsets are UTF-8
bytes, never characters"). The validity rule is `validRange` in
`benchmarks/lib/scoring.ts:34-35`. In Rust, the check is
`ByteRange::is_valid_in` (`crates/credential-eval-contracts/src/range.rs`).

## Expected spans

A case's `expected` spans are sorted by `start` and pairwise disjoint.
Touching is allowed (legacy `scoring.ts:64-73`). An `envelope`:

- is itself a valid range;
- contains its span (`envelope.start <= span.start` and `envelope.end >= span.end`);
- carries a non-blank authored `reason`;
- overlaps no other expected span.

The acceptable range of a span is its envelope, or the span itself when it
has no envelope. Companion spans are acceptable coverage and are never scored
as spans.

## Original bytes, and decoded text

Ranges always index the **original** `content`, never decoded text. A scanner
that reports a finding in decoded coordinates (a decoded base64 or hex value,
which is absent from the file) is placed on the original bytes by its adapter
only when the placement can be re-derived, and then as a bound: the whole
encoded segment. `fragments` of a span are ranges of the same kind, and a
`decoded` fact describes the bytes of `[start, end)` (or the fragments
concatenated); see [representation.md](representation.md).

## Adapter boundary

Scanners report positions in many conventions: 1-based lines and columns,
UTF-16 code unit indices (JavaScript), character indices, or matched text
with no offsets at all. Each adapter converts to UTF-8 byte ranges before it
emits a `NormalizedFinding`. The kernel accepts no other convention. It
rejects any finding whose range is invalid for its path, with no clamping and
no repair.

The legacy adapters convert this way (`scanners/index.mjs`, see
`docs/migration/legacy-map.md`):

- In-process JavaScript scanners report UTF-16 indices. The adapter converts
  each index `i` with `Buffer.byteLength(text.slice(0, i))`. A lone surrogate
  counts as 3 bytes (U+FFFD).
- Binary scanners (gitleaks, trufflehog) report matched text and a 1-based
  line. The adapter searches for the matched bytes in the fixture, filters
  candidates by line, and assigns repeated identical matches in ascending
  byte order. A zero or ambiguous match is an adapter error, not a guess.

## Derived variants

Generating operators transform content, and they must map every expected
range and envelope through the transformation. They must not search for
secret values to do it. The legacy `mapFixture` does this in
`evaluation/domains/credential/operators/context.ts:5-19`. A variant's
ranges follow the same convention and pass the same validation.
