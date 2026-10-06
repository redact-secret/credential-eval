# Outcomes, measurements and failure states (protocol 1)

Protocol 1 reproduces the legacy `measurement-v4` lattice and the engine v1.1
accounting at legacy commit `c403475476647bc98cc5864bccd7265eddebeb91`.
Changing anything on this page is a protocol revision.

## Span outcome lattice

Take one **secret** span `S` with acceptable range `E` (its envelope, or `S`
itself). Let `F` be the deduplicated findings on the case's path. The rules
below are evaluated in order (`benchmarks/lib/lattice.ts:44-50`; ported as
`credential_eval_kernel::lattice::span_outcome`):

1. `EXACT`: some `f ∈ F` has `f == S`.
2. If some `f ∈ F` contains `S` (`f.start <= S.start && f.end >= S.end`):
   - `COVERED` when at least one such containing `f` also lies within `E`;
   - `OVERBROAD` otherwise.
3. `PARTIAL`: some `f ∈ F` overlaps `S` (half-open) without containing it.
4. `MISS`: no finding overlaps `S`.

`PARTIAL` and `MISS` **leak**. `EXACT`, `COVERED` and `OVERBROAD` do not.
Leakage and overbreadth are separate axes. **Acceptable** means `EXACT` or
`COVERED`, and this is what the twin and assertion rules use. `OVERBROAD`
does not leak, but it is not acceptable.

## Per-case measurement

This is legacy `scoreRow`, `lattice.ts:76-97`, ported as
`lattice::score_row`.

- **Pending** (`tier == T0`): the findings are recorded in `actual`, and no
  outcome or byte counts are computed.
- **Positive** (the case has at least one `secret` span):
  - `span_outcomes`: one outcome per secret span, in span order.
  - `leaked_bytes`: the sum, over leaked spans only, of span bytes outside
    the union of all findings.
  - `collateral_bytes`: finding bytes outside the union of the acceptable
    ranges of **all** expected spans (secrets and companions).
- **Control** (the case has no secret span):
  - `findings`: the number of deduplicated findings.
  - Unscoped (benign control): `flagged` when there is any finding.
  - Scoped (a twin whose `grouping.family` is set): a finding whose `family`
    is a known family *other* than the twin's is co-detection. It sets
    `co_detected` and does not flag. A finding with no family, or with the
    twin's own family, flags. So unattributed findings fail closed. Two ids
    are the same family when they are equal or when a legacy id covers an
    evidence `provider:family` id (`family_ids::same_family`, table version
    `2`, [ADR 0018](../decisions/0018-family-id-namespaces-and-twin-scoping.md),
    [ADR 0019](../decisions/0019-provider-wide-coverage-and-sibling-class-twins.md)).
    When the twin declares `twin.sibling_family`
    ([ADR 0020](../decisions/0020-sibling-family-on-twin-lineage.md)), a
    finding that is the same family as it is co-detection too, even if the same
    finding also covers the twin's own family (a provider-wide legacy id cannot
    say which class it found). A class-specific finding of the twin's own family
    still flags.
  - `action_counts`: a tally of scanner-reported `action` values. It is
    additive and never changes `flagged` or `findings`.
- **Not measured**: the scanner's status is not `complete`. Every case records
  `{"type": "not-measured", "status": ...}`.

## Scanner failure states

| Status | Meaning | Scored? |
|---|---|---|
| `complete` | Ran; replays agreed; output normalized. | yes |
| `unstable` | Replays over identical input disagreed. Findings discarded. | no |
| `unsupported` | The adapter cannot produce source byte ranges. | no |
| `unavailable` | The scanner binary or package is absent or not runnable. | no |
| `timeout` | The wall-clock limit was exceeded. | no |
| `malformed` | Output could not be parsed or mapped to ranges, or exceeded output limits. | no |
| `error` | Any other failure. | no |

No non-complete status becomes `MISS`, an empty finding list, or a pass. A
status that is not measured consumes denominator in assertion resolution
(`not-measured`) and never resolves.

Legacy has only `complete`, `unstable`, `unsupported`, `unavailable` and
`error`. It folds timeouts and parse or size failures into `error`
(`scanners/index.mjs:40-60`). The compatibility mapping sends `timeout` and
`malformed` to `error`.

## Group aggregates

Groups are keyed `<kind>/<tier>`, and every `T0` case goes to `pending/T0`
(`lattice.ts:99`). No figure is ever summed across groups.

The v1.0 counts come from `aggregateGroups`, `lattice.ts:113-182`, and the
v1.1 publication from `accountGroups`,
`evaluation/domains/credential/accounting.ts:65-115`:

- `control` (`must-not-flag/*`):
  - `false_alarm_rate` = `flagged_files / files` (upper Wilson bound).
  - `mean_findings_per_flagged` = `findings / flagged_files` (a ratio with no
    bound; its `n` for the evidence floor is `files`).
- `positive` (`must-redact/*`, `policy/*`):
  - Counts: spans, secret bytes and outcome counts.
  - `leaked_span_rate` = `leaked_spans / spans` (upper bound).
  - `leaked_byte_rate` = `leaked_bytes / secret_bytes` (upper bound, n = spans).
  - `collateral_ratio` = `collateral_bytes / secret_bytes` (ratio, n = spans).
  - `pending_files`: the T0 cases of the same kind.
  - `measurable_share` = `files / (files + pending_files)` (lower bound). When
    the share is below `measurable_share_floor[kind]`, the leak and collateral
    rates are withheld as `insufficient-evidence`.
  - `envelope_width`: the spans that carry an envelope, and the extra bytes
    the envelope adds.
  - `twins`:
    - `positives`: the scored positives.
    - `pairs`: the (positive, twin) pairs where neither side is T0 and the
      positive is not `must-not-flag`.
    - `discriminated`: pairs whose positive is all-acceptable and whose twin
      is not flagged. This is v1.1 strict: `OVERBROAD` does not count.
    - `co_detected`
    - `coverage` = `pairs / positives` (lower bound).
    - `rate` = `discriminated / pairs` (lower bound). It is `null` without
      pairs, `insufficient-evidence` when the group is not measurable, and
      `insufficient-coverage` when coverage is below `twin_coverage_floor[kind]`.
- A published figure is `null` when its denominator is 0. It is
  `insufficient-evidence` when `n < min_denominator`. Otherwise it is
  `{point, bound, n, direction}`: `point` is rounded to `interval_precision`,
  and `bound` is the pessimistic Wilson endpoint
  (`accounting/shared/primitives.ts:36-54`), or `null` for ratios.
- Exact-match `diagnostics` (tp/fp/fn/tn) are carried for inspection only.
  They are not comparable across scanners.
- Rounding reproduces JavaScript `Number(x.toFixed(p))`: round half up on
  the exact binary value (`credential_eval_kernel::jsnum::round_to_fixed`).
  When a point exceeds 1 (twin coverage with several twins for one
  positive) the Wilson bound is undefined and is published as `null`, as in
  legacy.
- A case whose measurement contradicts its population (a `must-redact` case
  without a secret span, a twin that is not a control) is refused, never
  aggregated.
- `by_target` groups use the legacy cross-suite selection rule
  (`run-summary.ts:39-50`) with `CaseResult.group` as the suite.

Implemented in `credential_eval_kernel::accounting` and checked against the
legacy engine by the oracle tests (`tests/fixtures/oracle/`).
