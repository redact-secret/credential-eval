# Kernel deltas from the legacy engine

`credential-eval-kernel` ports the legacy measurement engine at
`redact-secret-benchmarks@c403475476647bc98cc5864bccd7265eddebeb91`
(inventory: [legacy-map.md](legacy-map.md)). Everything not listed here is
meant to be behavior-identical, and the golden oracle tests
(`crates/credential-eval-kernel/tests/oracle.rs`, goldens in
`tests/fixtures/oracle/`) check it against the legacy TypeScript on synthetic
inputs.

This page lists every **intentional** difference. Issue #5 (full-corpus
parity) must either configure the kernel to reproduce legacy behavior (the
"parity setting" column) or report the difference as expected.

## Neutrality

| # | Legacy behavior | Kernel behavior | Parity setting |
|---|---|---|---|
| N1 | The differential primary is hard-coded as `redact-secret` (`methods/differential.ts:26-49`). | The reference is a run parameter: `EvaluateOptions::reference`. `None` records no comparisons. Peers are ordered by scanner id. | `reference = redact-secret`. |
| N2 | The disagreement label is `redact-secret-only`. | `Disagreement::ReferenceOnly` (`reference-only`). | `compat::legacy_disagreement` maps it back. |
| N3 | Review ids strip only the `redact-secret` tool identity (`review.ts:4-10`). | The configured reference's identity is reduced to its id. | Same reference as N1. |
| N4 | `structural.remove-segment` hard-codes `sendgrid-token` (`.`, segments 1-2) and `slack-token` (`-`, segments 1-3) (`operators/structural.ts:27-31`). | Eligibility, delimiter and removable segments come from `FamilyContract::segments` (evidence data). A family without a rule is `unsupported`. | Supply exactly those two rules; see `tests/oracle.rs::evidence`. |
| N5 | Lexical operators read `pattern` and `validate` from the product `contracts` table (`operators/lexical.ts:3-21`). | Patterns are data (`FamilyContract::pattern`) compiled with the Rust `regex` crate. Validators are code and are supplied explicitly with `FamilyContracts::with_validator`. | Supply the contract patterns and the two legacy validators (`evaluation/domains/credential/assessment.ts:280` `discord-bot-token`, a numeric base64 id segment; `:324` `confluent-cloud-api-secret`, a checksum). Without them, variants of those two families can be `derived` where legacy says `review-required`. |
| N6 | `\d` and other shorthand classes are ASCII in ECMAScript regexes. | The `regex` crate's shorthand classes are Unicode-aware. The legacy patterns use no shorthand that differs on ASCII input. | None needed for the pinned contracts. |
| N7 | The benign taxonomy vocabulary is `AXES ∪ REAL_WORLD_AXES` from product code (`methods/benign.ts:7`). | `EvaluationEvidence::benign_taxonomies`. `None` accepts any non-blank taxonomy. | Supply the 13 legacy axes. |
| N8 | The eval family allowlist is the keys of the product `contracts` table (`normalization.ts:7`). | `observe::restrict_family(finding, classification, allowlist)` takes the allowlist as input. `bench` passes `None`. | Allowlist = contract family ids for `eval`; `None` for `bench`. |
| N9 | The twin probe reads families and un-probeable records from `contracts` and the family from `detectors[0]`. | `twin_probe(families, fixtures, cases, unprobeable)` takes all of it as input (`ProbeFixture::family`). | Pass legacy `detectors[0]`. |

## Identity and hashing

| # | Legacy behavior | Kernel behavior | Parity setting |
|---|---|---|---|
| H1 | Variant provenance, `sourceHash`, `parametersHash` and review ids are SHA-256 of insertion-order `JSON.stringify` over **legacy fixture objects** (including assessment reason and sources). | Canonical digests (`sha256:` over canonical JSON of the contract types). Review ids hash the case, its source digest and the observation, with the reference reduced to its id. | Not reproducible from a contract snapshot, which does not carry the legacy fixture fields. #5 compares review-queue **membership** by (case, variant, peer, disagreement, observations, classifications), as `tests/oracle.rs` does. |
| H2 | Seeded operator choices hash `{seed, operator}` with `seed = "<category>/<fixtureId>"` (`cases.ts:73`, `lexical.ts:41-43`). | Same hash (legacy JSON form, so choices are unchanged); the seed is `EvaluationCase::seed_key`. The canonical seed is the corpus case id (`cases::case_id_seed`). | `compat::legacy_seed`. |
| H3 | The review ledger keys use legacy ids. | Ledger reduction (`review::review_state`) works on canonical ids. Ledger validation and "last seen" writes (`review-ledger.ts:49-109`) are ledger lifecycle and are not ported. | A ledger migration maps legacy ids by queue membership (H1). |

## Semantics kept, representation changed

| # | Legacy | Kernel |
|---|---|---|
| R1 | Row `actual` and differential observations keep first-insertion order. | Sorted by `(start, end, family, action)`. Values are identical. |
| R2 | The canonical variant has no `parameters`; an invalid lexical edit has `relation: null`. | `parameters: {}`; an absent relation. |
| R3 | A Wilson bound of `NaN` (a point above 1, e.g. twin coverage with several twins for one positive) serializes as `null`. | `bound: None`. The published JSON is the same. |
| R4 | `timeout` and output/parse failures fold into `error`. | Distinct `timeout` and `malformed` statuses; a not-measured assertion's reason is the contract status name. `compat::legacy_status` folds them. `exit_code` treats all three as `error`. |
| R5 | `summaries.byDetector`, `axesByDetector`. | `Summaries::by_target`, `axes_by_target`. Targets are sorted (legacy keeps `fixture-detectors.json` order). |
| R6 | `accountingDelta`, `aggregateGroups` (v1.0), the assertion delta and `encodeOutcome` are emitted with the results. | Only in `compat` (`accounting_delta`, `aggregate_groups_v10`, `assertion_delta`, `encode_outcome`). The canonical artifact publishes v1.1 figures only. |
| R7 | Per-category group files. | `aggregates.groups` is over the whole snapshot. A per-category figure is `account_groups` over that category's cases (`CaseResult::group`). |
| R8 | `DeltaCause` is a string sorted with `Array.sort`. | An enum declared in the same (alphabetical) order. |

## Fail-closed refusals and bounds

| # | Legacy | Kernel |
|---|---|---|
| F1 | A `must-redact`/`policy` case without a secret span, a `must-not-flag` case with one, or a twin that is not a control makes `aggregateGroups` throw a `TypeError` or produce `NaN`. | `KernelError::InconsistentCase`. |
| F2 | `structural.remove-segment` on a single-segment value computes `seededChoice(..) % 0` (`NaN`) and emits the value unchanged. | The attempt is a suppressed generation `error`. |
| F3 | No bounds on generation. | `GenerationLimits` (`max_cases`, `max_variants_per_case`, `max_total_variants`, `max_variant_bytes`); exceeding one refuses the plan. Defaults are far above the legacy corpus. |
| F4 | `validateAssessment` and `classifyFixture` run at case construction and on every non-review variant. | Not run: they are evidence-authoring checks owned by the snapshot producer. Range and envelope rules still run on every variant. |
| F5 | Replay stability: `bench` compares ranges only (`run.ts:150-152`); `eval` compares complete findings (`runtime.ts:24-28`). | `observe::compare_replays` uses the stricter `eval` rule for both. |

## Ordering

| # | Legacy | Kernel |
|---|---|---|
| O1 | Cases are built per category in corpus order. | Built in corpus-case-id order; every output collection is sorted. |
| O2 | A mutation case attaches the **first twin in corpus order** of its seed. | The first twin **by case id**. It differs only when a positive has several twins. |

## Not ported (other owners)

- The `holdout` method and its runner guard (`methods/holdout.ts`, `engine/runner.ts:5-9`): #6 lifecycle.
- Support status, thresholds, scorer promotion, release drift and everything
  else classified #6 or "out" in [legacy-map.md](legacy-map.md) §3.
- Scanner execution, materialization and adapters (`runtime.ts` I/O,
  `scanners/*.mjs`): #4. The kernel exposes the pure rules they need
  (`observe::compare_replays`, `observe::restrict_family`).
