# ADR 0019: Provider-wide coverage and sibling-class twins

- Status: accepted
- Date: 2026-10-06
- Issue: #63 (found in the redact-secret alpha.5 vs alpha.13 control comparison).
- Partly superseded by [ADR 0020](0020-sibling-family-on-twin-lineage.md): decision 3 is done there, and the GitLab remark in the issue is withdrawn.
- Amends: ADR 0018 decision 2 (coverage table). Engine `0.1.0-alpha.14`,
  `FAMILY_COVERAGE_VERSION` `2`. No schema change; no adapter output change.

## Context

ADR 0018 lets a provider-wide legacy id (`anthropic-token` -> `anthropic:`)
cover every family of its provider. Some scoped twins wear another key class of
the same provider: `anthropic--anthropic-admin01-key-api03-prefix-twin`
(scope `anthropic:admin-api-key`) and
`anthropic--anthropic-api01-key-api03-prefix-twin` (scope
`anthropic:compliance-access-key`) carry a real `sk-ant-api03-` key. A product
that reports one `anthropic-token` finding there is read as `flagged` under
alpha.13 and as `co_detected` under the raw-equality rule of alpha.5. The same
shape appears for the GitLab, Vercel and other provider-wide ids.

The twin case carries no machine-readable marker for "sibling class". Its
`mutation_kind` is `prefix`, shared with plain broken-prefix twins
(`xk-ant-api03-`, `glrx-`) where a provider-wide finding is a true flag, and
the class is only named in the free-text `mutation`.

## Decision

1. **The rule does not change.** A provider-wide entry keeps covering the whole
   provider. Narrowing it for scoped twins would need either parsing authored
   prose or a per-case exception list, and a blanket narrowing turns genuine
   flags on plain near-miss twins into co-detections (the 23 and 34 flips
   ADR 0018 measured). Neither is a protocol-neutral rule.
2. **The finding is a granularity limit of the legacy label, not a scanner
   verdict.** `anthropic-token` cannot say which class it found. The
   measurement reports `flagged` for it; it does not claim the scanner is wrong
   and does not relabel the twin. A scanner that labels at class granularity
   (`anthropic-admin01-key`, `anthropic-api01-key`) is scored `co_detected` on
   the sibling twin.
3. **The missing input belongs to the corpus.** A structured twin field naming
   the sibling family (for example the family whose contract owns the twin's
   prefix) lets the scorer treat that family as co-detection without reading
   prose or a scanner. That is a `credential-evidence` schema change plus an
   evaluator protocol revision, tracked as a follow-up; it is not made here.
4. **Table correction.** `anthropic-api01-key` covered
   `anthropic:secret-api-key`, the `sk-ant-api03-` class. The `sk-ant-api01-`
   class is `anthropic:compliance-access-key` (contract
   `^sk-ant-api01-[A-Za-z0-9_-]{20,}$`), and the legacy fixtures pair
   `anthropic-api01-key` with that prefix. The entry now covers the compliance
   family. `FAMILY_COVERAGE_VERSION` is `2`.
5. ADR 0018 decisions 3 and 4 hold: no expected family is relabelled and no
   scanner output is read by the table.

## Measured effect

Not re-measured. By reading the table: only `anthropic-api01-key` changes. It
no longer covers `anthropic:secret-api-key` twins and now covers
`anthropic:compliance-access-key` twins. The issue observed no
`anthropic-api01-key` finding on either, so the accepted-control and
candidate-control runs (alpha.5 run 37296823599, alpha.13 run 37447804171) are
expected to move on no case. The listed twins
(`anthropic--anthropic-admin01-key-api03-prefix-twin`,
`anthropic--anthropic-api01-key-api03-prefix-twin`) keep their alpha.13
outcome (`flagged true`, `co_detected false` for `anthropic-token`) until
decision 3 lands. The next official run confirms the effect.

## Tests

`anthropic_class_ids_pin_their_prefix_class` pins each Anthropic class id to the
family owning its documented prefix and checks it does not cover the other
classes. `provider_wide_entry_covers_sibling_class_twin_scopes` pins decision 1.
