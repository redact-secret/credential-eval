# ADR 0020: Sibling family on twin lineage

- Status: accepted
- Date: 2026-10-06
- Issue: #65 (follow-up of #63 and ADR 0019; evidence side: credential-evidence#260,
  schema 1.8.0, `snapshot-2026.10.06.3`).
- Amends: scoped twin scoring (`docs/contracts/outcomes.md`); completes ADR 0019
  decision 3. Engine `0.1.0-alpha.15`, contract revision 1.9. Additive schema
  change. **Measured twin outcomes change** only for twins that declare a
  sibling family.

## Context

ADR 0019 left provider-wide legacy coverage unchanged because nothing machine
readable said a twin wears another class of the same provider. The evidence
repository now records it: `lineage.siblingFamily` names the family whose
contract owns the twin's value, validated against the snapshot (same provider,
different from the scoped family, a contract stating sibling classes), and set
on 8 Anthropic twins. It withdrew the GitLab remark of #63: the seven routable
GitLab twins change a checksum, boundary or length and carry no other class, so
they get no sibling family.

## Decision

1. `TwinLineage.sibling_family` is an optional family id (`provider:family`).
   Absent serializes and digests as before; present is part of the corpus
   digest. It is evidence input: not copied into artifacts, never read from a
   scanner, never a relabelled expected family.
2. Validation: non-blank and unpadded, the case has a scope family, and it
   differs from it. Provider and contract checks stay with the evidence side.
3. Scoring: for a scoped twin with a sibling family, a finding is co-detection
   when it is another family than the scope (unchanged) **or** the same family as
   the sibling (`same_family`). So `anthropic-token`, which covers both, is
   co-detection on `anthropic--anthropic-admin01-key-api03-prefix-twin`, while a
   class-specific finding of the scope class (`anthropic-admin01-key`) and a
   finding without a family still flag. A twin without the field scores exactly
   as before; ADR 0019's provider-wide coverage rule is untouched.
4. Generated must-flip variants of such a twin use the same rule.
5. The measurement kernel stays scanner neutral; the exporter maps
   `siblingFamily` to `twin.sibling_family` when it writes the snapshot, which
   is evidence-repository work.

## Measured effect

Not re-measured locally. By construction it applies to the 8 declared twins,
including the two named in #63. For redact-secret (`anthropic-token`
on both) the expectation is `flagged true -> false`, `co_detected false -> true`
on those two twins, which should clear `twinFailures: 1` and the failing
`<family>-dotenv--mutation` assertions for `anthropic-admin01-key` and
`anthropic-api01-key`, provided the snapshot carries the field. Existing
snapshots do not, so their results do not move. To be confirmed by the next
official run on a snapshot cut after the exporter change.

## Tests

`sibling_family_makes_provider_wide_findings_co_detection` (no sibling
unchanged, provider-wide, own-class, sibling-class and unattributed findings),
`twin_sibling_family_is_checked_and_digest_neutral_when_absent` (validation,
absent serialization, digest), the regenerated corpus schema, the frozen-v1
additive check and the schema guarantee allowlist.
