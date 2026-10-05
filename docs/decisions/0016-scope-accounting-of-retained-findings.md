# ADR 0016: Scope accounting of retained findings

- Status: accepted
- Date: 2026-10-05
- Issue: redact-secret-benchmarks#724 (parent: #723; builds on ADR 0011 and ADR 0012)
- Amends: nothing frozen. Contract revision v1.8 adds one optional field,
  `ScannerRun.scope_accounting`. Engine `0.1.0-alpha.11`. The measurement
  protocol, scoring, outcomes, families, denominators and floors are unchanged.

## Context

A finding with `family: None` stands for a credential nobody mapped, personal
data, a resource identifier, an ambiguous type, an unrecognized label or an
absent label. ADR 0011 preserved the native label and ADR 0012 reviewed all 575
OpenRedaction 1.1.5 types, but the review lived in `tools/` and tests; a consumer
would have had to recompute it to say how many findings are out of scope. The
benchmark site must not do that: the engine owns the classification and the
site reads it.

## Decision

1. **Engine-owned, versioned accounting.** For a complete scanner with a
   reviewed disposition table the run artifact carries `scope_accounting`
   (`version` "1"): the table identity (package, version, integrity), the
   retained finding count, a disposition for every retained finding, per-label
   counts and the multi-label and conflict counts.
2. **One table.** The table is generated from
   `tools/openredaction-audit/dispositions.json` by
   `generate-scope-table.mjs` into the contracts crate. A unit test fails when
   the generated code and the reviewed JSON differ, so ADR 0012's review and the
   engine cannot drift. `openredaction` and its three diagnostic profiles share
   it; other scanners have no reviewed set and carry no accounting.
3. **Six dispositions, exactly one per finding, always present (zeros are
   measured).** Reading order:
   - `mapped_credential`: the finding carries a family. The engine's family claim
     wins the primary reading; a conflict among its labels stays visible in
     `conflicting_label_findings`.
   - `native_label_unavailable`: no native label (older observation).
   - `unrecognized_label`: only the `~unrecognized` marker.
   - `ambiguous`: no family and the reviewed labels disagree on scope or
     status, mix reviewed with unrecognized, or the one label has an ambiguous
     scope. A mapped label on a finding without a family is table drift and is
     counted here rather than hidden.
   - `credential_related_unmapped`: no family, every label reviewed
     `unresolved` with a credential-related scope (credential, identifier of a
     credential, session).
   - `out_of_scope`: no family, every label reviewed `not-credential`
     (personal data, resource identifiers).
4. **Describes, never filters.** `findings` and `cases[].actual` are untouched.
   `by_disposition` sums to the retained findings and `by_label` reconciles to
   their labels (a multi-label finding counts under each label, so label counts
   may exceed the finding count; the artifact says so). An unresolved type stays
   unresolved: this is not a sensitivity verdict and no finding is converted to a
   false positive.
5. **Absent is not zero.** The field is absent for artifacts of older engines,
   scanners without a reviewed table and scanners that did not complete. A
   complete scanner with zero findings carries an explicit all-zero accounting.
6. **No new identity for scoring.** The accounting depends only on the retained
   findings and the table; it adds no scanner configuration. Observations are
   still reused under ADR 0008. The accounting is recomputed when an artifact is
   built, so an observation set reused from a labelled run produces it with no
   rescan; a label-less observation yields `native_label_unavailable`, never an
   inferred class (ADR 0011).

## Consequences

- Consumers read counts instead of recomputing them. Changing the package pin
  requires regenerating the label set, the dispositions and this table together.
- A profile result (ADR 0013, ADR 0015) can be read next to the default result
  by disposition and native label.
- The artifact grows by one small object per complete accounted scanner (at most
  575 label rows with a static reason each).

## Tests

The generated table equals the reviewed dispositions; every disposition is
reached by an authored finding; conflicting, mixed-with-unrecognized, multi-label
and family-carrying findings; zero findings; order independence and
reconciliation; scanner-to-table selection (default and three profiles in, four
other scanners out); end-to-end scoring attaches accounting only to a complete
scanner with a table; JSON schema regenerated and drift-checked.
