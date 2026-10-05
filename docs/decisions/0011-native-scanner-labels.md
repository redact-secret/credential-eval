# ADR 0011: Safe native scanner labels on normalized findings

- Status: accepted
- Date: 2026-10-05
- Issue: #48 (parent: redact-secret-benchmarks#723)
- Amends: nothing frozen. Contract revision v1.7 adds one optional field to
  `NormalizedFinding` and `ObservedRange`. Engine `0.1.0-alpha.10`, OpenRedaction
  adapter version 2. The measurement protocol, scoring and every outcome are unchanged.

## Context

The OpenRedaction shim emitted `label: r.type`, and `node.rs` used it only to
look up a family. A finding with `family: None` therefore stood for several
different facts: a PII type, a resource identifier, a credential type with no
mapping, or an absent label. The mapping audit (#49) and the profile study
(#50) cannot separate those without the scanner's own type.

## Decision

1. **A separate observed field.** `native_labels: NativeLabel[]` sits beside
   `family`. `family` stays a derived classification; the label is what the
   scanner said. Neither is computed from the other after normalization.
2. **Bounded values.** A `NativeLabel` is `[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}`
   or the marker `~unrecognized`. The marker starts with `~`, which the grammar
   otherwise forbids, so it cannot collide with a real label. A set holds at
   most 8 labels, sorted and unique; validation rejects anything else, and the
   JSON schema carries the same grammar.
3. **Reviewed static sets only.** An adapter records a label only when the
   scanner reported it and the label is in a reviewed set for the exact pinned
   package (`openredaction`: the 575 distinct types of the default pattern set
   of `@openredaction/core` 1.1.5, generated from the installed package and
   committed). Any other string (unknown, oversized, non-ASCII, derived from
   input) is dropped and replaced by `~unrecognized`; it is never stored,
   logged or copied. A label that is absent stays absent: no label is guessed.
4. **Adapters without a reviewed set record nothing.** Gitleaks, TruffleHog,
   flare-redact and Redact Secret keep their current output. Their rule and
   detector sets are large, version-dependent and unreviewed here, so their
   findings read as "native label unavailable", the same as every historical
   observation. Adding a reviewed set to one of them is an adapter change with
   its own version bump.
5. **Multiplicity is unchanged.** The kernel still keeps one finding per
   `(path, start, end)`. Duplicates now also merge their labels into one sorted
   set (capped at 8, smallest kept), independent of emission order, so a range
   reported under `EMAIL` and `JWT_TOKEN` is one finding with both labels. The
   existing rules for family, action and mapping are untouched, and a mapped
   range keeps its mapping while gaining the labels.
6. **Projection.** Labels pass through replay, restriction, per-case results
   and the run artifact. They are reviewed static strings, so the public
   projection may carry them; they contain no matched value.
7. **Compatibility.** Observations written before v1.7 have no field and read
   as no labels. Nothing is reconstructed. The observation-set and run-artifact
   schema tags stay v1; a v1.6 reader that rejects unknown fields must update.
   Identity changes: the OpenRedaction adapter version is 2, so its old
   observations are not reusable (see below) and its configuration hash changes
   only through that identity.

## Mapping-only rescoring

Decision: **not permitted in this change.** Retained labels make it possible
in principle to re-derive `family` without running the scanner. Doing it would
mean an observation produced under adapter version N is scored under the
mapping of version M, which the reuse rules (ADR 0008) deliberately refuse:
reuse needs the same scanner identity, and the adapter version is part of it.
This change does not add an exception. A test pins the rule: stored
observations of another adapter version are scanned again and the reason is
named. Mapping changes in #49 therefore require a fresh OpenRedaction scan;
a future ADR may add an explicit, identity-checked remap step for observations
that carry labels.

## Consequences

- Findings positions and outcomes are identical before and after for every
  scanner (tests compare ranges and families with and without labels).
- The OpenRedaction methods run's artifact grows by the label strings; they are
  short and repeat, and the semantic digest changes through the new field and
  the engine and adapter versions only.
- A newer package that reports a type outside the reviewed set yields
  `~unrecognized` and surfaces as such, instead of silently widening the set.

## Tests

Known mapped, known unmapped, absent, unknown, oversized and unsafe labels;
several labels on one range in both orders; mapped and plain duplicates;
UTF-16 to UTF-8 conversion with an emoji; the unlabelled table; round trip,
schema acceptance and rejection; old documents without the field; and reuse
refusal across adapter versions.
