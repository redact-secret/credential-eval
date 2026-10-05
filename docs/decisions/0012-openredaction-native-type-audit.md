# ADR 0012: OpenRedaction native-type audit: dispositions, no mapping change

- Status: accepted; decision 1 re-checked and confirmed for `DOCKER_AUTH` by [ADR 0015](0015-openredaction-mapping-recheck-and-credential-bearing-profile.md)
- Date: 2026-10-05
- Issue: #49 (parent: redact-secret-benchmarks#723; builds on ADR 0011, #48)
- Amends: nothing frozen. No contract field, adapter identity, mapping version
  or engine version changes. The audit is data and tests.

## Context

OpenRedaction `@openredaction/core` 1.1.5 (npm integrity
`sha512-SpQTBhVV4p3rmge818NH6iJiL/fvwFlDvhGaejoL0wbzY7jRHIhU5vEf3KzNARsIZmpCJV1eHdiavIjQyN1hXQ==`,
tag source `3c11cf570ae4f9e6206a5f8321e8fb8d60cb9c04`) has 579 patterns over
575 distinct native types. The `credentials` category holds 32 of them; 17 map
to a family and 15 do not. `URL_WITH_AUTH` is mapped from outside the category.
Native labels are now retained (ADR 0011), so each type can be reviewed against
what the installed package actually does, not against its name.

## What was done

- The inventory comes from the installed package, not from upstream `main`
  (`getPatterns()` of a default detector, and of one with
  `categories: ["credentials"]`).
- `tools/openredaction-audit/dispositions.json` gives every one of
  the 575 types a scope, a span semantic, the current mapping, an evidence
  family candidate where one exists, a status and a reason.
- `tools/openredaction-audit/` holds synthetic probe cases (positive, negative,
  benign identifier, public key, publishable key) and `probe.mjs`, which records
  only types, ranges and span relations to the marked credential part: never a
  value. `expected.json` is its recorded result for 1.1.5, under the default
  options, `categories: ["credentials"]` and `enableFalsePositiveFilter: false`.
- Unit tests tie the three together without Node (`openredaction_audit.rs`); a
  gated test (`CREDENTIAL_EVAL_REAL_SCANNERS=1`) re-runs the probe against the
  installed package.

The human-readable summary is
[docs/measurements/openredaction-1.1.5-audit.md](../measurements/openredaction-1.1.5-audit.md).

## Decision

1. **No mapping changes.** The audit found no change that the evidence
   supports. Every candidate for a new mapping is blocked, and each existing
   mapping that looked doubtful (`STRIPE_API_KEY`, `AWS_SECRET_KEY`,
   `URL_WITH_AUTH`, `DATABASE_CONNECTION`) is left as it is with the reason
   recorded. Removing a family from a finding because a pattern can also match
   something benign would be an automatic false-positive classification, which
   the issue forbids; adding one would invent support. Because nothing changes,
   `FAMILY_MAPPING_VERSION` and the adapter version stay as they are, and there
   are no outcome deltas to review before an official rerun.
2. **Dispositions.** 18 types are `mapped` (17 of the category plus
   `URL_WITH_AUTH`). The 15 unmapped category types split into 13 `unresolved`
   credential-bearing or ambiguous types, each with its reason, and 2
   `not-credential` resource identifiers (`AWS_ARN`, `AZURE_RESOURCE_ID`).
   Outside the category, `PAYMENT_TOKEN` and `CART_SESSION_ID` are `unresolved`
   (ambiguous scope) and the other 540 types are `not-credential`: personal
   data or identifiers. Those outside the category are not each reviewed for
   credential shape; the status says only that no credential family is claimed.
3. **Evidence family candidates are not mappings.** A candidate is recorded as
   `provider:family` and the status stays `unresolved`. All of the candidate
   contracts read are `draft`; most have no structure.
4. **Safe metadata at the boundary, specified not built.** A native type cannot
   tell `sk_` from `pk_` Stripe keys. If a mapping is to distinguish them, the
   shim would emit a fixed, enumerated, non-secret prefix class (`sk`, `pk`,
   with `live` or `test`), validated like a native label. Nothing in the
   current shim does this, so the state stays explicitly unresolved.
5. **Missing corpus families go to credential-evidence.** `AZURE_STORAGE_KEY`
   (account key), `KUBERNETES_SECRET`, a provider-neutral OAuth client secret
   and access token have no compatible evidence family.

## Findings that need an owner

- **Family namespace.** The adapter tables emit the legacy `bench` ids
  (`github-token`, `connection-string`, ...). Snapshot cases carry
  `provider:family` ids. This repository has no translation between them. A
  scoped twin reading treats a finding whose family differs from the twin's as
  co-detection (`docs/contracts/outcomes.md`), so the mismatch may affect twin
  results in plain runs. This was not measured here; it needs verification and an
  owner before any new mapping is written.
- **Default pipeline drops some patterns.** With default options
  `GCP_SERVICE_ACCOUNT` was never reported (its captured 40-hex
  `private_key_id` is dropped by the false-positive filter; it appears with the
  filter off), and `FIREBASE_API_KEY` is shadowed by `GOOGLE_API_KEY` (same regex).
- **A public key can carry a secret-key family.** A PEM public key body was
  reported as `AWS_SECRET_KEY`, which maps to `aws-secret-access-key`.
- **`categories: ["credentials"]` changes which spans survive.** It drops
  `URL_WITH_AUTH` entirely. This is input to #50.

## Consequences

- #50 can rely on the inventory, the arbitration observations and the probe.
- Adding or changing a mapping later has a test that fails until the
  dispositions agree, so the table and the review cannot drift apart.
- Updating the package pin requires regenerating the reviewed label set, the
  dispositions and `expected.json`; the gated probe test says when it is stale.
