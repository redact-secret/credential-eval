# ADR 0013: Credential-scoped OpenRedaction profiles as diagnostics

- Status: accepted; the recommended 33-type profile was built and measured in [ADR 0015](0015-openredaction-mapping-recheck-and-credential-bearing-profile.md)
- Date: 2026-10-05
- Issue: #50 (parent: redact-secret-benchmarks#723; follows ADR 0011 and ADR 0012)
- Amends: nothing frozen. Adds two diagnostic adapters; no contract field,
  protocol rule, default scanner set or official configuration changes.

## Context

The default `openredaction` scan dominates methods runs (ADR 0004, ADR 0009).
ADR 0009 removed output costs and left detector cost untouched. The public
option `categories: ["credentials"]` suggests a cheaper, credential-scoped
profile, but the category is not a sensitivity guarantee and changes which
overlapping spans survive. The study is in
[docs/measurements/openredaction-profile-diagnostics.md](../measurements/openredaction-profile-diagnostics.md).

## Decision

1. **Two diagnostic adapters, outside the default set.**
   `openredaction-credentials` (`categories: ["credentials"]`) and
   `openredaction-mapped` (an explicit allowlist generated from the adapter's
   mapping table). Each has its own scanner id, adapter version, `options`
   and therefore its own configuration hash. They are selectable with
   `--scanner` and absent from `builtin()`, `default-config` with no scanner
   and every official configuration. The default-options result is preserved
   and never replaced. Tests pin the separation.
2. **The shim, labels and mapping are unchanged.** Both profiles reuse the
   `openredaction` shim key, the reviewed label set (ADR 0011) and the family
   table (ADR 0012); no edit to padding, cases or findings was made.
3. **Go / no-go.**
   - Do **not** replace the default result with either profile, and do not
     present profile numbers as OpenRedaction's.
   - **Go** for one further bounded validation of a credential-scoped
     configuration as a separately labeled result, because the default no
     longer completes: on `snapshot-2026.10.05.3` it exceeds the 16 MiB output
     limit and a 300 s per-task timeout, while `credentials` finishes in
     about 9 s.
   - `openredaction-mapped` is **no-go**: it drops real credential ranges whose
     types have no family (51 EXACT or COVERED spans lost).
   - `openredaction-credentials` is incomplete as a credential set: it omits
     `URL_WITH_AUTH` and loses 11 EXACT or COVERED spans. The candidate for the
     validation is therefore the 33 types the audit calls credential-bearing
     (`credentials` category plus `URL_WITH_AUTH`) as an explicit allowlist,
     which does not exist yet and must be added with its own identity if the
     budget below is approved. Its sensitivity review is ADR 0012 (13
     unresolved types stay unresolved).
4. **Validation budget before any expensive methods trial.** One plain run and
   one methods run of the candidate on the current snapshot, `--jobs 2`, one
   trial each, estimated under 15 minutes of scanner time in total (the
   credentials profile took 8.6 s for a plain run). A trial of the default
   methods run on the current snapshot is not budgeted: it did not complete in
   10 minutes of scanner time for a plain run. Running it on GitHub Actions
   needs the expected minutes stated and approved first.
5. **Residual cost.** Dense inputs stay superlinear in every profile. The
   existing per-scanner timeout, output cap, concurrency and isolated-scan
   planning are the options; sharding is not recommended without a
   demonstrated state and ordering independence. No speedup is promised.
6. **Confirmed behavior versus measured time** are kept apart in the report.
   Confirmed from the package source: quadratic overlap checks, per-finding
   full-text redaction whose result our shim discards, a silent 10,000-match
   cap and a silent post-hoc regex timeout, and no detect-only API in 1.1.5.
   Measured: the profile attribution, which does not isolate the redaction
   loop. No upstream internals were patched.

## Consequences

- Reports of a profile must name the scanner id and the configuration hash,
  and state that it is a diagnostic profile of OpenRedaction, not OpenRedaction.
- Results from the default and the profiles are separate observations and can
  be compared by native label (ADR 0011).
- A package pin change invalidates the dispositions, the reviewed label set and
  the recorded probe at once, and the gated test says so.
