# ADR 0004: Per-case unmeasured handling in evaluation methods and for TruffleHog

- Status: accepted
- Date: 2026-10-04
- Issue: redact-secret-benchmarks#680 (official public methods run of `snapshot-2026.10.04`)
- Amends: [ADR 0003](0003-unmappable-findings-leave-the-case-unmeasured.md) decision 5 (methods fail closed). Adds no field to any v1 document.

## Context

With `v0.1.0-alpha.2` the public plain run of `snapshot-2026.10.04` completed
(Gitleaks left 10 of 6,449 cases unmeasured). The methods run over the same
evidence was refused: three scanners were `malformed`, so the official gate
(`a non-complete scanner is not measured`) refused the artifact.

| Scanner | Methods-run state | Cause |
| --- | --- | --- |
| Gitleaks 8.30.1 | `malformed` | ADR 0003 decision 5: a scanner that reports any unmeasured path in a methods run is made `malformed` for the run. The variant corpus (35,322 generated variants) contains decoded and hex-encoded variants Gitleaks reports as findings the adapter cannot place. |
| TruffleHog 3.97.4 | `malformed` | `Ambiguous or unmappable percent-encoded finding`. The plain run is `complete`; a percent-encoded *variant* (an operator output) names a value whose decoded form is absent or ambiguous in the variant. The adapter had no per-case handling at all. |
| OpenRedaction 1.1.5 | `malformed` | `scanner stdout exceeded max_stdout_bytes`. Its default patterns report 360,606 findings on the 6,449 plain cases and several times that on 35,322 variants; the official 256 MiB cap is a bound on one process's stdout. |

An evaluation method scores a scanner on many variants of one case. Failing the
whole scanner for one unplaceable variant voids every assertion of every method
for that scanner, which is the same over-reach ADR 0003 removed from the plain
run.

## Decision

1. **A variant is the unit, in methods as in plain runs.** When a scanner's
   configuration chose per-case handling, a variant whose finding the adapter
   cannot place is *unmeasured by that scanner*. The scan stays `complete`.
2. **An unmeasured variant is in no denominator and never a miss.** For the
   scanner that left it unmeasured the evaluation records
   - no absolute assertion for the variant, and no relation assertion whose
     baseline or candidate is the variant;
   - no differential comparison whose reference or peer is that scanner on the
     variant (the other peers are compared as usual), no disagreement queue
     entry and no per-variant observation for it;
   - a `scanners[].cases[]` row with measurement `not_measured`, no actual
     ranges, and an entry in `scanners[].unmeasured_cases[]` (the v1.2 field
     of ADR 0003, unchanged).

   The omission is the accounting: `not-measured` assertions *consume the
   denominator* (an unresolved case), and the point of this decision is that an
   unplaceable variant must not. Other scanners, and the same scanner on every
   other variant, are scored exactly as before. A relation needs both ends, so a
   baseline that is unmeasured drops every relation of its case for that scanner.
3. **It is counted per method and surfaced.** The run prints
   `<id> unmeasured: N of M cases ... (variants by method: differential: a,
   metamorphic: b, mutation: c)`. In the artifact, join
   `unmeasured_cases[].case_id` to `cases[].path` to `variants[].path` for the
   method. `--require-fully-measured` exits 3 for a methods run too.
   `--require-complete` keeps its meaning (every scanner `complete`).
4. **TruffleHog gets the same opt-in as Gitleaks.** The scanner configuration key
   `unmappable_findings` (`"fail"` default, or `"unmeasured-case"`) is accepted
   by the TruffleHog adapter. Attribution is conservative, identical to
   ADR 0003 decision 3: only a row whose file resolves to a known fixture is
   attributed; unparseable output or an unknown path still makes the scanner
   `malformed`. All findings on an unmeasured fixture are discarded. The key is
   part of the scanner configuration, so it is in `config_hash`. Other adapters
   do not implement it.
5. **The OpenRedaction cap is a configuration value, so it is raised in the
   official configuration**, not in the engine (see Consequences). The engine
   keeps bounding stdout: exceeding the cap is still `malformed`, never a
   truncated reading.
6. **Scope is unchanged.** The raw-input scope is kept. Nothing here maps a
   decoded or percent-encoded finding to a range, and no result claims that
   decoded or fragment semantics were measured. Not-assertable (T0) cases stay
   out of every TP/FN denominator; they remain `pending`/review as before.
7. **Opt-in only.** An adapter configuration without the key behaves exactly as
   in alpha.2 for plain and methods runs: with the key absent or `"fail"` a
   single unmappable row makes the scanner `malformed`.

## Consequences

- Official configurations (`configs/official/credential-public-v1*.json`) set
  `unmappable_findings: unmeasured-case` for Gitleaks (already) and TruffleHog,
  and raise OpenRedaction's `max_stdout_bytes` from 256 MiB to 1 GiB. Its
  methods output is about 1.8 million findings, over 256 MiB; peak engine
  memory stayed under 5 GB. `config_hash` changes, and with it every semantic
  digest: benchmarks re-resolves the hash from the first canonical CI run, as
  for every engine bump.
- The methods artifact is no longer rectangular for a scanner with gaps: it has
  fewer assertions and comparisons than variants times scanners. A consumer must
  show the unmeasured counts next to any methods result of that scanner.
- Methods that rest on a variant the reference could not measure
  (differential) lose that variant for every peer, because there is nothing to
  compare against.
- No schema change; contracts stay v1.2.
