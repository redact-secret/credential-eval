# ADR 0009: Batched, back-pressured Node shim output and typed normalization

- Status: accepted
- Date: 2026-10-04
- Issue: #41 (parent: redact-secret-benchmarks#704)
- Amends: nothing frozen. Engine `0.1.0-alpha.8`. The measurement protocol, scoring and every semantic field are unchanged.

## Context

A methods run of OpenRedaction reports about 1.8 million findings (ADR 0004).
The shim wrote one `process.stdout.write` per finding with no back-pressure,
and Rust read each line into a `serde_json::Value`, then resolved and
validated the same fixture path again for every row.

Per the issue's cost-first correction this was investigated with bounded
contract fixtures (1.8M synthetic rows, 112,604,400 bytes, 5,000 paths), not
with repeated 29-minute peer runs. Scanner CPU (OpenRedaction's own detection)
is not touched; it is not ours to rewrite and was not re-profiled here.

## Measurements

Same machine, same input, one trial each (pre-change → post-change):

| Phase | Before | After |
|---|---|---|
| Shim emit, `/dev/null` reader | 13.3 s | 3.1 s |
| Shim emit, slow reader (0.5 ms per 64 KiB) | 16.4 s, peak RSS 277 MB | 4.4 s, peak RSS 49 MB |
| Rust `normalize` (release) | 27.6 s | 7.6 s |
| Output bytes | 112,604,400 | 112,604,400 |

These are fixture timings of two phases.

### Pinned full-run validation

`openredaction` (and `redact-secret` as the differential reference) on the
public snapshot `snapshot-2026.10.01.2` (manifest digest verified, 5,950
cases), release builds of `02039c9` (alpha.7) and this change (alpha.8),
`--jobs 4`, exploratory class, one trial each, run back to back on one host.
The methods run uses the registry's selection (`differential,metamorphic,mutation`,
reference `redact-secret`, seed `case-id`, evaluation evidence from
`redact-secret-benchmarks`). The binary peers were not part of it: they are
not touched by this change.

| | Plain before → after | Methods before → after |
|---|---|---|
| Wall time | 46.0 s → 36.7 s | 270.0 s → 216.1 s |
| `openredaction` process time (2 replays) | 76.4 s → 57.9 s | 446.3 s → 346.7 s |
| `openredaction` normalize | 0.19 s → 0.11 s | 1.5 s → 0.55 s |
| Peak RSS (whole run) | 129.1 → 127.8 MB | 1,009 → 1,019 MB |
| `openredaction` stdout bytes | 6,276,700 → 6,276,700 | 30,638,624 → 30,638,624 |
| `openredaction` findings | 27,253 → 27,253 | 118,882 → 118,882 |

Semantic result: `scanners` (findings, per-case states, assertions,
aggregates), `variants` and `comparisons` are equal in both modes. In the
methods artifact the `review_queue` has 3,776 entries on both sides, equal in
every field except `id`: a review id binds the peer scanner identity, whose
`shim.mjs` digest changed (see below). The semantic digest differs only by the
engine version and that identity.

Limits of this evidence. One trial per side on a shared host, so differences of
a few seconds are within noise; the 20 to 25 % wall-time reduction is the order
of magnitude, not a precise figure. Peak RSS is dominated by the evaluator and
is unchanged. This pinned methods selection reports 118,882 `openredaction`
findings, not the ~1.8 million of ADR 0004, so the large-output regime was
exercised only by the synthetic fixture above; the batching matters most there.

## Decision

1. **Shim batches and back-pressures.** Findings are joined into ~64 KiB
   chunks and written with `drain` waiting, so memory stays bounded for a slow
   reader. The byte stream is unchanged: one JSON line per finding, same
   order, same `done` line. No finding is dropped, merged or sampled.
2. **Normalization reads rows typed and caches per path.** A path's
   resolution, `FixturePath` validation and UTF-16 offset table are computed
   once per distinct reported path; the first row of a path decides any
   failure exactly as before. Field reading keeps the `Value` accessor
   semantics (wrong-typed field reads as absent; `action: null` is invalid),
   enforced by a test that compares the new reader to the previous
   implementation on single rows and row pairs, including malformed ones.
3. **No parallelism, sharding or reordering.** Case independence of
   OpenRedaction's detector state has not been demonstrated, and sharding can
   raise total runner-minutes. Not adopted.
4. **Caps unchanged.** Stdout cap, timeout and stderr cap are as before. A
   reader that stops reading is still bounded by the timeout; one that closes
   the pipe fails the shim closed (`shim failed`, exit 1).

## Identity consequence

`adapters/node/shim.mjs` changes, so the `shim.mjs` provenance digest of every
Node scanner changes. Scanner identity therefore differs from alpha.7, and
observations recorded under alpha.7 are not reused for Node scanners (ADR
0008); other scanners are unaffected. Findings are byte-for-byte what the
previous shim produced.

## Verification

- `crates/credential-eval-adapters/tests/shim.rs` runs the real shim with a
  fake package and a slow reader; the output equals the expected one-line
  per-finding stream (also passes against the previous shim).
- `node::tests::typed_reading_matches_the_value_reference` and
  `repeated_ranges_keep_their_multiplicity_and_order` in `node.rs`.
