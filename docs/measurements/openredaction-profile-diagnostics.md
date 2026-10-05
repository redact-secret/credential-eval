# OpenRedaction 1.1.5 credential-scoped profile: diagnostics

Decision record: [ADR 0013](../decisions/0013-openredaction-credential-profile.md).
This is an operational diagnostic, not an official qualification and not a
performance claim (those need the controlled protocol, ADR 0002 and ADR 0010).
One host, one trial per corpus cell and three trials per synthetic cell.

- Package: `@openredaction/core` 1.1.5, integrity
  `sha512-SpQTBhVV4p3rmge818NH6iJiL/fvwFlDvhGaejoL0wbzY7jRHIhU5vEf3KzNARsIZmpCJV1eHdiavIjQyN1hXQ==`
  (lockfile), Node 22.16.0, engine `0.1.0-alpha.10` plus the diagnostic adapters
  of this change, adapter identities `openredaction` 2, `openredaction-credentials` 1,
  `openredaction-mapped` 1.
- Host: Apple M4, 10 cores, 24 GiB, arm64, macOS, other sessions running
  (load average about 5 to 6). Each synthetic measurement is one fresh process,
  strictly serial, `nice` 10.
- Evidence: `credential-evidence` `snapshot-2026.10.01.2` (5,950 cases, the
  release ADR 0009 used) for coverage deltas; `snapshot-2026.10.05.3`
  (6,596 cases) for completion.
- Inputs: deterministic synthetic generators in `tools/openredaction-profile/inputs.mjs`
  (padding, sparse, dense, overlap, negative, unicode, encoded). No padding or
  case was edited and no finding truncated to improve a result.
- Raw rows: `tools/openredaction-profile/results/diagnostics-1.1.5.json`.

## Profiles

| Id | Options | Patterns |
|---|---|---|
| `openredaction` (default, preserved) | `{}` | 579 |
| `openredaction-credentials` | `{categories:["credentials"]}` | 32 |
| `openredaction-mapped` | `{patterns:[the 18 mapped types]}` | 18 |

`patterns` takes precedence over `categories` in the package. The category is
not a sensitivity guarantee: it omits `URL_WITH_AUTH` and 15 of its 32 types
carry no family (ADR 0012).

## Confirmed code behavior (read in the installed package)

- Overlap rejection is `ranges.some(...)` over every previously accepted range,
  so it is linear per match and quadratic in the finding count.
- After scanning, `detect()` builds a redacted copy: for every finding it
  compiles a `RegExp` from the escaped value and runs `replace` over the whole
  text. This is per-finding, full-text work. Our shim reads only
  `detections[].type` and `position`, so the copy is discarded. `scan()` calls
  `detect()`; no supported detect-only API exists in 1.1.5 (no option skips it).
- Each pattern stops after 10,000 matches (`maxMatches`), silently.
- `regexTimeout` (100 ms) is checked after one `exec` returns. A pattern that
  exceeds it throws and the pattern is skipped for that input, silently.
- Cache is off by default; the shim builds one detector per scan.

## Measured CPU attribution (V8 profile, 256 KiB, one process)

| Input / profile | Largest self-time shares |
|---|---|
| dense, default (3.0 s profiled) | `processPatterns` 30 %, `detect` 15 %, `overlapsWithExisting` 7 %, GC 4 % |
| dense, credentials (1.2 s) | `detect` 29 %, GC 9 %, `overlapsWithExisting` 3 % |
| padding, default (1.0 s) | one regex (the NAME pattern over prose) 53 %, `checkProximity` 6 % |

The `detect` self time contains the per-finding redaction loop (inlined). The
split between that loop and the rest of `detect` was not isolated; no patched
copy was run, so no speedup from removing it is claimed.

## Synthetic costs (median of 3 fresh processes, ms; findings; peak RSS MiB)

| Input | Size | default | credentials | mapped |
|---|---|---|---|---|
| padding | 1 MiB | 3,761; 9,999 NAME findings; 106 | 16; 0; 64 | 11; 0; 64 |
| sparse (1 per ~4 KiB) | 1 MiB | 3,907; 10,181; 159 | 105; 230; 117 | 105; 259; 122 |
| dense (every line) | 256 KiB | 1,021; 6,004; 176 | 528; 4,658; 153 | 558; 5,240; 158 |
| dense | 1 MiB | 14,663; 33,169; 339 | 5,781; 18,386; 283 | 6,227; 20,685; 295 |
| overlap | 1 MiB | 7,895; 14,190; 298 | 2,018; 7,093; 236 | 4,540; 14,186; 275 |
| negative | 1 MiB | 1,657; 4,855; 106 | 1,290; 4,855; 86 | 36; 0; 70 |
| unicode | 1 MiB | 388; 537; 156 | 166; 424; 137 | 123; 477; 142 |
| encoded | 1 MiB | 5,175; 10,122; 151 | 93; 162; 110 | 88; 162; 112 |

What it shows:

- On credential-free prose the default's cost and findings are PII patterns
  (200 findings per 16 KiB of padding, all `NAME`); the credentials profile
  scans it in milliseconds. The 1 MiB padding run hit the 9,999 per-pattern
  cap, so the default's output was truncated on a clean input.
- Dense input stays superlinear in every profile: 4x the bytes cost 11x for
  the credentials profile (528 ms to 5,781 ms). Reducing the pattern set does
  not remove that cost; the overlap and redaction work scale with findings.
- The `negative` lookalikes (placeholders, UUIDs, hashes) still draw 4,855
  findings under `credentials`, the same count as the default (one type; which
  one was not examined). The allowlist removed them only because the lookalikes
  contain no mapped shape. This is a coverage observation, not a gain.
- Warm second-call times in the same process are close to the first
  (`warm_ms` in the rows), so process start is not the cost.

## Corpus: output, completion and classification deltas

`snapshot-2026.10.05.3` (plain run, `--jobs 2`):

- `openredaction` default exceeded the adapter's 16 MiB stdout limit (reported
  `malformed`, output discarded) and, with the limit raised to 256 MiB, timed
  out at 300 s per task (two replays, 10 minutes of scanner time, no result).
- `openredaction-credentials` completed: 1,396 findings, 387,142 bytes, 8.6 s of
  scanner process time. `openredaction-mapped` completed: 1,273 findings,
  352,764 bytes, 6.0 s.

`snapshot-2026.10.01.2` (plain run, `--jobs 2`, all three complete):

| | default | credentials | mapped |
|---|---|---|---|
| Findings (deduplicated) | 27,253 | 1,068 | 960 |
| Bytes received | 6,276,700 | 289,904 | 259,624 |
| Scanner process time, 2 replays | 23.8 s | 2.5 s | 2.2 s |
| Positive spans: EXACT / COVERED / OVERBROAD / PARTIAL / MISS | 535 / 28 / 9 / 200 / 1,653 | 531 / 23 / 8 / 117 / 1,746 | 485 / 28 / 9 / 108 / 1,795 |
| Controls flagged (of 3,486) | 1,057 | 119 | 72 |

Differences that explain those numbers (native labels from ADR 0011 made this
possible):

- Default controls flagged but not by credentials: 939 cases, from personal-data
  patterns. Credentials flags one control the default did not.
- Positives that go from PARTIAL to MISS under `credentials`: 81. These are
  accidental overlaps of personal-data findings (mostly `INSTAGRAM_USERNAME`,
  265 findings) with part of a secret, which the default scores as `PARTIAL`.
  A `MISS` is the honest result there, but the aggregate looks worse.
- EXACT or COVERED lost under `credentials`: 11 spans, labels `INSTAGRAM_USERNAME`
  (25 findings), `URL_WITH_AUTH` (4, outside the category), `BITCOIN_ADDRESS`,
  `GENERIC_SECRET`, `MINECRAFT_UUID`. Three spans gain EXACT or COVERED
  (`GITHUB_TOKEN`, `HEROKU_API_KEY`, `SENDGRID_API_KEY`) because the default's
  overlapping personal-data finding no longer wins arbitration.
- Under `mapped`, EXACT or COVERED lost: 51 spans, including `HEROKU_API_KEY`
  (28), `GOOGLE_API_KEY` (10), `OAUTH_TOKEN` (4), `DOCKER_AUTH`: types that carry
  no family but do report real credential ranges. The allowlist drops them.
- Findings with a family: 956 (default), 948 (credentials), 960 (mapped).
  Family-bearing coverage is almost unchanged; what the profiles remove is
  unfamilied personal-data findings and the accidental credit they gave.

## Residual cost and bounds

With either profile a dense 1 MiB input still takes 5.8 to 6.2 s and 280 to
300 MiB. The existing bounds apply: per-scanner `timeout_ms`, `max_stdout_bytes`
and `concurrency` in the scanner spec, and `--jobs`. Sharding a scanner's
fixtures across processes is not recommended: independence of state and
ordering has not been demonstrated, and 1.1.5 shares one detector across the
files of a batch. Isolating a heavy case in its own scan is possible with the
existing planner and was not needed here.

## Not measured

- A patched copy of the package (no per-finding redaction, indexed overlap):
  not run; an optional, diagnostic-only experiment, and it would not be the
  released competitor.
- The methods populations (differential, metamorphic, mutation) for the
  profiles. Those runs are the expensive ones and are the subject of the
  validation budget in the ADR.
- Variance: three fresh processes per synthetic cell; one trial per corpus cell.
