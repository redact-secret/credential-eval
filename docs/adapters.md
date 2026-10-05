# Scanner adapters

An adapter is the only place that knows anything about a particular scanner.
It prepares the scanner, records its identity, builds one bounded process
invocation, and maps the raw output to normalized findings. It never scores.
The code is in `crates/credential-eval-adapters`. Orchestration is in
`crates/credential-eval-cli/src/orchestrate.rs`.

```text
RunConfig.scanners[] ──► adapter.prepare ──► version, provenance
        │                                        │
CorpusSnapshot ──► materialize (temp dir) ──► adapter.scan_invocation ──► bounded process
                                                 │
                         raw stdout ──► adapter.normalize ──► NormalizedFinding[]  (raw dropped)
                                                 │
            replays compared ──► ScannerObservation ──► kernel build_artifact ──► RunArtifact
```

## The adapter protocol

`credential_eval_adapters::Adapter`:

| Method | Responsibility |
|---|---|
| `identity()` | Adapter id and implementation version (`AdapterIdentity`). Bump the version whenever the invocation, parsing, offset conversion or family mapping changes. |
| `default_spec()` | The default `ScannerSpec`: mode, `configuration` (recorded and hashed), `network: disabled`, and explicit `limits`. |
| `build(spec)` | Whether the spec runs a `released` or a `candidate` build (`ScannerIdentity.build`). It decides the artifact's publication class ([official-runs.md](official-runs.md)), so an adapter that cannot tell reports `candidate`. |
| `prepare(spec, env, cancel)` | Validate the configuration, resolve the executable or package, record provenance, probe the version (a bounded process). Returns `Prepared`, or a `PrepareFailure` that carries an explicit `ObservationResult`. |
| `scan_invocation(prepared, root, paths)` | One `Invocation`: a program path, an argument vector and optional stdin bytes. There is never a shell. |
| `normalize(prepared, stdout, fixtures)` | Map raw stdout to `NormalizedFinding`s in a deterministic order, or fail closed with a fixed `MapError` message. |
| `exit_failure(code)` | The status for a non-zero exit (default `error`). |

A `NormalizedFinding` is `{path, start, end, family?, action?}` with a
half-open UTF-8 byte range ([contracts/ranges.md](contracts/ranges.md)). It
never contains the matched value.

### Failure states (never an empty `complete`)

| Situation | Status | Where |
|---|---|---|
| Executable/runtime not found, package not installed, candidate root missing, version ≠ `required_version` | `unavailable` | `prepare` |
| Adapter cannot honour the spec (e.g. `network: allowed`) | `unsupported` | `prepare` |
| Invalid or changed adapter-owned configuration, lockfile drift, non-zero exit, spawn failure, cancellation | `error` | `prepare` / scan |
| Wall clock over `limits.timeout_ms` (version probe or scan) | `timeout` | process runner |
| Stdout over `limits.max_stdout_bytes`, unparseable output, an unmappable or ambiguous finding, an invalid byte range, truncated shim output | `malformed` | runner / `normalize` / orchestrator |
| Replays disagree | `unstable` (findings discarded, divergent paths listed) | orchestrator |

Every reason is a fixed string. It never contains scanner output or a value.
The kernel scores every case of a non-`complete` scanner as
`not-measured`, never as `MISS`.

## Normalization rules (ported from legacy `scanners/index.mjs`)

These rules reproduce the legacy adapters exactly
(`docs/migration/legacy-map.md` §5). They were ported at
`c403475476647bc98cc5864bccd7265eddebeb91`; the current parity pin,
`1020d2b5905e8973098235e57c4cdca3359bba57`, has byte-identical adapter code
([parity report](parity/parity-report.md#re-pin-to-1020d2b5-issue-20)).

- **Value + line → range** (`locate`): the reported value is byte-searched in
  the fixture, including overlapping hits. Candidates are filtered by the
  1-based reported line (the number of `\n` before the hit, plus one). When
  the same `(path, value, line)` is reported several times in one scan, the
  reports claim ascending unclaimed occurrences. Zero or several candidates
  fail closed. Scanner columns are never used, and expected ranges are never
  consulted.
- **Paths**: an absolute path is made relative to the canonical
  materialization root, and a leading `./` is stripped. A path outside the
  corpus fails closed.
- **Gitleaks**: a `decoded:base64` row that starts where a plain row of the
  same rule starts is dropped (except `private-key`). Decoded rows need
  `decode-depth:1`. A decoded PEM row recovers the single-line base64 block.
  Any other decoded row recovers the base64 run plus the original bytes the
  match extends over. Both computations use the legacy UTF-16 arithmetic.
  The optional scanner configuration key `unmappable_findings` chooses what a
  row the adapter cannot map does: absent or `"fail"` makes the scanner
  `malformed`; `"unmeasured-case"` makes the fixture the row names unmeasured
  and keeps the scan `complete` ([ADR 0003](decisions/0003-unmappable-findings-leave-the-case-unmeasured.md)).
  In an evaluation-methods run the unmeasured unit is the generated variant,
  which has no assertion or comparison for that scanner and is in no
  denominator ([ADR 0004](decisions/0004-per-case-unmeasured-handling-in-methods-and-trufflehog.md)).
- **Decoded findings** ([ADR 0005](decisions/0005-representation-contract.md),
  [contracts/representation.md](contracts/representation.md)): the optional
  scanner configuration key `decoded_mapping` (`"off"` default, or
  `"source-segment"`) for Gitleaks and TruffleHog places a finding the scanner
  reports as decoded (base64, hex, nested, up to four layers) on the original
  bytes **only when the placement can be re-derived**: exactly one run of
  encoded text on the reported line decodes strictly, through the reported
  codecs and depth, to text containing the reported value. The range is the
  whole segment, recorded as `mapping {bound, layers, codecs}`. With the key
  on, a decoded-tagged row runs this rule first and the rules above are the
  fallback, so the choice only adds mappings. Anything the rule cannot prove
  (other codecs, deeper layers, ambiguous or absent segments) stays what
  `unmappable_findings` makes it. The key is in `config_hash`; absent, output
  is byte for byte what it was.
- **TruffleHog**: the optional scanner configuration key
  `unmappable_findings` works as for Gitleaks (`"fail"` default, or
  `"unmeasured-case"`): a row the adapter cannot map, such as an ambiguous or
  unmappable percent-encoded finding, leaves the fixture it names unmeasured
  ([ADR 0004](decisions/0004-per-case-unmeasured-handling-in-methods-and-trufflehog.md)).
  The AWS `RawV2` pair yields both the key id and the
  secret. A Shopify `Raw` is token + shop domain, and only the token is
  kept (the domain must exist in the file). Postgres (`DetectorType` 968) is
  recovered by re-parsing URIs with WHATWG URL semantics and a strict
  `decodeURIComponent`. When `Raw` has a `%XX` escape and does not occur
  verbatim, a percent-encoded fallback matches each printable escape as the
  escape or as the literal byte.
- **npm packages** (`redact-secret`, `flare-redact`, `openredaction`): the
  shim reports the scanner's UTF-16 offsets. They are converted with
  `Buffer.byteLength(text.slice(0, i))` semantics (an index past the end
  clamps, and an index inside a surrogate pair fails closed). Only
  `redact-secret` reports `action`.
- **Families** (`families.rs`) are adapter-owned data ported from
  `scanners/families.mjs` (`FAMILY_MAPPING_VERSION = 2`). An unmapped label
  gets no family and is never guessed. The tables were verified identical to
  the legacy module.
- **Validation**: the orchestrator rejects any finding that is not a valid
  UTF-8 range of its fixture (`malformed`). This happens before the kernel
  sees it.

### Determinism

Gitleaks and TruffleHog scan files concurrently, and their report order
changes from run to run. The kernel keeps the **last** duplicate's
family/action ([determinism.md](contracts/determinism.md#deduplication)), so
report order can leak into the artifact. So their adapters process rows in a
canonical order: Gitleaks rows sorted by serialized row, TruffleHog lines
sorted by bytes. This is a deliberate, documented deviation from legacy, and
legacy's own result is nondeterministic here. The deviation matters only
when two rules report the identical range with different families. On the
legacy fixture corpus that happens for 5 Gitleaks ranges and no others. The
Node shim scans paths in sorted order, and each package's own emission order
is deterministic.

OpenRedaction 1.1.5 aborts any single regex execution that takes longer than
its `regexTimeout` (100 ms wall clock by default) and skips that pattern for
the input. On a heavily loaded host a long input can therefore produce
different findings in two replays. The replay rule catches it: the scanner is
`unstable` and its findings are discarded, never scored. Legacy runs the
package in process with the same default and is exposed to the same effect.

Legacy runs the three npm scanners in process without a timeout or output
cap; here they run in the bounded Node shim. The default 120 s timeout and
16 MiB stdout cap are enough for a corpus measurement of the legacy corpus but
not for its ~48k evaluation variants on a loaded host, so the parity run
config (`tools/parity/run-config.json`) raises both for the three shim
scanners (30 min, 256 MiB). Exceeding a bound is `timeout`/`malformed`, never
an empty result.

## Provenance

`ScannerIdentity.provenance` records how the scanner was set up. It uses
digests and versions only, and never host paths.

| Component `kind` | Recorded |
|---|---|
| `executable` | program file name, reported version, SHA-256 of the resolved binary |
| `runtime` | `node` file name, `node --version`, SHA-256 of the binary |
| `shim` | SHA-256 of `adapters/node/shim.mjs` |
| `lockfile` | SHA-256 of `package-lock.json`, `lockfileVersion` |
| `npm-package` | name, version and `integrity` (from the lockfile, checked against the installed `package.json`) for the package and its installed dependency closure; the main package also carries a SHA-256 tree digest of its installed files |

`network` is the posture the scanner ran under (`disabled`; adapters refuse
`allowed` as `unsupported`). `network_controls` lists the flags that keep it
there (TruffleHog: `--no-update`, `--no-verification`). The adapters turn
on no network feature for Gitleaks or the npm packages. The evaluator does
not sandbox scanner processes, so the posture is what the adapter
configures, not an enforced isolation.

The resolved absolute paths are never written to artifacts. The digests pin
the bytes.

## Execution bounds

- `execution.jobs` bounds concurrent scanner processes globally.
  `limits.concurrency` bounds them per scanner. The work unit is one
  (scanner, replay) process over the whole materialized corpus, which is
  how legacy ran scanners.
- Each process has `limits.timeout_ms`, a stdout cap
  (`limits.max_stdout_bytes`), and stderr that is drained and discarded (it
  is never retained or published). Timeout, overflow and cancellation kill
  the process.
- Environment: the parent environment minus `GITLEAKS_CONFIG` and
  `GITLEAKS_CONFIG_TOML` (legacy `command()`). There is no shell.
- `accounting.replays` scans run per scanner. When a replay fails, the
  scanner's later replays are cancelled. The lowest failing replay decides
  the status. Replays are compared as whole normalized findings per path
  (the stricter `eval` rule).
- Fixtures are written to a private temporary directory (`0700`
  directories, `0600` files). It is canonicalized, because scanners report
  canonical paths, and it is removed when the run ends, including on error.
- Ctrl-C cancels the run. Running processes are killed and no artifact is
  written (exit 130).
- Timing goes to `non_semantic`. `durations_ms` is per-scanner process
  time, including the version probe. `execution` holds `wall_ms`,
  `scanner_process_ms` (summed over processes) and `evaluator_ms` (loading,
  materialization, normalization, collation and scoring).

## Built-in adapters

| Scanner / adapter id | Adapter version | Scanner pin | Invocation |
|---|---|---|---|
| `gitleaks` | 2 | 8.30.1 (`required_version`) | `gitleaks dir <root> --no-banner --no-color --exit-code 0 --report-format json --report-path -`; 64 MiB stdout cap |
| `trufflehog` | 2 | **3.97.4** (`required_version`; 3.97.6 re-keys results) | `trufflehog filesystem <root> --json --no-verification --no-update --results=verified,unknown,unverified` |
| `redact-secret` | 3 | `@redact-secret/core` 0.1.0-beta.13 (lockfile, `sha512` integrity and tarball pinned in the official config) | shim, `initialize()` + `scan(text)` |
| `flare-redact` | 1 | `flare-redact` 1.6.1 (lockfile) | shim, `scan(text, {disable:['pii','generic_assignment'], includeValues:false})` |
| `openredaction` | 2 | `@openredaction/core` 1.1.5 (lockfile) | shim, `new OpenRedaction({}).detect(text)`; records the native pattern type as `native_labels` (reviewed set of 575 types, [ADR 0011](decisions/0011-native-scanner-labels.md); native-type audit in [ADR 0012](decisions/0012-openredaction-native-type-audit.md)) |

Diagnostic profiles of `openredaction` (`openredaction-credentials`, `openredaction-mapped`, adapter version 1) are selectable by `--scanner` but are not built in and not in the default set; see [ADR 0013](decisions/0013-openredaction-credential-profile.md).

Configuration keys are validated. An unknown key, or a change to an
adapter-owned value (`arguments`, `rules`, `options`, ...), is an `error`,
never a silently different run. The user-settable keys are:

- `binary` (a program name looked up on `PATH`, or a path), for Gitleaks
  and TruffleHog;
- `required_version` (`null` for exploratory runs with other versions),
  for Gitleaks and TruffleHog;
- `node` and `package_source` (`published` | `candidate`), for the npm
  scanners.

Print the defaults with `credential-eval default-config`.

### Node shim and package sources

`adapters/node/` holds `shim.mjs`, and `package.json`/`package-lock.json`
pinning the three packages to the legacy versions and integrity hashes.
Install them with:

```sh
(cd adapters/node && npm ci --ignore-scripts)
```

The shim imports each package through its `exports` entry point and uses
only the public API. It prints `{path, start, end, label, type?, action?}`
per finding and a final `{"done": true, "findings": n}`. It never prints
values. Exit code 3 means "package not installed" (`unavailable`).

`package_source: "candidate"` resolves the package from a root given at run
time with `--candidate-root <scanner>=<dir>`. That directory must contain
`node_modules/<package>` and, ideally, a `package-lock.json`. Provenance
then records the candidate's versions, integrity and tree digest. The
configuration hash differs from a published run. No product policy is
attached to candidate runs here.

## CLI

```sh
credential-eval run --corpus <snapshot.json> --out <artifact.json> \
  [--config <run-config.json>] [--scanner <id>]... [--jobs N] \
  [--observations-out <observation-set.json>] [--node-dir <dir>] \
  [--candidate-root <scanner>=<dir>]... [--work-dir <dir>] [--require-complete]
credential-eval default-config [--scanner <id>]... [--jobs N]
```

- Without `--config`, the selected built-in scanners run with their default
  specs and the legacy engine v1.1 accounting parameters. With `--config`,
  `--scanner` filters the configured scanners.
- `--jobs` overrides `execution.jobs`, which is not part of the config hash.
- Exit codes: 0 means the artifact was written. 1 means the run failed. 2
  means a usage or configuration error. 3 means `--require-complete` was
  given and a scanner did not complete. 130 means the run was cancelled.
- The stderr summary shows each scanner's id, version, status, sanitized
  detail and finding count, the timing split, and the semantic digest.

## Adding a scanner without touching credential-evidence schemas

A new scanner needs changes only in this crate and, if it has one, its own
shim directory. It never needs changes to `credential-evidence`, to the
corpus or artifact schemas, to Redact Secret, to the site, to the kernel, or
to other adapters.

1. **Implement `Adapter`** in `crates/credential-eval-adapters/src/<scanner>.rs`:
   - `identity()`: a new adapter id and version `1`.
   - `default_spec()`: the mode string, configuration and explicit limits,
     with `network: disabled`.
   - `build()`: `released` only for builds that are published releases;
     anything else (candidate roots, local builds) is `candidate`.
   - `prepare()`: reuse `binary::prepare` for a standalone executable (it
     gives you configuration validation, `PATH` resolution, the version
     probe, `required_version` and executable provenance). Follow
     `node::NodeAdapter` for a package run through a shim.
   - `scan_invocation()`: a fixed argument vector with the materialized
     root substituted. No shell and no string interpolation.
   - `normalize()`: parse the output and map every finding to a UTF-8 byte
     range with `locate::{locate, Claims, Line}` or `locate::Utf16Offsets`.
     Fail closed with a fixed `MapError` on anything ambiguous. If the
     scanner's report order is not stable, sort before mapping.
2. **Map labels to families** only where the native label is the same
   credential as an existing family. Add a `LabelTable` and a table in
   `families.rs`, and bump `FAMILY_MAPPING_VERSION`. Unmapped labels stay
   unmapped.
3. **Register** the adapter in `builtin()` in `lib.rs`, keeping the list
   sorted by id.
4. **Test** `normalize` with synthetic canned output: exact ranges on
   multi-byte content, every fail-closed path, and the family mapping. Add
   an orchestration test with a fake executable if the adapter has special
   exit codes.
5. **Run** `credential-eval run --scanner <id> ...` or give the scanner a
   spec in a run config. The artifact records its identity, provenance and
   configuration hash, and the existing schemas already describe it.

A new scanner that reports ranges in an unusual convention (lines/columns,
code points, UTF-16) converts them in its adapter. The kernel only ever sees
UTF-8 byte ranges.

## Legacy parity notes (for #5)

- `--observations-out` writes the `ObservationSet` handed to the kernel.
  Its findings are directly comparable with legacy adapter output
  (`{path, start, end, family?, action?}`) as multisets per scanner. The
  families are the legacy `bench` families (no `eval` allowlist is applied
  here; that is pipeline-specific, see legacy-map §1).
- Checked locally: 5,925 legacy fixtures (all `fixtures/generated/*.json`
  plus `accuracy`, `token-contexts` and `real-world-shapes`, each
  materialized under its category directory) were scanned by the legacy
  adapters and by these adapters, with the pinned peers (Gitleaks 8.30.1,
  TruffleHog 3.97.4) and packages. Every scanner's normalized findings were
  equal as multisets: flare-redact 1,111; gitleaks 2,440; openredaction
  27,249; redact-secret 2,986; trufflehog 1,047. `--jobs 1` and `--jobs 8`
  gave the same semantic digest.
- Legacy folds `timeout` and `malformed` into `error`. A compatibility
  writer must do the same.
- For the 5 Gitleaks ranges reported by two rules with different families,
  the surviving family depends on report order. Legacy is nondeterministic
  there, so compare those ranges without their family.
