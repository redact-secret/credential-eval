# Compatibility retirement contract and consumer inventory

Decision: [ADR 0014](../decisions/0014-compatibility-retirement-contract.md).
Issue: #33 (parent coordination:
[redact-secret-benchmarks#651](https://github.com/redact-secret/redact-secret-benchmarks/issues/651)).
This document defines what may be deleted, when, and what must be proven first.
It deletes nothing. It does not reopen CI performance work (#29, #31).

Evidence for the "known readers" column was gathered on 2026-10-05 from this
repository and by searching `redact-secret-benchmarks`; a search finds
references, it does not prove absence, so every deletion step re-checks callers
(section 5).

## 1. Boundary

| Class | Meaning | Rule |
|---|---|---|
| **Canonical** | The v1 contracts, the kernel, adapters, perf crate, the frozen baselines in `crates/credential-eval-contracts/tests/frozen-v1/`, the schemas, accounting and determinism tests. | Never removed by this plan. A change is a protocol or contract revision. |
| **Compatibility** | Code that renders or reproduces a legacy shape: legacy result writers, legacy-only figures and labels, the legacy seed convention. | Isolated, removable, deleted only through section 5. |
| **Oracle** | Tools, fixtures and tests that compare against the pinned TypeScript engine (`redact-secret-benchmarks@c403475`, parity at `1020d2b5`). | Kept until the recorded oracle exit; not "compatibility" in the sense of being unused. |
| **Product** | Qualification policy, support verdicts, thresholds, ledger, promotion, protected evidence, PII, MCP, calibration. | Never in this repository (AGENTS.md, ARCHITECTURE.md). Nothing here moves a verdict into the engine. |

## 2. Consumer inventory (this repository)

| Item | Where | Class | Known readers | Replacement | Disposition |
|---|---|---|---|---|---|
| Legacy value validators `legacy:discord-bot-token`, `legacy:confluent-cloud-api-secret`, `legacy:gitlab-routable-optional`, `legacy:gitlab-routable-required` | `crates/credential-eval-compat/src/validators.rs`, resolved by `crates/credential-eval-cli/src/evidence.rs` | Compatibility by name, **active product dependency** | `benchmarks/qualification/evaluation-evidence.ts` in redact-secret-benchmarks maps product validators to these names; evidence files reference them | A canonical validator registry with non-`legacy` names, plus a name alias for one window | **Keep; move first.** Not removable while the product names them. |
| Legacy bench renderer | `credential-eval-compat/src/bench.rs`; CLI `credential-eval compat legacy-bench` | Compatibility | `tools/parity/run.sh` (parity step `ours`). No reader found in redact-secret-benchmarks | None needed after parity | Remove after the last-reader check |
| Legacy eval renderer | `credential-eval-compat/src/eval.rs`; CLI `run --methods ... --legacy-eval-out` | Compatibility | `tools/parity/run.sh`. No reader found in redact-secret-benchmarks | None needed after parity | Remove after the last-reader check |
| Legacy-only kernel views | `credential-eval-kernel/src/compat.rs`: `aggregate_groups_v10`, `accounting_delta`, `assertion_delta`, `encode_outcome`, `legacy_status`, `legacy_disagreement`, `legacy_seed` | Compatibility (in the kernel crate, isolated by module) | `credential-eval-kernel/tests/oracle.rs`, one test in `tests/rules.rs`, CLI `orchestrate.rs` (`--seed legacy-category`) | None | Remove with the oracle tests; `legacy_seed` goes with the `legacy-category` convention |
| Seed convention `legacy-category` | CLI `--seed`, `SeedConvention` | Compatibility | Parity runs only. Official runs use `case-id` (redact-secret-benchmarks `docs/specs/official-runs.md`) | `case-id` | Remove with the kernel views |
| Oracle goldens and generator | `crates/credential-eval-kernel/tests/oracle.rs`, `tests/fixtures/oracle/` (3.9 MB), `tools/oracle/generate.mts` | Oracle | `cargo test` (same job as canonical tests) | Canonical goldens (`contracts-smoke`, `representation-smoke`) | Keep until oracle exit |
| Legacy exporter and parity tools | `tools/legacy-export/export.mts`, `tools/parity/{run.sh,compare.mjs,run-config.json}` | Oracle | Humans re-running parity; benchmarks' legacy export | None | Keep until oracle exit |
| Durable records | `docs/parity/`, `docs/migration/{legacy-map,kernel-deltas,redact-secret-cutover}.md`, ADRs 0001 to 0014 | Record | History, audits | n/a | **Never delete.** Mark superseded instead. |
| Identity strings | `LEGACY_MEASUREMENT_PROFILE`, `LEGACY_ACCOUNTING_VERSION`, `SnapshotIdentity.source = legacy:redact-secret-benchmarks`, `ScannerSpec`/`NormalizedFinding` field semantics ported from legacy | Canonical (they name the protocol's lineage, not a writer) | Every v1 artifact | n/a | Keep; changing them is a protocol revision |

Measured remaining cost, 2026-10-05, Apple M4, one trial: the compatibility and
oracle test targets (`cargo test -p credential-eval-compat -p credential-eval-kernel
--test oracle`) run in about 2.7 s warm; 3,722 lines of source and tooling, 3.9 MB
of fixtures. Compile time is shared with the canonical crates (the CLI links the
compat crate). The cost is small, which is why none of it is a reason to remove
anything early.

## 3. Consumer inventory (downstream)

| Consumer | What it reads | Needs compat? |
|---|---|---|
| redact-secret-benchmarks, `benchmarks/qualification/run-artifact.ts` | `RunArtifact` v1 through the vendored schema `schemas/credential-eval-run-artifact-v1.json`; imports no credential-eval code | No |
| `scripts/run-official-credential-eval.ts`, `scripts/record-official-run.mjs` | Runs the pinned CLI; records the run identity | No (`case-id` seed; no `--legacy-eval-out`) |
| `benchmarks/qualification/evaluation-evidence.ts` | Evidence files that name `legacy:*` validators | **Yes: validators** |
| Benchmark `bench` / `eval` / matrix / candidate / baseline / ledger | Still the legacy TypeScript engine and its own result files until the oracle exit (redact-secret-benchmarks#653, #654, #657, #660) | Not credential-eval's writers |
| credential-evidence | Releases the `CorpusSnapshot` and fixtures credential-eval consumes; its migration checks (credential-evidence#79) | No |
| pii-eval (planned, redact-secret-benchmarks#652) | See section 6 | No |

The benchmark-side file-level inventory with owners and callers is
redact-secret-benchmarks#653; this table is credential-eval's half and links
to it. Where the two disagree, the later-dated one is re-checked, not assumed.

## 4. What stays, and the canonical-only CI question

Keep: all schemas and frozen baselines, adapters and their tests, accounting
and determinism tests, the `contracts-smoke` and `representation-smoke` golden
artifacts, `schema_guarantees`, and the reference qualification consumer.

CI today runs one test job (`cargo test --workspace --locked`) that includes
the compatibility and oracle targets. Making a failure attributable to a class
needs no new runner time:

- The canonical gate stays `cargo test --workspace --locked` until removal.
  Splitting targets by name would risk silently dropping a new test target.
- The compatibility audit is the explicit command
  `cargo test --locked -p credential-eval-compat -p credential-eval-kernel --test oracle`.
  It is documented here and run on demand, not a separate job; a separate job
  would repeat compilation on a billed runner for about 3 s of tests.
- When removal is scheduled (step D5 below), the audit targets are deleted and
  the canonical gate is unchanged, which is the point at which "canonical-only"
  becomes true by construction.

## 5. Retirement requirements and sequence

A compatibility item may be deleted only when all of these hold:

1. **Oracle exit recorded.** redact-secret-benchmarks has qualified at least
   one further published release through both paths with zero unexplained
   differences, renewed rollback rehearsal, and caller inventories
   (`benchmarks/qualification-authority.json`, `docs/specs/qualification-cutover.md`;
   redact-secret-benchmarks#660).
2. **Last reader gone.** A caller search of this repository and of
   redact-secret-benchmarks, credential-evidence and any consumer repository
   finds no reader of the item, and the owner of each former reader confirms in
   writing (an issue comment). A search that finds nothing is necessary, not
   sufficient.
3. **Parity evidence preserved.** The parity report and summary under
   `docs/parity/` are kept and marked superseded, not deleted.
4. **Rollback.** The release immediately before the deletion is tagged and its
   binary and `schemas/` stay available; the cutover plan's fallback (the legacy
   engine in the benchmark tree) is still in place or has itself been retired
   by its own gate.
5. **Canonical outputs unchanged.** The run-artifact semantic digest of the
   `contracts-smoke` and `representation-smoke` goldens is identical before and
   after, apart from the engine version.

Support window: after the oracle exit, the compatibility surface stays for one
minor release (engine `0.N`) marked deprecated in `credential-eval capabilities`
and the CLI help, then is removed in the next minor release. Frozen v1 schemas
and canonical identities are not part of the window and do not change.

Versioning: removing a compatibility writer or the `legacy-category` seed is a
minor engine release, not a contract revision, because no v1 document changes.
Moving a validator to a canonical name is also an engine release; the document
that names validators (evidence files) keeps both names resolving through the
window.

Sequence:

| Step | Action | Gate |
|---|---|---|
| D0 | Done by this document: inventory, boundary, sequence. | n/a |
| D1 | Add canonical validator names and keep `legacy:*` as aliases; the benchmark updates `evaluation-evidence.ts` to the canonical names. | benchmarks owner confirms (#653 inventory lists the file) |
| D2 | Deprecate `compat legacy-bench`, `--legacy-eval-out` and `--seed legacy-category` in help and `capabilities`. | oracle exit recorded (1) |
| D3 | Run the last-reader check (2) for each deprecated item; record results in the issue. | owners confirm |
| D4 | Wait one minor release (support window). | window elapsed |
| D5 | Remove, in this order: `credential-eval-compat` writers, the `compat` subcommand and `--legacy-eval-out`, `kernel/src/compat.rs` with its oracle tests and goldens, `tools/legacy-export`, `tools/oracle`, `tools/parity`. One pull request per item, each listing its callers. | (3), (4), (5) |
| D6 | Remove the `legacy:*` alias names once no evidence file uses them. | benchmarks owner confirms |

No item is removed in D0 to D4. Nothing that a consumer still reads is removed
by moving a CI command.

## 6. Seams shared with the planned pii-eval extraction

pii-eval (redact-secret-benchmarks#652, pii-eval#1) is a Rust engine from the
outset. The generic seams it can use without credential semantics, and without a
shared framework:

| Seam | Where it is specified | Credential-specific parts it must not inherit |
|---|---|---|
| Byte ranges (`[start, end)` UTF-8, UTF-16 conversion rules) | [../contracts/ranges.md](../contracts/ranges.md) | none |
| Normalized observations bound to a corpus digest, with explicit non-complete states | `ObservationSet`, [../contracts/outcomes.md](../contracts/outcomes.md) | `family` is an optional adapter-owned string; `native_labels` (ADR 0011) are optional and bounded. A PII type identity belongs in its own field, never in `family`. |
| Replay, stability and deterministic ordering | [../contracts/determinism.md](../contracts/determinism.md) | none |
| Bounded execution (jobs, timeouts, output caps) | [../adapters.md](../adapters.md) | none |
| Reuse identity (input and scanner identity) | ADR 0008, ADR 0010 | none |
| Outcome lattice and accounting | `credential-eval-kernel` | credential span roles, twins and family scoping are credential semantics; PII has its own axes |

Decision: pii-eval implements these seams from the documents, with its own
versioned protocol, and does not depend on a credential-eval crate. If a shared
crate is ever justified it would hold only ranges and canonical JSON, and
would be proposed as its own issue. Nothing here is required by this plan.

## 7. Prerequisite links

- redact-secret-benchmarks#651 (epic), #653 (ownership map, unblocks this
  inventory's downstream half), #660 (retire the legacy evaluator, blocked by
  this contract), #652 (pii-eval coordination).
- credential-evidence#79 (downstream cutover reconciliation).
- credential-eval#1 (extraction epic), #29 and #31 (CI performance, delivered,
  not reopened).
