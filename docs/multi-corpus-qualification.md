# Multi-corpus qualification

`credential-eval` measures the corpus it is given. It does not decide where
that corpus came from, and it does not decide whether the corpus is enough
for a product release. This document defines how a product such as Redact
Secret qualifies against **several separately identified corpora**, each
measured into its own run artifact, and what the consumer that combines them
must do (issue #18).

It extends, and does not repeat:

- [qualification-boundary.md](qualification-boundary.md): the policy that
  stays outside this repository and the single-artifact consumer obligations
  (§4);
- [official-runs.md](official-runs.md): run class, evidence release
  verification, scanner pins and publication class;
- [contracts/identity.md](contracts/identity.md): the reproduction identities
  in every artifact.

## 1. Terms

These terms are shared with `credential-evidence` (its issue #35).

| Term | Meaning | Owner |
|---|---|---|
| **population** | One separately identified body of cases with its own provenance, for example the public evidence snapshot or a product regression corpus. One population is one `CorpusSnapshot` and so one corpus identity. | whoever authors the corpus |
| **evidence class** | The basis of a case's expectation, for example `provider-documented`, `tool-corroborated` or `project-policy`. Carried per case as `Grouping.evidence_class` and copied to `CaseResult.evidence_class`. | the corpus author (`credential-evidence` for the public snapshot) |
| **scanner behavior** | What a scanner did on a case: the outcome lattice, flags, aggregates. The content of a run artifact. | credential-eval |
| **support status** | A product's claim about a family (`stable`, `provisional`, `pending`, `unsupported`) and the release decisions built on it. | the product's qualification policy (for Redact Secret, `redact-secret-benchmarks`) |

The three axes are independent. An evidence class is not a scanner result, a
scanner result is not a support status, and none of them is derived from
another inside credential-eval.

## 2. One public snapshot is not the only qualification path

`credential-evidence → credential-eval → redact-secret-benchmarks` is one
valid path, not the only one. The public evidence snapshot is a shared,
scanner-neutral source. It is not the whole universe a product must or may
qualify against. A product may measure, through the same engine and the same
protocol, any number of corpora it owns:

```text
public credential-evidence snapshot  ──▶ credential-eval ──▶ RunArtifact A
product regression corpus            ──▶ credential-eval ──▶ RunArtifact B
product policy corpus                ──▶ credential-eval ──▶ RunArtifact C
protected / candidate evidence       ──▶ credential-eval ──▶ RunArtifact D
                                         (or a specialized runner ──▶ its own artifact)

A + B + C + D ──▶ product qualification policy (redact-secret-benchmarks)
                  ──▶ stable / provisional / pending / release decisions
```

Every corpus is a `CorpusSnapshot` v1 like any other. The engine does not
special-case the public snapshot: `identity.source` and `identity.revision`
are whatever the corpus author records (`credential-evidence`,
`redact-secret-benchmarks/regression`, ...), and the corpus digest, case
rules and validation are the same for all of them. A corpus that is not a
credential-evidence release can still be measured in an official run if its
owner publishes a release manifest in the shape the verifier reads
(`tag`, `files[] {path, sha256}` with a `credential-eval/corpus-snapshot.json`
entry; [official-runs.md](official-runs.md#evidence-input)). The verifier
checks bytes and digests, not who published them.

A protected or holdout corpus may also be run by a specialized runner that is
not credential-eval. Its output is not a `RunArtifact`, and the consumer
validates and keys it under its own contract. Nothing below lets it be mixed
into a credential-eval artifact.

## 3. One population, one artifact

Each population is measured by its own run and produces its own artifact
with its own corpus and evidence identity
(`manifest.evidence {source, revision, evidence_schema, corpus_digest,
release?}`). Corpora are **never silently concatenated** into one snapshot
before a run.

Why separate artifacts:

- **Provenance.** Each artifact names exactly one corpus revision and, when
  pinned, one release. A merged snapshot would name only the merge.
- **Evidence class and origin.** Public, product-owned and protected cases
  keep their origin without a per-case origin field the v1 contract does not
  have (§8).
- **Denominator meaning.** `aggregates.groups` and `by_target` are accounted
  over one corpus. A rate over a merged corpus would be a rate over a
  population nobody authored, and its Wilson bound would treat cases from
  different sources as one sample.
- **Reproducibility.** An artifact is reproducible from its identities
  alone. A merge step outside the engine would be an unrecorded input.
- **Explaining change.** When a product decision changes, the consumer can
  say which population changed (a new public release, a new regression case,
  a new scanner) because each one has its own identity.

Merging is not forbidden forever. A future **composed-corpus mode** is
acceptable only if source partitions stay first-class in the artifact: each
case tagged with its partition, the partition identities in the manifest, and
aggregates published per partition, never pooled by default. That is a
contract change and is not part of v1 (§8).

## 4. Evidence class, scanner behavior and support status

- **Evidence class describes the basis of an expectation.** credential-eval
  copies it from the corpus to `CaseResult.evidence_class` as a label. It
  never changes an outcome, a group or an aggregate.
- **A run artifact describes scanner behavior.** A `project-policy`
  `must-redact` case is measured with exactly the same lattice as a
  `provider-documented` one. credential-eval never converts a
  `project-policy` case into a weaker result (for example, `not-measured`,
  `pending` or an excused `MISS`), and never treats a `MISS` there as less of
  a miss.
- **Support status is downstream policy.** credential-eval never promotes a
  family because its cases are `provider-documented`, never demotes one
  because they are `project-policy`, and emits no status at all
  ([qualification-boundary.md](qualification-boundary.md) §3.8).

Consequences for consumers:

- A public evidence record may legitimately be `project-policy` while the
  product separately qualifies the family on product-owned evidence (a
  regression or policy population). Both facts coexist; neither overrides the
  other inside the engine.
- A reclassification in the public evidence (for example,
  `tool-corroborated → project-policy`) changes the case's grouping, so it
  changes `corpus_digest` and produces a new population identity. The scanner
  outcomes on unchanged fixtures stay the same. Whether the product's status
  changes is a policy decision taken by explicit review, never an automatic
  effect of the new snapshot. Equally, if the reclassification exposes a real
  coverage gap, policy may act on it, again by review.

## 5. Run class and publication class across populations

The run and publication classes are defined in
[official-runs.md](official-runs.md). Applied to several populations:

| Run | Typical inputs | `run_class` | `publication` | Use |
|---|---|---|---|---|
| Exploratory local run | any corpus, any scanner, under `results/local/` | `exploratory` | `internal` | development only; never qualification evidence, never published |
| Official public run | a pinned corpus release, every scanner a pinned `released` build | `official` | `public` | product qualification; may be consumed outside it, subject to the corpus rule below |
| Official internal run | a pinned corpus release, at least one `candidate` build | `official` | `internal` | product qualification and candidate acceptance only |

Rules a multi-corpus consumer adds:

- **Qualification and release decisions read official artifacts only.**
  Exploratory artifacts may inform a developer, never a status.
- **`publication = public` is necessary, not sufficient.** The publication
  class is derived from the run class and scanner builds. It knows nothing
  about the corpus. An official run of released scanners over a protected or
  holdout population is `public` by that derivation, yet its case ids,
  taxonomy and expected offsets describe evidence the owner has not
  released. Whether an artifact may leave product qualification is decided by
  the corpus owner as well: the consumer publishes an artifact only when its
  `publication` is `public` **and** its population is declared publishable in
  the consumer's own population registry (§6, rule 4).
- **Reproduction identity is per artifact.** Every derived record keeps the
  identities in [contracts/identity.md](contracts/identity.md#reproduction-identities-in-a-run-artifact)
  for each artifact it used, plus the digest of the artifact bytes. A
  qualification decision that cites four artifacts records four identity
  sets.

## 6. Consumer contract

A benchmark or product consumer that combines artifacts follows these rules
in addition to the per-artifact obligations in
[qualification-boundary.md](qualification-boundary.md) §4.

1. **Validate each artifact on its own.** Check the `schema` tag and validate
   every artifact against `schemas/run-artifact-v1.schema.json` of the engine
   version that wrote it (or a later v1 schema) before reading any field.
   One invalid artifact invalidates the decisions that cite it; it is never
   skipped silently.
2. **Bind the corpus and evidence identity.** For each population the
   consumer pins, in its own registry, the expected `manifest.evidence`
   (`source`, `revision`, `corpus_digest` and, for official runs,
   `release {tag, manifest_digest}`). An artifact is accepted for a
   population only if its `manifest.evidence` equals that pin. This is what
   stops a regression artifact from being read as the public one.
3. **Never compare incompatible identities by accident.** Two artifacts are
   comparable (baseline vs candidate, release N vs N+1) only if their
   `protocol_version` and `corpus_digest` are equal, or the policy names the
   difference it accepts and records both identities. Artifacts of different
   populations are never compared case by case, even when case ids happen to
   be equal.
4. **Retain the source population identity.** Every derived record (a count,
   a family view, a status reason) carries the population label and the
   artifact identities it came from. Case-level keys are
   `(population, case_id)`, never `case_id` alone: the v1 `CaseId` is unique
   only within one snapshot. The registry also records, per population,
   whether it may be published (§5).
5. **Let product policy combine and count.** Combining populations is the
   consumer's job. Counts and rates stay per population. A policy that needs
   a figure across populations defines it explicitly (which populations,
   which groups, how duplicates across populations are handled), records
   every contributing population's identity and count next to the result,
   and still never sums across groups or scanners into one score
   (boundary §4, rule 7). Bounded rates come from each artifact's own
   `aggregates`; a consumer does not pool the underlying counts and recompute
   an interval for a published claim.
6. **Never ask credential-eval for a status.** `stable`, `provisional`,
   `pending`, `unsupported`, release blockers and promotions are computed by
   the consumer. A request for the engine to emit them, or to accept a
   threshold, is rejected as a boundary violation
   ([qualification-boundary.md](qualification-boundary.md) §1).

## 7. Worked example

A Redact Secret release qualification cites four artifacts. Digests are
shortened for reading; real values are full `sha256:` digests.

| Artifact | Population | `manifest.evidence` | `run_class` / scanner builds / `publication` |
|---|---|---|---|
| A | `public-evidence` | `source: credential-evidence`, `revision: snapshot-2026.10.01`, `corpus_digest: sha256:a1…`, `release {tag: snapshot-2026.10.01, manifest_digest: sha256:a9…}` | `official` / redact-secret, gitleaks, trufflehog all `released` / `public` |
| B | `rs-regression` | `source: redact-secret-benchmarks/regression`, `revision: 4f0c…`, `corpus_digest: sha256:b1…`, `release {tag: regression-2026.10.01, manifest_digest: sha256:b9…}` | `official` / redact-secret `released` / `public` |
| C | `rs-policy` | `source: redact-secret-benchmarks/policy`, `revision: 4f0c…`, `corpus_digest: sha256:c1…`, `release {tag: policy-2026.10.01, manifest_digest: sha256:c9…}` | `official` / redact-secret `released` / `public` |
| D | `rs-protected` | `source: redact-secret-benchmarks/protected`, `revision: 77aa…`, `corpus_digest: sha256:d1…`, `release {tag: protected-2026.10.01, manifest_digest: sha256:d9…}` | `official` / redact-secret `candidate` / `internal` |

The consumer's registry (a product file, not a credential-eval format):

```json
{
  "populations": {
    "public-evidence": { "source": "credential-evidence", "release": "snapshot-2026.10.01",
                         "manifest_digest": "sha256:a9…", "corpus_digest": "sha256:a1…", "publishable": true },
    "rs-regression":   { "source": "redact-secret-benchmarks/regression", "release": "regression-2026.10.01",
                         "manifest_digest": "sha256:b9…", "corpus_digest": "sha256:b1…", "publishable": true },
    "rs-policy":       { "source": "redact-secret-benchmarks/policy", "release": "policy-2026.10.01",
                         "manifest_digest": "sha256:c9…", "corpus_digest": "sha256:c1…", "publishable": true },
    "rs-protected":    { "source": "redact-secret-benchmarks/protected", "release": "protected-2026.10.01",
                         "manifest_digest": "sha256:d9…", "corpus_digest": "sha256:d1…", "publishable": false }
  }
}
```

How it keys and uses them:

1. Validate A-D against the v1 schema (rule 1). Match each artifact's
   `manifest.evidence` against exactly one registry entry (rule 2). An
   artifact that matches none, or the wrong one, stops the qualification.
2. Build one family view per artifact
   ([qualification-boundary.md](qualification-boundary.md) §4.1) and key
   every row by `(population, scanner, family)`, and every case by
   `(population, case_id)` (rule 4). If A and B both contain a case id
   `aws-access-key--basic`, they stay two rows.
3. Policy reads the rows per population. Suppose family `aws-access-key`
   has, for redact-secret: in A, 12 `must-redact` cases, 12 `COVERED` or
   better, and `CaseResult.evidence_class = project-policy` on 4 of them; in
   B, 30 regression cases, all `EXACT`; in C, 6 `policy` cases. The policy
   may say "stable requires A without leaks plus B without leaks", and its
   output records `{A: 12/12, B: 30/30}` with both identity sets. It does not
   publish "42/42" as one rate unless the policy defines that figure
   explicitly and records its parts (rule 5). The 4 `project-policy` cases in
   A were measured like the others; whether they count toward a `stable`
   route is a policy rule, not an engine property (§4).
4. D is a candidate build on protected evidence. It is used only for
   candidate acceptance. It is never compared case by case with A, B or C,
   because its `corpus_digest` differs (rule 3), and it is compared with a
   previous protected run only when both share `protocol_version` and
   `corpus_digest`.
5. Only A, B and C may be attached to a public release note, because each is
   `publication: public` **and** `publishable` in the registry (§5). D is
   neither.
6. The status (`stable`, `provisional`, ...) is computed by the product's
   policy from these rows (rule 6). Next release, if only the public evidence
   moves to `snapshot-2026.11.01`, only A's identity changes, and the
   decision record shows that A is the population that changed.

## 8. Contract gaps (proposals, not changes)

The frozen v1 contract ([ADR 0001](decisions/0001-freeze-v1-contracts.md))
identifies a population only through `manifest.evidence`. That is sufficient
for the rules above, because the consumer binds the label to the identity in
its registry. It is not self-describing. Nothing in this issue changes a
contract. Proposed for a later review:

| Id | Proposal | Kind | Why |
|---|---|---|---|
| **P5** population label | Optional `SnapshotIdentity.population` (a constrained slug, e.g. `public-evidence`), declared by the corpus author, copied into `manifest.evidence.population` and covered by the semantic digest. | minor v1 revision (new optional field; absence keeps today's meaning) | Lets an artifact name its own population, so a consumer can cross-check its registry instead of relying on it alone. Needs a `schema_guarantees` allowlist entry with a pattern. |
| **P6** composed-corpus partitions | If a composed mode is ever wanted: a `partitions[]` list in the manifest (each with its own `source`, `revision`, `corpus_digest`, `release?`), a required `partition` on every `CaseResult`, and aggregates keyed per partition with no pooled figure by default. | larger than P5; likely needs a protocol review for the accounting rule | Required by §3 before any merge of populations into one run. Not proposed for implementation now. |
| **P7** corpus publishability | An optional corpus-level marker that would make `publication` `internal` for a protected population. | minor v1 revision, also touches the publication derivation | Today publishability of a population is consumer-held (§5). Open question: it may belong to the release manifest owned by the corpus author instead. |

Until any of these lands, consumers implement §6 with the v1 fields as they
are.
