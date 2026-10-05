# ADR 0015: Mapping re-check (no change) and the credential-bearing profile

- Status: accepted
- Date: 2026-10-05
- Issues: #49 and #50 (parent: redact-secret-benchmarks#723). Finishes work
  that ADR 0012 and ADR 0013 left open: ADR 0012 recorded reasons without
  testing the strongest mapping candidate against corpus findings, and ADR
  0013 recommended a profile it did not build.
- Amends: nothing. Adapter `openredaction` stays at version 2; no mapping
  changes. Adds one diagnostic adapter.
- Follow-up: #56 (family namespace).

## Mapping re-check (#49)

Every unmapped credential-category type was re-checked against its authored
format contract and against what the pattern actually matched in the corpus,
not only its name. The only candidate that fit its contract on span was
`DOCKER_AUTH` (the base64 `auth` value is the `auth` body of
`docker:registry-auth-config-entry`). A trial mapping was tested on
`snapshot-2026.10.01.2`: its single `DOCKER_AUTH` finding is on
`deepgram--deepgram-api-key-worker-json-log`. The pattern matches the `auth`
field of any JSON object, so it is not Docker-specific, and a docker family on
that case would be an unsupported family claim. The mapping was reverted before
merge. `DOCKER_AUTH` stays unresolved with that reason in the dispositions.

| Type | Decision | Why |
|---|---|---|
| `DOCKER_AUTH` | Unresolved | Span fits the contract; pattern is not Docker-specific (evidence above). A registry-key check or a provider-neutral disposition would be needed. |
| `COOKIE_SESSION`, `SESSION_ID` | Unresolved | Needs the explicit session scope decision; `generic:http-session-cookie` fits the span. |
| `SLACK_WEBHOOK` | Unresolved | Candidate is a proposed, draft family with no structure; span is the whole URL. |
| `HEROKU_API_KEY` | Unresolved | UUID shape is context-gated, claimed first by `GENERIC_API_KEY`; contract has no structure. |
| `GOOGLE_API_KEY`, `FIREBASE_API_KEY` | Unresolved | Sensitivity policy: public client keys. |
| `GCP_SERVICE_ACCOUNT` | Unresolved | Captures `private_key_id`, an identifier. |
| `TWILIO_API_KEY` | Unresolved | The SID is the identifier, not the secret. |
| `AZURE_STORAGE_KEY`, `KUBERNETES_SECRET`, `OAUTH_*` | Unresolved | No compatible evidence family; missing families go to credential-evidence. |
| `AWS_ARN`, `AZURE_RESOURCE_ID` | Not credentials | Resource identifiers. |
| `STRIPE_API_KEY` (existing) | Unchanged | `sk_` and `pk_` share one native type; separating them needs a fixed, enumerated, non-secret prefix class from the shim, specified here and not built. |

No mapping changes means no mapping or adapter version bump and no outcome
deltas to review. The family namespace mismatch found on the way is #56.

## Profile decision (#50)

`openredaction-credential-bearing` is a diagnostic adapter: an explicit
allowlist of the 33 credential-bearing types of the audit (the `credentials`
category plus `URL_WITH_AUTH`), its own id, version, options and configuration
hash, outside the default scanner set. The default result is preserved.

Measured (plain run, `--jobs 2`, one trial, `snapshot-2026.10.01.2`):

| | default | credentials | credential-bearing |
|---|---|---|---|
| Findings | 27,253 | 1,068 | 1,076 |
| Positive spans EXACT / COVERED / OVERBROAD / PARTIAL / MISS | 535 / 28 / 9 / 200 / 1,653 | 531 / 23 / 8 / 117 / 1,746 | 530 / 28 / 9 / 117 / 1,741 |
| Controls flagged (of 3,486) | 1,057 | 119 | 118 |
| Scanner process time (2 replays) | 23.8 s | 2.5 s | 1.8 s |

Against the default, the profile loses 7 EXACT spans (labels: 25
`INSTAGRAM_USERNAME` findings, `BITCOIN_ADDRESS`, `MINECRAFT_UUID`,
`GENERIC_SECRET`) and gains 2 (`PARTIAL` to `EXACT`); 81 `PARTIAL` become `MISS`
(accidental overlap with personal-data findings); 939 default control flags
(personal-data patterns) disappear. COVERED and OVERBROAD spans, which
`openredaction-credentials` lost, are restored by `URL_WITH_AUTH`. On
`snapshot-2026.10.05.3` the default completed with the limits raised (15 minutes,
256 MiB: 360,889 findings, 383 s scan wall time), and the profile completed with
1,406 findings in 7.5 s of scanner time. Its outcomes equal the default's in all
74 positives of the two long-input groups; elsewhere it loses 9 EXACT spans
(mostly `INSTAGRAM_USERNAME` accidental overlaps) and removes 1,006 control flags
from personal-data patterns. Details: the diagnostics report.

Decision: **go** for `openredaction-credential-bearing` as a separately labeled
credential-scoped result next to the default, never in place of it, and
**no-go** for presenting it as OpenRedaction's default behavior. The 14
unresolved types are still unresolved; the profile includes them as
credential-bearing detections without a family, which is the honest state.

Validation budget before the expensive methods trial: one methods run of this
profile on the current snapshot, `--jobs 2`, one trial; the plain run took 7.5 s
of scanner time, so the methods run is expected in the low minutes. It needs no
Actions minutes if run locally; run it on Actions only after the minutes are
stated and approved.

## Tests

`families` and `openredaction_audit` unit tests: the dispositions equal the
reviewed label set, `DOCKER_AUTH` is unmapped and the allowlist of
`openredaction-mapped` follows the table; the credential-bearing allowlist is
exactly the 32 category types plus `URL_WITH_AUTH`; the three profiles have
separate identities and are absent from the default set.
