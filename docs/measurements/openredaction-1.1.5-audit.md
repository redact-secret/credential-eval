# OpenRedaction 1.1.5 native-type audit

Decision record: [ADR 0012](../decisions/0012-openredaction-native-type-audit.md).
Data: [openredaction-1.1.5-dispositions.json](../../tools/openredaction-audit/dispositions.json)
(all 575 types) and [tools/openredaction-audit/](../../tools/openredaction-audit/)
(synthetic cases, probe, recorded result). Package: `@openredaction/core` 1.1.5,
integrity `sha512-SpQTBhVV4p3rmge818NH6iJiL/fvwFlDvhGaejoL0wbzY7jRHIhU5vEf3KzNARsIZmpCJV1eHdiavIjQyN1hXQ==`,
installed from the lockfile, not upstream `main`.

## Counts

| | Types |
|---|---|
| Patterns / distinct types | 579 / 575 |
| `credentials` category | 32 |
| Mapped today (category 17, plus `URL_WITH_AUTH`) | 18 |
| Category types without a mapping | 15 |
| Status `unresolved` | 13 category types, plus `PAYMENT_TOKEN` and `CART_SESSION_ID` (15) |
| Status `not-credential` | 542 (`AWS_ARN`, `AZURE_RESOURCE_ID` and 540 outside the category) |

## Source spans (observed)

The reported range is the pattern's first capture group when it has one, and
the whole match when it does not. For most credential types that is exactly the
credential part. Exceptions in the probe:

| Type | Range |
|---|---|
| `URL_WITH_AUTH`, `DATABASE_CONNECTION` | whole URL, scheme and host included: wider than a password-only span |
| `SLACK_WEBHOOK` | whole URL |
| `PRIVATE_KEY`, `SSH_PRIVATE_KEY` | the whole PEM block (equal to the authored block) |
| `GCP_SERVICE_ACCOUNT` | the `private_key_id`, an identifier, not key material (and not reported by default) |

## Unmapped category types

| Type | Scope | Why it stays unmapped |
|---|---|---|
| `DOCKER_AUTH` | credential | span fits `docker:registry-auth-config-entry`; namespace and draft contract |
| `SLACK_WEBHOOK` | credential | candidate `slack:workflow-webhook-token` is proposed, no structure |
| `TWILIO_API_KEY` | key SID (identifier) | the secret is a different value |
| `SESSION_ID`, `COOKIE_SESSION` | session | explicit scope decision needed |
| `AZURE_STORAGE_KEY` | credential | no account-key family in the evidence |
| `KUBERNETES_SECRET` | credential | no compatible family; loses to `GENERIC_SECRET` for a `password` key |
| `HEROKU_API_KEY` | credential | UUID shape ambiguous; `GENERIC_API_KEY` claims "heroku api key" first |
| `OAUTH_CLIENT_SECRET`, `OAUTH_TOKEN` | credential | provider-agnostic, every evidence family is provider-specific |
| `GOOGLE_API_KEY` | credential | sensitivity policy open (public client keys) |
| `FIREBASE_API_KEY` | identifier | public client config; shadowed by `GOOGLE_API_KEY` |
| `GCP_SERVICE_ACCOUNT` | identifier | captures `private_key_id` only |
| `AWS_ARN`, `AZURE_RESOURCE_ID` | resource identifier | not credentials |

## Existing mappings reviewed

`STRIPE_API_KEY` accepts `sk_` and `pk_` and maps both to `stripe-token`.
`AWS_SECRET_KEY` fired on a PEM public key body in the probe.
`URL_WITH_AUTH` (http, https, ftp userinfo) and `DATABASE_CONNECTION` share one
family and report the whole URL. `GENERIC_SECRET` and `GENERIC_API_KEY` map only
to the generic family and also claim values other patterns target. None was
changed; each reason is in the dispositions file.

## Arbitration and filtering seen in the probe

- The default pipeline reported nothing for `GCP_SERVICE_ACCOUNT`; with
  `enableFalsePositiveFilter: false` it reported the key id.
- With `categories: ["credentials"]`, `URL_WITH_AUTH` is absent.
- With the false-positive filter off, `DATABASE_CONNECTION` was not reported for
  the probe URL, so toggling the filter changes which pattern survives.
- `Authorization: Bearer ...` text also draws `CARD_AUTH_CODE` (family none).

These are one-trial observations on synthetic inputs, not rates.

## Re-running

```sh
(cd adapters/node && npm ci --ignore-scripts)
node tools/openredaction-audit/probe.mjs adapters/node --check
```
