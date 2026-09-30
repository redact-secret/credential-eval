---
name: scan-secrets-in-history
description: Scan credential-eval's Git history for accidentally committed credentials or unsanitized scanner output. Use before publication or when secret leakage is suspected. Report-only and never prints matched plaintext.
---

# Scan secrets in history

Use a reputable history-aware scanner with redaction enabled and record its
version and exact scope. Scan all history reachable from `HEAD` unless the user
requests a narrower range.

Triage by path and commit. Synthetic fixtures or documented public test values
may be expected, but evaluator logs, result artifacts, adapter snapshots, CI
files, and documentation are not safe locations for matched credential text.
Do not infer safety from a patterned-looking value; use repository provenance.

Report commit, path, rule ID, and disposition only: `verified synthetic/public
test`, `unclear`, or `needs private rotation and history remediation`.
Never print the match, even partially. Do not rewrite history, revoke a
credential, force-push, or open a public issue.

