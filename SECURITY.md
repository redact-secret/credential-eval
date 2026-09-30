# Security policy

Report suspected vulnerabilities privately through GitHub Security Advisories
for `redact-secret/credential-eval`. Do not open a public issue containing an
exploit, credential, matched value, or sensitive scanner output.

## Scope

Security issues include command or argument injection in adapters, path
traversal during fixture materialization, unsafe archive handling, unbounded
subprocess output or resource use, temporary-file leakage, artifact identity
confusion, and publication of matched values.

Incorrect scanner detections are measurement observations, not vulnerabilities
in this repository. Credential-fact corrections belong in
`credential-evidence`.

## Safe reports

Use synthetic inputs and include affected revision, platform, reproduction,
impact, and suggested mitigation. Never test with active or revoked real
credentials. Do not contact provider verification endpoints unless maintainers
explicitly authorize it.
