# contracts-smoke fixtures

This is a tiny synthetic fixture set that exercises the v1 input/output
contracts end to end. Every credential-shaped string contains `EXAMPLE` or
`FAKE`, or is an obvious placeholder, and none of them is a real credential.

| File | Contract |
|---|---|
| `corpus-snapshot.json` | `CorpusSnapshot` with 8 cases. The positives produce EXACT, COVERED (via an envelope), OVERBROAD, PARTIAL and MISS (with a companion span). There is also a benign control, a length twin and a T0 pending case. The content includes multi-byte UTF-8 (`é`, `ü`, `密钥`), so the byte offsets are not character offsets. |
| `run-config.json` | `RunConfig` for two canned scanners, with the legacy engine v1.1 accounting values. |
| `observation-set.json` | Canned `ObservationSet`. `fake-scanner-a` completes and includes one duplicate finding that the kernel deduplicates. `fake-scanner-b` times out and must never be scored as MISS. |
| `expected-run-artifact.json` | The golden `RunArtifact` produced by `credential-eval-kernel`. |

The tests that use these files are
`crates/credential-eval-contracts/tests/input_contract.rs` and
`crates/credential-eval-kernel/tests/contracts_smoke.rs`.

After an intentional change, regenerate the golden artifact with:

```sh
UPDATE_GOLDEN=1 cargo test -p credential-eval-kernel --test contracts_smoke
```

Then review the diff. If you edit `corpus-snapshot.json`, recompute
`identity.corpus_digest` using the rule in `docs/contracts/identity.md`. The
input test fails with the computed value when the declared one is stale.
