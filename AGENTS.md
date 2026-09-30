# Agent instructions

@/Users/minhokang/.codex/RTK.md

Read `README.md` and `ARCHITECTURE.md` before changing this repository. They
define the repository boundary and take precedence over inherited conventions
or assumptions from predecessor repositories.

## Repository boundary

`credential-eval` measures scanner behavior. It consumes versioned
`credential-evidence` snapshots, runs scanners through adapters, normalizes
file/range findings, applies the measurement protocol, and emits reproducible
artifacts.

This repository does not own credential truth, Redact Secret support status,
release policy, public-site content, or scanner rankings. Never change an
expected result merely to match a scanner's output.

## Working rules

- Preserve scanner neutrality. Product-specific behavior belongs in an adapter
  or downstream qualification policy, not the measurement kernel.
- Treat the outcome lattice and accounting rules as protocol semantics.
  Refactors must preserve them; intentional changes require an explicit,
  reviewed protocol revision.
- Keep execution bounded: concurrency, subprocess output, timeouts, buffers,
  and generated variants must all have explicit limits.
- Keep results deterministic. Parallel scheduling may not alter semantic
  output ordering or aggregate results.
- Record all identities needed for reproduction: engine, protocol, evidence
  snapshot, scanner, adapter, configuration, and corpus digest.
- Use only synthetic or documented public-test credential material. Never log
  matched values or copy raw scanner output into public artifacts.
- Keep compatibility code isolated and removable. Do not shape the canonical
  model around a legacy benchmark schema.

## Work discipline

- 5분 이상 걸리는 명령을 제안하기 전에, 그 입력을 먼저 읽어서 검증한다.
  검증 비용이 실행 비용보다 두 자릿수 작으면 무조건 먼저 검증한다.
- 시험/검증 작업에서는 "무엇을 측정하는가"와 "무엇이 입력으로 필요한가"를
  분리한다. 입력은 측정 대상을 만족하는 최소 크기여야 한다.
- 기존 자산(이슈, 브랜치, 파일)에서 고르는 것이 유일한 선택지라고 가정하지
  않는다. 새로 만드는 쪽이 더 싸면 그쪽을 먼저 제안한다.
- 반론이 들어오면, 내가 답하기 쉬운 반론이 아니라 실제로 제기된 반론에
  답한다.
- benchmarks 측정(eval:classify, eval:matrix, benchmark:candidate) 전에
  `trufflehog --version`이 핀(3.97.4)과 같은지 확인한다. 자동 업데이트로
  patch만 올라가도 stable 수가 43에서 5로 바뀐다
  (redact-secret-benchmarks#180). 다르면 수치를 보고하지 말고 핀 버전
  바이너리를 PATH 앞에 두고 다시 돌린다. stable 수에는 항상
  모드(published/candidate)를 함께 적는다.

## Before finishing

Run the repository's documented format, lint, test, schema, and parity checks
that exist at the time of the change. If the implementation is not present yet,
say which checks could not run instead of inventing commands. For changes to
scoring, normalization, accounting, or serialization, add focused tests and
verify deterministic output across repeated runs where practical.

## Local skills

Repository-specific workflows live in `.agents/skills/`. Security-review
skills inspect this evaluator's own attack surface; they do not assess whether
any scanner is good or bad.
