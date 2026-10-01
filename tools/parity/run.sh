#!/bin/sh
# Dual-run parity (issue #5): legacy redact-secret-benchmarks@1020d2b5 vs credential-eval.
#
# Usage (from the credential-eval repository root):
#
#   LEGACY=/path/to/redact-secret-benchmarks   # pinned clone at 1020d2b5..., `npm ci` done,
#                                              # fixtures generated (npm run fixtures)
#   PEER_BIN=/path/to/peer-bin                 # gitleaks 8.30.1 + trufflehog 3.97.4, provisioned
#                                              # by $LEGACY/scripts/provision-peers.mjs
#   OUT=/path/to/output-dir
#   sh tools/parity/run.sh [export|legacy|ours|compare|all]
#
# Steps (default `all`):
#   export   tools/legacy-export/export.mts -> $OUT/export/{snapshot,evidence,legacy-index}.json
#   legacy   legacy `npm run bench -- --live-peers` and `npm run eval` inside $LEGACY
#            (writes $LEGACY/public/results/*.json and $OUT/legacy/evaluation.json)
#   ours     credential-eval bench and eval pipelines, each twice (runs 1 and 2),
#            and the compat bench rendering of run 1
#   compare  tools/parity/compare.mjs for both pipelines, plus the run-1/run-2
#            semantic digests
#
# Never commit $OUT: it holds fixture-derived rows. The sanitized summaries
# (counts, ids and digests only) are what docs/parity/ records.
set -eu
: "${LEGACY:?set LEGACY to the pinned legacy clone}"
: "${PEER_BIN:?set PEER_BIN to the pinned peer scanner directory}"
: "${OUT:?set OUT to an output directory}"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
BIN="$ROOT/target/release/credential-eval"
JOBS=${JOBS:-8}
export PATH="$PEER_BIN:$PATH"
STEP=${1:-all}
mkdir -p "$OUT/export" "$OUT/legacy" "$OUT/ce"

step_export() {
  "$LEGACY/node_modules/.bin/tsx" "$ROOT/tools/legacy-export/export.mts" "$LEGACY" "$OUT/export"
}

step_legacy() {
  (cd "$LEGACY" && npm run bench -- --live-peers) > "$OUT/legacy/bench.log" 2>&1
  (cd "$LEGACY" && npm run eval -- --output="$OUT/legacy/evaluation.json") > "$OUT/legacy/eval.log" 2>&1
}

step_ours() {
  (cd "$ROOT" && cargo build --release --locked -p credential-eval-cli)
  (cd "$ROOT/adapters/node" && npm ci --ignore-scripts --no-audit --no-fund) > /dev/null
  for run in 1 2; do
    "$BIN" run --corpus "$OUT/export/snapshot.json" --config "$ROOT/tools/parity/run-config.json" \
      --node-dir "$ROOT/adapters/node" --jobs "$JOBS" \
      --out "$OUT/ce/bench-artifact-$run.json" --observations-out "$OUT/ce/bench-observations-$run.json" \
      2> "$OUT/ce/bench-$run.log"
    "$BIN" run --corpus "$OUT/export/snapshot.json" --config "$ROOT/tools/parity/run-config.json" \
      --node-dir "$ROOT/adapters/node" --jobs "$JOBS" \
      --methods twin,benign,mutation,metamorphic,differential --reference redact-secret \
      --evidence "$OUT/export/evidence.json" --seed legacy-category \
      --legacy-eval-out "$OUT/ce/eval-legacy-$run.json" \
      --out "$OUT/ce/eval-artifact-$run.json" --observations-out "$OUT/ce/eval-observations-$run.json" \
      2> "$OUT/ce/eval-$run.log"
  done
  "$BIN" compat legacy-bench --artifact "$OUT/ce/bench-artifact-1.json" \
    --index "$OUT/export/legacy-index.json" --out-dir "$OUT/ce/bench-legacy-1"
}

step_compare() {
  status=0
  node "$ROOT/tools/parity/compare.mjs" bench "$LEGACY/public/results" "$OUT/ce/bench-legacy-1" \
    --observations "$OUT/ce/bench-observations-1.json" --json "$OUT/bench-summary.json" || status=1
  node --max-old-space-size=16384 "$ROOT/tools/parity/compare.mjs" eval "$OUT/legacy/evaluation.json" \
    "$OUT/ce/eval-legacy-1.json" --observations "$OUT/ce/eval-observations-1.json" \
    --snapshot "$OUT/export/snapshot.json" --json "$OUT/eval-summary.json" || status=1
  for pipeline in bench eval; do
    for run in 1 2; do
      printf '%s run %s: ' "$pipeline" "$run"
      grep '^semantic digest' "$OUT/ce/$pipeline-$run.log"
    done
  done
  return $status
}

case "$STEP" in
  export) step_export ;;
  legacy) step_legacy ;;
  ours) step_ours ;;
  compare) step_compare ;;
  all) step_export; step_legacy; step_ours; step_compare ;;
  *) echo "unknown step $STEP" >&2; exit 2 ;;
esac
